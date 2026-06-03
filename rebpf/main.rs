use argh::FromArgs;
use eyre::bail;
use log::{info, warn};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fmt::Display,
    fs::File,
    io::{Read, Seek, Write},
    net::{IpAddr, Ipv4Addr},
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    time::Duration,
};
use tokio::{
    sync::{Mutex, watch},
    time::Instant,
};
use zbus::Connection;

#[allow(unused)]
#[allow(non_camel_case_types)]
#[allow(non_upper_case_globals)]
mod bindings;
use bindings as bpf;

mod dbus;
mod macros;
mod netlink;

struct Watch<T> {
    tx: watch::Sender<T>,
    rx: watch::Receiver<T>,
}

impl<T> Watch<T> {
    fn new(val: T) -> Self {
        let (tx, rx) = watch::channel(val);
        Self { tx, rx }
    }
}

impl<T: Default> Default for Watch<T> {
    fn default() -> Self {
        let (tx, rx) = watch::channel(T::default());
        Self { tx, rx }
    }
}

#[derive(Clone, Debug, Default)]
struct Route {
    ifindex: u32,
    ifname: String,
    mac: Option<[u8; 6]>,
    nexthop_addr: Option<IpAddr>,
    nexthop_mac: Option<[u8; 6]>,
    addr: Option<IpAddr>,
}

#[derive(Clone, Debug, Default)]
struct Routes {
    from: Option<Route>,
    to: Option<Route>,
}

struct BpfCtx {
    dtime_sec: f64,
    stats_time: Instant,
    stats: bpf::Stats,

    matches_time: Instant,
    matches: Arc<String>,
    ptr: usize,
    len: u64,
    cap: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
struct State {
    enable: bool,
    to_dev: String,
    config: Config,
    matches: Matches,
    generation: u64,
}

struct Ctx {
    conn: &'static Connection,
    state: Watch<State>,
    attached: Watch<bool>,
    blocker: Watch<&'static str>,
    to_changed: Watch<()>,
    from_changed: Watch<()>,
    routes_changed: Watch<Routes>,
    do_reload: Watch<()>,
    bpf: Mutex<BpfCtx>,
}

#[derive(FromArgs)]
/// Per-process network traffic redirection using eBPF.
#[argh(help_triggers("-h", "--help"))]
struct CliArgs {
    /// start enabled
    #[argh(switch)]
    enable: bool,
    /// start disabled
    #[argh(switch)]
    disable: bool,
    /// state directory
    #[argh(option)]
    state_dir: Option<PathBuf>,
    /// verbose output, same as RUST_LOG=debug
    #[argh(switch)]
    verbose: bool,
}

fn main() -> eyre::Result<()> {
    let args: CliArgs = argh::from_env();

    let logger_env =
        env_logger::Env::default().default_filter_or(if args.verbose { "debug" } else { "warn" });
    env_logger::Builder::from_env(logger_env).init();

    unsafe {
        bpf::bpf_init();
    }

    let state_dir = args
        .state_dir
        .as_deref()
        .unwrap_or(Path::new("/var/lib/rebpf"));
    let _ = std::fs::create_dir(state_dir);

    let mut files = Vec::new();
    for i in 0..2 {
        let path = state_dir.join(format!("rebpf.state.{i}"));
        let file = std::fs::File::options()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path);

        match file {
            Ok(file) => files.push((path, file)),
            Err(err) => {
                warn!("Can't open state file: {path:?}: {err}");
                files.clear();
                break;
            }
        }
    }

    let conn = zbus::blocking::connection::Builder::system()?.build()?;

    unsafe {
        bpf::bpf_drop_caps();
    }

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Failed building the Runtime")
        .block_on(run(args, files, conn))
}

async fn run(
    args: CliArgs,
    mut files: Vec<(PathBuf, File)>,
    conn: zbus::blocking::Connection,
) -> eyre::Result<()> {
    let conn = zbus::Connection::from(conn);

    let state = Watch::new(State {
        enable: false,
        to_dev: String::new(),
        config: Default::default(),
        matches: Matches::default(),
        generation: 0,
    });

    let mut save_state_handle = None;
    if !files.is_empty() {
        let mut last_i = 0;
        let mut last_gen = 0;
        let mut buf = String::new();
        for (i, (p, c)) in files.iter_mut().enumerate() {
            buf.clear();
            info!("Reading state file {p:?}");
            c.read_to_string(&mut buf)?;

            let next: State = match serde_json::from_str(&buf) {
                Ok(next) => next,
                Err(err) => {
                    warn!("Error parsing state file: {err}");
                    continue;
                }
            };

            if last_gen <= next.generation {
                last_gen = next.generation;
                last_i = i;
                state.tx.send(next).unwrap();
            }
        }

        let mut rx = state.rx.clone();
        rx.mark_unchanged();
        save_state_handle = Some(tokio::spawn(save_state(rx, files, last_i)));
    };

    if args.enable && args.disable {
        bail!("Can't simultaneously set --enable and --disable");
    }
    if (args.enable || args.disable) && state.rx.borrow().enable != args.enable {
        state.tx.send_modify(|s| s.enable = args.enable);
    }

    let ctx = Ctx {
        conn: Box::leak(Box::new(conn)),
        attached: Default::default(),
        state,
        blocker: Default::default(),
        to_changed: Default::default(),
        from_changed: Default::default(),
        routes_changed: Default::default(),
        do_reload: Default::default(),
        bpf: Mutex::new(BpfCtx {
            dtime_sec: Default::default(),
            stats_time: Instant::now(),
            stats: unsafe { std::mem::zeroed() },
            matches_time: Instant::now(),
            matches: Default::default(),
            ptr: 0,
            len: 0,
            cap: 0,
        }),
    };
    let ctx = Box::leak(Box::new(ctx));

    ctx.conn.object_server().at("/", dbus::Item { ctx }).await?;
    ctx.conn.request_name("service.rebpf").await?;

    ctx.to_changed.tx.send(()).unwrap();
    ctx.from_changed.tx.send(()).unwrap();

    tokio::select! {
        res = tokio::spawn(netlink::watch_reload(ctx)) => res??,
        res = tokio::spawn(netlink::watch_routes(ctx)) => res??,
        res = tokio::task::spawn_blocking(|| netlink::watch_multicast(ctx)) => res??,
        res = save_state_handle.unwrap_or_else(|| tokio::spawn(std::future::pending())) => res??,
    };

    Ok(())
}

async fn save_state(
    mut conf: watch::Receiver<State>,
    mut files: Vec<(PathBuf, File)>,
    mut i: usize,
) -> eyre::Result<()> {
    let mut generation = conf.borrow().generation;

    loop {
        conf.changed().await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        info!("Saving state in slot {i}");
        let mut conf = conf.borrow_and_update().clone();
        generation += 1;
        conf.generation = generation;
        let buf = serde_json::to_vec(&conf).unwrap();
        files[i].1.seek(std::io::SeekFrom::Start(0))?;
        files[i].1.write_all(&buf)?;
        files[i].1.flush()?;
        unsafe {
            libc::ftruncate(files[i].1.as_raw_fd(), buf.len() as i64);
        }
        i = (i + 1) % files.len();
    }
}

to_from_enum! {
    #[derive(Clone, Debug, Default, PartialEq)]
    #[derive(Serialize, Deserialize)]
    #[allow(non_camel_case_types)]
    enum Kind {
        #[default]
        basename,
        substring,
        full,
        prefix,
    }
}

to_from_enum! {
    #[derive(Clone, Debug, Default, PartialEq)]
    #[derive(Serialize, Deserialize)]
    #[allow(non_camel_case_types)]
    enum Direction {
        #[default]
        redirect,
        bypass,
    }
}

to_from_hashmap_or_default! {
    #[derive(Clone, Debug, PartialEq)]
    #[derive(Serialize, Deserialize)]
    #[serde(default)]
    struct Config {
        => probe_ipv4_addr: Ipv4Addr,
        => allow_lan: bool,
        => spoof_dns: bool,
        => spoof_dns_ipv4: Ipv4Addr,
        => drop_egress_without_output: bool,
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            probe_ipv4_addr: "1.2.3.4".parse().unwrap(),
            allow_lan: true,
            spoof_dns: false,
            spoof_dns_ipv4: "8.8.8.8".parse().unwrap(),
            drop_egress_without_output: false,
        }
    }
}

to_from_hashmap! {
    #[derive(Clone, Debug, Default, PartialEq)]
    #[derive(Serialize, Deserialize)]
    #[serde(default)]
    struct Match {
        pattern: String,
        => kind: Kind,
        => direction: Direction,
        user: String,
        => => uid: u32,
    }
}

impl Match {
    fn applies_to(&self, r: &Match) -> bool {
        self.kind == r.kind
            && self.pattern == r.pattern
            && self.direction == r.direction
            && (self.uid == 0
                || self.uid == r.uid
                || (!self.user.is_empty() && self.user == r.user))
    }

    fn is_eq_to(&self, r: &Match) -> bool {
        self.kind == r.kind
            && self.pattern == r.pattern
            && self.direction == r.direction
            && self.uid == r.uid
            && self.user == r.user
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct Matches {
    matches: Vec<Match>,
    strings_len: usize,
    generation: u64,
}

impl Matches {
    fn add(&mut self, new: Match) -> eyre::Result<()> {
        if self.matches.iter().any(|m| m.applies_to(&new)) {
            return Ok(());
        }

        let new_len = self.strings_len + new.pattern.len() + 1;
        if new_len >= bpf::STRINGS_BUF_MAX as usize
            || self.matches.len() + 1 > bpf::MATCHES_BUF_MAX as usize
        {
            bail!("Not enough space for a new match");
        }

        self.strings_len = new_len;
        self.matches.push(new);
        self.generation += 1;
        Ok(())
    }

    fn replace(&mut self, from: Match, to: Match) -> eyre::Result<()> {
        let Some(pos) = self.matches.iter().position(|m| m.is_eq_to(&from)) else {
            bail!("No such match");
        };

        let new_len = self.strings_len - self.matches[pos].pattern.len() + to.pattern.len();
        if new_len >= bpf::STRINGS_BUF_MAX as usize {
            bail!("Not enough space for a new match");
        }

        self.matches[pos] = to;
        self.strings_len = new_len;
        self.generation += 1;
        Ok(())
    }

    fn del(&mut self, new: Match) -> eyre::Result<()> {
        let Some(pos) = self.matches.iter().position(|m| m.is_eq_to(&new)) else {
            bail!("No such match");
        };

        let old = self.matches.remove(pos);
        self.strings_len -= old.pattern.len() + 1;
        self.generation += 1;
        Ok(())
    }
}
