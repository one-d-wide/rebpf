use argh::FromArgs;
use eyre::bail;
use log::{info, warn};
use netlink_socket2::NetlinkSocket;
use std::{
    fs::File,
    io::{Read, Seek, Write},
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{
    signal::unix::SignalKind,
    sync::{Mutex, watch},
    task::JoinHandle,
    time::Instant,
};

mod dbus;
mod netlink;

use rebpf::{BpfCtx, Ctx, Matches, State, Watch, bpf};

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

#[tokio::main(flavor = "current_thread")]
async fn main() -> eyre::Result<()> {
    let args: CliArgs = argh::from_env();

    let logger_env =
        env_logger::Env::default().default_filter_or(if args.verbose { "debug" } else { "warn" });
    env_logger::Builder::from_env(logger_env)
        .filter_module("zbus", log::LevelFilter::Warn)
        .init();

    let res = run(args).await;
    let mut code = 0;
    if let Err(err) = res {
        log::error!("{err:?}");
        code = 1;
    }
    std::process::exit(code)
}

async fn run(args: CliArgs) -> eyre::Result<()> {
    unsafe {
        bpf::bpf_init();
    }

    let conn = zbus::connection::Builder::system()?.build().await?;

    let state = Watch::new(State {
        enable: false,
        to_dev: String::new(),
        config: Default::default(),
        matches: Matches::default(),
        generation: 0,
    });

    let save_state_handle = load_state(&args, &state)?;

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
        default_route_changed: Default::default(),
        do_reload: Default::default(),
        stats: Default::default(),
        bpf: Mutex::new(BpfCtx {
            mark: None,
            matches_time: Instant::now(),
            matches: Default::default(),
            cstrings: Vec::with_capacity(bpf::STRINGS_BUF_MAX as usize),
            cmatches: Vec::with_capacity(bpf::MATCHES_BUF_MAX as usize),
            last_gen: 0,
            ptr: 0,
            len: 0,
            cap: 0,
        }),
    };
    let ctx = &*Box::leak(Box::new(ctx));

    ctx.conn.object_server().at("/", dbus::Item { ctx }).await?;
    ctx.conn.request_name("service.rebpf").await?;

    ctx.to_changed.tx.send(()).unwrap();
    ctx.from_changed.tx.send(()).unwrap();

    let mut signals = tokio::task::JoinSet::new();
    for kind in [
        SignalKind::interrupt(),
        SignalKind::terminate(),
        SignalKind::quit(),
    ] {
        if let Ok(mut signal) = tokio::signal::unix::signal(kind) {
            signals.spawn(async move {
                signal.recv().await;
            });
        }
    }

    let mut sock = NetlinkSocket::new();

    let res = tokio::select! {
        res = save_state_handle => res,
        _ = signals.join_next() => Ok(Ok(())),
        res = tokio::spawn(netlink::watch_reload(ctx)) => res,
        res = tokio::spawn(netlink::watch_routes(ctx)) => res,
        res = tokio::task::spawn_blocking(|| netlink::watch_multicast(ctx)) => res,
    };

    if let Some(mark) = ctx.bpf.lock().await.mark {
        netlink::clear_rules(&mut sock, mark).ok();
    }

    res?
}

fn load_state(args: &CliArgs, state: &Watch<State>) -> eyre::Result<JoinHandle<eyre::Result<()>>> {
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

    if files.is_empty() {
        return Ok(tokio::spawn(std::future::pending()));
    }

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
    Ok(tokio::spawn(save_state(rx, files, last_i)))
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
