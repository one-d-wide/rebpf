use argh::FromArgs;
use eyre::{Context, bail};
use log::{info, warn};
use netlink_socket2::NetlinkSocket;
use std::{
    ffi::CString,
    fs::File,
    io::{self, Read, Seek, Write},
    os::{
        fd::AsRawFd,
        linux::net::SocketAddrExt,
        unix::{
            ffi::OsStrExt,
            net::{SocketAddr, UnixStream},
        },
    },
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{
    signal::unix::SignalKind,
    sync::{Mutex, watch::Receiver},
    task::JoinSet,
    time::Instant,
};
use zbus::address::{self, transport};

mod dbus;
mod dns;
mod netlink;

use rebpf::{BpfCtx, Ctx, DnsState, Matches, State, Watch, bpf};

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

    /// dbus user name or uid
    #[argh(option)]
    dbus_user: Option<CString>,
}

fn main() -> eyre::Result<()> {
    let args: CliArgs = argh::from_env();

    let logger_env =
        env_logger::Env::default().default_filter_or(if args.verbose { "debug" } else { "warn" });
    env_logger::Builder::from_env(logger_env)
        .filter_module("zbus", log::LevelFilter::Warn)
        .init();

    let (refresh_tx, mut refresh_rx) = std::os::unix::net::UnixStream::pair()?;

    unsafe {
        check_kernel_version().ok();

        if libc::getuid() != 0 {
            warn!("Rebpf requires root capabilities to load the eBPF program and do pidfd_getfd()");
        }

        bpf::bpf_init();

        // Fork off a privileged process dedicated to marking sockets.
        // The main process does a bunch of parsing, so it's probably better to
        // have it drop root capabilities.
        if libc::fork() == 0 {
            drop(refresh_tx);

            let mut buf = [0u8; 4];
            loop {
                refresh_rx.read_exact(&mut buf[..])?;

                let mark = u32::from_ne_bytes(buf);
                bpf::bpf_refresh_sockets(mark);

                refresh_rx.write_all(&0u32.to_ne_bytes())?;
            }
        } else {
            drop(refresh_rx);
        }
    }

    let (uid, gid) = unsafe {
        if let Some(name) = &args.dbus_user {
            if name.as_bytes().iter().all(|b| b.is_ascii_digit()) {
                let uid = name.to_str()?.parse()?;
                (uid, uid)
            } else {
                let pw = libc::getpwnam(name.as_ptr());
                if pw.is_null() {
                    bail!("Can't get user {name:?}: {}", io::Error::last_os_error());
                }
                ((*pw).pw_uid, (*pw).pw_uid)
            }
        } else {
            (libc::getuid(), libc::getgid())
        }
    };

    let mut conn = None;
    if uid == 0 {
        // A dedicated D-Bus user isn't set up, connect to the bus as root before dropping caps
        conn = match zbus::Address::system()?.transport() {
            address::Transport::Unix(unix) => {
                let path = match unix.path() {
                    transport::UnixSocket::File(path) => SocketAddr::from_pathname(path)?,
                    transport::UnixSocket::Abstract(path) => {
                        SocketAddr::from_abstract_name(path.as_bytes())?
                    }
                    t => bail!("Unknown dbus transport: {t}"),
                };
                let sock = UnixStream::connect_addr(&path)
                    .with_context(|| format!("Can't connect to {path:?}"))?;
                Some((sock, uid))
            }
            t => bail!("Unknown dbus transport: {t}"),
        };
    }

    let (state, files) = load_state(&args)?;

    // Check sanity before dropping caps
    if let Ok(iter) = std::fs::read_dir("/proc/self/task/") {
        assert_eq!(iter.count(), 1);
    }

    unsafe {
        bpf::bpf_drop_caps(uid, gid);
    }

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Failed building the Runtime")
        .block_on(wrap_run(args, state, files, conn, refresh_tx))
}

async fn wrap_run(
    args: CliArgs,
    state: Watch<State>,
    files: Option<Files>,
    conn: Option<(UnixStream, u32)>,
    refresh_tx: UnixStream,
) -> eyre::Result<()> {
    let mut code = 0;
    if let Err(err) = run(args, state, files, conn, refresh_tx).await {
        log::error!("{err:?}");
        code = 1;
    }
    std::process::exit(code)
}

async fn run(
    args: CliArgs,
    state: Watch<State>,
    files: Option<Files>,
    conn: Option<(UnixStream, u32)>,
    refresh_tx: UnixStream,
) -> eyre::Result<()> {
    let conn = if let Some((conn, conn_uid)) = conn {
        conn.set_nonblocking(true)?;
        let conn = tokio::net::UnixStream::from_std(conn)?;
        zbus::connection::Builder::unix_stream(conn)
            .user_id(conn_uid)
            .build()
            .await?
    } else {
        zbus::connection::Connection::system().await?
    };

    if args.enable && args.disable {
        bail!("Can't simultaneously set --enable and --disable");
    }
    if (args.enable || args.disable) && state.tx.borrow().enable != args.enable {
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
        dns: Mutex::new(DnsState {
            sock: NetlinkSocket::new(),
            ttl_sleeper: Default::default(),
            heap: Default::default(),
            hash: Default::default(),
            cache: Default::default(),
        }),
        dns_table: netlink::rand_table(),
        bpf: Mutex::new(BpfCtx {
            mark: None,
            matches_time: Instant::now(),
            matches: Default::default(),
            arena: Vec::new(),
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

    let mut sock = NetlinkSocket::new();
    netlink::setup_static_rules(ctx, &mut sock)?;

    let mut tasks = JoinSet::new();

    for kind in [
        SignalKind::interrupt(),
        SignalKind::terminate(),
        SignalKind::quit(),
        SignalKind::alarm(),
        SignalKind::hangup(),
    ] {
        if let Ok(mut signal) = tokio::signal::unix::signal(kind) {
            tasks.spawn(async move {
                signal.recv().await;
                Ok(())
            });
        }
    }

    if let Some(files) = files {
        tasks.spawn(save_state(files));
    }

    refresh_tx.set_nonblocking(true)?;
    tasks.spawn(netlink::watch_reload(ctx, refresh_tx.try_into()?));
    tasks.spawn(netlink::watch_routes(ctx));
    tasks.spawn(dns::watch_dns_routes(ctx));
    tasks.spawn(dns::watch_dns_ttl(ctx));
    tasks
        .spawn(async move { tokio::task::spawn_blocking(|| netlink::watch_multicast(ctx)).await? });
    tasks.spawn(async move {
        tokio::task::spawn_blocking(move || unsafe {
            bpf::bpf_run_dns_ringbuf(Some(dns::callback), &raw const ctx as *mut std::ffi::c_void);
        })
        .await?;
        bail!("DNS ringbuf listener exited unexpectedly");
    });

    let res = tasks.join_next().await.unwrap();
    tasks.shutdown().await;

    if let Some(mark) = ctx.bpf.lock().await.mark {
        netlink::clear_rules(&mut sock, mark).ok();
    }

    netlink::clear_static_rules(ctx, &mut sock).ok();

    res?
}

struct Files {
    rx: Receiver<State>,
    files: Vec<(PathBuf, File)>,
    last_i: usize,
}

fn load_state(args: &CliArgs) -> eyre::Result<(Watch<State>, Option<Files>)> {
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

    let state = Watch::new(State {
        enable: false,
        to_dev: String::new(),
        config: Default::default(),
        matches: Matches::default(),
        generation: 0,
    });

    if files.is_empty() {
        return Ok((state, None));
    }

    let mut rx = state.rx.clone();
    let mut last_i = 0;
    let mut last_gen = 0;
    let mut buf = String::new();
    for (i, (p, c)) in files.iter_mut().enumerate() {
        buf.clear();
        info!("Reading state file {p:?}");
        c.read_to_string(&mut buf)?;

        let mut next: State = match serde_json::from_str(&buf) {
            Ok(next) => next,
            Err(err) => {
                warn!("Error parsing state file: {err}");
                continue;
            }
        };

        if last_gen <= next.generation {
            last_gen = next.generation;
            last_i = i;
            next.matches.update();
            state.tx.send(next).unwrap();
        }
    }

    rx.mark_unchanged();

    Ok((state, Some(Files { rx, files, last_i })))
}

async fn save_state(files: Files) -> eyre::Result<()> {
    let Files {
        mut rx,
        mut files,
        mut last_i,
    } = files;
    let mut generation = rx.borrow().generation;

    loop {
        rx.changed().await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        info!("Saving state in slot {last_i}");
        let mut conf = rx.borrow_and_update().clone();
        generation += 1;
        conf.generation = generation;
        let buf = serde_json::to_vec(&conf).unwrap();
        files[last_i].1.seek(std::io::SeekFrom::Start(0))?;
        files[last_i].1.write_all(&buf)?;
        files[last_i].1.flush()?;
        unsafe {
            libc::ftruncate(files[last_i].1.as_raw_fd(), buf.len() as i64);
        }
        last_i = (last_i + 1) % files.len();
    }
}

fn check_kernel_version() -> eyre::Result<()> {
    unsafe {
        let mut uts: libc::utsname = std::mem::zeroed();
        if libc::uname(&raw mut uts) != 0 {
            return Err(io::Error::last_os_error().into());
        }

        let os = std::ffi::CStr::from_ptr(uts.sysname.as_ptr()).to_str()?;
        let ver = std::ffi::CStr::from_ptr(uts.release.as_ptr()).to_str()?;

        let (major, _) = ver.split_once('.').unwrap_or_default();
        let major: u32 = major.parse()?;

        if !os.eq_ignore_ascii_case("linux") || major < 7 {
            warn!("Rebpf only support Linux 7.0 and later. Current {os} version is {ver}.");
        }
    }
    return Ok(());
}
