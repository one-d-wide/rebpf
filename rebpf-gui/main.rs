use iced::{
    Subscription, Theme,
    futures::{self, SinkExt, StreamExt},
    keyboard::{self, Key, key},
    window,
};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};
use tokio::sync::Semaphore;
use zbus::{Connection, proxy, proxy::CacheProperties, zvariant::OwnedValue};

use message::{
    Attached, D, M, Match, Rx, SERVICE_NAME_DBUS, Settings, Stats, TrayState, TrayTheme, Tx,
};

static mut RX_M: Option<Rx<M>> = None;
static mut RX_D: Option<Rx<D>> = None;
static mut RX_T: Option<Rx<TrayState>> = None;

#[derive(argh::FromArgs)]
/// Per-process network traffic redirection using eBPF.
#[argh(help_triggers("-h", "--help"))]
struct CliArgs {
    /// start in tray
    #[argh(switch)]
    tray: bool,
    /// verbose output, same as RUST_LOG=info
    #[argh(switch)]
    verbose: bool,
}

fn main() -> iced::Result {
    let args: CliArgs = argh::from_env();

    let logger_env =
        env_logger::Env::default().default_filter_or(if args.verbose { "info" } else { "warn" });
    env_logger::Builder::from_env(logger_env)
        .filter_module("zbus", log::LevelFilter::Warn)
        .init();

    let (m_tx, m_rx) = futures::channel::mpsc::unbounded();
    let (d_tx, d_rx) = futures::channel::mpsc::unbounded();
    let (t_tx, t_rx) = futures::channel::mpsc::unbounded();

    // How else are we supposed to bring in non-Clone-able Rx<T> into Fn() closure?!
    #[allow(static_mut_refs)]
    unsafe {
        RX_M.replace(m_rx);
        RX_D.replace(d_rx);
        RX_T.replace(t_rx);
    }

    let tray_theme_res = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let conn = zbus::Connection::session().await?;
            let proxy = dbus::settings::SettingsProxy::new(&conn).await?;
            let val = proxy
                .read_one("org.freedesktop.appearance", "color-scheme")
                .await?;
            let val: u32 = val.downcast_ref()?;
            zbus::Result::Ok(val)
        });

    let tray_theme = match tray_theme_res {
        zbus::Result::Ok(2) => TrayTheme::Light,
        zbus::Result::Ok(_) => TrayTheme::Dark,
        zbus::Result::Err(err) => {
            log::info!("Can't get system theme, defaulting to dark: {err}");
            TrayTheme::Dark
        }
    };

    iced::daemon(
        {
            let m_tx = m_tx.clone();
            move || {
                if !args.tray {
                    m_tx.unbounded_send(M::WindowOpen).unwrap();
                }
                (
                    {
                        gui::State {
                            tray_theme,
                            d_tx: Some(d_tx.clone()),
                            t_tx: Some(t_tx.clone()),
                            proc_input_kind: gui::KIND_DEFAULT,
                            proc_input_dir: "redirect",
                            proc_input_default_dir: "bypass",
                            ..Default::default()
                        }
                    },
                    iced::Task::future(background(m_tx.clone(), d_tx.clone())),
                )
            }
        },
        gui::update,
        gui::view,
    )
    .subscription(|_| {
        Subscription::batch([
            window::close_requests().map(M::WindowCloseId),
            keyboard::listen().filter_map(|e| match e {
                keyboard::Event::KeyPressed {
                    key: Key::Named(key::Named::Escape),
                    ..
                } => Some(M::Esc),
                _ => None,
            }),
            Subscription::run(|| {
                #[allow(static_mut_refs)]
                let mut r = unsafe { RX_M.take().unwrap() };
                iced::stream::channel(16, async move |mut output| {
                    loop {
                        output.send(r.recv().await.unwrap()).await.unwrap();
                    }
                })
            }),
        ])
    })
    .theme(match tray_theme {
        TrayTheme::Dark => Theme::Dark,
        TrayTheme::Light => Theme::Light,
    })
    .title(message::NAME)
    .run()
}

const ERR: zbus::fdo::Error = zbus::fdo::Error::ServiceUnknown(String::new());
const ERR_FN: fn() -> zbus::Error = || zbus::Error::FDO(Box::new(ERR));

async fn listen_props(
    conn: &Connection,
    proxy: dbus::service::SerProxy<'_>,
    m_tx: Tx<M>,
) -> zbus::Result<()> {
    let h = proxy.attached().await?;
    m_tx.unbounded_send(M::Attached(Attached::from_hashmap(h)))
        .unwrap();

    let h = proxy.matches().await?;
    m_tx.unbounded_send(M::Matches(h.into_iter().map(Match::from_hashmap).collect()))
        .unwrap();

    let h = proxy.config().await?;
    m_tx.unbounded_send(M::Settings(Settings::from_hashmap(h)))
        .unwrap();

    let props_proxy = zbus::fdo::PropertiesProxy::new(&conn, SERVICE_NAME_DBUS, "/").await?;
    let mut iter = props_proxy.receive_properties_changed().await?;

    while let Some(n) = iter.next().await {
        let (_, props, _): (String, HashMap<String, OwnedValue>, Vec<String>) =
            n.message().body().deserialize()?;

        for (k, _) in props.into_iter() {
            match k.as_str() {
                "Attached" => {
                    let h = proxy.attached().await?;
                    m_tx.unbounded_send(M::Attached(Attached::from_hashmap(h)))
                        .unwrap();
                }
                "Matches" => {
                    let h = proxy.matches().await?;
                    m_tx.unbounded_send(M::Matches(
                        h.into_iter().map(Match::from_hashmap).collect(),
                    ))
                    .unwrap();
                }
                "Config" => {
                    let h = proxy.config().await?;
                    m_tx.unbounded_send(M::Settings(Settings::from_hashmap(h)))
                        .unwrap();
                }
                _ => {}
            }
        }
    }

    Err(ERR_FN())
}

async fn listen_proc_names(
    proxy: dbus::service::SerProxy<'_>,
    m_tx: Tx<M>,
    sema: Arc<Semaphore>,
) -> zbus::Result<()> {
    loop {
        let _guard = sema.acquire().await.unwrap();

        let mut set = HashSet::new();

        if let Ok(records) = proxy.get_dns_records().await {
            set.extend(records.into_iter().filter_map(|mut r| r.remove("name")));
        }

        set.extend(
            proxy
                .get_proc_names()
                .await?
                .split('\n')
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string()),
        );

        m_tx.unbounded_send(M::ActiveProcs(set)).unwrap();

        let h = proxy.get_stats().await?;
        m_tx.unbounded_send(M::Stats(Stats::from_hashmap(h)))
            .unwrap();

        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

async fn process_requests_sema(sema: &Arc<Semaphore>, d: &D) -> bool {
    match d {
        D::WindowClosed => {
            sema.acquire().await.unwrap().forget();
            true
        }
        D::WindowOpened => {
            sema.add_permits(1);
            true
        }
        _ => false,
    }
}

async fn process_requests(
    proxy: dbus::service::SerProxy<'_>,
    m_tx: Tx<M>,
    d_rx: &mut Rx<D>,
    sema: Arc<Semaphore>,
) -> zbus::Result<()> {
    loop {
        let d = d_rx.recv().await.unwrap();
        log::debug!("Got event {d:?}");
        let res = match d {
            D::WindowOpened | D::WindowClosed => {
                process_requests_sema(&sema, &d).await;
                continue;
            }
            D::Enable => {
                let _ = proxy.enable().await;
                continue;
            }
            D::Disable => {
                let _ = proxy.disable().await;
                continue;
            }
            D::ChangeOutput(new_out) => proxy.change_output(&new_out).await,
            D::SettingsUpdate(m) => {
                let h = m.into_hashmap();
                log::debug!("{h:?}");
                proxy.update_config(&h).await
            }
            D::MatchAdd(m) => {
                let h = m.into_hashmap();
                log::debug!("{h:?}");
                proxy.add_match(&h).await
            }
            D::MatchDelete(m) => {
                let h = m.into_hashmap();
                log::debug!("{h:?}");
                proxy.delete_match(&h).await
            }
            D::MatchUpdate(f, t) => {
                let f = f.into_hashmap();
                let t = t.into_hashmap();
                log::debug!("{f:?}");
                log::debug!("{t:?}");
                proxy.update_match(&f, &t).await
            }
        };

        if let Err(err) = res {
            m_tx.unbounded_send(M::DbusErr(err)).unwrap();
        }
    }
}

async fn dbus_service_harness(m_tx: Tx<M>) -> zbus::Result<()> {
    #[allow(static_mut_refs)]
    let mut d_rx = unsafe { RX_D.take().unwrap() };

    let conn = Connection::system().await?;
    let proxy = dbus::service::SerProxy::builder(&conn)
        .cache_properties(CacheProperties::No)
        .build()
        .await?;

    let own_proxy = proxy::Proxy::new(&conn, SERVICE_NAME_DBUS, "/", SERVICE_NAME_DBUS).await?;
    let mut own_iter = own_proxy.receive_owner_changed().await?;

    let mut err_sent = false;
    let sema = Arc::new(Semaphore::new(0));
    loop {
        let res = tokio::select! {
            res = proxy.attached() => res,
            d = d_rx.recv() => {
                process_requests_sema(&sema, &d.unwrap()).await;
                continue;
            },
        };

        if let Err(err) = res {
            if !err_sent {
                err_sent = true;
                m_tx.unbounded_send(M::DbusCantConnect(err)).unwrap();
            }
            own_iter.next().await;
            continue;
        }

        err_sent = false;
        m_tx.unbounded_send(M::DbusConnected).unwrap();

        let err = tokio::select! {
            _ = own_iter.next() => continue,
            err = listen_props(&conn, proxy.clone(), m_tx.clone()) => err,
            err = listen_proc_names(proxy.clone(), m_tx.clone(), sema.clone()) => err,
            err = process_requests(proxy.clone(), m_tx.clone(), &mut d_rx, sema.clone()) => err,
        };
        let err = err.unwrap_err();

        m_tx.unbounded_send(M::DbusFail(err)).unwrap();
    }
}

async fn background(m_tx: Tx<M>, d_tx: Tx<D>) -> M {
    #[allow(static_mut_refs)]
    let t_rx = unsafe { RX_T.take().unwrap() };
    tokio::spawn(tray::tray(m_tx.clone(), d_tx.clone(), t_rx));

    tokio::spawn(async move {
        let err = dbus_service_harness(m_tx.clone()).await.unwrap_err();
        m_tx.unbounded_send(M::DbusFail(err)).unwrap();
    });

    M::Nop
}
