use std::{
    collections::HashMap,
    ffi::{CStr, c_char},
    sync::Arc,
    time::Duration,
};
use tokio::time::Instant;
use zbus::{Connection, interface, message::Header};
use zbus_polkit::policykit1::{AuthorityProxy, CheckAuthorizationFlags, Subject};

use crate::{Config, Ctx, Match, Route, State, bpf};
use rebpf::{Config, Ctx, Match, Route, State, bpf};

async fn peer_uid(conn: &Connection, header: &Header<'_>) -> zbus::fdo::Result<u32> {
    let proxy = zbus::fdo::DBusProxy::new(conn).await?;
    let Some(sender) = header.sender() else {
        return Err(zbus::fdo::Error::AuthFailed(format!("Can't get UID")));
    };
    let res = proxy
        .get_connection_unix_user(zbus::names::BusName::Unique(sender.clone()))
        .await?;
    Ok(res)
}

#[must_use]
async fn auth_or_err(conn: &Connection, header: Header<'_>) -> zbus::fdo::Result<()> {
    let res = AuthorityProxy::new(conn)
        .await?
        .check_authorization(
            &Subject::new_for_message_header(&header).unwrap(),
            "service.rebpf.modify.system",
            &std::collections::HashMap::new(),
            CheckAuthorizationFlags::AllowUserInteraction.into(),
            "",
        )
        .await?;

    if !res.is_authorized {
        return Err(zbus::fdo::Error::AuthFailed(
            if let Some(member) = header.member() {
                format!("Not permitted to {member}")
            } else {
                format!("Not permitted")
            },
        ));
    }

    Ok(())
}

pub struct Item {
    pub ctx: &'static Ctx,
}

fn str_to_inval<S: ToString>(err: S) -> zbus::fdo::Error {
    zbus::fdo::Error::InvalidArgs(err.to_string())
}

fn err_to_inval<E: Error>(err: E) -> zbus::fdo::Error {
    zbus::fdo::Error::InvalidArgs(err.to_string())
}

fn eyre_to_inval(err: eyre::ErrReport) -> zbus::fdo::Error {
    zbus::fdo::Error::InvalidArgs(err.to_string())
}

impl Item {
    async fn try_modify_matches(
        &self,
        f: impl FnOnce(&mut State) -> zbus::fdo::Result<()>,
    ) -> zbus::fdo::Result<()> {
        let mut err = Ok(());
        self.ctx.state.tx.send_if_modified(|m| {
            err = f(m);
            err.is_ok()
        });
        err?;

        self.matches_changed(
            self.ctx
                .conn
                .object_server()
                .interface::<&str, Item>("/")
                .await?
                .signal_emitter(),
        )
        .await
        .ok();

        Ok(())
    }
}

#[interface(interface = "service.rebpf")]
impl Item {
    async fn enable(&self) {
        self.ctx.state.tx.send_modify(|s| s.enable = true);
    }

    async fn disable(&self) {
        self.ctx.state.tx.send_modify(|s| s.enable = false);
    }

    async fn toggle(&self) {
        self.ctx.state.tx.send_modify(|s| s.enable = !s.enable);
    }

    async fn change_output(
        &self,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] header: Header<'_>,
        output: String,
    ) -> zbus::fdo::Result<()> {
        auth_or_err(conn, header).await?;

        self.ctx.state.tx.send_modify(|s| s.to_dev = output);
        Ok(())
    }

    async fn update_config(
        &self,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] header: Header<'_>,
        new: HashMap<String, String>,
    ) -> zbus::fdo::Result<()> {
        auth_or_err(conn, header).await?;

        let new =
            Config::from_hashmap(new, &self.ctx.state.rx.borrow().config).map_err(eyre_to_inval)?;
        self.ctx.state.tx.send_modify(|s| s.config = new);

        self.config_changed(
            self.ctx
                .conn
                .object_server()
                .interface::<&str, Item>("/")
                .await?
                .signal_emitter(),
        )
        .await
        .ok();
        Ok(())
    }

    async fn add_match(
        &self,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] header: Header<'_>,
        new: HashMap<String, String>,
    ) -> zbus::fdo::Result<()> {
        let uid = peer_uid(conn, &header).await?;
        let new = Match::from_hashmap(new, uid).map_err(eyre_to_inval)?;

        if uid != 0 && uid != new.uid {
            auth_or_err(conn, header).await?;
        }

        self.try_modify_matches(|m| m.matches.add(new).map_err(eyre_to_inval))
            .await
    }

    async fn update_match(
        &self,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] header: Header<'_>,
        from: HashMap<String, String>,
        to: HashMap<String, String>,
    ) -> zbus::fdo::Result<()> {
        let uid = peer_uid(conn, &header).await?;
        let from = Match::from_hashmap(from, uid).map_err(eyre_to_inval)?;
        let to = Match::from_hashmap(to, uid).map_err(eyre_to_inval)?;

        if uid != 0 && (uid != from.uid || uid != to.uid) {
            auth_or_err(conn, header).await?;
        }

        self.try_modify_matches(|m| m.matches.replace(from, to).map_err(eyre_to_inval))
            .await
    }

    async fn delete_match(
        &self,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] header: Header<'_>,
        del: HashMap<String, String>,
    ) -> zbus::fdo::Result<()> {
        let uid = peer_uid(conn, &header).await?;
        let del = Match::from_hashmap(del, uid).map_err(eyre_to_inval)?;

        if uid != 0 && uid != del.uid {
            auth_or_err(conn, header).await?;
        }

        self.try_modify_matches(|m| m.matches.del(del).map_err(eyre_to_inval))
            .await
    }

    async fn get_proc_names(&self) -> Arc<String> {
        let mut lock = self.ctx.bpf.lock().await;
        if lock.matches_time.elapsed() > Duration::from_secs(1) {
            lock.matches_time = Instant::now();
            unsafe {
                bpf::bpf_get_proc_names(
                    &mut lock.ptr as *mut usize as *mut *mut c_char,
                    &mut lock.len as *mut u64,
                    &mut lock.cap as *mut u64,
                );

                assert_ne!(lock.ptr, 0);
                assert_ne!(lock.len, 0);
                lock.matches = Arc::new(
                    CStr::from_ptr(lock.ptr as *const i8)
                        .to_string_lossy()
                        .to_string(),
                );
            }
        }

        lock.matches.clone()
    }

    async fn get_stats(&self) -> HashMap<&str, String> {
        let mut stats = self.ctx.stats.lock().await;
        if stats.cur.time.elapsed() > Duration::from_secs(1) {
            if let Err(err) =
                crate::netlink::get_stats(&self.ctx.state.rx.borrow().to_dev, &mut stats)
            {
                debug!("Error getting stats: {err}");
                *stats = Default::default();
            }
        }

        let mut tx = stats.cur.tx_bytes.saturating_sub(stats.prev.tx_bytes);
        let mut rx = stats.cur.rx_bytes.saturating_sub(stats.prev.rx_bytes);
        let mut dt = stats.cur.time.duration_since(stats.prev.time).as_secs_f32();

        if stats.prev.tx_bytes == 0 && stats.prev.rx_bytes == 0 {
            tx = 0;
            rx = 0;
            dt = 0.0;
        }

        let mut res = HashMap::new();
        res.insert("tx-bytes", format!("{tx}"));
        res.insert("rx-bytes", format!("{rx}"));
        res.insert("dtime-sec", format!("{dt}",));
        res
    }

    // async fn get_dump(&self) -> HashMap<&str, String> {
    //     unsafe {
    //         let mut dump: bpf::Dump = std::mem::zeroed();
    //         bpf::bpf_get_dump(&mut ddump as *mut bpf::Dump);
    //         dbg!(dump);
    //     }
    //     HashMap::new()
    // }

    async fn force_reload(&self) {
        self.ctx.do_reload.tx.send(()).unwrap();
    }

    #[zbus(property)]
    async fn attached(&self) -> HashMap<String, String> {
        let mut res = HashMap::new();
        let c = self.ctx;
        res.insert(
            format!("enabled"),
            format!("{}", c.state.rx.borrow().enable),
        );
        res.insert(format!("attached"), format!("{}", *c.attached.rx.borrow()));
        let blocker = c.blocker.rx.borrow().clone();
        if !blocker.is_empty() {
            res.insert(format!("blocker"), blocker.to_string());
        }

        let mut fmt_dev = |p: &str, r: &Route| {
            res.insert(format!("{p}is-up"), format!("{}", r.is_up));
            res.insert(format!("{p}ifname"), r.ifname.clone());
            res.insert(format!("{p}ifindex"), format!("{}", r.ifindex));
            if let Some(addr) = r.addrs.first() {
                res.insert(format!("{p}addr"), format!("{addr}"));
            }
        };

        let routes = c.routes_changed.rx.borrow();
        if let Some(to) = routes.as_ref() {
            fmt_dev("to-", to);
        } else {
            res.insert(format!("to-ifname"), c.state.rx.borrow().to_dev.clone());
        }

        res
    }

    #[zbus(property)]
    async fn matches(&self) -> Vec<HashMap<&str, String>> {
        let mut res = Vec::new();
        for m in &self.ctx.state.rx.borrow().matches.matches {
            res.push(m.to_hashmap())
        }
        res
    }

    #[zbus(property)]
    async fn config(&self) -> HashMap<&str, String> {
        self.ctx.state.rx.borrow().config.to_hashmap()
    }
}
