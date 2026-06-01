use log::{debug, info};
use netlink_bindings::{
    rt_addr::{self, Ifaddrmsg},
    rt_link::{self, Ifinfomsg},
    rt_neigh::{self, Ndmsg},
    rt_route::{self, Rtmsg},
    traits::NetlinkRequest,
};
use netlink_socket2::{MulticastSocketRaw, NetlinkSocket};
use scopeguard::guard;
use std::{
    ffi::CString,
    net::{IpAddr, Ipv4Addr},
};
use tokio::sync::watch;

use crate::{Ctx, Direction, Kind, Route, Routes, bpf, dbus};

pub async fn watch_reload(ctx: &'static Ctx) -> eyre::Result<()> {
    let mut conf = ctx.state.rx.clone();
    let mut routes_changed = ctx.routes_changed.rx.clone();
    let mut do_reload = ctx.do_reload.rx.clone();

    loop {
        tokio::select! {
            res = conf.changed() => res.unwrap(),
            res = routes_changed.changed() => res.unwrap(),
            res = do_reload.changed() => res.unwrap(),
        };

        conf.mark_unchanged();
        routes_changed.mark_unchanged();
        do_reload.mark_unchanged();

        let default_route = Route {
            addr: Some(Ipv4Addr::UNSPECIFIED.into()),
            ..Default::default()
        };
        let drop_without_output = conf.borrow().config.drop_egress_without_output;
        let mut blocker = "";

        let r = routes_changed.borrow().clone();
        let Some(from) = &r.from else {
            blocked(ctx, "Input interface not found").await?;
            continue;
        };

        let mut to;
        if let Some(r) = &r.to {
            to = r;
        } else {
            if !drop_without_output {
                blocked(ctx, "Output interface not found").await?;
                continue;
            }
            to = &default_route;
            blocker = "Output interface not found (dropping traffic)";
        };

        if from.ifname == to.ifname {
            blocked(ctx, "Output and input interfaces are the same").await?;
            continue;
        };

        let Some(from_addr) = from.addr else {
            blocked(ctx, "Input interface address doesn't have address").await?;
            continue;
        };

        let to_addr;
        if let Some(a) = to.addr {
            to_addr = a;
        } else {
            if !drop_without_output {
                blocked(ctx, "Output interface doesn't have address").await?;
                continue;
            }
            to = &default_route;
            to_addr = to.addr.unwrap();
            blocker = "Output interface doesn't have address (dropping traffic)";
        };

        if !*ctx.attached.tx.borrow() {
            info!("ATTACHED");
        } else {
            info!("RELOAD");
        }

        unsafe {
            let mut _lock = ctx.bpf.lock().await;
            let conf = conf.borrow();
            let mut bpf: bpf::BpfConfig = std::mem::zeroed();
            bpf.enable = conf.enable;
            bpf.drop = conf.enable && !blocker.is_empty();
            bpf.generation = conf.matches.generation;
            bpf.mark = 48723; // xkcd.com/221
            use bpf::MatchDir as D;
            use bpf::MatchKind as K;
            let mut cstrings: Vec<u8> = Vec::with_capacity(bpf::STRINGS_BUF_MAX as usize);
            // TODO: cloning matches isn't necessary if generation hasn't changed
            let mut cmatches: Vec<_> = conf
                .matches
                .matches
                .iter()
                .map(|m| bpf::MatchStr {
                    kind: match m.kind {
                        Kind::basename => K::MATCH_KIND_BASENAME,
                        Kind::substring => K::MATCH_KIND_SUBSTR,
                        Kind::full => K::MATCH_KIND_FULL,
                        Kind::prefix => K::MATCH_KIND_PREFIX,
                    },
                    dir: match m.direction {
                        Direction::redirect => D::MATCH_DIR_REDIRECT,
                        Direction::allow => D::MATCH_DIR_ALLOW,
                    },
                    pat: {
                        let ptr = cstrings.as_ptr().wrapping_add(cstrings.len());
                        cstrings.extend(m.pattern.as_bytes());
                        cstrings.push(b'\0');
                        assert!(cstrings.len() <= bpf::STRINGS_BUF_MAX as usize);
                        ptr as *mut i8
                    },
                    uid: m.uid,
                })
                .collect();
            assert_eq!(cstrings.len(), conf.matches.strings_len);

            bpf.matches = cmatches.as_mut_ptr();
            bpf.nmatches = cmatches.len() as u32;
            bpf.strings_len = conf.matches.strings_len as u32;

            let IpAddr::V4(to_addr) = to_addr else {
                todo!()
            };
            let IpAddr::V4(from_addr) = from_addr else {
                todo!()
            };

            let set_dev = |to_dev: &mut bpf::Redirect, to: &Route, to_addr: &Ipv4Addr| {
                if let Some(mac) = &to.mac {
                    to_dev.checked_mac = true;
                    to_dev.set_l2 = true;
                    to_dev.mac = *mac;
                } else {
                    to_dev.checked_mac = true;
                    to_dev.set_l2 = false;
                }
                to_dev.ifindex = to.ifindex;
                to_dev.family = libc::AF_INET as u8;
                to_dev.addr[0] = to_addr.to_bits().to_be();
                if let Some(nexthop_addr) = &to.nexthop_addr {
                    let IpAddr::V4(nexthop_addr) = nexthop_addr else {
                        todo!()
                    };
                    to_dev.set_nexthop_addr = true;
                    to_dev.nexthop_addr[0] = nexthop_addr.to_bits().to_be();
                }
                if let Some(nexthop_mac) = &to.nexthop_mac {
                    to_dev.set_nexthop_mac = true;
                    to_dev.nexthop_mac = *nexthop_mac;
                }
            };

            set_dev(&mut bpf.from_dev, from, &from_addr);
            set_dev(&mut bpf.to_dev, to, &to_addr);
            bpf.from_dev.is_ingress = true;
            bpf.to_dev.is_ingress = false;

            bpf.allow_lan = conf.config.allow_lan;
            bpf.spoof_dns = conf.config.spoof_dns;
            bpf.spoof_dns_ipv4 = conf.config.spoof_dns_ipv4.to_bits().to_be();

            bpf::bpf_reload_config(&mut bpf as *mut bpf::BpfConfig);
        }

        ctx.attached.tx.send(true).unwrap();
        ctx.blocker.tx.send(blocker).unwrap();
        dbus::Item { ctx }
            .attached_changed(
                ctx.conn
                    .object_server()
                    .interface::<&str, dbus::Item>("/")
                    .await?
                    .signal_emitter(),
            )
            .await
            .ok();
    }
}

async fn blocked(ctx: &'static Ctx, blocker: &'static str) -> eyre::Result<()> {
    let needs_unload = *ctx.attached.tx.borrow();

    ctx.attached.tx.send(false).unwrap();
    ctx.blocker.tx.send(blocker).unwrap();
    dbus::Item { ctx }
        .attached_changed(
            ctx.conn
                .object_server()
                .interface::<&str, dbus::Item>("/")
                .await?
                .signal_emitter(),
        )
        .await
        .ok();

    if needs_unload {
        info!("TEARDOWN");
        unsafe {
            let _lock = ctx.bpf.lock().await;
            bpf::bpf_unload();
        }
    }

    Ok(())
}

pub async fn watch_routes(ctx: &Ctx) -> eyre::Result<()> {
    let mut sock = NetlinkSocket::new();

    let mut conf = ctx.state.rx.clone();
    let mut to_changed = ctx.to_changed.rx.clone();
    let mut from_changed = ctx.from_changed.rx.clone();
    let routes = ctx.routes_changed.tx.clone();

    loop {
        let from_dev = tokio::select! {
            res = from_changed.changed() => { res.unwrap(); true },
            res = to_changed.changed() => { res.unwrap(); false },
            res = conf.changed() => { res.unwrap(); false },
        };

        if from_dev {
            debug!("Probing from device");
            from_changed.mark_unchanged();
        } else {
            debug!("Probing to device");
            conf.mark_unchanged();
            to_changed.mark_unchanged();
        }

        let _guard = guard(
            &routes,
            if from_dev {
                inval_from_routes
            } else {
                inval_to_routes
            },
        );

        let ifindex;
        let ifname;
        let prefsrc;
        let nexthop_addr;

        let header = Rtmsg {
            rtm_family: libc::AF_INET as u8,
            rtm_dst_len: 32,
            rtm_table: libc::RT_TABLE_MAIN,
            rtm_scope: libc::RT_SCOPE_UNIVERSE,
            rtm_type: libc::RTN_UNICAST,
            rtm_flags: libc::RTM_F_LOOKUP_TABLE,
            ..Default::default()
        };

        let mut req = rt_route::Request::new().op_getroute_do(&header);
        req.encode()
            .push_dst(conf.borrow().config.probe_ipv4_addr.into());

        if !from_dev
            && let ifname = CString::new(conf.borrow().to_dev.as_str()).unwrap()
            && let ifindex = unsafe { libc::if_nametoindex(ifname.as_c_str().as_ptr()) }
            && ifindex > 0
        {
            req.encode().push_oif(ifindex);
        }

        let mut res = sock.request(&req)?;
        let attrs = match res.recv_one() {
            Err(err) => {
                info!("Error probing output route: {err}");
                continue;
            }
            Ok((_, a)) => a,
        };

        if from_dev {
            ifindex = Some(attrs.get_oif()?);
            ifname = None;
            prefsrc = attrs.get_prefsrc().ok();
            nexthop_addr = attrs.get_gateway().ok();
        } else {
            ifindex = None;
            ifname = Some(conf.borrow().to_dev.clone());
            prefsrc = attrs.get_prefsrc().ok();
            nexthop_addr = attrs.get_gateway().ok();
        }

        let new_route =
            match get_link(&mut sock, ifindex, ifname.as_deref(), prefsrc, nexthop_addr).await {
                Ok(r) => r,
                Err(err) => {
                    info!("Error getting route for device: {err}");
                    continue;
                }
            };

        routes.send_modify(|r| {
            if from_dev {
                r.from = Some(new_route);
            } else {
                r.to = Some(new_route);
            }
        });

        std::mem::forget(_guard);
    }
}

pub fn watch_multicast(ctx: &Ctx) -> eyre::Result<()> {
    let mut msock = MulticastSocketRaw::new(rt_link::PROTONUM)?;
    msock.listen(libc::RTNLGRP_LINK)?;
    msock.listen(libc::RTNLGRP_IPV4_ROUTE)?;
    // msock.listen(libc::RTNLGRP_IPV6_ROUTE)?;
    msock.listen(libc::RTNLGRP_NEIGH)?;

    loop {
        let (recv, buf) = msock.recv()?;

        match recv.message_type & !0b11 {
            libc::RTM_NEWROUTE => {
                let (_, attrs) = netlink_bindings::rt_route::OpGetrouteDo::decode_reply(buf);
                debug!("RTM_NEWROUTE: {attrs:?}");

                if let Some(ifindex) = attrs.get_oif().ok()
                    && let Some(to) = &ctx.routes_changed.rx.borrow().to
                    && to.ifindex == ifindex
                {
                    ctx.to_changed.tx.send(()).unwrap();
                    continue;
                }

                ctx.from_changed.tx.send(()).unwrap();
            }
            libc::RTM_NEWLINK => {
                let (header, attrs) = rt_link::OpGetlinkDo::decode_reply(buf);
                debug!("RTM_NEWLINK: {attrs:?}");

                let routes = ctx.routes_changed.rx.borrow();
                let ifindex = header.ifi_index.clamp(0, i32::MAX) as u32;
                let ifname = attrs.get_ifname().unwrap_or_default().to_bytes();

                if ifname == ctx.state.rx.borrow().to_dev.as_bytes() {
                    ctx.to_changed.tx.send(()).unwrap();
                }

                if let Some(to) = &routes.to
                    && (to.ifindex == ifindex || to.ifname.as_bytes() == ifname)
                {
                    ctx.to_changed.tx.send(()).unwrap();
                }

                if let Some(from) = &routes.from
                    && (from.ifindex == ifindex || from.ifname.as_bytes() == ifname)
                {
                    ctx.from_changed.tx.send(()).unwrap();
                }
            }
            libc::RTM_NEWNEIGH => {
                let (_, attrs) = rt_neigh::OpGetneighDo::decode_reply(buf);
                debug!("RTM_NEWNEIGH: {attrs:?}");

                let Ok(addr) = attrs.get_dst() else {
                    continue;
                };
                let Ok(mac) = attrs.get_lladdr() else {
                    continue;
                };

                let check_neigh = |route: &Option<Route>| {
                    if let Some(to) = route
                        && let Some(neigh_addr) = to.nexthop_addr
                        && addr == neigh_addr
                        && let Some(neigh_mac) = to.nexthop_mac
                        && mac != neigh_mac
                    {
                        ctx.to_changed.tx.send(()).unwrap();
                    }
                };

                let routes = ctx.routes_changed.rx.borrow();
                check_neigh(&routes.to);
                check_neigh(&routes.from);
            }
            _ => {}
        }
    }
}

async fn get_link(
    sock: &mut NetlinkSocket,
    ifindex: Option<u32>,
    ifname: Option<&str>,
    mut prefsrc: Option<IpAddr>,
    nexthop_addr: Option<IpAddr>,
) -> eyre::Result<Route> {
    let header = Ifinfomsg {
        ifi_family: libc::AF_PACKET as u8,
        ifi_index: ifindex.unwrap_or(0) as i32,
        ..Default::default()
    };

    let mut req = rt_link::Request::new().op_getlink_do(&header);
    assert!(ifindex.is_some() != ifname.is_some());
    if let Some(ifname) = ifname {
        req.encode().push_ifname_bytes(ifname.as_bytes());
    }

    let mut res = sock.request(&req)?;
    let (h, res) = res.recv_one()?;

    let ifindex = h.ifi_index as u32;
    let ifname = res.get_ifname()?.to_string_lossy().to_string();
    let mac = res.get_address().ok().map(|m| m.to_vec());

    let header = Ifaddrmsg {
        ifa_family: libc::AF_INET as u8,
        ifa_scope: libc::RT_SCOPE_LINK,
        ..Default::default()
    };

    if prefsrc.is_none() {
        let req = rt_addr::Request::new().op_getaddr_dump(&header);
        let mut res = sock.request(&req)?;
        while let Some((h, attrs)) = res.recv().transpose()? {
            if h.ifa_index == ifindex
                && let Ok(new_addr) = attrs.get_local()
            {
                prefsrc = Some(new_addr);
                break;
            }
        }
    }

    let mut nexthop_mac = None;
    if let Some(nexthop_addr) = nexthop_addr {
        let header = Ndmsg {
            ndm_family: libc::AF_INET as u8,
            ..Default::default()
        };

        let mut req = rt_neigh::Request::new().op_getneigh_dump(&header);
        req.encode().push_ifindex(ifindex);

        let mut res = sock.request(&req)?;
        while let Some((h, attrs)) = res.recv().transpose()? {
            if h.ndm_ifindex as u32 == ifindex
                && let Ok(dst) = attrs.get_dst()
                && dst == nexthop_addr
                && let Ok(mac) = attrs.get_lladdr()
            {
                nexthop_mac = Some(mac.to_vec());
                break;
            }
        }
    }

    Ok(Route {
        ifindex,
        ifname,
        mac: mac.map(|m| m.try_into().unwrap()),
        nexthop_addr,
        nexthop_mac: nexthop_mac.map(|m| m.try_into().unwrap()),
        addr: prefsrc,
    })
}

fn inval_to_routes(tx: &watch::Sender<Routes>) {
    tx.send_modify(|r| r.to = None);
}

fn inval_from_routes(tx: &watch::Sender<Routes>) {
    tx.send_modify(|r| r.from = None);
}
