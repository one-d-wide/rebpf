use log::{debug, info, warn};
use netlink_bindings::{
    nftables::{self, CmpOps, MetaKeys, NatRangeFlags, Nfgenmsg, PayloadBase, Registers},
    rt_addr,
    rt_link::{self, IfinfoFlags},
    rt_route::{self, Rtmsg},
    rt_rule,
    traits::{NetlinkRequest, Protocol},
    utils::IterableChunks,
};
use netlink_socket2::{MulticastSocketRaw, NetlinkSocket, ReplyError};
use std::{ffi, io, marker::PhantomData, net::Ipv4Addr};
use tokio::time::Instant;

use crate::dbus;
use rebpf::{BpfCtx, Ctx, Direction, Kind, Method, Route, State, Stats, StatsHist, bpf};

pub fn rand_table() -> u32 {
    rand::random_range(u16::MAX as u32..u32::MAX)
}

pub async fn watch_reload(ctx: &'static Ctx) -> eyre::Result<()> {
    let mut sock = NetlinkSocket::new();
    let mut sock2 = NetlinkSocket::new();
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

        let new_mark = rand_table();

        if let Some(old_mark) = ctx.bpf.lock().await.mark.replace(new_mark) {
            clear_rules(&mut sock, old_mark)?;
        }

        let mut enable = true;
        let mut blocker = "".to_string();
        if let Some(to) = routes_changed.borrow().clone()
            && to.is_up
            && conf.borrow().enable
        {
            for addr in &to.addrs {
                // ip rule add from <prefix> lookup <mark> prio 0
                let mut req = rt_rule::Request::new()
                    .set_create()
                    .set_excl()
                    .op_newrule_do(&rt_rule::FibRuleHdr {
                        family: libc::AF_INET as u8,
                        src_len: 32,
                        action: rt_rule::FrAct::ToTbl as u8,
                        ..Default::default()
                    });
                req.encode()
                    .push_src(*addr)
                    .push_table(new_mark)
                    .push_priority(0);
                sock.request(&req)?.recv_ack()?;
            }

            // ip rule add fwmark <mark> table <mark> prio 0
            let mut req = rt_rule::Request::new()
                .set_create()
                .set_excl()
                .op_newrule_do(&rt_rule::FibRuleHdr {
                    family: libc::AF_INET as u8,
                    action: rt_rule::FrAct::ToTbl as u8,
                    ..Default::default()
                });
            req.encode()
                .push_fwmark(new_mark)
                .push_table(new_mark)
                .push_priority(0);
            sock.request(&req)?.recv_ack()?;

            for m in &conf.borrow().matches.matches {
                if m.kind != Kind::ipv4 {
                    continue;
                }
                let (addr, addr_len) = match m.method {
                    Method::full => {
                        let Ok(addr) = m.pattern.parse::<Ipv4Addr>() else {
                            continue;
                        };
                        (addr, 32)
                    }
                    Method::subnet => {
                        let Ok(addr) = m.pattern.parse::<ipnet::Ipv4Net>() else {
                            continue;
                        };
                        (addr.network(), addr.prefix_len())
                    }
                    _ => continue,
                };

                // ip rule add to <addr> table <mark> prio 0
                // TODO: Consider setting up ip matches as routes
                let mut req =
                    rt_rule::Request::new()
                        .set_create()
                        .op_newrule_do(&rt_rule::FibRuleHdr {
                            family: libc::AF_INET as u8,
                            dst_len: addr_len,
                            action: rt_rule::FrAct::ToTbl as u8,
                            ..Default::default()
                        });

                match m.direction {
                    Direction::redirect => {
                        req.encode().push_table(new_mark);
                    }
                    Direction::bypass => {
                        req.encode().push_table(libc::RT_TABLE_MAIN as u32);
                    }
                }

                // if m.uid != 0 {
                //     req.encode().push_uid_range(rt_rule::FibRuleUidRange {
                //         start: m.uid,
                //         end: m.uid,
                //     });
                // }

                req.encode()
                    .push_dst(addr.into())
                    .push_priority(0)
                    // fwmark with mask=0 doesn't do anything, we just use it as a marker
                    .push_fwmark(new_mark)
                    .push_fwmask(0);

                sock.request(&req)?.recv_ack()?;
            }

            // ip route add default dev <dev> table <mark>
            let mut req = rt_route::Request::new()
                .set_create()
                .set_excl()
                .op_newroute_do(&rt_route::Rtmsg {
                    rtm_family: libc::AF_INET as u8,
                    rtm_protocol: libc::RTPROT_BOOT as u8,
                    rtm_type: rt_route::RtmType::Unicast as u8,
                    ..Default::default()
                });
            req.encode().push_table(new_mark).push_oif(to.ifindex);
            if let Some(addr) = to.addrs.first() {
                req.encode().push_prefsrc(*addr);
            }
            if let Some(gateway) = to.gateway {
                req.encode().push_gateway(gateway);
            }
            sock.request(&req)?.recv_ack()?;

            if conf.borrow().config.allow_lan {
                if let Err(err) = clone_routes(&mut sock, &mut sock2, new_mark) {
                    warn!("Error while cloning local routes: {err}");
                }
            } else {
                // ip rule add fwmark <mark> unreachable prio 0
                let mut req = rt_rule::Request::new()
                    .set_create()
                    .set_excl()
                    .op_newrule_do(&rt_rule::FibRuleHdr {
                        family: libc::AF_INET as u8,
                        action: rt_rule::FrAct::Unreachable as u8,
                        ..Default::default()
                    });
                req.encode()
                    .push_fwmark(new_mark)
                    .push_table(new_mark)
                    .push_priority(0);
                sock.request(&req)?.recv_ack()?;
            }

            if conf.borrow().config.spoof_dns {
                let res = iptables_rule(
                    &mut sock,
                    true,
                    new_mark,
                    conf.borrow().config.spoof_dns_ipv4,
                    53,
                );
                if let Err(err) = res {
                    warn!("Can't setup ip-rule to spoof dns: {err}");
                }
            }
        } else if routes_changed.borrow().is_some() && !conf.borrow().enable {
            enable = false;
        } else if routes_changed.borrow().as_ref().is_some_and(|r| !r.is_up) {
            blocker = "Output interface is down".to_string();
            enable = false;
        } else {
            blocker = "Output interface not found".to_string();
            enable = false;
        }

        if !enable && blocker != "" && conf.borrow().config.drop_egress_without_output {
            blocker = format!("{blocker} (dropping traffic)");

            // ip rule add fwmark <mark> unreachable
            let mut req = rt_rule::Request::new()
                .set_create()
                .set_excl()
                .op_newrule_do(&rt_rule::FibRuleHdr {
                    family: libc::AF_INET as u8,
                    action: rt_rule::FrAct::Unreachable as u8,
                    ..Default::default()
                });
            req.encode().push_fwmark(new_mark).push_table(new_mark);
            sock.request(&req)?.recv_ack()?;
        }

        {
            info!("RELOAD");
            let mut bpf = ctx.bpf.lock().await;
            let conf = conf.borrow();
            bpf_reload(&mut bpf, &conf, enable, new_mark);
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

pub async fn watch_routes(ctx: &Ctx) -> eyre::Result<()> {
    let mut sock = NetlinkSocket::new();

    let mut conf = ctx.state.rx.clone();
    let mut to_changed = ctx.to_changed.rx.clone();
    let routes = ctx.routes_changed.tx.clone();

    loop {
        tokio::select! {
            res = to_changed.changed() => { res.unwrap() },
            res = conf.changed() => { res.unwrap() },
        };

        conf.mark_unchanged();
        to_changed.mark_unchanged();

        let ifname = &conf.borrow().to_dev.clone();
        debug!("Probing device {ifname:?}");
        match get_link(&mut sock, ifname) {
            Ok(new_route) if routes.borrow().as_ref().is_some_and(|r| r == &new_route) => {
                continue;
            }
            Ok(new_route) => {
                routes.send(Some(new_route)).unwrap();
            }
            Err(err) => {
                info!("Error getting route for device: {err}");
                routes.send(None).unwrap();
                continue;
            }
        };
    }
}

pub fn watch_multicast(ctx: &Ctx) -> eyre::Result<()> {
    let mut sock = NetlinkSocket::new();
    let mut msock = MulticastSocketRaw::new(rt_link::PROTONUM)?;
    msock.listen(libc::RTNLGRP_LINK)?;
    msock.listen(libc::RTNLGRP_IPV4_ROUTE)?;
    // msock.listen(libc::RTNLGRP_IPV6_ROUTE)?;

    ctx.default_route_changed
        .tx
        .send(get_default_link(ctx, &mut sock).ok().flatten())
        .unwrap();

    loop {
        let (recv, buf) = msock.recv()?;

        match recv.message_type & !0b11 {
            libc::RTM_NEWROUTE => {
                let (_, attrs) = netlink_bindings::rt_route::OpGetrouteDo::decode_reply(buf);
                debug!("RTM_NEWROUTE: {attrs:?}");

                if attrs.get_table().unwrap_or_default() != 0 {
                    continue;
                }

                // Only update default_route if we need have dns matches
                if ctx.state.rx.borrow().matches.dns_count > 0 {
                    let new_default = get_default_link(ctx, &mut sock).ok().flatten();
                    if new_default != *ctx.default_route_changed.tx.borrow() {
                        ctx.default_route_changed.tx.send(new_default).unwrap();
                    }
                }

                if let Some(to) = &*ctx.routes_changed.rx.borrow()
                    && (attrs.get_oif().unwrap_or_default() == to.ifindex
                        || ctx.state.rx.borrow().config.allow_lan)
                {
                    ctx.to_changed.tx.send(()).unwrap();
                }
            }
            libc::RTM_NEWLINK => {
                let (header, attrs) = rt_link::OpGetlinkDo::decode_reply(buf);
                debug!("RTM_NEWLINK: {attrs:?}");

                let ifindex = header.ifi_index.clamp(0, i32::MAX) as u32;
                let ifname = attrs.get_ifname().unwrap_or_default().to_bytes();

                if ifname == ctx.state.rx.borrow().to_dev.as_bytes() {
                    ctx.to_changed.tx.send(()).unwrap();
                    continue;
                }

                if let Some(to) = &*ctx.routes_changed.rx.borrow()
                    && (to.ifindex == ifindex || to.ifname.as_bytes() == ifname)
                {
                    ctx.to_changed.tx.send(()).unwrap();
                }
            }
            _ => {}
        }
    }
}

fn get_default_link(ctx: &Ctx, sock: &mut NetlinkSocket) -> eyre::Result<Option<Route>> {
    let mut req = rt_route::Request::new().op_getroute_do(&rt_route::Rtmsg {
        rtm_family: libc::AF_INET as u8,
        rtm_dst_len: 32,
        ..Default::default()
    });
    req.encode()
        .push_dst(ctx.state.rx.borrow().config.probe_ipv4_addr.into());
    let mut res = sock.request(&req)?;
    let (_, attrs) = res.recv_one()?;

    let Ok(ifindex) = attrs.get_oif() else {
        return Ok(None);
    };
    let addrs = attrs.get_prefsrc().into_iter().collect();
    let gateway = attrs.get_gateway().ok();

    let req = rt_link::Request::new().op_getlink_do(&rt_link::Ifinfomsg {
        ifi_index: ifindex as i32,
        ..Default::default()
    });
    let mut res = sock.request(&req)?;
    let (h, attrs) = res.recv_one()?;

    let is_up = h.ifi_flags & IfinfoFlags::Up as u32 != 0;
    let Ok(ifname) = attrs.get_ifname() else {
        return Ok(None);
    };
    let ifname = ifname.to_string_lossy().to_string();

    Ok(Some(Route {
        is_up,
        ifindex,
        ifname,
        addrs,
        gateway,
    }))
}

fn get_link(sock: &mut NetlinkSocket, ifname: &str) -> eyre::Result<Route> {
    let header = rt_link::Ifinfomsg {
        ifi_family: libc::AF_PACKET as u8,
        ..Default::default()
    };

    let mut req = rt_link::Request::new().op_getlink_do(&header);
    req.encode().push_ifname_bytes(ifname.as_bytes());

    let mut res = sock.request(&req)?;
    let (h, res) = res.recv_one()?;

    let is_up = h.ifi_flags & IfinfoFlags::Up as u32 != 0;
    let ifindex = h.ifi_index as u32;
    let ifname = res.get_ifname()?.to_string_lossy().to_string();

    let header = rt_addr::Ifaddrmsg {
        ifa_family: libc::AF_INET as u8,
        ifa_scope: libc::RT_SCOPE_LINK,
        ..Default::default()
    };

    let mut addrs = Vec::new();

    let req = rt_addr::Request::new().op_getaddr_dump(&header);
    let mut res = sock.request(&req)?;
    while let Some((h, attrs)) = res.recv().transpose()? {
        if h.ifa_index == ifindex
            && let Ok(new_addr) = attrs.get_local()
        {
            addrs.push(new_addr);
        }
    }

    let mut req = rt_route::Request::new().op_getroute_dump(&rt_route::Rtmsg {
        rtm_family: libc::AF_INET as u8,
        rtm_table: libc::RT_TABLE_MAIN as u8,
        ..Default::default()
    });
    req.encode().push_oif(ifindex);

    let mut gateway = None;

    let mut iter = sock.request(&req)?;
    while let Some((_, attrs)) = iter.recv().transpose()? {
        if let Ok(table) = attrs.get_table()
            && table == libc::RT_TABLE_MAIN as u32
            && let Ok(oif) = attrs.get_oif()
            && oif == ifindex
            && let Ok(addr) = attrs.get_gateway()
        {
            gateway = Some(addr);
            break;
        }
    }

    Ok(Route {
        is_up,
        ifindex,
        ifname,
        addrs,
        gateway,
    })
}

fn bpf_reload(bpf_ctx: &mut BpfCtx, conf: &State, enable: bool, mark: u32) {
    unsafe {
        let mut bpf: bpf::BpfConfig = std::mem::zeroed();
        bpf.enable = enable;
        bpf.enable_dns = enable && conf.matches.dns_count > 0;
        bpf.mark = mark;
        bpf.generation = conf.matches.generation;

        if bpf_ctx.last_gen != bpf.generation {
            bpf_ctx.last_gen = bpf.generation;

            let mut pat_id_map = Vec::new();
            let mut set = Vec::new();
            for (i, m) in conf.matches.matches.iter().enumerate() {
                set.push(m);
                pat_id_map.push(i);
            }

            bpf_ctx.arena.clear();
            match conf.matches.build_path_dfa(&mut bpf_ctx.arena) {
                Ok(dfa) => {
                    bpf.has_dfa = true;
                    bpf.dfa = dfa;
                }
                Err(err) => {
                    warn!("Error compiling DFA for {set:?}: {err}");
                }
            }
        }

        bpf.arena_buf = bpf_ctx.arena.as_mut_ptr() as *mut ffi::c_void;
        bpf.arena_buf_len = bpf_ctx.arena.len() as u32;
        bpf::bpf_reload_config(&mut bpf as *mut bpf::BpfConfig);
    }
}

pub fn setup_static_rules(ctx: &Ctx, sock: &mut NetlinkSocket) -> eyre::Result<()> {
    // ip rule add table <table>
    let mut req = rt_rule::Request::new()
        .set_create()
        .set_excl()
        .op_newrule_do(&rt_rule::FibRuleHdr {
            family: libc::AF_INET as u8,
            action: rt_rule::FrAct::ToTbl as u8,
            ..Default::default()
        });
    req.encode()
        .push_priority(0)
        .push_src(Ipv4Addr::UNSPECIFIED.into())
        .push_table(ctx.dns_table);
    sock.request(&req)?.recv_ack()?;

    Ok(())
}

pub fn clear_static_rules(ctx: &Ctx, sock: &mut NetlinkSocket) -> eyre::Result<()> {
    clear_table(sock, ctx.dns_table).ok();

    for _ in 0..1000 {
        // ip rule del table <mark>
        let mut req = rt_rule::Request::new().op_delrule_do(&rt_rule::FibRuleHdr {
            family: libc::AF_INET as u8,
            ..Default::default()
        });
        req.encode().push_table(ctx.dns_table);
        let res = sock.request(&req)?.recv_ack();

        if res.is_err() {
            break;
        }
    }

    Ok(())
}

pub fn clear_table(sock: &mut NetlinkSocket, table: u32) -> eyre::Result<()> {
    // ip route show table <table>
    let mut req = rt_route::Request::new()
        .set_replace()
        .set_excl()
        .op_getroute_dump(&rt_route::Rtmsg {
            rtm_family: libc::AF_INET as u8,
            ..Default::default()
        });
    req.encode().push_table(table);
    let mut iter = sock.request(&req)?;

    let mut routes = Vec::new();
    while let Some((h, attrs)) = iter.recv().transpose()? {
        if !attrs.get_table().is_ok_and(|t| t == table) {
            continue;
        };

        let dest = attrs.get_dst().unwrap_or(Ipv4Addr::UNSPECIFIED.into());
        let len = h.rtm_dst_len;

        routes.push((dest, len));
    }

    for (dest, len) in routes {
        debug!("Deleting route {dest}/{len} from table {table}");

        // ip route del table <mark>
        let mut req = rt_route::Request::new().op_delroute_do(&rt_route::Rtmsg {
            rtm_family: libc::AF_INET as u8,
            rtm_dst_len: len,
            rtm_scope: libc::RT_SCOPE_NOWHERE as u8,
            ..Default::default()
        });
        req.encode().push_dst(dest).push_table(table);
        if let Err(err) = sock.request(&req)?.recv_ack() {
            warn!("Error deleting route {dest}/{len} from table {table}: {err}");
        }
    }

    Ok(())
}

pub fn clear_rules(sock: &mut NetlinkSocket, old_mark: u32) -> eyre::Result<()> {
    debug!("Clearing rules for fwmark={old_mark}");

    clear_table(sock, old_mark)?;

    for _ in 0..1000 {
        // ip rule del table <mark>
        let mut req = rt_rule::Request::new().op_delrule_do(&rt_rule::FibRuleHdr {
            family: libc::AF_INET as u8,
            ..Default::default()
        });
        req.encode().push_table(old_mark);
        let res = sock.request(&req)?.recv_ack();

        if res.is_err() {
            break;
        }
    }

    for _ in 0..1000 {
        // ip rule del fwmark <mark>
        let mut req = rt_rule::Request::new().op_delrule_do(&rt_rule::FibRuleHdr {
            family: libc::AF_INET as u8,
            ..Default::default()
        });
        req.encode().push_fwmark(old_mark).push_fwmask(0);
        let res = sock.request(&req)?.recv_ack();

        if res.is_err() {
            break;
        }
    }

    for i in 0..1000 {
        let res = iptables_rule(sock, false, old_mark, Ipv4Addr::UNSPECIFIED, 0);

        if let Err(err) = &res
            && i == 0
        {
            debug!("Error deleting iptables rule: {err}");
        }

        if res.is_err() {
            break;
        }
    }

    Ok(())
}

fn iptables_rule(
    sock: &mut NetlinkSocket,
    insert_rule: bool,
    mark: u32,
    addr: Ipv4Addr,
    port: u16,
) -> eyre::Result<()> {
    loop {
        match iptables_rule_try(sock, insert_rule, mark, addr, port) {
            Err(err) if err.as_io_error().kind() == io::ErrorKind::Interrupted => continue,
            res => return Ok(res?),
        }
    }
}

fn iptables_rule_try(
    sock: &mut NetlinkSocket,
    insert_rule: bool,
    mark: u32,
    addr: Ipv4Addr,
    port: u16,
) -> Result<(), ReplyError> {
    let mut addr_bits = [0u8; 16];
    addr_bits[0..4].clone_from_slice(&addr.to_bits().to_be_bytes());

    let header = nftables::Nfgenmsg {
        nfgen_family: libc::AF_INET as u8, // aka ipv4
        ..Default::default()
    };

    let mut batch_header = nftables::Nfgenmsg::new();
    batch_header.set_res_id(10);

    let mut c = nftables::Chained::new(sock.reserve_seq(256));
    c.request()
        .op_batch_begin_do(&batch_header)
        .encode()
        .push_genid(get_latest_genid(sock)?);

    // iptables -t nat -D OUTPUT -m mark --mark <mark> -p udp -m udp --dport <port> -j DNAT --to-destination <addr>
    if insert_rule {
        c.request()
            .set_create()
            .op_newrule_do(&header)
            .encode()
            .push_table_bytes(b"nat")
            .push_chain_bytes(b"OUTPUT")
            .push_userdata(&mark.to_ne_bytes())
            //
            .nested_expressions()
            //
            .nested_elem()
            .nested_data_payload()
            .push_dreg(Registers::Reg1 as u32)
            .push_base(PayloadBase::NetworkHeader as u32)
            .push_offset(9)
            .push_len(1)
            .end_nested()
            .end_nested()
            //
            .nested_elem()
            .nested_data_cmp()
            .push_sreg(Registers::Reg1 as u32)
            .push_op(CmpOps::Eq as u32)
            .nested_data()
            .push_value(&[17])
            .end_nested()
            .end_nested()
            .end_nested()
            //
            .nested_elem()
            .nested_data_meta()
            .push_dreg(Registers::Reg1 as u32)
            .push_key(MetaKeys::Mark as u32)
            .end_nested()
            .end_nested()
            //
            .nested_elem()
            .nested_data_cmp()
            .push_sreg(Registers::Reg1 as u32)
            .push_op(CmpOps::Eq as u32)
            .nested_data()
            .push_value(&mark.to_ne_bytes())
            .end_nested()
            .end_nested()
            .end_nested()
            //
            .nested_elem()
            .nested_data_payload()
            .push_dreg(Registers::Reg1 as u32)
            .push_base(PayloadBase::TransportHeader as u32)
            .push_offset(2)
            .push_len(2)
            .end_nested()
            .end_nested()
            //
            .nested_elem()
            .nested_data_cmp()
            .push_sreg(Registers::Reg1 as u32)
            .push_op(CmpOps::Eq as u32)
            .nested_data()
            .push_value(&port.to_be_bytes())
            .end_nested()
            .end_nested()
            .end_nested()
            //
            .nested_elem()
            .nested_data_target()
            .push_name_bytes(b"DNAT")
            .push_rev(2)
            .push_info(
                nftables::NatRange2 {
                    flags: NatRangeFlags::MapIps as u32,
                    min_addr: addr_bits,
                    max_addr: addr_bits,
                    ..Default::default()
                }
                .as_slice(),
            );
    } else {
        let mut handle = None;

        let mut request = nftables::Request::new().op_getrule_dump(&header);
        request
            .encode()
            .push_table_bytes(b"nat")
            .push_chain_bytes(b"OUTPUT");
        let mut iter = sock.request(&request).unwrap();
        while let Some((_, attrs)) = iter.recv().transpose()? {
            if attrs.get_userdata().is_ok_and(|d| d == mark.to_ne_bytes()) {
                handle = Some(attrs.get_handle()?);
                break;
            }
        }

        let Some(handle) = handle else {
            return Err(io::Error::other("Didn't found the rule").into());
        };

        c.request()
            .set_append()
            .op_delrule_do(&header)
            .encode()
            .push_table_bytes(b"nat")
            .push_chain_bytes(b"OUTPUT")
            .push_handle(handle);
    };

    c.request().op_batch_end_do(&batch_header);

    sock.request_chained(&c.finalize())?.recv_all()?;

    Ok(())
}

fn get_latest_genid(sock: &mut NetlinkSocket) -> Result<u32, ReplyError> {
    let request = nftables::Request::new().op_getgen_do(&Nfgenmsg::new());
    let mut iter = sock.request(&request)?;
    let (_, attrs) = iter.recv_one()?;

    Ok(attrs.get_id()?)
}

fn clone_routes(
    sock1: &mut NetlinkSocket,
    sock2: &mut NetlinkSocket,
    new_mark: u32,
) -> eyre::Result<()> {
    let mut buf = Vec::new();
    let req = rt_route::Request::new().op_getroute_dump(&rt_route::Rtmsg {
        rtm_family: libc::AF_INET as u8,
        rtm_table: libc::RT_TABLE_MAIN as u8,
        ..Default::default()
    });

    let mut iter = sock1.request(&req)?;
    while let Some((mut h, attrs)) = iter.recv().transpose()? {
        if attrs.get_table().unwrap_or_default() != libc::RT_TABLE_MAIN as u32 {
            continue;
        }

        // Exclude destinations like 0.0.0.0/0, 0.0.0.0/1, and 128.0.0.0/1
        if h.rtm_dst_len <= 1 {
            continue;
        }

        debug!("Cloning ip-route: {h:?} {attrs:?}");

        h.rtm_table = 0;
        h.rtm_flags &= !16; // unset link-is-down flag

        buf.clear();
        buf.extend_from_slice(h.as_slice());
        buf.extend_from_slice(attrs.get_buf());

        // Replace table id
        let mut pos = 0;
        for (header, bytes) in IterableChunks::new(&buf[Rtmsg::len()..]) {
            if header.r#type == 15 {
                pos = unsafe { bytes.as_ptr().byte_offset_from_unsigned(buf.as_ptr()) };
                break;
            }
        }

        buf[pos..(pos + 4)].clone_from_slice(&new_mark.to_ne_bytes());

        let req = DummyRequest::<rt_route::OpNewrouteDo>::new(&buf, 24);
        sock2.request(&req)?.recv_ack()?;
    }

    Ok(())
}

struct DummyRequest<'a, T: NetlinkRequest> {
    buf: &'a [u8],
    request_type: u16,
    phantom: PhantomData<T>,
}

impl<'a, T: NetlinkRequest> DummyRequest<'a, T> {
    fn new(buf: &'a [u8], request_type: u16) -> Self {
        Self {
            buf,
            request_type,
            phantom: PhantomData,
        }
    }
}

impl<T: NetlinkRequest> NetlinkRequest for DummyRequest<'_, T> {
    fn protocol(&self) -> Protocol {
        Protocol::Raw {
            protonum: 0, // rtnetlink
            request_type: self.request_type,
        }
    }
    fn flags(&self) -> u16 {
        libc::NLM_F_CREATE as u16
    }
    fn payload(&self) -> &[u8] {
        self.buf
    }
    type ReplyType<'buf> = T::ReplyType<'buf>;
    fn decode_reply<'buf>(buf: &'buf [u8]) -> Self::ReplyType<'buf> {
        T::decode_reply(buf)
    }
}

pub fn get_stats(ifname: &str, hist: &mut StatsHist) -> eyre::Result<()> {
    let mut sock = NetlinkSocket::new();

    let mut req = rt_link::Request::new().op_getlink_do(&Default::default());
    req.encode().push_ifname_bytes(ifname.as_bytes());

    let mut res = sock.request(&req)?;
    let (_, attrs) = res.recv_one()?;

    let stats = attrs.get_stats64()?;

    hist.prev = hist.cur.clone();
    hist.cur = Stats {
        time: Instant::now(),
        tx_bytes: stats.tx_bytes,
        rx_bytes: stats.rx_bytes,
    };

    Ok(())
}
