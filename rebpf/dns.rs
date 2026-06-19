use eyre::bail;
use hickory_proto::{
    rr::{Name, RData, rdata},
    serialize::binary::BinDecodable,
};
use netlink_bindings::rt_route;
use netlink_socket2::NetlinkSocket;
use std::{net::Ipv4Addr, time::Duration};
use tokio::time::Instant;

use log::{debug, info};
use rebpf::{Ctx, Direction, DnsRecord, DnsState, Kind};

pub async fn watch_dns_ttl(ctx: &Ctx) -> eyre::Result<()> {
    let mut ttl = ctx.dns.lock().await.ttl_sleeper.rx.clone();

    loop {
        let Some(next) = ttl.borrow().clone() else {
            ttl.changed().await.unwrap();
            continue;
        };

        debug!(
            "Next cleanup in {:.3}s",
            next.duration_since(Instant::now()).as_secs_f32()
        );

        tokio::select! {
            _ = ttl.changed() => continue,
            _ = tokio::time::sleep_until(next) => {},
        };

        let mut dns = ctx.dns.lock().await;
        let now = Instant::now();
        while dns.heap.peek().is_some_and(|r| r.ttl_expire <= now) {
            let mut rec = dns.heap.pop().unwrap();
            let expires = dns.hash.remove(&(rec.name.clone(), rec.dest));

            if let Some(expires) = expires
                && expires > now
            {
                debug!(
                    "Renewing record for {:.3}s: {}",
                    expires.duration_since(now).as_secs_f32(),
                    rec.name
                );
                rec.ttl_expire = expires;
                dns.hash.insert((rec.name.clone(), rec.dest), expires);
                dns.heap.push(rec);
                continue;
            }

            remove_record(ctx, &mut dns.sock, &rec)?;
        }
    }
}

pub fn remove_records(
    ctx: &Ctx,
    dns: &mut DnsState,
    name: Option<&Name>,
    dest: Option<Ipv4Addr>,
) -> bool {
    let mut found = false;
    dns.heap.retain(|rec| {
        if let Some(name) = name
            && &rec.name != name
        {
            return true;
        }

        if let Some(dest) = dest
            && rec.dest != dest
        {
            return true;
        }

        found = true;
        dns.hash.remove(&(rec.name.clone(), rec.dest));
        remove_record(ctx, &mut dns.sock, &rec).ok();

        false
    });
    found
}

pub fn remove_record(ctx: &Ctx, sock: &mut NetlinkSocket, rec: &DnsRecord) -> eyre::Result<()> {
    info!("Removing record for {:?}: {}", rec.name, rec.dest);

    // ip route del table <table>
    let mut req = rt_route::Request::new().op_delroute_do(&rt_route::Rtmsg {
        rtm_family: libc::AF_INET as u8,
        rtm_dst_len: 32,
        rtm_type: rt_route::RtmType::Unicast as u8,
        ..Default::default()
    });
    req.encode()
        .push_dst(rec.dest.into())
        .push_table(ctx.dns_table);

    if let Err(err) = sock.request(&req)?.recv_ack() {
        debug!("Error deleting route for expired dns record: {err}");
    }

    Ok(())
}

pub async fn watch_dns_routes(ctx: &Ctx) -> eyre::Result<()> {
    let mut sock = NetlinkSocket::new();

    let mut conf = ctx.state.rx.clone();
    let mut routes = ctx.routes_changed.rx.clone();
    let mut default_route = ctx.default_route_changed.rx.clone();

    conf.mark_changed();

    loop {
        let mut update_caches = tokio::select! {
            _ = conf.changed() => true,
            _ = routes.changed() => false,
            _ = default_route.changed() => false,
        };

        update_caches |= conf.has_changed().unwrap();

        conf.mark_unchanged();
        routes.mark_unchanged();
        default_route.mark_unchanged();

        let mut dns = ctx.dns.lock().await;

        if update_caches {
            debug!("Updating dns caches");
            dns.cache.clear();
            for m in &conf.borrow().matches.matches {
                if m.kind == Kind::dns {
                    if let Ok(mut name) = Name::from_str_relaxed(&m.pattern) {
                        name.set_fqdn(true);
                        dns.cache.insert(name, m.direction);
                    }
                }
            }
        }

        let DnsState {
            hash, cache, heap, ..
        } = &mut *dns;

        heap.retain(|h| cache.contains_key(&h.name));
        hash.retain(|(n, _), _| cache.contains_key(n));

        crate::netlink::clear_table(&mut sock, ctx.dns_table)?;
        if conf.borrow().enable {
            for rec in heap.iter() {
                let dir = *cache.get(&rec.name).unwrap();
                if let Err(err) = setup_record(ctx, &mut sock, &rec, dir) {
                    debug!("Error setting up dns record: {err}");
                }
            }
        }
    }
}

fn setup_record(
    ctx: &Ctx,
    sock: &mut NetlinkSocket,
    rec: &DnsRecord,
    dir: Direction,
) -> eyre::Result<()> {
    let route = match dir {
        Direction::redirect => &ctx.routes_changed.rx.borrow(),
        Direction::bypass => &ctx.default_route_changed.rx.borrow(),
    };
    let Some(route) = route.as_ref() else {
        return Ok(());
    };

    info!(
        "Setting up record for {:?} ({}): {}",
        rec.name, route.ifname, rec.dest
    );

    // ip route add <addr> dev <dev> table <table>
    let mut req = rt_route::Request::new()
        .set_create()
        .set_excl()
        .op_newroute_do(&rt_route::Rtmsg {
            rtm_family: libc::AF_INET as u8,
            rtm_dst_len: 32,
            rtm_protocol: libc::RTPROT_BOOT as u8,
            rtm_type: rt_route::RtmType::Unicast as u8,
            ..Default::default()
        });
    req.encode()
        .push_dst(rec.dest.into())
        .push_table(ctx.dns_table)
        .push_oif(route.ifindex);
    if let Some(addr) = route.addrs.first() {
        req.encode().push_prefsrc(*addr);
    }
    if let Some(gateway) = route.gateway {
        req.encode().push_gateway(gateway);
    }
    sock.request(&req)?.recv_ack()?;

    Ok(())
}

fn parse(ctx: &Ctx, data: &[u8]) -> eyre::Result<()> {
    let m = hickory_proto::op::Message::from_bytes(data)?;

    if m.queries.is_empty() && m.answers.is_empty() {
        bail!("Can't parse any queries nor answers");
    }

    if m.message_type != hickory_proto::op::MessageType::Response {
        bail!("Not a response");
    }

    if m.response_code != hickory_proto::op::ResponseCode::NoError {
        bail!("Has errors: {}", m.response_code);
    }

    let now = Instant::now();
    let max_ttl = ctx.state.rx.borrow().config.dns_max_ttl_sec;
    let mut dns = ctx.dns.blocking_lock();
    for mut ans in m.answers {
        debug!(
            "Dns answer: {}: {}: {}",
            ans.name,
            ans.record_type(),
            ans.data
        );

        let RData::A(rdata::A(dest)) = ans.data else {
            continue;
        };

        ans.name.set_fqdn(true);
        let Some(dir) = dns.cache.get(&ans.name).cloned() else {
            debug!("No match");
            debug!("{:?}", dns.cache);
            continue;
        };

        let ttl_expire = now + Duration::from_secs(ans.ttl.min(max_ttl) as u64);
        let rec = DnsRecord {
            ttl_expire,
            dest,
            name: ans.name,
        };

        if dns
            .hash
            .insert((rec.name.clone(), rec.dest), ttl_expire)
            .is_some()
        {
            // New ttl is applied from hash map when renewing
            debug!("Already in cache");
            continue;
        }

        dns.heap.push(rec.clone());
        dns.ttl_sleeper
            .send_if_changed(dns.heap.peek().map(|r| r.ttl_expire));

        if let Err(err) = setup_record(ctx, &mut dns.sock, &rec, dir) {
            debug!("Error setting up dns record: {err}");
        }
    }

    Ok(())
}

pub unsafe extern "C" fn callback(
    ctx: *mut std::ffi::c_void,
    data: *mut std::ffi::c_void,
    data_sz: usize,
) -> i32 {
    debug!("Got dns packet");

    let ctx: &Ctx = unsafe { std::mem::transmute(ctx) };
    let data: &[u8] = unsafe { std::slice::from_raw_parts(data as *const u8, data_sz) };

    if let Err(err) = parse(ctx, data) {
        debug!("Not using dns response: {err}");
    }

    0
}
