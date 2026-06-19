use eyre::bail;
use netlink_socket2::NetlinkSocket;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BinaryHeap, HashMap},
    fmt::Display,
    net::{IpAddr, Ipv4Addr},
    str::FromStr,
    sync::Arc,
};
use tokio::{
    sync::{Mutex, watch},
    time::Instant,
};
use zbus::Connection;

mod macros;

#[allow(unused)]
#[allow(non_camel_case_types)]
#[allow(non_upper_case_globals)]
pub mod bindings;
pub use bindings as bpf;

#[derive(Clone)]
pub struct Watch<T> {
    pub tx: watch::Sender<T>,
    pub rx: watch::Receiver<T>,
}

impl<T> Watch<T> {
    pub fn new(val: T) -> Self {
        let (tx, rx) = watch::channel(val);
        Self { tx, rx }
    }
}

impl<T: PartialEq> Watch<T> {
    pub fn send_if_changed(&self, new_val: T) {
        if *self.tx.borrow() != new_val {
            self.tx.send(new_val).unwrap();
        }
    }
}

impl<T: Default> Default for Watch<T> {
    fn default() -> Self {
        let (tx, rx) = watch::channel(T::default());
        Self { tx, rx }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Route {
    pub is_up: bool,
    pub ifindex: u32,
    pub ifname: String,
    pub addrs: Vec<IpAddr>,
    pub gateway: Option<IpAddr>,
}

pub struct BpfCtx {
    pub mark: Option<u32>,
    pub matches_time: Instant,
    pub matches: Arc<String>,
    pub last_gen: u64,
    pub cstrings: Vec<u8>,
    pub cmatches: Vec<bpf::MatchStr>,

    pub ptr: usize,
    pub len: u64,
    pub cap: u64,
}
unsafe impl Send for BpfCtx {}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    pub enable: bool,
    pub to_dev: String,
    pub config: Config,
    pub matches: Matches,
    pub generation: u64,
}

pub struct Ctx {
    pub conn: &'static Connection,
    pub state: Watch<State>,
    pub attached: Watch<bool>,
    pub blocker: Watch<String>,
    pub to_changed: Watch<()>,
    pub from_changed: Watch<()>,
    pub routes_changed: Watch<Option<Route>>,
    pub default_route_changed: Watch<Option<Route>>,
    pub do_reload: Watch<()>,
    pub bpf: Mutex<BpfCtx>,
    pub stats: Mutex<StatsHist>,
}

to_from_enum! {
    #[derive(Copy, Clone, Debug, Default, PartialEq)]
    #[derive(Serialize, Deserialize)]
    #[allow(non_camel_case_types)]
    enum Kind {
        #[default]
        basename,
        substring,
        full,
        prefix,
        ipv4,
        #[[rename = "ipv4/subnet"]]
        ipv4_subnet,
    }
}

to_from_enum! {
    #[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[derive(Serialize, Deserialize)]
    #[allow(non_camel_case_types)]
    enum Direction {
        #[default]
        redirect,
        bypass,
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Stats {
    pub time: Instant,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

impl Default for Stats {
    fn default() -> Self {
        Stats {
            time: Instant::now(),
            tx_bytes: Default::default(),
            rx_bytes: Default::default(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct StatsHist {
    pub prev: Stats,
    pub cur: Stats,
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
    pub fn try_parse(&self) -> eyre::Result<()> {
        match self.kind {
            Kind::basename | Kind::substring | Kind::full | Kind::prefix => {}
            Kind::ipv4 => {
                let _ = self.pattern.parse::<Ipv4Addr>()?;
            }
            Kind::ipv4_subnet => {
                let _ = self.pattern.parse::<IpNet>()?;
            }
        }
        Ok(())
    }

    pub fn is_per_process(&self) -> bool {
        match self.kind {
            Kind::basename | Kind::substring | Kind::full | Kind::prefix => true,
            _ => false,
        }
    }

    pub fn applies_to(&self, r: &Match) -> bool {
        self.kind == r.kind
            && self.pattern == r.pattern
            && self.direction == r.direction
            && (self.uid == 0
                || self.uid == r.uid
                || (!self.user.is_empty() && self.user == r.user))
    }

    pub fn is_eq_to(&self, r: &Match) -> bool {
        self.kind == r.kind
            && self.pattern == r.pattern
            && self.direction == r.direction
            && self.uid == r.uid
            && self.user == r.user
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Matches {
    pub matches: Vec<Match>,
    pub strings_len: usize,
    pub generation: u64,
}

impl Matches {
    pub fn add(&mut self, new: Match) -> eyre::Result<()> {
        new.try_parse()?;

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

    pub fn replace(&mut self, from: Match, to: Match) -> eyre::Result<()> {
        from.try_parse()?;
        to.try_parse()?;

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

    pub fn del(&mut self, new: Match) -> eyre::Result<()> {
        new.try_parse()?;

        let Some(pos) = self.matches.iter().position(|m| m.is_eq_to(&new)) else {
            bail!("No such match");
        };

        let old = self.matches.remove(pos);
        self.strings_len -= old.pattern.len() + 1;
        self.generation += 1;

        Ok(())
    }
}
