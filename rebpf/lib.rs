use eyre::bail;
use hickory_proto::rr::Name;
use ipnet::IpNet;
use log::{debug, warn};
use netlink_socket2::NetlinkSocket;
use regex_automata::{
    Anchored, Input,
    dfa::{Automaton, dense},
};
use regex_syntax::escape;
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

pub mod dfa;
pub mod macros;

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
    pub matches: Arc<Vec<HashMap<&'static str, String>>>,
    pub last_gen: u64,

    pub arena: Vec<u8>,

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

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DnsRecord {
    pub ttl_expire: Instant,
    pub dest: Ipv4Addr,
    pub name: Name,
}

impl PartialOrd for DnsRecord {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(Ord::cmp(self, other))
    }
}

impl Ord for DnsRecord {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        Ord::cmp(&self.ttl_expire, &other.ttl_expire).reverse()
    }
}

pub struct DnsState {
    pub sock: NetlinkSocket,
    pub ttl_sleeper: Watch<Option<Instant>>,
    pub heap: BinaryHeap<DnsRecord>,
    pub hash: HashMap<(Name, Ipv4Addr), Instant>,
    pub cache: HashMap<Name, Direction>,
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
    pub dns: Mutex<DnsState>,
    pub dns_table: u32,
}

to_from_enum! {
    #[derive(Copy, Clone, Debug, Default, PartialEq)]
    #[derive(Serialize, Deserialize)]
    #[allow(non_camel_case_types)]
    enum Kind {
        #[default]
        basename,
        path,
        ipv4,
        dns,
    }
}

to_from_enum! {
    #[derive(Copy, Clone, Debug, Default, PartialEq)]
    #[derive(Serialize, Deserialize)]
    #[allow(non_camel_case_types)]
    enum Method {
        #[default]
        full,
        substring,
        prefix,
        suffix,
        regex,
        subnet,
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
        => dns_max_ttl_sec: u32,
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
            dns_max_ttl_sec: 3600, // 1h
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
        => method: Method,
        => direction: Direction,
        user: String,
        => => uid: u32,
    }
}

impl Match {
    pub fn is_dns(&self) -> bool {
        match self.kind {
            Kind::dns => true,
            _ => false,
        }
    }

    pub fn is_per_process(&self) -> bool {
        match self.kind {
            Kind::basename | Kind::path => true,
            _ => false,
        }
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
    pub generation: u64,
    pub dns_count: i32,
}

impl Matches {
    pub fn update(&mut self) {
        self.dns_count = self.matches.iter().filter(|m| m.is_dns()).count() as i32;
    }

        if self.matches.iter().any(|m| m.applies_to(&new)) {
            return Ok(());
    pub fn method_regex(m: &Match) -> Option<String> {
        let pat = &m.pattern;
        if pat.is_empty() {
            return None;
        }
        let method = match m.method {
            Method::full => format!("{}", escape(pat)),
            Method::substring => format!("[^/]*{}.*", escape(pat)),
            Method::prefix => format!("{}.*", escape(pat)),
            Method::suffix => format!("[^/]*{}", escape(pat)),
            Method::regex => format!("{}", pat),
            Method::subnet => return None,
        };
        Some(method)
    }

    pub fn build_path_dfa(&self, arena: &mut Vec<u8>) -> eyre::Result<bpf::DFA> {
        let mut pat_id_map = Vec::new();
        let mut set = Vec::new();

        for (i, m) in self.matches.iter().enumerate() {
            // N.B. Our dfa is configured only for anchored searches
            let Some(method) = Self::method_regex(m) else {
                continue;
            };
            let pat = match m.kind {
                Kind::basename => format!(r"^(?:.*/)?{method}$"), // TODO: "." in regex will also match "/"
                Kind::path => format!(r"^{method}$"),
                Kind::ipv4 | Kind::dns => continue,
            };
            set.push(pat);
            pat_id_map.push(i);
        }

        dfa::encode_dfa(&set, arena, &pat_id_map, self)
    }

    pub fn try_parse(&mut self, m: &Match) -> eyre::Result<()> {
        match m.kind {
            Kind::basename | Kind::path => {
                self.matches.push(m.clone());
                let res = self.build_path_dfa(&mut Vec::new());
                self.matches.pop();
                res?;
            }
            Kind::ipv4 => match m.method {
                Method::full => {
                    let _ = m.pattern.parse::<Ipv4Addr>()?;
                }
                Method::subnet => {
                    let _ = m.pattern.parse::<IpNet>()?;
                }
                _ => bail!("Invalid method {:?} for kind {:?}", m.method, m.kind),
            },
            _ => {},
        }
        Ok(())
    }

    pub fn add(&mut self, new: Match) -> eyre::Result<()> {
        self.try_parse(&new)?;

        self.dns_count += new.is_dns() as i32;
        self.matches.push(new);
        self.generation += 1;

        Ok(())
    }

    pub fn replace(&mut self, from: Match, to: Match) -> eyre::Result<()> {
        self.try_parse(&from)?;
        self.try_parse(&to)?;

        let Some(pos) = self.matches.iter().position(|m| m.is_eq_to(&from)) else {
            bail!("No such match");
        };

        self.dns_count += to.is_dns() as i32 - from.is_dns() as i32;
        self.matches[pos] = to;
        self.generation += 1;

        Ok(())
    }

    pub fn del(&mut self, new: Match) -> eyre::Result<()> {
        self.try_parse(&new)?;

        let Some(pos) = self.matches.iter().position(|m| m.is_eq_to(&new)) else {
            bail!("No such match");
        };

        let old = self.matches.remove(pos);
        self.dns_count -= old.is_dns() as i32;
        self.generation += 1;

        Ok(())
    }
}
