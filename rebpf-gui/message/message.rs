use iced::futures::channel::mpsc::{UnboundedReceiver, UnboundedSender};
use std::collections::{HashMap, HashSet};

mod macros;

pub type Tx<T> = UnboundedSender<T>;
pub type Rx<T> = UnboundedReceiver<T>;

pub const NAME: &str = "Rebpf";
pub const NAME_DBUS: &str = "service.rebpf-gui";
pub const SERVICE_NAME_DBUS: &str = "service.rebpf";

#[derive(Clone, Debug)]
pub enum M {
    Enable,
    Disable,
    Exit,
    TrayUp,
    WindowOpen,
    WindowToggle,
    WindowCloseId(iced::window::Id),
    Settings(Settings),
    SettingsSubmit,
    SettingsOpen,
    SettingsClose,
    SettingsLan(bool),
    SettingsDns(bool),
    SettingsDnsIp(String),
    SettingsDnsIpSubmit,
    SettingsDropEgressWithoutOutput(bool),
    MatchAdd,
    MatchDelete(u64, usize),
    MatchFromProc(u64, usize),
    MatchUpdate(u64, usize, String),
    MatchKind(u64, usize, &'static str),
    MatchDir,
    MatchUpdateDir(u64, usize),
    MatchSubmit(u64, usize),
    Procs(String),
    Kind(&'static str),
    Attached(Attached),
    Matches(Vec<Match>),
    Stats(Stats),
    DbusErr(zbus::Error),
    DbusFail(zbus::Error),
    DbusCantConnect(zbus::Error),
    DbusConnected,
    ActiveProcs(HashSet<String>),
    MatchFocus,
    MatchUnfocus,
    ProcPopupFocus,
    ProcPopupUnfocus,

    OutputDevClick,
    OutputDevFocus,
    OutputDevUnfocus,
    OutputDevPopupFocus,
    OutputDevPopupUnfocus,
    OutputDevSet(String),
    OutputDevSubmit,
    OutputDevSetSubmit(String),

    Esc,
    ModalNext,
    ModalReplace,
    ModalDismiss,
    StatusShow,
    ModalEditAction(iced::widget::text_editor::Action),
    NopString(String),
    Nop,
}

#[derive(Debug)]
pub enum D {
    WindowOpened,
    WindowClosed,
    Enable,
    Disable,
    ChangeOutput(String),
    SettingsUpdate(Settings),
    MatchAdd(Match),
    MatchDelete(Match),
    MatchUpdate(Match, Match),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Tray {
    NotConnected,
    Enabled,
    Disabled,
}

#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub enum TrayTheme {
    #[default]
    Dark,
    Light,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TrayState {
    pub state: Tray,
    pub theme: TrayTheme,
    pub blocker: String,
    pub output_dev: String,
}

to_from_hashmap_all! {
    struct Settings {
        allow_lan: bool,
        spoof_dns: bool,
        spoof_dns_ipv4: String,
        drop_egress_without_output: bool,
    }
}

to_from_hashmap! {
    struct Attached {
        enabled: bool,
        attached: bool,
        blocker: String,

        to_ifname: String,
        to_ifindex: String,
        to_addr: String,
    }
}

to_from_hashmap! {
    struct Stats {
        tx_bytes: u64,
        rx_bytes: u64,
        dtime_sec: f64,
    }
}

to_from_hashmap! {
    struct Match {
        pattern: String,
        kind: String,
        direction: String,
        user: String,
        uid: String,
    }
}

impl Match {
    pub fn is_in(&self, h: &HashSet<String>) -> bool {
        if self.kind == "basename" {
            return h.contains(&self.pattern);
        }
        h.iter().any(|s| self.matches(s))
    }

    pub fn matches(&self, s: &str) -> bool {
        match self.kind.as_str() {
            "basename" => s.rsplit_once('/').map(|(_, r)| r).unwrap_or(s) == self.pattern,
            "prefix" => s.strip_prefix(&self.pattern).is_some(),
            "substring" => s.contains(&self.pattern),
            "dns" => self.pattern == s.trim_matches('.'),
            _ => self.pattern == s,
        }
    }
}
