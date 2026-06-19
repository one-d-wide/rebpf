use iced::{
    Element, Font,
    Length::{self, Fill, Shrink},
    Padding, Task,
    alignment::{Horizontal, Vertical},
    color,
    font::{Family, Weight},
    widget::{column, pick_list::Handle, *},
    window,
};
use iced_aw::{DropDown, drop_down};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::net::Ipv4Addr;

use message::{Attached, D, M, Match, Settings, Stats, Tray, TrayState, TrayTheme, Tx};
use widgets::{container_hook, modal};

mod utils;

const HCENTER: Horizontal = Horizontal::Center;
const VCENTER: Vertical = Vertical::Center;
const MONO: Font = Font {
    family: Family::Monospace,
    ..Font::DEFAULT
};
const SEMIBOLD: Font = Font {
    weight: Weight::Semibold,
    ..Font::DEFAULT
};
const MONO_BOLD: Font = Font {
    family: Family::Monospace,
    weight: Weight::Bold,
    ..Font::DEFAULT
};

pub const KINDS: [&str; 6] = [
    "basename",
    "substring",
    "prefix",
    "ipv4",
    "ipv4/subnet",
    "dns",
];
pub const KIND_DEFAULT: &str = KINDS[1];

pub const THEME_DEFAULT: Theme = Theme::Dark;

pub struct UniqueId(pub Id);
impl Default for UniqueId {
    fn default() -> Self {
        Self(Id::unique())
    }
}

#[derive(Default)]
pub struct State {
    pub d_tx: Option<Tx<D>>,
    pub t_tx: Option<Tx<TrayState>>,
    pub theme: Option<Theme>,
    pub tray_theme: TrayTheme,
    pub tray_up: bool,
    pub window: Option<window::Id>,
    pub settings: Settings,
    pub settings_override: Settings,
    pub show_settings: bool,

    pub output_dev_input_id: UniqueId,
    pub output_dev_input_focus: bool,
    pub output_dev_input: String,
    pub output_dev_input_sent: bool,
    pub output_dev_popup_focus: bool,

    pub proc_input_id: UniqueId,
    pub proc_input_focus: bool,
    pub proc_input: String,
    pub proc_input_sent: bool,
    pub proc_popup_focus: bool,
    pub proc_input_dir: &'static str,
    pub proc_input_default_dir: &'static str,
    pub proc_input_kind: &'static str,
    pub proc_input_kind_after_refine: bool,
    pub attached: Attached,
    pub stats: Stats,
    pub matches: Vec<(Match, Id)>,
    pub matches_override: HashMap<usize, Match>,
    pub matches_gen: u64,
    pub procs_active: HashSet<String>,
    pub procs_all: Option<BTreeMap<String, u32>>,
    pub procs_all_max: usize,
    pub dbus_conn_err: Option<zbus::Error>,
    pub dbus_errs: VecDeque<zbus::Error>,
    pub modal_editor: Option<text_editor::Content>,
}

fn kind_or_unk(s: &str) -> &'static str {
    KINDS.into_iter().find(|x| *x == s).unwrap_or(KIND_DEFAULT)
}

fn current_match(s: &State) -> Match {
    Match {
        kind: s.proc_input_kind.to_string(),
        pattern: s.proc_input.clone(),
        direction: s.proc_input_dir.to_string(),
        ..Default::default()
    }
}

fn refresh_procs_all(s: &mut State) {
    let m = current_match(s);
    s.procs_all_max = 10;
    s.procs_all = Some(utils::procs_all_with(
        &mut |s| m.matches(s),
        s.procs_all_max,
    ));
}

pub fn update(s: &mut State, message: M) -> Task<M> {
    log::debug!("Got event {message:?}");
    match message {
        M::Exit => return iced::exit(),
        M::TrayUp => s.tray_up = true,
        M::WindowToggle | M::WindowCloseId(_) if s.window.is_some() => {
            s.d_tx
                .as_ref()
                .unwrap()
                .unbounded_send(D::WindowClosed)
                .unwrap();

            let id = s.window.take().unwrap();
            if s.tray_up {
                return window::close(id);
            } else {
                return iced::exit();
            }
        }
        M::WindowToggle | M::WindowOpen if s.window.is_none() => {
            s.d_tx
                .as_ref()
                .unwrap()
                .unbounded_send(D::WindowOpened)
                .unwrap();

            let (id, task) = window::open(window::Settings {
                exit_on_close_request: false,
                blur: true,
                platform_specific: window::settings::PlatformSpecific {
                    application_id: "rebpf-gui".to_string(),
                    ..Default::default()
                },
                ..Default::default()
            });
            s.window = Some(id);
            return task.map(|_| M::Nop);
        }
        M::SettingsOpen => s.show_settings = true,
        M::SettingsClose => {
            s.show_settings = false;
            return update(s, M::SettingsSubmit);
        }
        M::SettingsLan(n) => {
            s.settings.allow_lan = n;
            return update(s, M::SettingsSubmit);
        }
        M::SettingsDns(n) => {
            s.settings.spoof_dns = n;
            return update(s, M::SettingsSubmit);
        }
        M::SettingsDnsIp(n) => s.settings.spoof_dns_ipv4 = n,
        M::SettingsDnsIpSubmit => {
            return update(s, M::SettingsSubmit);
        }
        M::SettingsDropEgressWithoutOutput(n) => {
            s.settings.drop_egress_without_output = n;
            return update(s, M::SettingsSubmit);
        }
        M::SettingsSubmit if s.settings != s.settings_override => {
            s.d_tx
                .as_ref()
                .unwrap()
                .unbounded_send(D::SettingsUpdate(s.settings.clone()))
                .unwrap();
        }
        M::Settings(n) => {
            s.settings_override = n.clone();
            s.settings = n;
        }
        M::MatchAdd => {
            let m = current_match(s);
            s.d_tx
                .as_ref()
                .unwrap()
                .unbounded_send(D::MatchAdd(m))
                .unwrap();
            s.proc_input_sent = true;
            return iced::advanced::widget::operate(utils::DoUnfocus(s.proc_input_id.0.clone()));
        }
        M::MatchDelete(g, i) if g == s.matches_gen => {
            let m = &s.matches[i].0;
            s.d_tx
                .as_ref()
                .unwrap()
                .unbounded_send(D::MatchDelete(m.clone()))
                .unwrap();
        }
        M::MatchKind(g, i, k) if g == s.matches_gen => {
            s.matches_override
                .entry(i)
                .or_insert_with(|| s.matches[i].0.clone())
                .kind = k.to_string();
            return update(s, M::MatchSubmit(g, i));
        }
        M::Enable => {
            s.d_tx.as_ref().unwrap().unbounded_send(D::Enable).unwrap();
        }
        M::Disable => {
            s.d_tx.as_ref().unwrap().unbounded_send(D::Disable).unwrap();
        }
        M::MatchUpdate(g, i, n) if g == s.matches_gen => {
            s.matches_override
                .entry(i)
                .or_insert_with(|| s.matches[i].0.clone())
                .pattern = n;
        }
        M::MatchDir => {
            s.proc_input_dir = match s.proc_input_dir {
                "redirect" => "bypass",
                "bypass" => "redirect",
                _ => unreachable!(),
            };
        }
        M::MatchUpdateDir(g, i) if g == s.matches_gen => {
            let m = s
                .matches_override
                .entry(i)
                .or_insert_with(|| s.matches[i].0.clone());
            m.direction = match m.direction.as_str() {
                "redirect" => "bypass",
                "bypass" => "redirect",
                _ => "redirect",
            }
            .to_string();
            return update(s, M::MatchSubmit(g, i));
        }
        M::MatchFromProc(g, i) if g == s.matches_gen => {
            let (m, _) = s.procs_all.as_ref().unwrap().iter().nth(i).unwrap();
            s.proc_input_kind = "basename";
            s.proc_input = m.rsplit_once('/').map(|(_, r)| r).unwrap_or(m).to_string();
            s.proc_input_kind_after_refine = true;
            refresh_procs_all(s);
            s.proc_popup_focus = false;
            s.proc_input_focus = false;
        }
        M::MatchSubmit(g, i) if g == s.matches_gen => {
            if let Some(m) = s.matches_override.remove(&i)
                && m != s.matches[i].0
            {
                s.d_tx
                    .as_ref()
                    .unwrap()
                    .unbounded_send(D::MatchUpdate(s.matches[i].0.clone(), m.clone()))
                    .unwrap();
            }
            return iced::advanced::widget::operate(utils::DoUnfocus(s.matches[i].1.clone()));
        }
        M::Procs(n) => {
            s.proc_input_sent = false;
            s.proc_input = n;
            s.procs_all = None;

            if s.proc_input_kind_after_refine {
                s.proc_input_kind = KIND_DEFAULT;
                s.proc_input_kind_after_refine = false;
            }

            if !s.proc_input.is_empty() {
                refresh_procs_all(s);
            }
        }

        M::OutputDevClick => s.output_dev_input_focus = true,
        M::OutputDevFocus => s.output_dev_input_focus |= s.output_dev_popup_focus,
        M::OutputDevUnfocus if s.output_dev_popup_focus => s.output_dev_input_focus = false,
        M::OutputDevUnfocus => return update(s, M::OutputDevSubmit),
        M::OutputDevPopupFocus => s.output_dev_popup_focus = true,
        M::OutputDevPopupUnfocus if s.output_dev_input_focus => s.output_dev_popup_focus = false,
        M::OutputDevPopupUnfocus => return update(s, M::OutputDevSubmit),
        M::OutputDevSetSubmit(n) => {
            return Task::none()
                .chain(update(s, M::OutputDevSet(n)))
                .chain(update(s, M::OutputDevSubmit));
        }
        M::OutputDevSet(n) => {
            s.output_dev_input_sent = s.attached.to_ifname == n;
            s.output_dev_input = n;
        }
        M::OutputDevSubmit => {
            s.output_dev_input_focus = false;
            s.output_dev_popup_focus = false;

            if !s.output_dev_input_sent && s.output_dev_input != s.attached.to_ifname {
                s.output_dev_input_sent = true;
                s.d_tx
                    .as_ref()
                    .unwrap()
                    .unbounded_send(D::ChangeOutput(s.output_dev_input.clone()))
                    .unwrap();
            }

            return iced::advanced::widget::operate(utils::DoUnfocus(
                s.output_dev_input_id.0.clone(),
            ));
        }

        M::Attached(n) => {
            s.attached = n;
            s.output_dev_input = s.attached.to_ifname.clone();
            s.output_dev_input_sent = true;
            s.t_tx
                .as_ref()
                .unwrap()
                .unbounded_send(TrayState {
                    state: if !s.attached.attached {
                        Tray::NotConnected
                    } else if s.attached.enabled {
                        Tray::Enabled
                    } else {
                        Tray::Disabled
                    },
                    theme: s.tray_theme,
                    blocker: s.attached.blocker.clone(),
                    output_dev: s.attached.to_ifname.clone(),
                })
                .unwrap();
        }
        M::Stats(n) => s.stats = n,
        M::Matches(n) => {
            if s.proc_input_sent && n.iter().any(|m| m.pattern == s.proc_input) {
                s.proc_input_sent = false;
                s.proc_input.clear();
            }
            s.matches_override.clear();
            s.matches = n.into_iter().map(|m| (m, Id::unique())).collect();
            s.matches_gen += 1;
        }
        M::ActiveProcs(n) => {
            s.procs_active = n;
            s.matches_gen += 1;
        }
        M::Kind(n) => {
            s.proc_input_kind = n;
            s.proc_input_kind_after_refine = false;
        }
        M::ProcPopupFocus => s.proc_popup_focus = true,
        M::ProcPopupUnfocus => s.proc_popup_focus = false,
        M::MatchUnfocus => {
            s.proc_input_focus = false;
            return iced::advanced::widget::operate(utils::DoUnfocus(s.proc_input_id.0.clone()));
        }
        M::MatchFocus => s.proc_input_focus = true,
        M::DbusConnected => {
            s.dbus_conn_err = None;
        }
        M::DbusFail(err) => {
            return update(s, M::DbusErr(err.clone())).chain(update(s, M::DbusCantConnect(err)));
        }
        M::DbusErr(err) => {
            // Rollback pending configuration changes
            s.settings_override = s.settings.clone();
            s.output_dev_input = s.attached.to_ifname.clone();
            s.output_dev_input_sent = true;
            s.matches_override.clear();

            s.dbus_errs.push_back(err);
            if s.modal_editor.is_none() {
                return update(s, M::ModalReplace);
            }
        }
        M::DbusCantConnect(err) => {
            s.attached = Default::default();
            s.matches = Default::default();
            s.matches_override = Default::default();
            s.matches_gen += 1;

            s.dbus_conn_err = Some(err);
            s.t_tx
                .as_ref()
                .unwrap()
                .unbounded_send(TrayState {
                    state: Tray::NotConnected,
                    theme: s.tray_theme,
                    output_dev: s.attached.to_ifname.clone(),
                    blocker: s.attached.blocker.clone(),
                })
                .unwrap();
        }
        M::Esc => {
            if !s.dbus_errs.is_empty() {
                return update(s, M::ModalNext);
            } else if s.show_settings {
                s.show_settings = false;
            } else if (s.proc_input_focus || s.proc_popup_focus) && !s.proc_input.is_empty() {
                s.proc_input_focus = false;
                s.proc_popup_focus = false;
            }
        }
        M::ModalNext => {
            s.dbus_errs.pop_front();
            return update(s, M::ModalReplace);
        }
        M::ModalReplace => {
            if let Some(err) = s.dbus_errs.front() {
                s.modal_editor = Some(text_editor::Content::with_text(&format!("{err}")));
            } else {
                s.modal_editor = None;
            }
        }
        M::StatusShow => {
            if let Some(err) = s.dbus_conn_err.clone() {
                return update(s, M::DbusErr(err));
            }
        }
        M::ModalEditAction(a) => {
            if !matches!(a, text_editor::Action::Edit(_))
                && let Some(t) = s.modal_editor.as_mut()
            {
                t.perform(a);
            }
        }
        _ => {}
    }

    Task::none()
}

pub fn view(s: &State, _window: window::Id) -> Element<'_, M> {
    const LOADING: &str = "";
    const S: f32 = 8.0;

    let text_input_style: for<'a> fn(&'a _, _) -> _ = |t, s| text_input::Style {
        value: text_input::default(t, text_input::Status::Active).value,
        background: text_input::default(t, s).background.scale_alpha(0.4),
        ..text_input::default(t, s)
    };

    let overlay_active = s.modal_editor.is_some() || s.show_settings;

    let button_style = |t: &Theme, s: button::Status| {
        let mut p = button::primary(t, s);
        p.border.color = t.extended_palette().background.weak.color;
        p.border.width = 1.0;
        p.border.radius = S.into();
        p.background = match s {
            button::Status::Active | button::Status::Disabled => None,
            _ => p.background.map(|c| c.scale_alpha(0.3)),
        };
        p
    };

    let pick_width = 120;

    let output_dev = container_hook::Container::new(
        text_input(LOADING, &s.output_dev_input)
            .id(s.output_dev_input_id.0.clone())
            .width(Length::FillPortion(2))
            .on_input(M::OutputDevSet)
            .on_submit(M::OutputDevSubmit)
            .style({
                let found = utils::ifnames().contains(&s.output_dev_input);
                move |t, state| {
                    let mut style = text_input_style(t, state);
                    if !found {
                        style.border.color = t.palette().warning;
                    }
                    style
                }
            }),
    )
    .gutter(S)
    .on_click(M::OutputDevClick)
    .on_hover(M::OutputDevFocus)
    .on_leave(M::OutputDevUnfocus);

    let mut output_devs_overlay = column!().spacing(S);
    let output_devs_overlay_show = s.output_dev_popup_focus || s.output_dev_input_focus;
    if output_devs_overlay_show {
        let output_devs_all = utils::ifnames();
        let output_devs_all = output_devs_all
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<&str>>();
        let output_devs_sorted =
            rust_fuzzy_search::fuzzy_search_sorted(&s.output_dev_input, &output_devs_all);
        for (ifname, _) in output_devs_sorted {
            output_devs_overlay = output_devs_overlay.push(
                button(text(ifname.to_string()))
                    .on_press(M::OutputDevSetSubmit(ifname.to_string()))
                    .style(button_style)
                    .width(Length::Fill),
            );
        }
        if output_devs_all.is_empty() {
            output_devs_overlay = output_devs_overlay.push(
                button(text("Nothing matched").align_x(Horizontal::Center))
                    .style(button_style)
                    .width(Length::Fill),
            );
        }
    }

    let output_devs_overlay = container_hook::Container::new(container(
        container(scrollable(container(output_devs_overlay).padding(S)))
            .style(container::rounded_box),
    ))
    .on_hover(M::OutputDevPopupFocus)
    .on_leave(M::OutputDevPopupUnfocus);

    let output_devs_search =
        DropDown::new(output_dev, output_devs_overlay, output_devs_overlay_show)
            .on_dismiss(M::ModalDismiss)
            .alignment(drop_down::Alignment::Bottom);

    let output_dev = column![
        row![
            row![
                text("Interface").width(Length::FillPortion(1)),
                output_devs_search,
            ]
            .align_y(Vertical::Center)
            .spacing(S),
            container(
                float(
                    text(if !overlay_active { "<" } else { "" })
                        .wrapping(text::Wrapping::None)
                        .align_x(Horizontal::Right)
                        .align_y(Vertical::Center)
                )
                .translate(|_, _| iced::Vector { x: -S, y: 0.0 })
            )
            .max_width(0)
        ]
        .align_y(Vertical::Center),
        row![
            text("Local IP").width(Length::FillPortion(1)),
            text_input(LOADING, &s.attached.to_addr)
                .width(Length::FillPortion(2))
                .style(text_input_style)
        ]
        .align_y(Vertical::Center)
        .spacing(S),
    ]
    .spacing(S)
    .padding(S)
    .height(Shrink);

    fn dir(d: &str) -> &'static str {
        match d {
            "redirect" => "R",
            "bypass" => "B",
            _ => "R",
        }
    }

    let dir_hint = |cur: &str| {
        let mut fonts = [Font::default(); 2];
        let i = match cur {
            "redirect" => 0,
            "bypass" => 1,
            _ => 0,
        };
        fonts[i] = SEMIBOLD;

        rich_text([
            span("R:").font(MONO),
            span(" Redirect\n").font(fonts[0]),
            span("B:").font(MONO),
            span(" Bypass\n").font(fonts[1]),
        ])
        .on_link_click(iced::never)
    };

    let search = row![
        button(text("+").font(MONO_BOLD).size(22))
            .padding([2, 14])
            .on_press(M::MatchAdd)
            .style(button_style),
        pick_list(KINDS, Some(s.proc_input_kind), M::Kind).width(pick_width),
        tooltip(
            button(text(dir(s.proc_input_dir)).font(MONO))
                .on_press(M::MatchDir)
                .style(button_style),
            container(dir_hint(s.proc_input_dir))
                .padding(S)
                .style(container::rounded_box),
            tooltip::Position::Bottom,
        ),
        container_hook::Container::new(
            text_input("New process...", &s.proc_input)
                .id(s.proc_input_id.0.clone())
                .on_input(M::Procs)
                .on_submit(M::MatchAdd)
                .style(text_input_style),
        )
        .gutter(S)
        .on_click(M::MatchFocus)
        .on_leave(M::MatchUnfocus),
    ]
    .spacing(S)
    .align_y(Vertical::Center)
    .width(Fill)
    .height(Shrink);

    let search_overlay_show =
        (s.proc_popup_focus || s.proc_input_focus) && !s.proc_input.is_empty();
    let mut search_overlay = column!().spacing(S);

    if search_overlay_show {
        let procs_all = s.procs_all.as_ref().unwrap();
        for (i, (c, num)) in procs_all.iter().enumerate() {
            search_overlay = search_overlay.push(
                button(text(format!("{c} ({num})")))
                    .on_press(M::MatchFromProc(s.matches_gen, i))
                    .style(button_style)
                    .width(Length::Fill),
            );
        }
        if !procs_all.is_empty() && s.procs_all_max == procs_all.len() {
            search_overlay = search_overlay.push(
                button(text(LOADING).align_x(Horizontal::Center))
                    .style(button_style)
                    .width(Length::Fill),
            );
        }
        if procs_all.is_empty() {
            search_overlay = search_overlay.push(
                button(text("Nothing matched").align_x(Horizontal::Center))
                    .style(button_style)
                    .width(Length::Fill),
            );
        }
    }

    let search_overlay = container_hook::Container::new(
        container(
            container(scrollable(container(search_overlay).padding(S)))
                .style(container::rounded_box),
        )
        .padding(Padding::new(S * 4.0).top(0.0)),
    )
    .gutter(S)
    .on_hover(M::ProcPopupFocus)
    .on_leave(M::ProcPopupUnfocus);

    let search = DropDown::new(search, search_overlay, search_overlay_show)
        .width(Length::Fill)
        .on_dismiss(M::ModalDismiss)
        .alignment(drop_down::Alignment::Bottom);

    let mut patterns = column!().spacing(S);
    for (i, (m, id)) in s.matches.iter().enumerate() {
        let is_active = !overlay_active && s.proc_input.is_empty() && m.is_in(&s.procs_active);
        let m = s.matches_override.get(&i).unwrap_or(m);
        let g = s.matches_gen;
        let mut pattern = row![
            container_hook::Container::new(
                row![
                    button(text("-").font(MONO_BOLD).size(22))
                        .padding([2, 14])
                        .on_press(M::MatchDelete(s.matches_gen, i))
                        .style(button_style),
                    pick_list(KINDS, Some(kind_or_unk(&m.kind)), move |k| M::MatchKind(
                        g, i, k
                    ))
                    .style(|t, _| pick_list::default(t, pick_list::Status::Active))
                    .handle(Handle::None)
                    .width(pick_width),
                    tooltip(
                        button(text(dir(&m.direction)).font(MONO))
                            .on_press(M::MatchUpdateDir(g, i))
                            .style(button_style),
                        container(dir_hint(&m.direction))
                            .padding(S)
                            .style(container::rounded_box),
                        tooltip::Position::Bottom,
                    ),
                    text_input(LOADING, &m.pattern)
                        .id(id.clone())
                        .on_input(move |n| M::MatchUpdate(g, i, n))
                        .on_submit(M::MatchSubmit(g, i))
                        .style(text_input_style),
                ]
                .spacing(S),
            )
            .on_leave(M::MatchSubmit(g, i))
        ]
        .align_y(Vertical::Center)
        .width(Fill)
        .height(Shrink);

        if is_active {
            pattern = pattern.push(
                container(
                    float(
                        text(&m.pattern)
                            .color(color!(0x24cc9e))
                            .wrapping(text::Wrapping::None)
                            .align_x(Horizontal::Right),
                    )
                    .translate(|_, _| iced::Vector { x: -S, y: 0.0 }),
                )
                .max_width(0),
            );
        }

        patterns = patterns.push(pattern);
    }

    let patterns = container(
        container(
            column![
                rule::horizontal(4),
                space().height(S / 4.0),
                search,
                rule::horizontal(1),
                scrollable(patterns).height(Fill).anchor_bottom(),
            ]
            .spacing(S),
        )
        .padding(Padding::new(S).top(S / 4.0)),
    )
    .padding(Padding::new(S).top(0));

    let theme = s.theme.as_ref().unwrap_or(&THEME_DEFAULT);
    let mut status_color = theme.palette().text;
    let mut status = if s.attached.attached && s.attached.blocker.is_empty() {
        if s.attached.enabled {
            "Status: Enabled"
        } else {
            "Status: Disabled"
        }
    } else {
        status_color = theme.palette().warning;
        if s.attached.blocker.is_empty() {
            "Not connected"
        } else {
            &s.attached.blocker
        }
    }
    .to_string();

    if let Some(err) = &s.dbus_conn_err {
        status_color = theme.palette().warning;

        match err {
            zbus::Error::FDO(err) if matches!(**err, zbus::fdo::Error::ServiceUnknown(_)) => {
                status = format!("Service not started");
            }
            zbus::Error::MethodError(name, _, _)
                if *name == "org.freedesktop.DBus.Error.ServiceUnknown" =>
            {
                status = format!("Service not started");
            }
            _ => status = format!("{err}"),
        };
    }

    fn scale_mono(n: f64) -> String {
        if n < 1_000_000.0 {
            format!("{: >6.2} KB/s", n / 1_000.0)
        } else if n < 1_000_000_000.0 {
            format!("{: >6.2} MB/s", n / 1_000_000.0)
        } else {
            format!("{: >6.2} GB/s", n / 1_000_000_000.0)
        }
    }

    let bar = row![
        column![
            text(format!("TX: {} ", scale_mono(s.stats.tx_bytes as f64))).font(MONO),
            text(format!("RX: {} ", scale_mono(s.stats.rx_bytes as f64))).font(MONO),
        ],
        space::horizontal().width(Fill),
        if !s.attached.attached {
            button("Enable")
        } else if !s.attached.enabled {
            button("Enable").on_press(M::Enable)
        } else {
            button("Disable")
                .on_press(M::Disable)
                .style(|t: &Theme, s: button::Status| {
                    let mut p = button::primary(t, s);
                    p.background = Some(t.extended_palette().danger.weak.color.into());
                    p
                })
        },
        space::horizontal().width(S),
        button(svg(icons::settings(s.tray_theme)))
            .on_press(M::SettingsOpen)
            .width(Shrink)
            .height(Shrink)
            .padding(Padding::new(S))
            .style(button_style),
    ]
    .align_y(VCENTER);

    let status_text =
        container(text(status).font(MONO).color(status_color)).padding(Padding::default());
    let status = column![
        bar,
        container_hook::Container::new(status_text)
            .show_clickable(s.dbus_conn_err.is_some() && s.modal_editor.is_none())
            .on_click(M::StatusShow),
    ]
    .align_x(Horizontal::Left)
    .padding(Padding::default().horizontal(S).vertical(S / 2.0));

    let content = column![row![output_dev, status].spacing(S).padding(S), patterns];

    if let Some(t) = &s.modal_editor {
        let popup = container(column![
            row![
                text("System service replied with error:"),
                space::horizontal().width(Fill),
                text(if s.dbus_errs.len() != 1 {
                    format!("1 / {}", s.dbus_errs.len())
                } else {
                    format!("")
                }),
            ]
            .width(600),
            space::vertical().height(S),
            text_editor(t)
                .width(600)
                .min_height(200)
                .on_action(|a| M::ModalEditAction(a)),
            space::vertical().height(S),
            button(text("Got it").align_x(HCENTER))
                .width(600)
                .on_press(M::ModalNext),
        ])
        .padding(10)
        .style(container::rounded_box);

        modal::modal(content, popup, M::ModalNext)
    } else if s.show_settings {
        let popup = container(column![
            checkbox(s.settings.allow_lan)
                .label("Allow traffic to devices on LAN (including DNS request)")
                .on_toggle(M::SettingsLan),
            checkbox(s.settings.spoof_dns)
                .label("Spoof DNS traffic")
                .on_toggle(M::SettingsDns),
            row![
                text("DNS IP address: "),
                space::horizontal().width(S),
                container_hook::Container::new(
                    text_input(LOADING, &s.settings.spoof_dns_ipv4)
                        .on_input_maybe(s.settings.spoof_dns.then_some(M::SettingsDnsIp))
                        .on_submit(M::SettingsDnsIpSubmit)
                        .style({
                            let is_ok = s.settings.spoof_dns_ipv4.parse::<Ipv4Addr>().is_ok();
                            move |t, state| {
                                let mut style = text_input_style(t, state);
                                if !is_ok {
                                    style.border.color = t.palette().warning;
                                }
                                style
                            }
                        }),
                )
                .gutter(S)
                .on_leave(M::SettingsDnsIpSubmit),
            ]
            .align_y(Vertical::Center),
            checkbox(s.settings.drop_egress_without_output)
                .label("Drop egress traffic if output interface not setup")
                .on_toggle(M::SettingsDropEgressWithoutOutput),
        ])
        .padding(10)
        .width(600)
        .style(container::rounded_box);

        modal::modal(content, popup, M::SettingsClose)
    } else {
        content.into()
    }
}
