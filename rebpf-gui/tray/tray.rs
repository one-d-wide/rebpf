use serde::Serialize;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use zbus::{
    interface,
    object_server::SignalEmitter,
    zvariant::{ObjectPath, OwnedValue, Type, Value},
};

use message::{D, M, NAME, NAME_DBUS, Rx, Tray, TrayState, TrayTheme, Tx};

pub async fn tray(m_tx: Tx<M>, d_tx: Tx<D>, mut t_rx: Rx<TrayState>) -> zbus::Result<()> {
    let item = "/StatusNotifierItem";
    let menu = "/MenuBar";
    let interface = "org.kde.StatusNotifierItem";

    let state = Arc::new(Mutex::new(TrayState {
        state: Tray::NotConnected,
        theme: TrayTheme::Dark,
        output_dev: String::new(),
        blocker: String::new(),
    }));

    let conn = zbus::connection::Builder::session()?
        .serve_at(
            menu,
            Menu {
                m_tx: m_tx.clone(),
                d_tx: d_tx.clone(),
            },
        )?
        .serve_at(
            item,
            Item {
                m_tx: m_tx.clone(),
                state: state.clone(),
            },
        )?
        .build()
        .await?;

    match conn
        .request_name_with_flags(NAME_DBUS, zbus::fdo::RequestNameFlags::DoNotQueue.into())
        .await
    {
        Err(zbus::Error::NameTaken) => {
            log::warn!("Another {NAME} instance is already registered on dbus as {NAME_DBUS}");
            if let Ok(_) = conn
                .call_method(
                    Some(NAME_DBUS),
                    item,
                    Some(interface),
                    "Activate",
                    &(0i32, 0i32),
                )
                .await
            {
                std::process::exit(0);
            }
        }
        _ => {}
    }

    dbus::notifier_watcher_proxy::StatusNotifierWatcherProxy::new(&conn)
        .await?
        .register_status_notifier_item(item)
        .await?;

    m_tx.unbounded_send(M::TrayUp).unwrap();

    loop {
        let new_state = t_rx.recv().await.unwrap();
        *state.lock().unwrap() = new_state;

        let emitter = SignalEmitter::new(&conn, item)?;

        emitter.emit(interface, "NewIcon", &()).await?;
        emitter.emit(interface, "NewToolTip", &()).await?;
    }
}

pub struct Item {
    m_tx: Tx<M>,
    state: Arc<Mutex<TrayState>>,
}

/// Width, height, ARGB32 data
pub type IconData = (i32, i32, Vec<u8>);

/// System icon name, Icon data, Title, Text (with certain html tags)
///
/// https://www.freedesktop.org/wiki/Specifications/StatusNotifierItem/Markup/
pub type ToolTip = (String, IconData, String, String);

#[interface(interface = "org.kde.StatusNotifierItem")]
impl Item {
    /// Activate method
    fn activate(&self, _x: i32, _y: i32) {
        self.m_tx.unbounded_send(M::WindowToggle).unwrap();
    }

    /// NewIcon signal
    #[zbus(signal)]
    async fn new_icon(emitter: &SignalEmitter<'_>) -> zbus::Result<()>;

    /// NewToolTip signal
    #[zbus(signal)]
    async fn new_tool_tip(emitter: &SignalEmitter<'_>) -> zbus::Result<()>;

    /// Category property
    #[zbus(property)]
    fn category(&self) -> &str {
        "SystemServices"
    }

    // /// IconName property
    // #[zbus(property)]
    // fn icon_name(&self) -> &str {
    //     "kate-symbolic.svg"
    // }

    /// IconPixmap property
    #[zbus(property)]
    fn icon_pixmap(&self) -> Vec<(i32, i32, Vec<u8>)> {
        let s = self.state.lock().unwrap();
        vec![(128, 128, icons::tray_argb(s.state, s.theme))]
    }

    /// Id property
    #[zbus(property)]
    fn id(&self) -> &str {
        NAME
    }

    /// ItemIsMenu property
    #[zbus(property)]
    fn item_is_menu(&self) -> bool {
        false
    }

    /// Menu property
    #[zbus(property)]
    fn menu(&self) -> ObjectPath<'_> {
        ObjectPath::from_str_unchecked("/MenuBar").into()
    }

    /// Status property
    #[zbus(property)]
    fn status(&self) -> &str {
        "Active"
    }

    /// Title property
    #[zbus(property)]
    fn title(&self) -> &str {
        NAME
    }

    /// ToolTip property
    #[zbus(property)]
    fn tool_tip(&self) -> (&str, Vec<IconData>, String, &str) {
        let state = self.state.lock().unwrap();
        let blocker = if state.blocker.is_empty() {
            format!("{:?}", state.state)
        } else {
            state.blocker.clone()
        };
        let mut text = format!("{NAME}: {}", blocker);
        if !state.output_dev.is_empty() {
            text = format!("{text} ({})", state.output_dev)
        };

        ("", Vec::new(), text, "")
    }
}

struct Menu {
    m_tx: Tx<M>,
    d_tx: Tx<D>,
}

#[derive(Serialize, Type, PartialEq, Debug, Default)]
pub(crate) struct MenuLayout {
    pub id: u32,
    pub fields: SubMenuLayout,
}

#[derive(Serialize, Type, PartialEq, Debug, Default)]
pub(crate) struct SubMenuLayout {
    pub id: i32,
    pub fields: HashMap<String, Value<'static>>,
    pub submenus: Vec<Value<'static>>,
}

#[derive(Serialize, Type, PartialEq, Debug, Default)]
pub(crate) struct SimpleMenuItem {
    pub id: i32,
    pub fields: HashMap<String, Value<'static>>,
}

#[allow(dead_code)]
type GroupProperties = Vec<(i32, HashMap<String, zbus::zvariant::OwnedValue>)>;

#[derive(Serialize, Type, Debug, Clone)]
pub struct PropertiesUpdate<'a> {
    #[serde(borrow)]
    pub(crate) updated: Vec<UpdatedProps<'a>>,
    pub(crate) removed: Vec<RemovedProps<'a>>,
}

#[derive(Serialize, Type, Debug, Clone)]
pub struct UpdatedProps<'a> {
    pub(crate) id: i32,
    #[serde(borrow)]
    pub(crate) fields: HashMap<&'a str, Value<'a>>,
}

#[derive(Serialize, Type, Debug, Clone)]
pub struct RemovedProps<'a> {
    pub(crate) id: i32,
    #[serde(borrow)]
    pub(crate) fields: Vec<&'a str>,
}

impl Menu {
    fn simple_menu_layout(&self) -> Vec<SimpleMenuItem> {
        vec![
            SimpleMenuItem {
                id: 2,
                fields: [
                    ("enabled".to_string(), Value::new(true)),
                    ("label".to_string(), Value::new("Enable")),
                    ("visible".to_string(), Value::new(true)),
                ]
                .into_iter()
                .collect::<HashMap<String, Value<'static>>>(),
            },
            SimpleMenuItem {
                id: 3,
                fields: [
                    ("enabled".to_string(), Value::new(true)),
                    ("label".to_string(), Value::new("Disable")),
                    ("visible".to_string(), Value::new(true)),
                ]
                .into_iter()
                .collect::<HashMap<String, Value<'static>>>(),
            },
            SimpleMenuItem {
                id: 4,
                fields: [
                    ("enabled".to_string(), Value::new(true)),
                    ("label".to_string(), Value::new(format!("Quit {NAME}"))),
                    ("visible".to_string(), Value::new(true)),
                ]
                .into_iter()
                .collect::<HashMap<String, Value<'static>>>(),
            },
        ]
    }
}

#[interface(interface = "com.canonical.dbusmenu")]
impl Menu {
    /// Event method
    fn event(&self, id: i32, event_id: String, _data: OwnedValue, _timestamp: u32) {
        if event_id == "clicked" {
            match id {
                2 => self.d_tx.unbounded_send(D::Enable).unwrap(),
                3 => self.d_tx.unbounded_send(D::Disable).unwrap(),
                4 => self.m_tx.unbounded_send(M::Exit).unwrap(),
                _ => {}
            }
        }
    }

    /// EventGroup method
    fn event_group(&self, events: Vec<(i32, String, OwnedValue, u32)>) -> Vec<i32> {
        for (id, ev_id, data, timestamp) in events {
            self.event(id, ev_id, data, timestamp);
        }
        vec![]
    }

    /// GetGroupProperties method
    fn get_group_properties(
        &self,
        ids: Vec<i32>,
        _property_names: Vec<String>,
    ) -> Vec<(i32, HashMap<String, Value<'static>>)> {
        self.simple_menu_layout()
            .into_iter()
            .filter(|s| ids.contains(&s.id))
            .map(|s| (s.id, s.fields))
            .collect()
    }

    /// GetLayout method
    fn get_layout(
        &self,
        parent_id: i32,
        _recursion_depth: i32,
        _property_names: Vec<String>,
    ) -> MenuLayout {
        if parent_id != 0 {
            return MenuLayout {
                id: 1,
                fields: SubMenuLayout {
                    id: parent_id,
                    ..Default::default()
                },
            };
        }

        MenuLayout {
            id: 1,
            fields: SubMenuLayout {
                id: 0,
                fields: [(format!("children-display"), Value::new("submenu"))]
                    .into_iter()
                    .collect(),
                submenus: self
                    .simple_menu_layout()
                    .into_iter()
                    .map(|s| Value::new((s.id, s.fields, <Vec<OwnedValue>>::default())))
                    .collect(),
            },
        }
    }

    #[zbus(property)]
    fn status(&self) -> &'static str {
        "normal"
    }

    /// TextDirection property
    #[zbus(property)]
    fn text_direction(&self) -> String {
        "ltr".into()
    }

    #[zbus(property)]
    fn version(&self) -> u32 {
        4
    }
}
