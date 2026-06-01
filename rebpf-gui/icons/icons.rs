use iced::{
    Padding, Rectangle, Size,
    advanced::{
        renderer::Headless,
        svg::{Handle, Renderer, Svg},
    },
};

use message::{Tray, TrayTheme};

pub fn rgba_to_argb(mut b: Vec<u8>) -> Vec<u8> {
    for c in b.chunks_exact_mut(4) {
        (c[0], c[1], c[2], c[3]) = (c[3], c[0], c[1], c[2]);
    }
    b
}

pub fn draw_rgba(svg: &'static [u8]) -> Vec<u8> {
    let mut r = iced::Renderer::new(Default::default(), Default::default());
    r.draw_svg(
        Svg::new(Handle::from_memory(svg)),
        Rectangle::with_size(Size::new(128.0, 128.0)).shrink(Padding::new(8.0)),
        Rectangle::with_size(Size::new(128.0, 128.0)).shrink(Padding::new(8.0)),
    );
    r.screenshot(iced::Size::new(128, 128), 1.0, iced::Color::TRANSPARENT)
}

pub fn settings(theme: TrayTheme) -> Handle {
    let svg = match theme {
        TrayTheme::Dark => &include_bytes!("rebpf-settings-white.svg")[..],
        TrayTheme::Light => &include_bytes!("rebpf-settings-black.svg")[..],
    };
    iced::advanced::svg::Handle::from_memory(svg)
}

pub fn tray_argb(state: Tray, theme: TrayTheme) -> Vec<u8> {
    rgba_to_argb(tray_rgba(state, theme))
}

pub fn tray_rgba(state: Tray, theme: TrayTheme) -> Vec<u8> {
    let svg = match (state, theme) {
        (Tray::NotConnected, TrayTheme::Dark) => &include_bytes!("rebpf-warn-white.svg")[..],
        (Tray::Disabled, TrayTheme::Dark) => &include_bytes!("rebpf-off-white.svg")[..],
        (Tray::Enabled, TrayTheme::Dark) => &include_bytes!("rebpf-on-white.svg")[..],
        (Tray::NotConnected, TrayTheme::Light) => &include_bytes!("rebpf-warn-black.svg")[..],
        (Tray::Disabled, TrayTheme::Light) => &include_bytes!("rebpf-off-black.svg")[..],
        (Tray::Enabled, TrayTheme::Light) => &include_bytes!("rebpf-on-black.svg")[..],
    };
    draw_rgba(svg)
}
