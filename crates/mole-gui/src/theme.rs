//! Mole's look: Windows 11's own design language rather than egui's defaults.
//!
//! The colours are Fluent's published tokens (window, card, control, text and
//! the success/caution/critical set), the type is the system's Segoe UI in
//! Fluent's ramp (12 caption, 14 body, 20 subtitle), controls have 4 px corners
//! and cards 8 px. The aim is a window that looks like it belongs on the desktop
//! it runs on, not like a toolkit demo.

use std::sync::Arc;

use eframe::egui::{self, Color32, CornerRadius, FontFamily, FontId, Stroke, TextStyle};

/// Fluent colour tokens for one theme.
#[derive(Clone, Copy)]
pub struct Palette {
    pub dark: bool,
    pub window: Color32,
    pub card: Color32,
    pub card_stroke: Color32,
    pub text: Color32,
    pub text2: Color32,
    pub text3: Color32,
    pub accent: Color32,
    pub accent_hover: Color32,
    pub accent_pressed: Color32,
    pub on_accent: Color32,
    pub control: Color32,
    pub control_hover: Color32,
    pub control_pressed: Color32,
    pub control_stroke: Color32,
    pub disabled: Color32,
    pub success: Color32,
    pub caution: Color32,
    pub critical: Color32,
    pub caution_bg: Color32,
    pub neutral_icon: Color32,
    pub divider: Color32,
}

const fn hex(v: u32) -> Color32 {
    Color32::from_rgb((v >> 16) as u8, (v >> 8) as u8, v as u8)
}

pub const LIGHT: Palette = Palette {
    dark: false,
    window: hex(0xF3F3F3),
    card: hex(0xFBFBFB),
    card_stroke: hex(0xE5E5E5),
    text: hex(0x1B1B1B),
    text2: hex(0x5F5F5F),
    text3: hex(0x8A8A8A),
    accent: hex(0x005FB8),
    accent_hover: hex(0x196EBF),
    accent_pressed: hex(0x327EC5),
    on_accent: hex(0xFFFFFF),
    control: hex(0xFEFEFE),
    control_hover: hex(0xF9F9F9),
    control_pressed: hex(0xF5F5F5),
    control_stroke: hex(0xE0E0E0),
    disabled: hex(0xBFBFBF),
    success: hex(0x0F7B0F),
    caution: hex(0x9D5D00),
    critical: hex(0xC42B1C),
    caution_bg: hex(0xFFF4CE),
    neutral_icon: hex(0x8A8A8A),
    divider: hex(0xEBEBEB),
};

pub const DARK: Palette = Palette {
    dark: true,
    window: hex(0x202020),
    card: hex(0x2B2B2B),
    card_stroke: hex(0x1D1D1D),
    text: hex(0xFFFFFF),
    text2: hex(0xC8C8C8),
    text3: hex(0x9D9D9D),
    accent: hex(0x60CDFF),
    accent_hover: hex(0x5BBBE8),
    accent_pressed: hex(0x56A9D1),
    on_accent: hex(0x000000),
    control: hex(0x373737),
    control_hover: hex(0x3D3D3D),
    control_pressed: hex(0x323232),
    control_stroke: hex(0x444444),
    disabled: hex(0x5D5D5D),
    success: hex(0x6CCB5F),
    caution: hex(0xFCE100),
    critical: hex(0xFF99A4),
    caution_bg: hex(0x433519),
    neutral_icon: hex(0x9D9D9D),
    divider: hex(0x3A3A3A),
};

pub fn palette(dark: bool) -> Palette {
    if dark {
        DARK
    } else {
        LIGHT
    }
}

/// The semibold face, for titles and emphasis.
pub fn semibold() -> FontFamily {
    FontFamily::Name("semibold".into())
}

/// Use the system's Segoe UI (and Consolas for technical values). Read at run
/// time from the Windows font folder — never bundled. If a file is missing, the
/// family falls back to egui's own fonts, so nothing can fail to render.
pub fn install_fonts(ctx: &egui::Context) {
    let mut defs = egui::FontDefinitions::default();
    let fonts_dir = std::env::var("WINDIR")
        .map(|w| std::path::PathBuf::from(w).join("Fonts"))
        .unwrap_or_else(|_| std::path::PathBuf::from(r"C:\Windows\Fonts"));
    let mut load = |name: &str, file: &str| -> bool {
        match std::fs::read(fonts_dir.join(file)) {
            Ok(bytes) => {
                defs.font_data
                    .insert(name.to_owned(), Arc::new(egui::FontData::from_owned(bytes)));
                true
            }
            Err(_) => false,
        }
    };
    let regular = load("Segoe UI", "segoeui.ttf");
    let bold = load("Segoe UI Semibold", "seguisb.ttf");
    let mono = load("Consolas", "consola.ttf");

    let fallback = defs
        .families
        .get(&FontFamily::Proportional)
        .cloned()
        .unwrap_or_default();
    let mut proportional = fallback.clone();
    if regular {
        proportional.insert(0, "Segoe UI".into());
    }
    let mut strong = proportional.clone();
    if bold {
        strong.insert(0, "Segoe UI Semibold".into());
    }
    defs.families.insert(FontFamily::Proportional, proportional);
    defs.families.insert(semibold(), strong);
    if mono {
        if let Some(list) = defs.families.get_mut(&FontFamily::Monospace) {
            list.insert(0, "Consolas".into());
        }
    }
    ctx.set_fonts(defs);
}

/// Apply the palette, type ramp and spacing. Cheap; called every frame so a
/// theme change takes effect at once.
pub fn apply(ctx: &egui::Context, p: &Palette) {
    let mut v = if p.dark {
        egui::Visuals::dark()
    } else {
        egui::Visuals::light()
    };
    v.panel_fill = p.window;
    v.window_fill = p.card;
    v.window_stroke = Stroke::new(1.0, p.card_stroke);
    v.window_corner_radius = CornerRadius::same(8);
    v.menu_corner_radius = CornerRadius::same(8);
    v.extreme_bg_color = p.control;
    v.faint_bg_color = p.card;
    v.hyperlink_color = p.accent;
    v.selection.bg_fill = p.accent.gamma_multiply(0.35);
    v.selection.stroke = Stroke::new(1.0, p.accent);
    v.override_text_color = None;
    v.popup_shadow = egui::Shadow {
        offset: [0, 4],
        blur: 16,
        spread: 0,
        color: Color32::from_black_alpha(if p.dark { 90 } else { 30 }),
    };

    let r4 = CornerRadius::same(4);
    let w = &mut v.widgets;
    w.noninteractive.bg_fill = p.card;
    w.noninteractive.weak_bg_fill = p.card;
    w.noninteractive.bg_stroke = Stroke::new(1.0, p.card_stroke);
    w.noninteractive.fg_stroke = Stroke::new(1.0, p.text);
    w.noninteractive.corner_radius = r4;
    for (state, fill, fg) in [
        (&mut w.inactive, p.control, p.text),
        (&mut w.hovered, p.control_hover, p.text),
        (&mut w.active, p.control_pressed, p.text2),
        (&mut w.open, p.control_hover, p.text),
    ] {
        state.bg_fill = fill;
        state.weak_bg_fill = fill;
        state.bg_stroke = Stroke::new(1.0, p.control_stroke);
        state.fg_stroke = Stroke::new(1.0, fg);
        state.corner_radius = r4;
        state.expansion = 0.0;
    }
    ctx.set_visuals(v);

    ctx.all_styles_mut(|style| {
        use FontFamily::{Monospace, Proportional};
        style.text_styles = [
            (TextStyle::Small, FontId::new(12.0, Proportional)),
            (TextStyle::Body, FontId::new(14.0, Proportional)),
            (TextStyle::Button, FontId::new(14.0, Proportional)),
            (TextStyle::Heading, FontId::new(20.0, semibold())),
            (TextStyle::Monospace, FontId::new(13.0, Monospace)),
        ]
        .into();
        style.spacing.item_spacing = egui::vec2(8.0, 8.0);
        style.spacing.button_padding = egui::vec2(12.0, 5.0);
        style.spacing.interact_size.y = 32.0;
        style.spacing.combo_width = 140.0;
    });
}

/// A settings-style card: 8 px corners, a hairline border, 16 px padding.
pub fn card(p: &Palette) -> egui::Frame {
    egui::Frame::new()
        .fill(p.card)
        .stroke(Stroke::new(1.0, p.card_stroke))
        .corner_radius(CornerRadius::same(8))
        .inner_margin(egui::Margin::symmetric(16, 14))
}

/// Fluent's caution InfoBar background.
pub fn info_bar(p: &Palette) -> egui::Frame {
    egui::Frame::new()
        .fill(p.caution_bg)
        .stroke(Stroke::new(1.0, p.card_stroke))
        .corner_radius(CornerRadius::same(8))
        .inner_margin(egui::Margin::symmetric(16, 12))
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ButtonKind {
    /// The one main action on screen: filled with the accent colour.
    Primary,
    /// Everything else: a quiet control fill with a hairline border.
    Standard,
}

/// The width [`button`] will take for `label`.
pub fn button_width(ui: &egui::Ui, label: &str) -> f32 {
    let font = FontId::new(14.0, FontFamily::Proportional);
    let galley = ui
        .painter()
        .layout_no_wrap(label.to_owned(), font, Color32::PLACEHOLDER);
    (galley.size().x + 24.0).max(96.0)
}

/// A Fluent button: 32 px tall, 4 px corners, real hover/pressed/disabled
/// states. Painted by hand so the accent button gets its hover shade too.
pub fn button(
    ui: &mut egui::Ui,
    p: &Palette,
    kind: ButtonKind,
    label: &str,
    enabled: bool,
) -> egui::Response {
    let font = FontId::new(14.0, FontFamily::Proportional);
    let galley = ui
        .painter()
        .layout_no_wrap(label.to_owned(), font, Color32::PLACEHOLDER);
    let size = egui::vec2(button_width(ui, label), 32.0);
    let sense = if enabled {
        egui::Sense::click()
    } else {
        egui::Sense::hover()
    };
    let (rect, resp) = ui.allocate_exact_size(size, sense);
    if ui.is_rect_visible(rect) {
        let pressed = resp.is_pointer_button_down_on();
        let hovered = resp.hovered() && enabled;
        let (fill, stroke, text) = match (kind, enabled) {
            (_, false) => (p.control, Stroke::new(1.0, p.control_stroke), p.disabled),
            (ButtonKind::Primary, true) => {
                let fill = if pressed {
                    p.accent_pressed
                } else if hovered {
                    p.accent_hover
                } else {
                    p.accent
                };
                (fill, Stroke::NONE, p.on_accent)
            }
            (ButtonKind::Standard, true) => {
                let fill = if pressed {
                    p.control_pressed
                } else if hovered {
                    p.control_hover
                } else {
                    p.control
                };
                let text = if pressed { p.text2 } else { p.text };
                (fill, Stroke::new(1.0, p.control_stroke), text)
            }
        };
        let painter = ui.painter();
        painter.rect(
            rect,
            CornerRadius::same(4),
            fill,
            stroke,
            egui::StrokeKind::Inside,
        );
        let pos = rect.center() - galley.size() / 2.0;
        painter.galley_with_override_text_color(pos, galley, text);
    }
    resp
}

/// The status badge: a filled circle with a painted glyph, like the ones in
/// Windows Security. No font glyphs, so it renders the same everywhere.
#[derive(Clone, Copy)]
pub enum Badge {
    Check,
    Alert,
    Dash,
}

pub fn badge(ui: &mut egui::Ui, p: &Palette, kind: Badge, color: Color32, size: f32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
    let c = rect.center();
    let r = size / 2.0;
    let painter = ui.painter();
    painter.circle_filled(c, r, color);
    let glyph = if p.dark {
        Color32::from_rgb(0x1C, 0x1C, 0x1C)
    } else {
        Color32::WHITE
    };
    let s = size / 36.0; // glyphs are drawn on a 36 px grid
    let stroke = Stroke::new(2.6 * s, glyph);
    match kind {
        Badge::Check => {
            let pts = vec![
                c + egui::vec2(-7.5, 0.5) * s,
                c + egui::vec2(-2.5, 5.5) * s,
                c + egui::vec2(8.0, -5.5) * s,
            ];
            painter.add(egui::Shape::line(pts, stroke));
        }
        Badge::Alert => {
            painter.line_segment(
                [c + egui::vec2(0.0, -8.0) * s, c + egui::vec2(0.0, 2.5) * s],
                stroke,
            );
            painter.circle_filled(c + egui::vec2(0.0, 7.5) * s, 1.7 * s, glyph);
        }
        Badge::Dash => {
            painter.line_segment(
                [c + egui::vec2(-7.0, 0.0) * s, c + egui::vec2(7.0, 0.0) * s],
                stroke,
            );
        }
    }
}

/// A small filled dot, for inline results.
pub fn dot(ui: &mut egui::Ui, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(10.0, 18.0), egui::Sense::hover());
    ui.painter().circle_filled(rect.center(), 4.0, color);
}

/// A thin chevron for a ComboBox, in place of egui's filled triangle.
pub fn combo_icon(
    color: Color32,
) -> impl FnOnce(&egui::Ui, egui::Rect, &egui::style::WidgetVisuals, bool) {
    move |ui, rect, _visuals, open| {
        let c = rect.center();
        let dy = if open { -2.0 } else { 2.0 };
        let pts = vec![
            c + egui::vec2(-4.5, -dy),
            c + egui::vec2(0.0, dy),
            c + egui::vec2(4.5, -dy),
        ];
        ui.painter()
            .add(egui::Shape::line(pts, Stroke::new(1.3, color)));
    }
}

/// A chevron for the expander row, pointing down when closed and up when open.
pub fn chevron(ui: &mut egui::Ui, p: &Palette, open: bool) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(16.0, 16.0), egui::Sense::hover());
    let c = rect.center();
    let dy = if open { -2.0 } else { 2.0 };
    let pts = vec![
        c + egui::vec2(-4.5, -dy),
        c + egui::vec2(0.0, dy),
        c + egui::vec2(4.5, -dy),
    ];
    ui.painter()
        .add(egui::Shape::line(pts, Stroke::new(1.3, p.text2)));
}
