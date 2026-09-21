//! Mole's look: a warm, earthy accent over egui's light or dark base, with
//! rounder corners and calmer panels than the default. One call each frame keeps
//! the window in step with the light/dark toggle.

use eframe::egui::{self, Color32, CornerRadius, Stroke};

/// The mole-green "protected" accent, at full and muted strengths.
pub const ACCENT: Color32 = Color32::from_rgb(72, 178, 104);
pub const AMBER: Color32 = Color32::from_rgb(221, 168, 74);
pub const RED: Color32 = Color32::from_rgb(214, 90, 90);

pub fn apply(ctx: &egui::Context, dark: bool) {
    let mut v = if dark {
        egui::Visuals::dark()
    } else {
        egui::Visuals::light()
    };

    v.selection.bg_fill = ACCENT.gamma_multiply(0.55);
    v.selection.stroke = Stroke::new(1.0, ACCENT);
    v.hyperlink_color = ACCENT;

    // Softer, rounder widgets.
    let r = CornerRadius::same(8);
    v.widgets.noninteractive.corner_radius = r;
    v.widgets.inactive.corner_radius = r;
    v.widgets.hovered.corner_radius = r;
    v.widgets.active.corner_radius = r;
    v.window_corner_radius = CornerRadius::same(12);

    if dark {
        v.panel_fill = Color32::from_rgb(20, 22, 26);
        v.window_fill = Color32::from_rgb(26, 28, 33);
        v.extreme_bg_color = Color32::from_rgb(15, 16, 19);
    } else {
        v.panel_fill = Color32::from_rgb(247, 246, 243);
        v.window_fill = Color32::from_rgb(252, 251, 249);
    }

    ctx.set_visuals(v);

    ctx.all_styles_mut(|style| {
        style.spacing.item_spacing = egui::vec2(8.0, 8.0);
        style.spacing.button_padding = egui::vec2(12.0, 7.0);
        style.spacing.interact_size.y = 26.0;
    });
}

/// A rounded panel background used for the status and site-check cards.
pub fn card(dark: bool) -> egui::Frame {
    let fill = if dark {
        Color32::from_rgb(30, 33, 39)
    } else {
        Color32::from_rgb(255, 255, 255)
    };
    let stroke = if dark {
        Color32::from_rgb(46, 50, 58)
    } else {
        Color32::from_rgb(228, 226, 221)
    };
    egui::Frame::new()
        .fill(fill)
        .stroke(Stroke::new(1.0, stroke))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(egui::Margin::same(14))
}

/// A tinted callout box for a warning line (amber) or note.
pub fn callout(color: Color32) -> egui::Frame {
    egui::Frame::new()
        .fill(color.gamma_multiply(0.12))
        .stroke(Stroke::new(1.0, color.gamma_multiply(0.5)))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(egui::Margin::symmetric(12, 9))
}
