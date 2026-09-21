//! Mole's window: see the line's state, test any site, and protect in one click.
//!
//! A thin, honest front over the CLI. It reads state directly (no elevation) and,
//! for anything that touches the driver or the service, relaunches `mole.exe`
//! through UAC so the privileged work runs in one audited place — the same code
//! the command line exercises. The site checker runs a plain DoH + TLS probe with
//! no driver, so it works unelevated. Nothing here bypasses on its own.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod i18n;
mod status;
mod theme;
mod tray;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use eframe::egui;

use i18n::Lang;
use mole_probe::Reachable;
use status::{Health, Status};

const INITIAL_SIZE: [f32; 2] = [440.0, 620.0];
const LANG_KEY: &str = "mole_lang";
const DARK_KEY: &str = "mole_dark";

fn main() -> eframe::Result {
    let args: Vec<String> = std::env::args().collect();
    let screenshot = arg_value(&args, "--screenshot").map(PathBuf::from);
    let lang_override = arg_value(&args, "--lang");
    let theme_override = arg_value(&args, "--theme");
    let check_host = arg_value(&args, "--check");

    let mut viewport = egui::ViewportBuilder::default()
        .with_title("Mole")
        .with_inner_size(INITIAL_SIZE)
        .with_min_inner_size([400.0, 520.0])
        .with_app_id("dev.vertexsoftware.mole");
    if let Some(icon) = icon() {
        viewport = viewport.with_icon(icon);
    }

    eframe::run_native(
        "Mole",
        eframe::NativeOptions {
            viewport,
            centered: true,
            ..Default::default()
        },
        Box::new(move |cc| {
            Ok(Box::new(MoleApp::new(
                cc,
                Startup {
                    screenshot,
                    lang_override,
                    theme_override,
                    check_host,
                },
            )))
        }),
    )
}

/// Command-line startup options (mostly for `--screenshot` self-tests).
struct Startup {
    screenshot: Option<PathBuf>,
    lang_override: Option<String>,
    theme_override: Option<String>,
    check_host: Option<String>,
}

fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

/// A pending `--screenshot`: let a few frames settle, capture, save, close.
struct Shot {
    path: PathBuf,
    frames: u32,
    requested: bool,
}

/// The inline "is this site blocked?" checker — a DoH + TLS probe on a worker.
struct SiteCheck {
    input: String,
    running: bool,
    host: String,
    result: Arc<Mutex<Option<Reachable>>>,
}

impl Default for SiteCheck {
    fn default() -> Self {
        SiteCheck {
            input: "www.roblox.com".to_string(),
            running: false,
            host: String::new(),
            result: Arc::new(Mutex::new(None)),
        }
    }
}

struct MoleApp {
    status: Status,
    last_refresh: Instant,
    mole_exe: PathBuf,
    last_action: Option<String>,
    lang: Lang,
    dark: bool,
    icon_tex: Option<egui::TextureHandle>,
    check: SiteCheck,
    shot: Option<Shot>,
    /// A site to check automatically on startup (`--check`, for demo screenshots).
    pending_check: bool,
    tray: Option<tray::Tray>,
    /// Create the tray on the first frame, once the event loop is running.
    want_tray: bool,
    /// Set when the user chose Quit from the tray — the next close really exits.
    quitting: bool,
}

impl MoleApp {
    fn new(cc: &eframe::CreationContext<'_>, startup: Startup) -> MoleApp {
        let storage = cc.storage;
        let lang = match startup.lang_override.as_deref() {
            Some("tr") => Lang::Tr,
            Some("en") => Lang::En,
            _ => storage
                .and_then(|s| eframe::get_value::<Lang>(s, LANG_KEY))
                .unwrap_or_default(),
        };
        let dark = match startup.theme_override.as_deref() {
            Some("light") => false,
            Some("dark") => true,
            _ => storage
                .and_then(|s| eframe::get_value::<bool>(s, DARK_KEY))
                .unwrap_or(true),
        };
        let mut check = SiteCheck::default();
        if let Some(host) = &startup.check_host {
            check.input = host.clone();
        }
        let want_tray = startup.screenshot.is_none();
        MoleApp {
            status: Status::gather(),
            last_refresh: Instant::now(),
            mole_exe: mole_exe_path(),
            last_action: None,
            lang,
            dark,
            icon_tex: None,
            check,
            shot: startup.screenshot.map(|path| Shot {
                path,
                frames: 0,
                requested: false,
            }),
            pending_check: startup.check_host.is_some(),
            tray: None,
            // Create the tray on the first frame (when the event loop is up), but
            // not for a headless screenshot run.
            want_tray,
            quitting: false,
        }
    }

    /// The tray tooltip for the current health.
    fn status_tip(&self) -> &'static str {
        let s = self.lang.strings();
        match self.status.headline() {
            Health::Protected => s.protected,
            Health::Idle => s.idle,
            Health::Off => s.off,
        }
    }

    /// Poll the tray, act on Open/Quit, and drop the window to the tray on close.
    fn handle_tray(&mut self, ctx: &egui::Context) {
        // Lazily create the tray on the first frame, guarding against any panic
        // from the OS tray API so a tray failure never takes the window down.
        if self.want_tray {
            self.want_tray = false;
            let s = self.lang.strings();
            let (open, quit, tip) = (s.tray_open, s.tray_quit, s.protected);
            self.tray = std::panic::catch_unwind(|| {
                tray_icon_rgba()
                    .and_then(|(rgba, w, h)| tray::Tray::new(rgba, w, h, tip, open, quit))
            })
            .ok()
            .flatten();
        }
        let tip = self.status_tip();
        let action = match &self.tray {
            Some(t) => {
                t.set_tooltip(tip);
                t.poll()
            }
            None => return,
        };
        match action {
            tray::TrayAction::Open => {
                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
            }
            tray::TrayAction::Quit => {
                self.quitting = true;
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            tray::TrayAction::None => {}
        }
        // Closing the window hides it to the tray instead of quitting.
        if ctx.input(|i| i.viewport().close_requested()) && !self.quitting {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        }
    }

    fn refresh(&mut self) {
        self.status = Status::gather();
        self.last_refresh = Instant::now();
    }

    fn run_elevated(&mut self, args: &str) {
        match elevate::run(&self.mole_exe, args) {
            Ok(()) => self.last_action = Some(self.lang.started(args)),
            Err(e) => self.last_action = Some(self.lang.could_not_start(args, &e)),
        }
    }

    /// Kick off a site reachability check on a worker thread.
    fn start_check(&mut self, ctx: &egui::Context) {
        let host = self.check.input.trim().to_string();
        if host.is_empty() || self.check.running {
            return;
        }
        self.check.running = true;
        self.check.host = host.clone();
        *self.check.result.lock().unwrap() = None;
        let result = self.check.result.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let r = mole_probe::check_reachable(&host);
            *result.lock().unwrap() = Some(r);
            ctx.request_repaint();
        });
    }
}

impl eframe::App for MoleApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        theme::apply(ctx, self.dark);
        if self.last_refresh.elapsed() > Duration::from_secs(2) {
            self.refresh();
        }
        // A finished site check flips `running` off.
        if self.check.running && self.check.result.lock().unwrap().is_some() {
            self.check.running = false;
        }
        // `--check`: kick the check off once, for a demo screenshot.
        if self.pending_check {
            self.pending_check = false;
            self.start_check(ctx);
        }
        self.handle_tray(ctx);
        self.drive_screenshot(ctx);
        // Poll the tray often enough to feel responsive even while hidden.
        let beat = if self.tray.is_some() {
            Duration::from_millis(400)
        } else {
            Duration::from_secs(2)
        };
        ctx.request_repaint_after(beat);
    }

    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, LANG_KEY, &self.lang);
        eframe::set_value(storage, DARK_KEY, &self.dark);
    }

    /// The window background behind the panel, matched to the theme.
    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] {
        let [r, g, b] = if self.dark {
            [20u8, 22, 26]
        } else {
            [247u8, 246, 243]
        };
        [r as f32 / 255.0, g as f32 / 255.0, b as f32 / 255.0, 1.0]
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        ui.add_space(6.0);
        self.header(ui);
        ui.add_space(10.0);
        self.status_card(ui);
        ui.add_space(10.0);
        self.warnings(ui);
        self.actions(ui);
        ui.add_space(10.0);
        self.site_check(ui);

        // Footer pinned nowhere — plain flow so it never overlaps.
        ui.add_space(12.0);
        let s = self.lang.strings();
        ui.label(egui::RichText::new(s.failopen).weak().small());
        ui.label(egui::RichText::new(s.tagline).weak().small());
    }
}

impl MoleApp {
    fn header(&mut self, ui: &mut egui::Ui) {
        let s = self.lang.strings();
        ui.horizontal(|ui| {
            let tex = self.icon_tex.get_or_insert_with(|| {
                ui.ctx()
                    .load_texture("mole-icon", icon_image(), Default::default())
            });
            ui.add(egui::Image::new(egui::load::SizedTexture::new(
                tex.id(),
                egui::vec2(40.0, 40.0),
            )));
            ui.add_space(4.0);
            ui.vertical(|ui| {
                ui.label(egui::RichText::new("Mole").size(22.0).strong());
                ui.label(egui::RichText::new(s.subtitle).weak().small());
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                self.language_switch(ui);
                self.theme_toggle(ui);
            });
        });
    }

    /// A sun (in dark mode) / crescent moon (in light mode) button, painted so it
    /// never depends on a font having the glyph.
    fn theme_toggle(&mut self, ui: &mut egui::Ui) {
        let (rect, resp) = ui.allocate_exact_size(egui::vec2(30.0, 26.0), egui::Sense::click());
        if resp.clicked() {
            self.dark = !self.dark;
        }
        let wv = ui.style().interact(&resp);
        let painter = ui.painter();
        painter.rect_filled(rect, egui::CornerRadius::same(8), wv.weak_bg_fill);
        painter.rect_stroke(
            rect,
            egui::CornerRadius::same(8),
            wv.bg_stroke,
            egui::StrokeKind::Inside,
        );
        let c = rect.center();
        let col = wv.fg_stroke.color;
        if self.dark {
            // Sun: a small disc with eight short rays.
            painter.circle_filled(c, 4.0, col);
            for i in 0..8 {
                let a = std::f32::consts::TAU * i as f32 / 8.0;
                let d = egui::vec2(a.cos(), a.sin());
                painter.line_segment([c + d * 6.5, c + d * 8.5], egui::Stroke::new(1.3, col));
            }
        } else {
            // Crescent: a disc with a bite taken out by overpainting the bg.
            painter.circle_filled(c, 6.5, col);
            painter.circle_filled(c + egui::vec2(3.0, -2.0), 5.5, wv.weak_bg_fill);
        }
        resp.on_hover_text(self.lang.strings().theme_tooltip);
    }

    fn language_switch(&mut self, ui: &mut egui::Ui) {
        let tip = self.lang.strings().language_tooltip;
        egui::ComboBox::from_id_salt("language")
            .selected_text(self.lang.label())
            .width(52.0)
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut self.lang, Lang::Tr, Lang::Tr.label());
                ui.selectable_value(&mut self.lang, Lang::En, Lang::En.label());
            })
            .response
            .on_hover_text(tip);
    }

    fn status_card(&mut self, ui: &mut egui::Ui) {
        let s = self.lang.strings();
        let (text, color) = match self.status.headline() {
            Health::Protected => (s.protected, theme::ACCENT),
            Health::Idle => (s.idle, theme::AMBER),
            Health::Off => (s.off, egui::Color32::GRAY),
        };
        theme::card(self.dark).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                // A painted status dot — no font glyph needed.
                let (dot, _) = ui.allocate_exact_size(egui::vec2(16.0, 16.0), egui::Sense::hover());
                ui.painter().circle_filled(dot.center(), 6.0, color);
                ui.label(egui::RichText::new(text).size(16.0).strong().color(color));
            });
            ui.add_space(8.0);
            details(ui, &self.status, self.lang);
        });
    }

    fn warnings(&mut self, ui: &mut egui::Ui) {
        let lang = self.lang;
        if let Some(av) = self.status.antivirus.clone() {
            theme::callout(theme::AMBER).show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.label(
                    egui::RichText::new(format!("⚠  {}", lang.antivirus_interferes(&av)))
                        .color(theme::AMBER),
                );
            });
            ui.add_space(6.0);
        }
        if let Some(r) = self.status.rival.clone() {
            theme::callout(theme::AMBER).show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.label(
                    egui::RichText::new(format!("⚠  {}", lang.rival_running(&r)))
                        .color(theme::AMBER),
                );
            });
            ui.add_space(6.0);
        }
    }

    fn actions(&mut self, ui: &mut egui::Ui) {
        let s = self.lang.strings();
        ui.horizontal_wrapped(|ui| {
            let measure =
                egui::Button::new(egui::RichText::new(s.measure_protect).size(15.0).strong())
                    .fill(theme::ACCENT.gamma_multiply(if self.dark { 0.85 } else { 1.0 }));
            if ui.add(measure).on_hover_text(s.measure_hover).clicked() {
                self.run_elevated("install --auto");
            }
            if self.status.is_installed()
                && ui
                    .button(egui::RichText::new(s.stop_remove).size(15.0))
                    .on_hover_text(s.stop_hover)
                    .clicked()
            {
                self.run_elevated("uninstall");
            }
            if ui.button(s.refresh).clicked() {
                self.refresh();
            }
        });
        if let Some(msg) = &self.last_action {
            ui.add_space(6.0);
            ui.label(egui::RichText::new(msg).italics().weak());
        }
    }

    fn site_check(&mut self, ui: &mut egui::Ui) {
        let s = self.lang.strings();
        theme::card(self.dark).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.label(egui::RichText::new(s.check_title).strong());
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                let edit = egui::TextEdit::singleline(&mut self.check.input)
                    .hint_text(s.check_hint)
                    .desired_width(ui.available_width() - 90.0);
                let resp = ui.add(edit);
                let go = ui.button(s.check_button).clicked()
                    || (resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)));
                if go {
                    self.start_check(ui.ctx());
                }
            });
            ui.add_space(6.0);
            self.check_result(ui);
        });
    }

    fn check_result(&mut self, ui: &mut egui::Ui) {
        let s = self.lang.strings();
        if self.check.running {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(egui::RichText::new(format!("{} {}", self.check.host, s.checking)).weak());
            });
            return;
        }
        let guard = self.check.result.lock().unwrap();
        if let Some(r) = guard.as_ref() {
            let (icon, text, color) = match r {
                Reachable::Yes => ("✓", s.reach_open.to_string(), theme::ACCENT),
                Reachable::Blocked(reason) => ("✗", self.lang.reach_blocked(reason), theme::RED),
                Reachable::IpBlocked => ("✗", s.reach_ip.to_string(), theme::RED),
                Reachable::DnsFailed(reason) => ("…", self.lang.reach_dns(reason), theme::AMBER),
            };
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new(icon).color(color).strong());
                ui.label(
                    egui::RichText::new(format!("{}  —  {text}", self.check.host)).color(color),
                );
            });
        }
    }

    /// Save one screenshot after a few settled frames, then close (`--screenshot`).
    fn drive_screenshot(&mut self, ctx: &egui::Context) {
        if self.shot.is_none() {
            return;
        }
        let captured = ctx.input(|input| {
            input.raw.events.iter().find_map(|e| match e {
                egui::Event::Screenshot { image, .. } => Some(image.clone()),
                _ => None,
            })
        });
        if let Some(image) = captured {
            let [w, h] = image.size;
            let bytes: Vec<u8> = image.pixels.iter().flat_map(|p| p.to_array()).collect();
            let path = self.shot.as_ref().unwrap().path.clone();
            let _ = image::save_buffer(&path, &bytes, w as u32, h as u32, image::ColorType::Rgba8);
            self.shot = None;
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }
        // Wait for a pending/running site check to finish, so the picture shows
        // the result rather than the spinner.
        if self.pending_check || self.check.running {
            ctx.request_repaint();
            return;
        }
        let shot = self.shot.as_mut().unwrap();
        shot.frames += 1;
        if shot.frames >= 6 && !shot.requested {
            shot.requested = true;
            ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(egui::UserData::default()));
        }
        ctx.request_repaint();
    }
}

fn details(ui: &mut egui::Ui, status: &Status, lang: Lang) {
    let s = lang.strings();
    row(
        ui,
        s.service,
        match status.service_state {
            Some(4) => s.running.into(),
            Some(1) => s.installed_stopped.into(),
            Some(_) => s.installed_transitioning.into(),
            None => s.not_installed.into(),
        },
    );
    match &status.config {
        Some(c) => {
            row(ui, s.strategy, c.strategy.clone());
            row(ui, s.resolver, c.resolver.clone());
            row(
                ui,
                s.block_quic,
                if c.block_quic {
                    s.yes.into()
                } else {
                    s.no.into()
                },
            );
        }
        None => row(ui, s.strategy, s.none_chosen.into()),
    }
    row(
        ui,
        s.administrator,
        if status.elevated {
            s.yes.into()
        } else {
            s.admin_no.into()
        },
    );
    row(
        ui,
        s.driver,
        if status.driver_available {
            s.driver_found.into()
        } else {
            s.driver_missing.into()
        },
    );
}

fn row(ui: &mut egui::Ui, label: &str, value: String) {
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new(format!("{label}:")).weak());
        ui.label(egui::RichText::new(value).strong());
    });
}

/// The taskbar and title-bar icon. Missing is not fatal: Windows has a default.
fn icon() -> Option<egui::IconData> {
    let img = decode_icon()?;
    let (width, height) = img.dimensions();
    Some(egui::IconData {
        rgba: img.into_raw(),
        width,
        height,
    })
}

/// The in-window header icon as an egui image.
fn icon_image() -> egui::ColorImage {
    match decode_icon() {
        Some(img) => {
            let (w, h) = img.dimensions();
            egui::ColorImage::from_rgba_unmultiplied([w as usize, h as usize], img.as_raw())
        }
        None => egui::ColorImage::new([1, 1], vec![egui::Color32::TRANSPARENT]),
    }
}

fn decode_icon() -> Option<image::RgbaImage> {
    const PNG: &[u8] = include_bytes!("../../../icons/256x256.png");
    Some(image::load_from_memory(PNG).ok()?.into_rgba8())
}

/// The small tray icon as raw RGBA.
fn tray_icon_rgba() -> Option<(Vec<u8>, u32, u32)> {
    const PNG: &[u8] = include_bytes!("../../../icons/32x32.png");
    let img = image::load_from_memory(PNG).ok()?.into_rgba8();
    let (w, h) = img.dimensions();
    Some((img.into_raw(), w, h))
}

/// The CLI sits next to this window's executable.
fn mole_exe_path() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(|p| p.join("mole.exe")))
        .unwrap_or_else(|| PathBuf::from("mole.exe"))
}

/// UAC relaunch of the CLI via ShellExecute "runas".
mod elevate {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    fn wide(s: &str) -> Vec<u16> {
        OsStr::new(s).encode_wide().chain(Some(0)).collect()
    }
    fn wide_path(p: &Path) -> Vec<u16> {
        p.as_os_str().encode_wide().chain(Some(0)).collect()
    }

    pub fn run(exe: &Path, args: &str) -> Result<(), String> {
        let verb = wide("runas");
        let file = wide_path(exe);
        let params = wide(args);
        let r = unsafe {
            ShellExecuteW(
                std::ptr::null_mut(),
                verb.as_ptr(),
                file.as_ptr(),
                params.as_ptr(),
                std::ptr::null(),
                SW_SHOWNORMAL,
            )
        };
        if r as isize > 32 {
            Ok(())
        } else {
            Err(format!("ShellExecute returned {}", r as isize))
        }
    }
}
