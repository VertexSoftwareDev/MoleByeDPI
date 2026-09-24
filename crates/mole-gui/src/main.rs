//! Mole's window: see whether you're protected, check any site, set it up in one
//! click.
//!
//! A thin, honest front over the CLI. It reads state directly (no elevation) and,
//! for anything that touches the driver or the service, runs `mole.exe` through
//! UAC — hidden, with its result reported back here — so the privileged work runs
//! in one audited place, the same code the command line exercises. The site
//! checker runs a plain DoH + TLS probe with no driver, so it works unelevated.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod i18n;
mod status;
mod theme;
mod tray;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use eframe::egui::{self, FontId, Margin, RichText};
use serde::{Deserialize, Serialize};

use i18n::Lang;
use mole_probe::{Block, Reachable};
use status::{Health, Status};
use theme::{Badge, ButtonKind, Palette};

const INITIAL_SIZE: [f32; 2] = [460.0, 600.0];
const LANG_KEY: &str = "mole_lang";
const THEME_KEY: &str = "mole_theme";

fn main() -> eframe::Result {
    let args: Vec<String> = std::env::args().collect();
    let screenshot = arg_value(&args, "--screenshot").map(PathBuf::from);
    // A windows-subsystem app shows no console, so a panic or a window that fails
    // to open would just vanish — exactly how a missing runtime DLL looked on a
    // friend's PC. Surface it in a dialog instead. Skipped for --screenshot runs.
    let headless = screenshot.is_some();
    if !headless {
        dialog::install_panic_hook();
    }
    let lang_override = arg_value(&args, "--lang");
    let theme_override = arg_value(&args, "--theme");
    let check_host = arg_value(&args, "--check");
    let open_details = args.iter().any(|a| a == "--details");
    let scroll_to = arg_value(&args, "--scroll").and_then(|v| v.parse().ok());

    let mut viewport = egui::ViewportBuilder::default()
        .with_title("Mole")
        .with_inner_size(INITIAL_SIZE)
        .with_min_inner_size([420.0, 480.0])
        .with_app_id("dev.vertexsoftware.mole");
    if let Some(icon) = icon() {
        viewport = viewport.with_icon(icon);
    }

    let result = eframe::run_native(
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
                    open_details,
                    scroll_to,
                },
            )))
        }),
    );
    if !headless {
        if let Err(e) = &result {
            dialog::error(&format!(
                "Mole penceresi açılamadı:\n\n{e}\n\n\
                 Bilgisayarın grafik (OpenGL) sürücüsü eksik ya da çok eski olabilir."
            ));
        }
    }
    result
}

/// Native message boxes, so a failure the window can't show is never silent.
mod dialog {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    use windows_sys::Win32::UI::WindowsAndMessaging::{
        MessageBoxW, MB_ICONERROR, MB_OK, MB_SETFOREGROUND,
    };

    fn wide(s: &str) -> Vec<u16> {
        OsStr::new(s).encode_wide().chain(Some(0)).collect()
    }

    /// Show an error dialog titled "Mole".
    pub fn error(text: &str) {
        let body = wide(text);
        let title = wide("Mole");
        unsafe {
            MessageBoxW(
                std::ptr::null_mut(),
                body.as_ptr(),
                title.as_ptr(),
                MB_OK | MB_ICONERROR | MB_SETFOREGROUND,
            );
        }
    }

    /// Report a panic in a dialog (and the service log) instead of vanishing.
    pub fn install_panic_hook() {
        let default = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let msg = info.to_string();
            mole_core::servicelog::log(&format!("mole-gui panic: {msg}"));
            error(&format!(
                "Mole beklenmedik bir şekilde kapandı.\n\n{msg}\n\n\
                 Ayrıntı: %ProgramData%\\Mole\\mole.log"
            ));
            default(info);
        }));
    }
}

/// Command-line startup options (mostly for `--screenshot` self-tests).
struct Startup {
    screenshot: Option<PathBuf>,
    lang_override: Option<String>,
    theme_override: Option<String>,
    check_host: Option<String>,
    open_details: bool,
    scroll_to: Option<f32>,
}

fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

#[derive(Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
enum ThemeChoice {
    #[default]
    System,
    Light,
    Dark,
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

/// A privileged action running in a hidden, elevated `mole.exe`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Job {
    Install,
    Remove,
}

struct RunningJob {
    job: Job,
    outcome: Arc<Mutex<Option<elevate::Outcome>>>,
}

/// A line under the headline after an action, and whether it reports a failure.
struct Notice {
    text: String,
    failure: bool,
}

struct MoleApp {
    status: Status,
    last_refresh: Instant,
    mole_exe: PathBuf,
    lang: Lang,
    theme: ThemeChoice,
    palette: Palette,
    icon_tex: Option<egui::TextureHandle>,
    check: SiteCheck,
    job: Option<RunningJob>,
    notice: Option<Notice>,
    details_open: bool,
    /// Scroll offset for `--scroll` screenshots of the lower sections.
    scroll_to: Option<f32>,
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
        theme::install_fonts(&cc.egui_ctx);
        let storage = cc.storage;
        let lang = match startup.lang_override.as_deref() {
            Some("tr") => Lang::Tr,
            Some("en") => Lang::En,
            _ => storage
                .and_then(|s| eframe::get_value::<Lang>(s, LANG_KEY))
                .unwrap_or_default(),
        };
        let theme = match startup.theme_override.as_deref() {
            Some("light") => ThemeChoice::Light,
            Some("dark") => ThemeChoice::Dark,
            _ => storage
                .and_then(|s| eframe::get_value::<ThemeChoice>(s, THEME_KEY))
                .unwrap_or_default(),
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
            lang,
            theme,
            palette: theme::LIGHT,
            icon_tex: None,
            check,
            job: None,
            notice: None,
            details_open: startup.open_details,
            scroll_to: startup.scroll_to,
            shot: startup.screenshot.map(|path| Shot {
                path,
                frames: 0,
                requested: false,
            }),
            pending_check: startup.check_host.is_some(),
            tray: None,
            want_tray,
            quitting: false,
        }
    }

    fn is_dark(&self, ctx: &egui::Context) -> bool {
        match self.theme {
            ThemeChoice::Light => false,
            ThemeChoice::Dark => true,
            ThemeChoice::System => ctx.system_theme() == Some(egui::Theme::Dark),
        }
    }

    /// The tray tooltip for the current health.
    fn status_tip(&self) -> &'static str {
        let s = self.lang.strings();
        match self.status.health() {
            Health::Protected => s.protected,
            Health::Starting => s.starting,
            Health::Stopped => s.stopped,
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
            let (open, quit, tip) = (s.tray_open, s.tray_quit, self.status_tip());
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

    /// Run `mole.exe install --auto` or `uninstall` elevated and hidden; the
    /// outcome arrives on a worker thread and is picked up in `poll_job`.
    fn start_job(&mut self, job: Job, ctx: &egui::Context) {
        if self.job.is_some() {
            return;
        }
        self.notice = None;
        let args = match job {
            Job::Install => "install --auto",
            Job::Remove => "uninstall",
        };
        let outcome = Arc::new(Mutex::new(None));
        let slot = outcome.clone();
        let exe = self.mole_exe.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let r = elevate::run_and_wait(&exe, args);
            *slot.lock().unwrap() = Some(r);
            ctx.request_repaint();
        });
        self.job = Some(RunningJob { job, outcome });
    }

    fn poll_job(&mut self) {
        let Some(running) = &self.job else {
            return;
        };
        let Some(outcome) = running.outcome.lock().unwrap().take() else {
            return;
        };
        let job = running.job;
        self.job = None;
        self.refresh();
        let s = self.lang.strings();
        self.notice = match outcome {
            elevate::Outcome::Exited(0) => None,
            elevate::Outcome::Exited(_) => Some(Notice {
                text: match job {
                    Job::Install => s.install_failed,
                    Job::Remove => s.remove_failed,
                }
                .to_string(),
                failure: true,
            }),
            elevate::Outcome::Declined => Some(Notice {
                text: s.uac_declined.to_string(),
                failure: false,
            }),
            elevate::Outcome::LaunchFailed => Some(Notice {
                text: s.launch_failed.to_string(),
                failure: true,
            }),
        };
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
        self.palette = theme::palette(self.is_dark(ctx));
        theme::apply(ctx, &self.palette);
        if self.last_refresh.elapsed() > Duration::from_secs(2) {
            self.refresh();
        }
        self.poll_job();
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
        let beat = if self.tray.is_some() || self.job.is_some() {
            Duration::from_millis(400)
        } else {
            Duration::from_secs(2)
        };
        ctx.request_repaint_after(beat);
    }

    /// Keep only our own settings (language, theme) — not egui's memory, which
    /// would bring back a stale scroll position or open popup on the next launch.
    fn persist_egui_memory(&self) -> bool {
        false
    }

    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        // eframe still *loads* egui memory saved by older builds; blank that
        // entry ("egui") so a stale scroll position can't come back.
        storage.set_string("egui", String::new());
        eframe::set_value(storage, LANG_KEY, &self.lang);
        eframe::set_value(storage, THEME_KEY, &self.theme);
    }

    /// The window background behind the content, matched to the theme.
    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] {
        self.palette.window.to_normalized_gamma_f32()
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let p = self.palette;
        let mut area = egui::ScrollArea::vertical().auto_shrink([false, false]);
        if let Some(y) = self.scroll_to {
            area = area.vertical_scroll_offset(y);
        }
        area.show(ui, |ui| {
            egui::Frame::new()
                .inner_margin(Margin {
                    left: 20,
                    right: 20,
                    top: 18,
                    bottom: 20,
                })
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    self.header(ui, &p);
                    ui.add_space(12.0);
                    self.headline(ui, &p);
                    self.warnings(ui, &p);
                    let s = self.lang.strings();
                    section(ui, &p, s.check_section);
                    self.site_check(ui, &p);
                    section(ui, &p, s.settings_section);
                    self.settings(ui, &p);
                    ui.add_space(20.0);
                    ui.label(
                        RichText::new(format!(
                            "Mole {} · VertexSoftwareDev",
                            env!("CARGO_PKG_VERSION")
                        ))
                        .small()
                        .color(p.text3),
                    );
                });
        });
    }
}

impl MoleApp {
    fn header(&mut self, ui: &mut egui::Ui, p: &Palette) {
        ui.horizontal(|ui| {
            let tex = self.icon_tex.get_or_insert_with(|| {
                ui.ctx()
                    .load_texture("mole-icon", icon_image(), Default::default())
            });
            ui.add(egui::Image::new(egui::load::SizedTexture::new(
                tex.id(),
                egui::vec2(28.0, 28.0),
            )));
            ui.label(
                RichText::new("Mole")
                    .font(FontId::new(20.0, theme::semibold()))
                    .color(p.text),
            );
        });
    }

    /// The one card that matters: are you protected, and the single next step.
    fn headline(&mut self, ui: &mut egui::Ui, p: &Palette) {
        let s = self.lang.strings();
        let health = self.status.health();
        let (badge, color, title, body) = match health {
            Health::Protected => (Badge::Check, p.success, s.protected, s.protected_body),
            Health::Starting => (Badge::Dash, p.neutral_icon, s.starting, s.starting_body),
            Health::Stopped => (Badge::Alert, p.caution, s.stopped, s.stopped_body),
            Health::Off => (Badge::Dash, p.neutral_icon, s.off, s.off_body),
        };
        let action = match health {
            Health::Protected => Some((ButtonKind::Standard, s.remeasure)),
            Health::Stopped => Some((ButtonKind::Primary, s.start_again)),
            Health::Off => Some((ButtonKind::Primary, s.protect)),
            Health::Starting => None,
        };
        let busy = self.job.is_some();

        theme::card(p)
            .inner_margin(Margin::same(20))
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.horizontal_top(|ui| {
                    theme::badge(ui, p, badge, color, 36.0);
                    ui.add_space(6.0);
                    ui.vertical(|ui| {
                        ui.spacing_mut().item_spacing.y = 4.0;
                        ui.label(
                            RichText::new(title)
                                .font(FontId::new(20.0, theme::semibold()))
                                .color(p.text),
                        );
                        ui.label(RichText::new(body).color(p.text2));
                        ui.add_space(12.0);
                        ui.horizontal(|ui| {
                            if let Some((kind, label)) = action {
                                let resp = theme::button(ui, p, kind, label, !busy);
                                let resp = if health == Health::Protected {
                                    resp.on_hover_text(s.remeasure_hover)
                                } else {
                                    resp
                                };
                                if resp.clicked() {
                                    self.start_job(Job::Install, ui.ctx());
                                }
                            }
                            if let Some(job) = &self.job {
                                ui.add_space(4.0);
                                ui.add(egui::Spinner::new().size(16.0).color(p.accent));
                                let text = match job.job {
                                    Job::Install => s.measuring,
                                    Job::Remove => s.removing,
                                };
                                ui.label(RichText::new(text).color(p.text2));
                            }
                        });
                        if let Some(n) = &self.notice {
                            ui.add_space(4.0);
                            let color = if n.failure { p.critical } else { p.text2 };
                            ui.label(RichText::new(&n.text).small().color(color));
                        }
                    });
                });
            });
    }

    /// Fluent InfoBars for the two things that can quietly defeat Mole.
    fn warnings(&mut self, ui: &mut egui::Ui, p: &Palette) {
        let lang = self.lang;
        let s = lang.strings();
        let mut bars = Vec::new();
        if let Some(av) = &self.status.antivirus {
            bars.push((lang.antivirus_title(av), s.antivirus_body));
        }
        if let Some(r) = &self.status.rival {
            bars.push((lang.rival_title(r), s.rival_body));
        }
        for (title, body) in bars {
            ui.add_space(4.0);
            theme::info_bar(p).show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.horizontal_top(|ui| {
                    theme::badge(ui, p, Badge::Alert, p.caution, 18.0);
                    ui.add_space(4.0);
                    ui.vertical(|ui| {
                        ui.spacing_mut().item_spacing.y = 2.0;
                        ui.label(
                            RichText::new(title)
                                .font(FontId::new(14.0, theme::semibold()))
                                .color(p.text),
                        );
                        ui.label(RichText::new(body).color(p.text));
                    });
                });
            });
        }
    }

    fn site_check(&mut self, ui: &mut egui::Ui, p: &Palette) {
        let s = self.lang.strings();
        theme::card(p).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                let button_w = theme::button_width(ui, s.check_button);
                let edit = egui::TextEdit::singleline(&mut self.check.input)
                    .hint_text(RichText::new(s.check_hint).color(p.text3))
                    .text_color(p.text)
                    .margin(Margin::symmetric(10, 7))
                    .desired_width(ui.available_width() - button_w - 8.0);
                let resp = ui.add(edit);
                let enter = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                let clicked = theme::button(
                    ui,
                    p,
                    ButtonKind::Standard,
                    s.check_button,
                    !self.check.running,
                )
                .clicked();
                if clicked || enter {
                    self.start_check(ui.ctx());
                }
            });
            self.check_result(ui, p);
        });
    }

    fn check_result(&mut self, ui: &mut egui::Ui, p: &Palette) {
        let s = self.lang.strings();
        if self.check.running {
            ui.spacing_mut().interact_size.y = 18.0;
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.add(egui::Spinner::new().size(14.0).color(p.accent));
                ui.label(RichText::new(s.checking).color(p.text2));
            });
            return;
        }
        let guard = self.check.result.lock().unwrap();
        let Some(r) = guard.as_ref() else {
            return;
        };
        let (word, detail, color) = match r {
            Reachable::Yes => (s.open, s.open_detail, p.success),
            Reachable::Blocked(Block::Reset) => (s.blocked, s.reset_detail, p.critical),
            Reachable::Blocked(Block::Dropped) => (s.blocked, s.dropped_detail, p.critical),
            Reachable::Blocked(Block::Broke) => (s.blocked, s.broke_detail, p.critical),
            Reachable::IpBlocked => (s.ip_blocked, s.ip_detail, p.critical),
            Reachable::DnsFailed(_) => (s.unresolved, s.unresolved_detail, p.caution),
        };
        // Text rows here, not control rows: don't reserve a 32 px control height.
        ui.spacing_mut().interact_size.y = 18.0;
        ui.spacing_mut().item_spacing.y = 2.0;
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 6.0;
            theme::dot(ui, color);
            ui.label(
                RichText::new(word)
                    .font(FontId::new(14.0, theme::semibold()))
                    .color(p.text),
            );
            ui.label(RichText::new(&self.check.host).color(p.text2));
        });
        ui.horizontal(|ui| {
            ui.add_space(16.0);
            ui.label(RichText::new(detail).small().color(p.text2));
        });
    }

    fn settings(&mut self, ui: &mut egui::Ui, p: &Palette) {
        let s = self.lang.strings();
        ui.spacing_mut().item_spacing.y = 4.0;

        setting_row(ui, p, s.language, None, |ui| {
            egui::ComboBox::from_id_salt("language")
                .icon(theme::combo_icon(p.text2))
                .selected_text(self.lang.name())
                .width(170.0)
                .show_ui(ui, |ui| {
                    for l in [Lang::Tr, Lang::En] {
                        ui.selectable_value(&mut self.lang, l, l.name());
                    }
                });
        });

        setting_row(ui, p, s.theme, None, |ui| {
            let name = |t: ThemeChoice| match t {
                ThemeChoice::System => s.theme_system,
                ThemeChoice::Light => s.theme_light,
                ThemeChoice::Dark => s.theme_dark,
            };
            egui::ComboBox::from_id_salt("theme")
                .icon(theme::combo_icon(p.text2))
                .selected_text(name(self.theme))
                .width(170.0)
                .show_ui(ui, |ui| {
                    for t in [ThemeChoice::System, ThemeChoice::Light, ThemeChoice::Dark] {
                        ui.selectable_value(&mut self.theme, t, name(t));
                    }
                });
        });

        self.details(ui, p);

        if self.status.is_installed() {
            let busy = self.job.is_some();
            let mut remove = false;
            setting_row(ui, p, s.remove_title, Some(s.remove_body), |ui| {
                remove = theme::button(ui, p, ButtonKind::Standard, s.remove, !busy).clicked();
            });
            if remove {
                self.start_job(Job::Remove, ui.ctx());
            }
        }
    }

    /// A Windows-style expander: a header row that opens onto the technical facts.
    fn details(&mut self, ui: &mut egui::Ui, p: &Palette) {
        let s = self.lang.strings();
        let open = self.details_open;
        let inner = theme::card(p).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            let top = ui.cursor().top();
            row(
                ui,
                "details",
                |ui| text_block(ui, p, s.details, Some(s.details_body)),
                |ui| theme::chevron(ui, p, open),
            );
            let mut header = ui.min_rect();
            header.min.y = top;
            // The whole card top, padding included, is the click target.
            let header = header.expand(16.0);
            if !open {
                return header;
            }
            ui.add_space(6.0);
            let r = ui.available_rect_before_wrap();
            ui.painter().hline(
                r.left() - 16.0..=r.right() + 16.0,
                r.top(),
                egui::Stroke::new(1.0, p.divider),
            );
            ui.add_space(10.0);
            ui.spacing_mut().item_spacing.y = 8.0;

            let st = &self.status;
            let service = match st.service_state {
                Some(4) => s.running,
                Some(1) => s.stopped_word,
                Some(_) => s.changing,
                None => s.not_installed,
            };
            fact(ui, p, s.service, service, false);
            match &st.config {
                Some(c) => {
                    fact(ui, p, s.method, &c.strategy, true);
                    fact(ui, p, s.dns, &format!("{} (DoH)", c.resolver), false);
                    let quic = if c.block_quic {
                        s.quic_blocked
                    } else {
                        s.quic_allowed
                    };
                    fact(ui, p, s.quic, quic, false);
                    if !c.canary.trim().is_empty() {
                        fact(ui, p, s.watching, &c.canary, false);
                    }
                }
                None => fact(ui, p, s.method, s.none, false),
            }
            if let Some(line) = &st.last_event {
                ui.label(RichText::new(s.last_event).color(p.text2));
                ui.label(
                    RichText::new(line)
                        .font(FontId::monospace(12.0))
                        .color(p.text2),
                );
            }
            header
        });
        let header_rect = inner.inner;
        let id = ui.id().with("details-toggle");
        if ui.interact(header_rect, id, egui::Sense::click()).clicked() {
            self.details_open = !self.details_open;
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

/// A section heading, Windows Settings style: body-strong, a little air above.
fn section(ui: &mut egui::Ui, p: &Palette, title: &str) {
    ui.add_space(18.0);
    ui.label(
        RichText::new(title)
            .font(FontId::new(14.0, theme::semibold()))
            .color(p.text),
    );
}

/// A settings card: title (and optional description) on the left, the control
/// on the right, the description wrapping in whatever width is left.
fn setting_row(
    ui: &mut egui::Ui,
    p: &Palette,
    title: &str,
    description: Option<&str>,
    control: impl FnOnce(&mut egui::Ui),
) {
    theme::card(p).show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        row(
            ui,
            title,
            |ui| text_block(ui, p, title, description),
            control,
        );
    });
}

/// Left content that shrinks and wraps, right content at its natural size, both
/// centred on one line — the layout of every row in Windows Settings.
///
/// egui lays out in one pass, so a two-line text block can't be centred against
/// a control it hasn't measured yet. The left block's height is remembered from
/// the previous frame and the row sized to fit it; both sides then centre in it.
fn row(
    ui: &mut egui::Ui,
    id_salt: &str,
    left: impl FnOnce(&mut egui::Ui),
    right: impl FnOnce(&mut egui::Ui),
) {
    let id = ui.make_persistent_id(("row", id_salt));
    let content_h: f32 = ui.data(|d| d.get_temp(id)).unwrap_or(20.0);
    let row_h = content_h.max(ui.spacing().interact_size.y);
    egui::Sides::new()
        .shrink_left()
        .wrap()
        .spacing(16.0)
        .height(row_h)
        .show(
            ui,
            |ui| {
                ui.vertical(|ui| {
                    ui.add_space(((row_h - content_h) / 2.0).max(0.0));
                    let h = ui.scope(left).response.rect.height();
                    ui.data_mut(|d| d.insert_temp(id, h));
                });
            },
            right,
        );
}

/// Title over an optional caption, for the left side of a row.
fn text_block(ui: &mut egui::Ui, p: &Palette, title: &str, description: Option<&str>) {
    ui.spacing_mut().item_spacing.y = 2.0;
    ui.label(RichText::new(title).color(p.text));
    if let Some(d) = description {
        ui.label(RichText::new(d).small().color(p.text2));
    }
}

/// One label/value line in the details expander.
fn fact(ui: &mut egui::Ui, p: &Palette, label: &str, value: &str, mono: bool) {
    egui::Sides::new().height(20.0).show(
        ui,
        |ui| {
            ui.label(RichText::new(label).color(p.text2));
        },
        |ui| {
            let text = if mono {
                RichText::new(value).font(FontId::monospace(13.0))
            } else {
                RichText::new(value)
            };
            ui.label(text.color(p.text));
        },
    );
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

/// Run the CLI elevated (UAC), hidden, and wait for it to finish.
mod elevate {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_CANCELLED};
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, WaitForSingleObject, INFINITE,
    };
    use windows_sys::Win32::UI::Shell::{
        ShellExecuteExW, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

    pub enum Outcome {
        /// The process ran; its exit code (0 = success).
        Exited(u32),
        /// The user said no at the UAC prompt.
        Declined,
        /// It could not be started at all (missing exe, say).
        LaunchFailed,
    }

    fn wide(s: &OsStr) -> Vec<u16> {
        s.encode_wide().chain(Some(0)).collect()
    }

    pub fn run_and_wait(exe: &Path, args: &str) -> Outcome {
        let verb = wide(OsStr::new("runas"));
        let file = wide(exe.as_os_str());
        let params = wide(OsStr::new(args));
        unsafe {
            let mut info: SHELLEXECUTEINFOW = std::mem::zeroed();
            info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
            info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
            info.lpVerb = verb.as_ptr();
            info.lpFile = file.as_ptr();
            info.lpParameters = params.as_ptr();
            info.nShow = SW_HIDE;
            if ShellExecuteExW(&mut info) == 0 {
                return if GetLastError() == ERROR_CANCELLED {
                    Outcome::Declined
                } else {
                    Outcome::LaunchFailed
                };
            }
            if info.hProcess.is_null() {
                return Outcome::LaunchFailed;
            }
            WaitForSingleObject(info.hProcess, INFINITE);
            let mut code = 1u32;
            GetExitCodeProcess(info.hProcess, &mut code);
            CloseHandle(info.hProcess);
            Outcome::Exited(code)
        }
    }
}
