//! Mole's window: see the line's state and protect it in one click.
//!
//! The window is a thin, honest front over the CLI. It reads state directly (no
//! elevation) and, for anything that touches the driver or the service, relaunches
//! `mole.exe` through UAC so the privileged work runs in one audited place — the
//! same code the command line exercises. Nothing here bypasses on its own.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod i18n;
mod status;

use std::path::PathBuf;
use std::time::{Duration, Instant};

use eframe::egui;

use i18n::Lang;
use status::{Health, Status};

const INITIAL_SIZE: [f32; 2] = [460.0, 560.0];
const LANG_KEY: &str = "mole_lang";

fn main() -> eframe::Result {
    let mut viewport = egui::ViewportBuilder::default()
        .with_title("Mole")
        .with_inner_size(INITIAL_SIZE)
        .with_min_inner_size([400.0, 480.0])
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
        Box::new(|cc| Ok(Box::new(MoleApp::new(cc)))),
    )
}

struct MoleApp {
    status: Status,
    last_refresh: Instant,
    /// Path to the CLI we relaunch elevated for privileged actions.
    mole_exe: PathBuf,
    last_action: Option<String>,
    lang: Lang,
}

impl MoleApp {
    fn new(cc: &eframe::CreationContext<'_>) -> MoleApp {
        // Restore the saved language, else follow the OS locale.
        let lang = cc
            .storage
            .and_then(|s| eframe::get_value::<Lang>(s, LANG_KEY))
            .unwrap_or_default();
        MoleApp {
            status: Status::gather(),
            last_refresh: Instant::now(),
            mole_exe: mole_exe_path(),
            last_action: None,
            lang,
        }
    }

    fn refresh(&mut self) {
        self.status = Status::gather();
        self.last_refresh = Instant::now();
    }

    /// Relaunch the CLI elevated with the given arguments (a UAC prompt appears).
    fn run_elevated(&mut self, args: &str) {
        match elevate::run(&self.mole_exe, args) {
            Ok(()) => self.last_action = Some(self.lang.started(args)),
            Err(e) => self.last_action = Some(self.lang.could_not_start(args, &e)),
        }
    }
}

impl eframe::App for MoleApp {
    /// Per-frame logic: keep the state fresh and keep an open window repainting.
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.last_refresh.elapsed() > Duration::from_secs(2) {
            self.refresh();
        }
        ctx.request_repaint_after(Duration::from_secs(2));
    }

    /// Persist the chosen language across runs.
    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, LANG_KEY, &self.lang);
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let s = self.lang.strings();

        // Top bar: title-side space and a TR/EN switch on the right.
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            self.language_switch(ui);
        });

        ui.add_space(4.0);
        headline(ui, &self.status, s);
        ui.add_space(8.0);
        ui.separator();
        ui.add_space(8.0);

        details(ui, &self.status, self.lang);
        ui.add_space(12.0);
        ui.separator();
        ui.add_space(12.0);

        self.controls(ui);

        if let Some(msg) = &self.last_action {
            ui.add_space(10.0);
            ui.label(egui::RichText::new(msg).italics().weak());
        }

        ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
            ui.add_space(6.0);
            ui.label(egui::RichText::new(s.failopen).weak().small());
            ui.label(egui::RichText::new(s.tagline).weak().small());
        });
    }
}

impl MoleApp {
    /// A small TR/EN toggle.
    fn language_switch(&mut self, ui: &mut egui::Ui) {
        let tip = self.lang.strings().language_tooltip;
        egui::ComboBox::from_id_salt("language")
            .selected_text(self.lang.label())
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut self.lang, Lang::Tr, Lang::Tr.label());
                ui.selectable_value(&mut self.lang, Lang::En, Lang::En.label());
            })
            .response
            .on_hover_text(tip);
    }
}

fn headline(ui: &mut egui::Ui, status: &Status, s: &i18n::Strings) {
    let (text, color) = match status.headline() {
        Health::Protected => (s.protected, egui::Color32::from_rgb(60, 190, 90)),
        Health::Idle => (s.idle, egui::Color32::from_rgb(220, 170, 60)),
        Health::Off => (s.off, egui::Color32::from_rgb(150, 150, 150)),
    };
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("●").color(color).size(22.0));
        ui.heading(text);
    });
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
    if let Some(av) = &status.antivirus {
        warn_row(ui, s.antivirus, lang.antivirus_interferes(av));
    }
    if let Some(r) = &status.rival {
        warn_row(ui, s.rival_tool, lang.rival_running(r));
    }
}

fn row(ui: &mut egui::Ui, label: &str, value: String) {
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new(format!("{label}:")).strong());
        ui.label(value);
    });
}

fn warn_row(ui: &mut egui::Ui, label: &str, value: String) {
    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new(format!("{label}:"))
                .strong()
                .color(egui::Color32::from_rgb(220, 170, 60)),
        );
        ui.label(egui::RichText::new(value).color(egui::Color32::from_rgb(220, 170, 60)));
    });
}

impl MoleApp {
    fn controls(&mut self, ui: &mut egui::Ui) {
        let s = self.lang.strings();
        let (measure, measure_hover) = (s.measure_protect, s.measure_hover);
        let (stop, stop_hover) = (s.stop_remove, s.stop_hover);
        let refresh = s.refresh;
        let rival_warning = s.rival_warning;

        ui.horizontal_wrapped(|ui| {
            if ui
                .button(egui::RichText::new(measure).size(15.0))
                .on_hover_text(measure_hover)
                .clicked()
            {
                self.run_elevated("install --auto");
            }

            if self.status.is_installed()
                && ui
                    .button(egui::RichText::new(stop).size(15.0))
                    .on_hover_text(stop_hover)
                    .clicked()
            {
                self.run_elevated("uninstall");
            }

            if ui.button(refresh).clicked() {
                self.refresh();
            }
        });

        if self.status.rival.is_some() {
            ui.add_space(6.0);
            ui.label(
                egui::RichText::new(rival_warning)
                    .color(egui::Color32::from_rgb(220, 170, 60))
                    .small(),
            );
        }
    }
}

/// The taskbar and title-bar icon. Missing is not fatal: Windows has a default.
fn icon() -> Option<egui::IconData> {
    const PNG: &[u8] = include_bytes!("../../../icons/256x256.png");
    let decoded = image::load_from_memory(PNG).ok()?.into_rgba8();
    let (width, height) = decoded.dimensions();
    Some(egui::IconData {
        rgba: decoded.into_raw(),
        width,
        height,
    })
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
        // ShellExecuteW returns a value > 32 on success.
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
