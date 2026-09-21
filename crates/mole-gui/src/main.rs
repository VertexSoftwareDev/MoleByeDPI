//! Mole's window: see the line's state and protect it in one click.
//!
//! The window is a thin, honest front over the CLI. It reads state directly (no
//! elevation) and, for anything that touches the driver or the service, relaunches
//! `mole.exe` through UAC so the privileged work runs in one audited place — the
//! same code the command line exercises. Nothing here bypasses on its own.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod status;

use std::path::PathBuf;
use std::time::{Duration, Instant};

use eframe::egui;

use status::{Health, Status};

const INITIAL_SIZE: [f32; 2] = [460.0, 560.0];

fn main() -> eframe::Result {
    let viewport = egui::ViewportBuilder::default()
        .with_title("Mole")
        .with_inner_size(INITIAL_SIZE)
        .with_min_inner_size([400.0, 480.0])
        .with_app_id("dev.vertexsoftware.mole");

    eframe::run_native(
        "Mole",
        eframe::NativeOptions {
            viewport,
            centered: true,
            ..Default::default()
        },
        Box::new(|_cc| Ok(Box::new(MoleApp::new()))),
    )
}

struct MoleApp {
    status: Status,
    last_refresh: Instant,
    /// Path to the CLI we relaunch elevated for privileged actions.
    mole_exe: PathBuf,
    last_action: Option<String>,
}

impl MoleApp {
    fn new() -> MoleApp {
        MoleApp {
            status: Status::gather(),
            last_refresh: Instant::now(),
            mole_exe: mole_exe_path(),
            last_action: None,
        }
    }

    fn refresh(&mut self) {
        self.status = Status::gather();
        self.last_refresh = Instant::now();
    }

    /// Relaunch the CLI elevated with the given arguments (a UAC prompt appears).
    fn run_elevated(&mut self, args: &str) {
        match elevate::run(&self.mole_exe, args) {
            Ok(()) => self.last_action = Some(format!("Started: mole {args}")),
            Err(e) => self.last_action = Some(format!("Could not start mole {args}: {e}")),
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

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        ui.add_space(12.0);
        headline(ui, &self.status);
        ui.add_space(8.0);
        ui.separator();
        ui.add_space(8.0);

        details(ui, &self.status);
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
            ui.label(
                egui::RichText::new("If Mole stops, your internet keeps working (fail-open).")
                    .weak()
                    .small(),
            );
            ui.label(
                egui::RichText::new("Mole — köstebek. Duvarı yıkmaz, altından geçer.")
                    .weak()
                    .small(),
            );
        });
    }
}

fn headline(ui: &mut egui::Ui, status: &Status) {
    let (dot, text, color) = match status.headline() {
        Health::Protected => (
            "●",
            "Protected — a bypass is applied",
            egui::Color32::from_rgb(60, 190, 90),
        ),
        Health::Idle => (
            "●",
            "Idle — measured but not running",
            egui::Color32::from_rgb(220, 170, 60),
        ),
        Health::Off => (
            "●",
            "Off — not measured yet",
            egui::Color32::from_rgb(150, 150, 150),
        ),
    };
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new(dot).color(color).size(22.0));
        ui.heading(text);
    });
}

fn details(ui: &mut egui::Ui, status: &Status) {
    row(
        ui,
        "Service",
        match status.service_state {
            Some(4) => "running".into(),
            Some(1) => "installed, stopped".into(),
            Some(_) => "installed, transitioning".into(),
            None => "not installed".into(),
        },
    );
    match &status.config {
        Some(c) => {
            row(ui, "Strategy", c.strategy.clone());
            row(ui, "Resolver", c.resolver.clone());
            row(
                ui,
                "Block QUIC",
                if c.block_quic {
                    "yes".into()
                } else {
                    "no".into()
                },
            );
        }
        None => row(ui, "Strategy", "none chosen yet".into()),
    }
    row(
        ui,
        "Administrator",
        if status.elevated {
            "yes".into()
        } else {
            "no (actions will ask)".into()
        },
    );
    row(
        ui,
        "Driver",
        if status.driver_available {
            "WinDivert found".into()
        } else {
            "WinDivert missing".into()
        },
    );
    if let Some(av) = &status.antivirus {
        warn_row(ui, "Antivirus", format!("{av} — its shield may interfere"));
    }
    if let Some(r) = &status.rival {
        warn_row(ui, "Rival tool", format!("{r} is running — keep only one"));
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
        ui.horizontal_wrapped(|ui| {
            if ui
                .button(egui::RichText::new("🔎  Measure & protect").size(15.0))
                .on_hover_text("Find the strategy that works on this line, then install the service. Asks for administrator.")
                .clicked()
            {
                self.run_elevated("install --auto");
            }

            if self.status.is_installed()
                && ui
                    .button(egui::RichText::new("⏹  Stop & remove").size(15.0))
                    .on_hover_text("Stop and uninstall the service. Traffic then flows normally.")
                    .clicked()
            {
                self.run_elevated("uninstall");
            }

            if ui.button("↻  Refresh").clicked() {
                self.refresh();
            }
        });

        if self.status.rival.is_some() {
            ui.add_space(6.0);
            ui.label(
                egui::RichText::new(
                    "Stop the rival tool first, or the two will fight over the same handshakes.",
                )
                .color(egui::Color32::from_rgb(220, 170, 60))
                .small(),
            );
        }
    }
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
