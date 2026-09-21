//! A snapshot of everything the window shows, gathered without elevation.
//!
//! Reading state needs no admin — the service state query, the saved config, and
//! the environment checks are all read-only. Only the *actions* (install, stop)
//! need elevation, and those relaunch `mole.exe` through UAC.

use mole_core::admin::is_elevated;
use mole_core::service::{conflicting_dpi_service, interfering_antivirus};
use mole_core::{Config, WinDivertApi};

pub struct Status {
    /// Service state code (4 = running), or None if not installed.
    pub service_state: Option<u32>,
    pub config: Option<Config>,
    pub elevated: bool,
    pub driver_available: bool,
    pub antivirus: Option<String>,
    pub rival: Option<String>,
}

impl Status {
    pub fn gather() -> Status {
        Status {
            service_state: mole_core::winservice::query_state(),
            config: Config::load(),
            elevated: is_elevated(),
            driver_available: WinDivertApi::load().is_ok(),
            antivirus: interfering_antivirus().map(|s| s.to_string()),
            rival: conflicting_dpi_service().map(|s| s.to_string()),
        }
    }

    pub fn is_running(&self) -> bool {
        self.service_state == Some(4)
    }

    pub fn is_installed(&self) -> bool {
        self.service_state.is_some()
    }

    /// One-word health for the headline dot: protected, idle, or off.
    pub fn headline(&self) -> Health {
        if self.is_running() {
            Health::Protected
        } else if self.is_installed() || self.config.is_some() {
            Health::Idle
        } else {
            Health::Off
        }
    }
}

#[derive(PartialEq, Eq)]
pub enum Health {
    Protected,
    Idle,
    Off,
}
