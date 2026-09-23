//! A snapshot of everything the window shows, gathered without elevation.
//!
//! Reading state needs no admin — the service state query, the saved config, the
//! service log and the environment checks are all read-only. Only the *actions*
//! (install, remove) need elevation, and those relaunch `mole.exe` through UAC.
//! Nothing here loads the driver: polling must not write files or hold WinDivert.

use mole_core::service::{conflicting_dpi_service, interfering_antivirus};
use mole_core::Config;

pub struct Status {
    /// Service state code (4 = running), or None if not installed.
    pub service_state: Option<u32>,
    pub config: Option<Config>,
    pub antivirus: Option<String>,
    pub rival: Option<String>,
    /// The newest line of the service log, if any.
    pub last_event: Option<String>,
}

impl Status {
    pub fn gather() -> Status {
        Status {
            service_state: mole_core::winservice::query_state(),
            config: Config::load(),
            antivirus: interfering_antivirus().map(|s| s.to_string()),
            rival: conflicting_dpi_service().map(|s| s.to_string()),
            last_event: mole_core::servicelog::tail(1).pop(),
        }
    }

    pub fn is_installed(&self) -> bool {
        self.service_state.is_some()
    }

    pub fn health(&self) -> Health {
        match self.service_state {
            Some(4) => Health::Protected,
            Some(1) => Health::Stopped,
            Some(_) => Health::Starting,
            None => Health::Off,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Health {
    Protected,
    Starting,
    Stopped,
    Off,
}
