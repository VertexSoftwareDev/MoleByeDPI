//! Interface text, in Turkish and English.
//!
//! Only the window chrome is translated; strategy labels, host names and Windows
//! error text are shown as they are. Plain strings live in a struct; the ones
//! that take an argument are methods, so a missing `{}` in one language shows up
//! the moment someone switches to it. The default follows the OS language.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Lang {
    Tr,
    En,
}

impl Default for Lang {
    /// Turkish when Windows is set to Turkish, English otherwise.
    fn default() -> Self {
        if windows_is_turkish() {
            Lang::Tr
        } else {
            Lang::En
        }
    }
}

impl Lang {
    pub fn strings(self) -> &'static Strings {
        match self {
            Lang::Tr => &TR,
            Lang::En => &EN,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Lang::Tr => "TR",
            Lang::En => "EN",
        }
    }

    // Strings that take an argument.

    pub fn antivirus_interferes(self, av: &str) -> String {
        match self {
            Lang::Tr => format!("{av} — kalkanı TLS'i araya girip bozabilir"),
            Lang::En => format!("{av} — its shield may interfere"),
        }
    }

    pub fn rival_running(self, name: &str) -> String {
        match self {
            Lang::Tr => format!("{name} çalışıyor — yalnızca birini tut"),
            Lang::En => format!("{name} is running — keep only one"),
        }
    }

    pub fn started(self, args: &str) -> String {
        match self {
            Lang::Tr => format!("Başlatıldı: mole {args}"),
            Lang::En => format!("Started: mole {args}"),
        }
    }

    pub fn could_not_start(self, args: &str, err: &str) -> String {
        match self {
            Lang::Tr => format!("mole {args} başlatılamadı: {err}"),
            Lang::En => format!("Could not start mole {args}: {err}"),
        }
    }

    pub fn reach_blocked(self, reason: &str) -> String {
        match self {
            Lang::Tr => format!("Engelli — {reason}"),
            Lang::En => format!("Blocked — {reason}"),
        }
    }

    pub fn reach_dns(self, reason: &str) -> String {
        match self {
            Lang::Tr => format!("Çözülemedi — {reason}"),
            Lang::En => format!("Couldn't resolve — {reason}"),
        }
    }
}

/// Every window string that needs no argument.
pub struct Strings {
    pub protected: &'static str,
    pub idle: &'static str,
    pub off: &'static str,
    pub service: &'static str,
    pub running: &'static str,
    pub installed_stopped: &'static str,
    pub installed_transitioning: &'static str,
    pub not_installed: &'static str,
    pub strategy: &'static str,
    pub none_chosen: &'static str,
    pub resolver: &'static str,
    pub block_quic: &'static str,
    pub yes: &'static str,
    pub no: &'static str,
    pub administrator: &'static str,
    pub admin_no: &'static str,
    pub driver: &'static str,
    pub driver_found: &'static str,
    pub driver_missing: &'static str,
    pub measure_protect: &'static str,
    pub measure_hover: &'static str,
    pub stop_remove: &'static str,
    pub stop_hover: &'static str,
    pub refresh: &'static str,
    pub failopen: &'static str,
    pub tagline: &'static str,
    pub language_tooltip: &'static str,
    pub subtitle: &'static str,
    pub check_title: &'static str,
    pub check_hint: &'static str,
    pub check_button: &'static str,
    pub checking: &'static str,
    pub reach_open: &'static str,
    pub reach_ip: &'static str,
    pub theme_tooltip: &'static str,
}

static EN: Strings = Strings {
    protected: "Protected — a bypass is applied",
    idle: "Idle — measured but not running",
    off: "Off — not measured yet",
    service: "Service",
    running: "running",
    installed_stopped: "installed, stopped",
    installed_transitioning: "installed, transitioning",
    not_installed: "not installed",
    strategy: "Strategy",
    none_chosen: "none chosen yet",
    resolver: "Resolver",
    block_quic: "Block QUIC",
    yes: "yes",
    no: "no",
    administrator: "Administrator",
    admin_no: "no (actions will ask)",
    driver: "Driver",
    driver_found: "WinDivert found",
    driver_missing: "WinDivert missing",
    measure_protect: "🔎  Measure & protect",
    measure_hover: "Find the strategy that works on this line, then install the service. Asks for administrator.",
    stop_remove: "⏹  Stop & remove",
    stop_hover: "Stop and uninstall the service. Traffic then flows normally.",
    refresh: "↻  Refresh",
    failopen: "If Mole stops, your internet keeps working (fail-open).",
    tagline: "Mole — it doesn't break the wall, it tunnels under.",
    language_tooltip: "Language",
    subtitle: "Finds the bypass that works on your line",
    check_title: "Is a site blocked right now?",
    check_hint: "e.g. www.roblox.com",
    check_button: "Check",
    checking: "checking…",
    reach_open: "Open — this site isn't blocked",
    reach_ip: "IP-level block — a local tool can't pass this",
    theme_tooltip: "Light / dark",
};

static TR: Strings = Strings {
    protected: "Korunuyorsun — bir atlatma uygulanıyor",
    idle: "Beklemede — ölçüldü ama çalışmıyor",
    off: "Kapalı — henüz ölçülmedi",
    service: "Servis",
    running: "çalışıyor",
    installed_stopped: "kurulu, durmuş",
    installed_transitioning: "kurulu, geçiş halinde",
    not_installed: "kurulu değil",
    strategy: "Strateji",
    none_chosen: "henüz seçilmedi",
    resolver: "Çözücü",
    block_quic: "QUIC engelle",
    yes: "evet",
    no: "hayır",
    administrator: "Yönetici",
    admin_no: "hayır (işlemler soracak)",
    driver: "Sürücü",
    driver_found: "WinDivert bulundu",
    driver_missing: "WinDivert yok",
    measure_protect: "🔎  Ölç ve koru",
    measure_hover: "Bu hatta çalışan stratejiyi bul, sonra servisi kur. Yönetici izni ister.",
    stop_remove: "⏹  Durdur ve kaldır",
    stop_hover: "Servisi durdur ve kaldır. Sonra trafik normal akar.",
    refresh: "↻  Yenile",
    failopen: "Mole dursa bile internetin çalışmaya devam eder (fail-open).",
    tagline: "Mole — köstebek. Duvarı yıkmaz, altından geçer.",
    language_tooltip: "Dil",
    subtitle: "Hattında çalışan atlatmayı bulur",
    check_title: "Bir site şu an engelli mi?",
    check_hint: "örn. www.roblox.com",
    check_button: "Test et",
    checking: "kontrol ediliyor…",
    reach_open: "Açık — bu sitenin engeli yok",
    reach_ip: "IP engeli — yerelde aşılamaz",
    theme_tooltip: "Açık / koyu",
};

/// True if the user's Windows locale is Turkish.
fn windows_is_turkish() -> bool {
    use windows_sys::Win32::Globalization::GetUserDefaultLocaleName;
    let mut buf = [0u16; 85];
    let n = unsafe { GetUserDefaultLocaleName(buf.as_mut_ptr(), buf.len() as i32) };
    if n <= 0 {
        return false;
    }
    let name = String::from_utf16_lossy(&buf[..(n as usize).saturating_sub(1)]);
    name.to_ascii_lowercase().starts_with("tr")
}
