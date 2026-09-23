//! Interface text, in Turkish and English.
//!
//! Written for someone who has never heard of DPI: the window says what is
//! happening and what to do, and keeps the technical names (strategy labels,
//! resolvers) in the details section. Plain strings live in a struct; the ones
//! that take an argument are methods, so a missing `{}` in one language shows up
//! the moment someone switches to it. The default follows the Windows language.

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

    /// The language's own name, for the picker.
    pub fn name(self) -> &'static str {
        match self {
            Lang::Tr => "Türkçe",
            Lang::En => "English",
        }
    }

    pub fn antivirus_title(self, av: &str) -> String {
        match self {
            Lang::Tr => format!("{av} bağlantıyı engelleyebilir"),
            Lang::En => format!("{av} may get in the way"),
        }
    }

    pub fn rival_title(self, name: &str) -> String {
        match self {
            Lang::Tr => format!("{name} da çalışıyor"),
            Lang::En => format!("{name} is also running"),
        }
    }
}

/// Every window string that needs no argument.
pub struct Strings {
    // Headline card, by state.
    pub protected: &'static str,
    pub protected_body: &'static str,
    pub starting: &'static str,
    pub starting_body: &'static str,
    pub stopped: &'static str,
    pub stopped_body: &'static str,
    pub off: &'static str,
    pub off_body: &'static str,

    // Actions.
    pub protect: &'static str,
    pub start_again: &'static str,
    pub remeasure: &'static str,
    pub remeasure_hover: &'static str,
    pub measuring: &'static str,
    pub removing: &'static str,
    pub uac_declined: &'static str,
    pub install_failed: &'static str,
    pub remove_failed: &'static str,
    pub launch_failed: &'static str,

    // Warnings.
    pub antivirus_body: &'static str,
    pub rival_body: &'static str,

    // Site check.
    pub check_section: &'static str,
    pub check_hint: &'static str,
    pub check_button: &'static str,
    pub checking: &'static str,
    pub open: &'static str,
    pub open_detail: &'static str,
    pub blocked: &'static str,
    pub reset_detail: &'static str,
    pub dropped_detail: &'static str,
    pub broke_detail: &'static str,
    pub ip_blocked: &'static str,
    pub ip_detail: &'static str,
    pub unresolved: &'static str,
    pub unresolved_detail: &'static str,

    // Settings.
    pub settings_section: &'static str,
    pub language: &'static str,
    pub theme: &'static str,
    pub theme_system: &'static str,
    pub theme_light: &'static str,
    pub theme_dark: &'static str,

    // Details.
    pub details: &'static str,
    pub details_body: &'static str,
    pub method: &'static str,
    pub service: &'static str,
    pub running: &'static str,
    pub stopped_word: &'static str,
    pub changing: &'static str,
    pub not_installed: &'static str,
    pub dns: &'static str,
    pub quic: &'static str,
    pub quic_blocked: &'static str,
    pub quic_allowed: &'static str,
    pub watching: &'static str,
    pub last_event: &'static str,
    pub none: &'static str,

    // Remove.
    pub remove_title: &'static str,
    pub remove_body: &'static str,
    pub remove: &'static str,

    // Tray.
    pub tray_open: &'static str,
    pub tray_quit: &'static str,
}

static EN: Strings = Strings {
    protected: "You're protected",
    protected_body: "Blocked sites open normally. Mole runs in the background, starts with Windows, and repairs itself if your provider changes something.",
    starting: "Starting…",
    starting_body: "The background service is starting up.",
    stopped: "Mole is paused",
    stopped_body: "It's installed but not running right now, so blocked sites stay blocked.",
    off: "Not set up yet",
    off_body: "Mole tests your connection, finds the method that works on it, and keeps it running in the background. Takes about ten seconds and asks for administrator permission.",

    protect: "Set up protection",
    start_again: "Measure and start",
    remeasure: "Measure again",
    remeasure_hover: "Test the connection again and switch to whatever works best now.",
    measuring: "Testing your connection…",
    removing: "Removing…",
    uac_declined: "Administrator permission wasn't given, so nothing changed.",
    install_failed: "Setup didn't finish. Run install.cmd to see each step.",
    remove_failed: "Mole couldn't be removed. Try uninstall.cmd.",
    launch_failed: "Couldn't start mole.exe. It should sit in the same folder as this window.",

    antivirus_body: "Its network shield can block the driver Mole relies on. If sites stay blocked, add an exception for WinDivert.",
    rival_body: "Two tools changing the same connection break each other. Keep only one of them.",

    check_section: "Check a site",
    check_hint: "www.example.com",
    check_button: "Check",
    checking: "Checking…",
    open: "Open",
    open_detail: "The site loads on this connection.",
    blocked: "Blocked",
    reset_detail: "The connection is cut as soon as the site's name is seen.",
    dropped_detail: "The request gets no answer.",
    broke_detail: "The site answered, but the connection then broke.",
    ip_blocked: "Blocked by address",
    ip_detail: "The site's address itself is blocked. A tool on your computer can't get past that.",
    unresolved: "Not found",
    unresolved_detail: "That name couldn't be looked up. Check the spelling.",

    settings_section: "Settings",
    language: "Language",
    theme: "Theme",
    theme_system: "Use system setting",
    theme_light: "Light",
    theme_dark: "Dark",

    details: "Technical details",
    details_body: "The method in use and the service's state",
    method: "Method",
    service: "Service",
    running: "Running",
    stopped_word: "Stopped",
    changing: "Changing state",
    not_installed: "Not installed",
    dns: "DNS",
    quic: "QUIC",
    quic_blocked: "Blocked",
    quic_allowed: "Allowed",
    watching: "Watched site",
    last_event: "Last event",
    none: "—",

    remove_title: "Remove Mole",
    remove_body: "Stops the service and deletes its files. Your internet keeps working as before.",
    remove: "Remove",

    tray_open: "Open Mole",
    tray_quit: "Quit",
};

static TR: Strings = Strings {
    protected: "Korunuyorsun",
    protected_body: "Engelli siteler normal açılıyor. Mole arka planda çalışır, Windows ile birlikte başlar ve operatör bir şey değiştirirse kendini yeniden ayarlar.",
    starting: "Başlıyor…",
    starting_body: "Arka plan servisi açılıyor.",
    stopped: "Mole duraklatıldı",
    stopped_body: "Kurulu ama şu an çalışmıyor, bu yüzden engelli siteler engelli kalıyor.",
    off: "Henüz kurulmadı",
    off_body: "Mole bağlantını test eder, sende çalışan yöntemi bulur ve arka planda çalıştırır. Yaklaşık on saniye sürer ve yönetici izni ister.",

    protect: "Korumayı kur",
    start_again: "Ölç ve başlat",
    remeasure: "Yeniden ölç",
    remeasure_hover: "Bağlantıyı yeniden test et ve şu an en iyi çalışan yönteme geç.",
    measuring: "Bağlantın test ediliyor…",
    removing: "Kaldırılıyor…",
    uac_declined: "Yönetici izni verilmedi, hiçbir şey değişmedi.",
    install_failed: "Kurulum tamamlanamadı. Adımları görmek için install.cmd'yi çalıştır.",
    remove_failed: "Mole kaldırılamadı. uninstall.cmd'yi dene.",
    launch_failed: "mole.exe başlatılamadı. Bu pencereyle aynı klasörde olmalı.",

    antivirus_body: "Ağ kalkanı, Mole'un kullandığı sürücüyü engelleyebilir. Siteler açılmazsa WinDivert için bir istisna ekle.",
    rival_body: "Aynı bağlantıyı değiştiren iki araç birbirini bozar. Yalnızca birini tut.",

    check_section: "Site kontrolü",
    check_hint: "www.ornek.com",
    check_button: "Kontrol et",
    checking: "Kontrol ediliyor…",
    open: "Açık",
    open_detail: "Site bu bağlantıda açılıyor.",
    blocked: "Engelli",
    reset_detail: "Sitenin adı görüldüğü anda bağlantı kesiliyor.",
    dropped_detail: "İsteğe hiç yanıt gelmiyor.",
    broke_detail: "Site yanıt verdi ama bağlantı ardından koptu.",
    ip_blocked: "Adresten engelli",
    ip_detail: "Sitenin adresi doğrudan engellenmiş. Bilgisayarındaki bir araç bunu aşamaz.",
    unresolved: "Bulunamadı",
    unresolved_detail: "Bu ad çözülemedi. Yazımı kontrol et.",

    settings_section: "Ayarlar",
    language: "Dil",
    theme: "Tema",
    theme_system: "Sistem ayarını kullan",
    theme_light: "Açık",
    theme_dark: "Koyu",

    details: "Teknik ayrıntılar",
    details_body: "Kullanılan yöntem ve servisin durumu",
    method: "Yöntem",
    service: "Servis",
    running: "Çalışıyor",
    stopped_word: "Durmuş",
    changing: "Durum değişiyor",
    not_installed: "Kurulu değil",
    dns: "DNS",
    quic: "QUIC",
    quic_blocked: "Engelli",
    quic_allowed: "Serbest",
    watching: "İzlenen site",
    last_event: "Son olay",
    none: "—",

    remove_title: "Mole'u kaldır",
    remove_body: "Servisi durdurur ve dosyalarını siler. İnternetin eskisi gibi çalışmaya devam eder.",
    remove: "Kaldır",

    tray_open: "Mole'u aç",
    tray_quit: "Çık",
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
