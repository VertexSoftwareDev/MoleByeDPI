//! Where the installed service lives, and how it gets there and goes away.
//!
//! A friend unzips Mole into Downloads, runs `install.cmd`, and later tidies
//! Downloads. If the service pointed at that folder, it would silently stop
//! starting at boot — fail-open, but unprotected. So `install` copies `mole.exe`
//! into `%ProgramFiles%\Mole` and registers *that* copy; the downloaded folder can
//! then be moved or deleted. `uninstall` removes the copy and the runtime files in
//! `%ProgramData%\Mole`, so nothing is left behind.

use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_DELAY_UNTIL_REBOOT};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE,
    KEY_WRITE, REG_DWORD, REG_OPTION_NON_VOLATILE, REG_SZ,
};

/// Where Windows lists installed programs (Settings › Apps, Control Panel).
const UNINSTALL_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\Mole";

/// `%ProgramFiles%\Mole` — the installed service's home.
pub fn install_dir() -> Option<PathBuf> {
    ["ProgramW6432", "ProgramFiles"]
        .iter()
        .find_map(|v| std::env::var(v).ok())
        .map(|pf| PathBuf::from(pf).join("Mole"))
}

/// `%ProgramData%\Mole` — config, log and the extracted WinDivert driver.
pub fn data_dir() -> Option<PathBuf> {
    std::env::var("ProgramData")
        .ok()
        .map(|pd| PathBuf::from(pd).join("Mole"))
}

/// Copy the running executable into [`install_dir`] and return the copy's path.
/// If this *is* the installed copy, it is returned as is. A previous service's
/// process may take a moment to exit and release its file, so the copy retries
/// briefly, and as a last resort renames the locked file aside (Windows allows
/// renaming a running executable) and schedules the old one for deletion.
pub fn deploy_self() -> io::Result<PathBuf> {
    let exe = std::env::current_exe()?;
    let dir = install_dir().ok_or_else(|| io::Error::other("ProgramFiles is not set"))?;
    let target = dir.join("mole.exe");
    if same_file(&exe, &target) {
        return Ok(target);
    }
    std::fs::create_dir_all(&dir)?;

    let mut last = None;
    for _ in 0..20 {
        match std::fs::copy(&exe, &target) {
            Ok(_) => return Ok(target),
            Err(e) => last = Some(e),
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    let aside = dir.join("mole.exe.old");
    let _ = std::fs::remove_file(&aside);
    if std::fs::rename(&target, &aside).is_ok() {
        remove_or_schedule(&aside);
        std::fs::copy(&exe, &target)?;
        return Ok(target);
    }
    Err(last.unwrap_or_else(|| io::Error::other("could not copy mole.exe")))
}

/// List Mole in Settings › Apps, with an Uninstall button that runs the installed
/// copy's `uninstall`. The downloaded folder (and its uninstall.cmd) may be long
/// gone by then; this is how people expect to remove a program. Best-effort.
pub fn register_uninstall_entry(exe: &Path) {
    let quoted = format!("\"{}\"", exe.display());
    let dir = exe
        .parent()
        .map(|d| d.display().to_string())
        .unwrap_or_default();
    let size_kb = std::fs::metadata(exe)
        .map(|m| (m.len() / 1024) as u32)
        .unwrap_or(0);
    unsafe {
        let mut key: HKEY = std::ptr::null_mut();
        let path = wide_str(UNINSTALL_KEY);
        if RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            path.as_ptr(),
            0,
            std::ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            std::ptr::null(),
            &mut key,
            std::ptr::null_mut(),
        ) != 0
        {
            return;
        }
        set_string(key, "DisplayName", "Mole");
        set_string(key, "DisplayVersion", env!("CARGO_PKG_VERSION"));
        set_string(key, "Publisher", "VertexSoftwareDev");
        set_string(key, "DisplayIcon", &quoted);
        set_string(key, "InstallLocation", &dir);
        set_string(key, "UninstallString", &format!("{quoted} uninstall"));
        set_dword(key, "EstimatedSize", size_kb);
        set_dword(key, "NoModify", 1);
        set_dword(key, "NoRepair", 1);
        RegCloseKey(key);
    }
}

/// Remove the Settings › Apps entry. Best-effort.
pub fn remove_uninstall_entry() {
    let path = wide_str(UNINSTALL_KEY);
    unsafe {
        RegDeleteTreeW(HKEY_LOCAL_MACHINE, path.as_ptr());
    }
}

unsafe fn set_string(key: HKEY, name: &str, value: &str) {
    let name = wide_str(name);
    let data = wide_str(value);
    RegSetValueExW(
        key,
        name.as_ptr(),
        0,
        REG_SZ,
        data.as_ptr() as *const u8,
        (data.len() * 2) as u32,
    );
}

unsafe fn set_dword(key: HKEY, name: &str, value: u32) {
    let name = wide_str(name);
    RegSetValueExW(
        key,
        name.as_ptr(),
        0,
        REG_DWORD,
        &value as *const u32 as *const u8,
        4,
    );
}

fn wide_str(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(Some(0))
        .collect()
}

/// Remove the installed copy, the Settings › Apps entry and Mole's runtime
/// files. Best-effort: a file still in use (the running uninstaller itself, a
/// driver not yet unloaded) is scheduled for deletion at the next reboot instead.
pub fn remove_deployed() {
    remove_uninstall_entry();
    if let Some(dir) = install_dir() {
        remove_tree(&dir);
    }
    if let Some(dir) = data_dir() {
        remove_tree(&dir);
    }
}

fn remove_tree(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() {
            remove_or_schedule(&path);
        }
    }
    if std::fs::remove_dir(dir).is_err() {
        remove_or_schedule(dir);
    }
}

fn remove_or_schedule(path: &Path) {
    if std::fs::remove_file(path).is_ok() {
        return;
    }
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    unsafe {
        MoveFileExW(wide.as_ptr(), std::ptr::null(), MOVEFILE_DELAY_UNTIL_REBOOT);
    }
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_dir_is_under_program_files() {
        let dir = install_dir().expect("ProgramFiles is set on Windows");
        assert!(dir.ends_with("Mole"));
    }

    #[test]
    fn a_path_is_the_same_file_as_itself_but_not_a_missing_one() {
        let exe = std::env::current_exe().unwrap();
        assert!(same_file(&exe, &exe));
        assert!(!same_file(&exe, &exe.with_extension("does-not-exist")));
    }
}
