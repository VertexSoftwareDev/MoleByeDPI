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
    RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW,
    RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE, REG_DWORD, REG_MULTI_SZ,
    REG_OPTION_NON_VOLATILE, REG_SZ,
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
/// briefly, and as a last resort moves the locked file out of the way.
///
/// First it cancels any delete-at-reboot still pending for the install folder
/// (left by an uninstall that couldn't delete its own running exe): otherwise
/// the next boot would delete this fresh install.
pub fn deploy_self() -> io::Result<PathBuf> {
    let exe = std::env::current_exe()?;
    let dir = install_dir().ok_or_else(|| io::Error::other("ProgramFiles is not set"))?;
    cancel_pending_deletes(&dir);
    let target = dir.join("mole.exe");
    if same_file(&exe, &target) {
        return Ok(target);
    }
    std::fs::create_dir_all(&dir)?;

    for _ in 0..20 {
        if std::fs::copy(&exe, &target).is_ok() {
            return Ok(target);
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    remove_or_schedule(&target);
    std::fs::copy(&exe, &target)?;
    Ok(target)
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
    // Empty now, unless something couldn't be moved out; then it stays. A
    // delete-at-reboot on the folder itself could take a later install with it.
    let _ = std::fs::remove_dir(dir);
}

/// Delete a file, or — if it is in use (the running uninstaller, a loaded
/// driver) — move it into the Windows temp folder and delete it at the next
/// reboot. Moving first means the pending delete never names a path a later
/// install will reuse.
fn remove_or_schedule(path: &Path) {
    if std::fs::remove_file(path).is_ok() {
        return;
    }
    let parked = parking_path(path).filter(|p| std::fs::rename(path, p).is_ok());
    let doomed = parked.as_deref().unwrap_or(path);
    let wide: Vec<u16> = doomed.as_os_str().encode_wide().chain(Some(0)).collect();
    unsafe {
        MoveFileExW(wide.as_ptr(), std::ptr::null(), MOVEFILE_DELAY_UNTIL_REBOOT);
    }
}

/// A unique name in `%SystemRoot%\Temp` (same volume as Program Files on a
/// normal install, so the rename is a cheap move).
fn parking_path(path: &Path) -> Option<PathBuf> {
    let root = std::env::var("SystemRoot").ok()?;
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_nanos();
    let name = path.file_name()?.to_string_lossy();
    Some(
        PathBuf::from(root)
            .join("Temp")
            .join(format!("mole-{stamp}-{name}.del")),
    )
}

const SESSION_MANAGER: &str = r"SYSTEM\CurrentControlSet\Control\Session Manager";
const PENDING_RENAMES: &str = "PendingFileRenameOperations";

/// Drop any delete-at-reboot entries for paths under `dir` from Windows'
/// pending file operations. Best-effort; needs administrator rights.
fn cancel_pending_deletes(dir: &Path) {
    let prefix = dir.to_string_lossy().to_lowercase();
    let name = wide_str(PENDING_RENAMES);
    unsafe {
        let mut key: HKEY = std::ptr::null_mut();
        let path = wide_str(SESSION_MANAGER);
        if RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            path.as_ptr(),
            0,
            KEY_READ | KEY_WRITE,
            &mut key,
        ) != 0
        {
            return;
        }
        let mut kind = 0u32;
        let mut size = 0u32;
        let found = RegQueryValueExW(
            key,
            name.as_ptr(),
            std::ptr::null(),
            &mut kind,
            std::ptr::null_mut(),
            &mut size,
        ) == 0;
        if found && kind == REG_MULTI_SZ {
            let mut buf = vec![0u16; size as usize / 2 + 1];
            let mut len = (buf.len() * 2) as u32;
            if RegQueryValueExW(
                key,
                name.as_ptr(),
                std::ptr::null(),
                &mut kind,
                buf.as_mut_ptr() as *mut u8,
                &mut len,
            ) == 0
            {
                buf.truncate(len as usize / 2);
                match without_pending_under(&buf, &prefix) {
                    Some(kept) if kept.len() <= 1 => {
                        RegDeleteValueW(key, name.as_ptr());
                    }
                    Some(kept) => {
                        RegSetValueExW(
                            key,
                            name.as_ptr(),
                            0,
                            REG_MULTI_SZ,
                            kept.as_ptr() as *const u8,
                            (kept.len() * 2) as u32,
                        );
                    }
                    None => {}
                }
            }
        }
        RegCloseKey(key);
    }
}

/// Given the raw `PendingFileRenameOperations` value (source/destination pairs
/// in a REG_MULTI_SZ; an empty destination means delete), return it without the
/// pairs whose source lies under `prefix` — or None if there were none.
fn without_pending_under(raw: &[u16], prefix: &str) -> Option<Vec<u16>> {
    // Strings end in NUL and the list in one more; destinations can be empty,
    // so split on NUL and pair up, rather than stopping at the first empty one.
    let body = raw.strip_suffix(&[0]).unwrap_or(raw);
    let mut strings: Vec<&[u16]> = body.split(|&c| c == 0).collect();
    if strings.last().is_some_and(|s| s.is_empty()) {
        strings.pop();
    }
    let mut kept: Vec<u16> = Vec::with_capacity(raw.len());
    let mut dropped = false;
    for pair in strings.chunks(2) {
        let source = String::from_utf16_lossy(pair[0]).to_lowercase();
        // Entries look like `\??\C:\...`, sometimes with a `*1` flag prefix.
        let bare = source.trim_start_matches(|c: char| c == '*' || c.is_ascii_digit());
        let bare = bare.strip_prefix(r"\??\").unwrap_or(bare);
        let under = bare
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('\\'));
        if under {
            dropped = true;
            continue;
        }
        for s in pair {
            kept.extend_from_slice(s);
            kept.push(0);
        }
    }
    kept.push(0);
    dropped.then_some(kept)
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

    /// Build a REG_MULTI_SZ from strings.
    fn multi(strings: &[&str]) -> Vec<u16> {
        let mut v = Vec::new();
        for s in strings {
            v.extend(s.encode_utf16());
            v.push(0);
        }
        v.push(0);
        v
    }

    #[test]
    fn pending_deletes_under_the_install_dir_are_dropped_and_the_rest_kept() {
        let raw = multi(&[
            r"\??\C:\Windows\System32\other.dll.0",
            "",
            r"*1\??\C:\Program Files\Mole\mole.exe",
            "",
            r"\??\C:\Program Files\Mole",
            "",
            r"\??\C:\Program Files\Molecule\keep.exe",
            "",
            r"\??\C:\a.tmp",
            r"\??\C:\b.tmp",
        ]);
        let kept = without_pending_under(&raw, r"c:\program files\mole").unwrap();
        assert_eq!(
            kept,
            multi(&[
                r"\??\C:\Windows\System32\other.dll.0",
                "",
                r"\??\C:\Program Files\Molecule\keep.exe",
                "",
                r"\??\C:\a.tmp",
                r"\??\C:\b.tmp",
            ])
        );
    }

    #[test]
    fn pending_deletes_elsewhere_leave_the_value_alone() {
        let raw = multi(&[r"\??\C:\Windows\x.dll", ""]);
        assert_eq!(without_pending_under(&raw, r"c:\program files\mole"), None);
    }

    #[test]
    fn dropping_every_entry_leaves_an_empty_list() {
        let raw = multi(&[r"\??\C:\Program Files\Mole\mole.exe", ""]);
        assert_eq!(
            without_pending_under(&raw, r"c:\program files\mole"),
            Some(vec![0])
        );
    }

    #[test]
    fn a_path_is_the_same_file_as_itself_but_not_a_missing_one() {
        let exe = std::env::current_exe().unwrap();
        assert!(same_file(&exe, &exe));
        assert!(!same_file(&exe, &exe.with_extension("does-not-exist")));
    }
}
