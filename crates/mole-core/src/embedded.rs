//! WinDivert baked into the executable.
//!
//! So a user can hand a friend just `mole.exe` (plus the two `.cmd` helpers) and
//! it works: on first use, if the driver isn't already beside the binary, Mole
//! writes the signed `WinDivert.dll` and `WinDivert64.sys` out itself. They stay
//! LGPL — the licence text ships alongside and nothing here modifies them.

use std::io;
use std::path::{Path, PathBuf};

pub const WINDIVERT_DLL: &[u8] = include_bytes!("../../../vendor/windivert/x64/WinDivert.dll");
pub const WINDIVERT_SYS: &[u8] = include_bytes!("../../../vendor/windivert/x64/WinDivert64.sys");

/// Write the driver pair into `dir` if either file is missing. The `.sys` must
/// sit beside the `.dll` — WinDivert installs the driver from there.
fn write_pair(dir: &Path) -> io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let dll = dir.join("WinDivert.dll");
    let sys = dir.join("WinDivert64.sys");
    if !dll.exists() {
        std::fs::write(&dll, WINDIVERT_DLL)?;
    }
    if !sys.exists() {
        std::fs::write(&sys, WINDIVERT_SYS)?;
    }
    Ok(())
}

/// Ensure the driver pair exists somewhere loadable and return that directory.
/// Prefers `%ProgramData%\Mole` (a runtime data folder, alongside the config and
/// log) so the distributed folder stays clean — just the exe and the .cmd helpers.
/// Falls back to the executable's own folder if ProgramData isn't usable.
pub fn ensure_extracted() -> Option<PathBuf> {
    if let Ok(pd) = std::env::var("ProgramData") {
        let dir = PathBuf::from(pd).join("Mole");
        if write_pair(&dir).is_ok() {
            return Some(dir);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            if write_pair(dir).is_ok() {
                return Some(dir.to_path_buf());
            }
        }
    }
    None
}
