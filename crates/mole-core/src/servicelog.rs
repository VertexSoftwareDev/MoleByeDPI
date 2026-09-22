//! A tiny append-only log for the background service, so a user (or `mole status`)
//! can see what it did and — crucially — *why it stopped protecting* when an
//! antivirus shield blocks the driver. Best-effort: logging never fails the caller.
//!
//! It lives beside the config in `%ProgramData%\Mole`. Kept small: when it grows
//! past a cap the oldest half is dropped, so it never bloats.

use std::io::Write;
use std::path::PathBuf;

use windows_sys::Win32::System::SystemInformation::GetLocalTime;

const CAP_BYTES: u64 = 64 * 1024;

fn log_path() -> PathBuf {
    if let Ok(pd) = std::env::var("ProgramData") {
        return PathBuf::from(pd).join("Mole").join("mole.log");
    }
    PathBuf::from("mole.log")
}

fn timestamp() -> String {
    unsafe {
        let mut st = std::mem::zeroed();
        GetLocalTime(&mut st);
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond
        )
    }
}

/// Append a timestamped line. Never panics or returns an error.
pub fn log(msg: &str) {
    let path = log_path();
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    trim_if_large(&path);
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = writeln!(f, "{}  {msg}", timestamp());
    }
}

/// The last `n` lines, newest last. Empty if there is no log.
pub fn tail(n: usize) -> Vec<String> {
    let Ok(text) = std::fs::read_to_string(log_path()) else {
        return Vec::new();
    };
    let lines: Vec<&str> = text.lines().collect();
    lines
        .iter()
        .rev()
        .take(n)
        .rev()
        .map(|s| s.to_string())
        .collect()
}

/// Drop the oldest half when the file grows past the cap.
fn trim_if_large(path: &std::path::Path) {
    let Ok(meta) = std::fs::metadata(path) else {
        return;
    };
    if meta.len() <= CAP_BYTES {
        return;
    }
    if let Ok(text) = std::fs::read_to_string(path) {
        let lines: Vec<&str> = text.lines().collect();
        let keep = &lines[lines.len() / 2..];
        let _ = std::fs::write(path, keep.join("\n") + "\n");
    }
}
