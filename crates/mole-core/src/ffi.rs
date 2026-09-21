//! Raw WinDivert bindings, loaded from `WinDivert.dll` at run time.
//!
//! We do not link against an import library. GoodByeDPI, zapret and pydivert all
//! ship the DLL beside the executable and let `WinDivertOpen` install the signed
//! driver from the same directory on first use; we do the same. Loading by hand
//! means Mole has no build-time dependency on the WinDivert SDK and can find the
//! DLL next to its own `.exe` (or wherever `MOLE_WINDIVERT_DIR` points).

use std::ffi::{c_char, c_int, CString, OsStr};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use windows_sys::Win32::Foundation::{FreeLibrary, GetLastError, HMODULE};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_WITH_ALTERED_SEARCH_PATH,
};

/// WinDivert's `WINDIVERT_ADDRESS`, 64 bytes on the NETWORK layer.
///
/// We keep the header fields we read and treat the trailing union as opaque
/// bytes. The struct is written wholesale by `WinDivertRecv`, so the size has to
/// match the driver exactly — 64 is the value every mature wrapper uses.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct WinDivertAddress {
    pub timestamp: i64,
    /// Packed bitfield word: Layer:8, Event:8, then the flag bits.
    pub flags: u32,
    pub reserved: u32,
    /// NETWORK layer: `IfIdx` at [0..4], `SubIfIdx` at [4..8]. The rest is other
    /// layers' data we never touch on NETWORK.
    pub union: [u8; 40],
}

impl WinDivertAddress {
    pub fn zeroed() -> Self {
        WinDivertAddress {
            timestamp: 0,
            flags: 0,
            reserved: 0,
            union: [0u8; 40],
        }
    }

    /// Bit 17 of the flag word: set for packets leaving this machine.
    pub fn is_outbound(&self) -> bool {
        (self.flags >> 17) & 1 == 1
    }

    /// Bit 20: the captured packet is IPv6.
    pub fn is_ipv6(&self) -> bool {
        (self.flags >> 20) & 1 == 1
    }

    pub fn if_idx(&self) -> u32 {
        u32::from_ne_bytes([self.union[0], self.union[1], self.union[2], self.union[3]])
    }
}

// WinDivert layers.
pub const WINDIVERT_LAYER_NETWORK: c_int = 0;

// WinDivert open flags.
pub const WINDIVERT_FLAG_SNIFF: u64 = 0x0001;
pub const WINDIVERT_FLAG_DROP: u64 = 0x0002;
#[allow(dead_code)]
pub const WINDIVERT_FLAG_RECV_ONLY: u64 = 0x0004;
#[allow(dead_code)]
pub const WINDIVERT_FLAG_SEND_ONLY: u64 = 0x0008;

// WinDivertShutdown "how".
pub const WINDIVERT_SHUTDOWN_BOTH: c_int = 0x3;

pub const INVALID_HANDLE_VALUE: isize = -1;

type FnOpen = unsafe extern "system" fn(*const c_char, c_int, i16, u64) -> isize;
type FnRecv =
    unsafe extern "system" fn(isize, *mut u8, u32, *mut u32, *mut WinDivertAddress) -> i32;
type FnSend =
    unsafe extern "system" fn(isize, *const u8, u32, *mut u32, *const WinDivertAddress) -> i32;
type FnClose = unsafe extern "system" fn(isize) -> i32;
type FnShutdown = unsafe extern "system" fn(isize, c_int) -> i32;
type FnCalcChecksums = unsafe extern "system" fn(*mut u8, u32, *mut WinDivertAddress, u64) -> i32;

/// The WinDivert DLL and the handful of entry points Mole calls.
pub struct WinDivertApi {
    module: HMODULE,
    pub open: FnOpen,
    pub recv: FnRecv,
    pub send: FnSend,
    pub close: FnClose,
    pub shutdown: FnShutdown,
    pub calc_checksums: FnCalcChecksums,
}

// The DLL is loaded once and its function pointers are stable for the process
// lifetime; sending the api between threads is sound.
unsafe impl Send for WinDivertApi {}
unsafe impl Sync for WinDivertApi {}

impl WinDivertApi {
    /// Load `WinDivert.dll` from the given directory. The matching
    /// `WinDivert64.sys` must sit beside it — the driver installs from there.
    pub fn load_from(dir: &Path) -> Result<WinDivertApi, LoadError> {
        let dll = dir.join("WinDivert.dll");
        let wide: Vec<u16> = OsStr::new(&dll).encode_wide().chain(Some(0)).collect();

        // ALTERED_SEARCH_PATH so the DLL's own directory is searched for its
        // dependencies, matching how the loader resolves a normal executable.
        let module = unsafe {
            LoadLibraryExW(
                wide.as_ptr(),
                std::ptr::null_mut(),
                LOAD_WITH_ALTERED_SEARCH_PATH,
            )
        };
        if module.is_null() {
            return Err(LoadError::DllNotLoaded {
                path: dll,
                code: unsafe { GetLastError() },
            });
        }

        // Resolve every symbol before handing back a usable api.
        let load = |name: &str| -> Result<*const (), LoadError> {
            let c = CString::new(name).unwrap();
            let p = unsafe { GetProcAddress(module, c.as_ptr() as *const u8) };
            match p {
                Some(p) => Ok(p as *const ()),
                None => Err(LoadError::MissingSymbol(name.to_string())),
            }
        };

        let api = unsafe {
            WinDivertApi {
                module,
                open: std::mem::transmute::<*const (), FnOpen>(load("WinDivertOpen")?),
                recv: std::mem::transmute::<*const (), FnRecv>(load("WinDivertRecv")?),
                send: std::mem::transmute::<*const (), FnSend>(load("WinDivertSend")?),
                close: std::mem::transmute::<*const (), FnClose>(load("WinDivertClose")?),
                shutdown: std::mem::transmute::<*const (), FnShutdown>(load("WinDivertShutdown")?),
                calc_checksums: std::mem::transmute::<*const (), FnCalcChecksums>(load(
                    "WinDivertHelperCalcChecksums",
                )?),
            }
        };
        Ok(api)
    }

    /// Load from the first directory that has the DLL: `MOLE_WINDIVERT_DIR`, the
    /// executable's own directory, then a `vendor/windivert/x64` checkout for
    /// development.
    pub fn load() -> Result<WinDivertApi, LoadError> {
        for dir in candidate_dirs() {
            if dir.join("WinDivert.dll").exists() {
                return Self::load_from(&dir);
            }
        }
        Err(LoadError::DllNotFound)
    }
}

impl Drop for WinDivertApi {
    fn drop(&mut self) {
        unsafe {
            FreeLibrary(self.module);
        }
    }
}

fn candidate_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(dir) = std::env::var("MOLE_WINDIVERT_DIR") {
        dirs.push(PathBuf::from(dir));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            dirs.push(parent.to_path_buf());
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        dirs.push(cwd.join("vendor").join("windivert").join("x64"));
    }
    dirs
}

#[derive(Debug)]
pub enum LoadError {
    /// No candidate directory held a `WinDivert.dll`.
    DllNotFound,
    /// The DLL was found but the OS refused to load it (code is `GetLastError`).
    DllNotLoaded { path: PathBuf, code: u32 },
    /// The DLL loaded but a required entry point was missing — wrong version.
    MissingSymbol(String),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::DllNotFound => write!(
                f,
                "WinDivert.dll not found next to the executable, in vendor/windivert/x64, \
                 or via MOLE_WINDIVERT_DIR"
            ),
            LoadError::DllNotLoaded { path, code } => write!(
                f,
                "WinDivert.dll at {} could not be loaded (Windows error {code}); \
                 is WinDivert64.sys beside it, and is this a 64-bit build?",
                path.display()
            ),
            LoadError::MissingSymbol(name) => {
                write!(
                    f,
                    "WinDivert.dll is missing {name}; it is an unexpected version"
                )
            }
        }
    }
}

impl std::error::Error for LoadError {}
