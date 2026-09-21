//! The Windows service: install, remove, and the service entry point itself.
//!
//! No `windows-service` crate — this is the raw SCM plumbing, kept in one place.
//! Install registers `mole.exe service-run` as an auto-start service and asks
//! Windows to restart it if it ever crashes (native self-healing, on top of the
//! engine's own retry). The service body loads the saved strategy and runs the
//! filter engine; on stop it winds the engine down cleanly, so traffic flows.
//!
//! Uninstall stops and deletes the service and leaves nothing behind — the
//! "reinstall loop" the plan set out to end is not something Mole itself creates.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use windows_sys::Win32::Foundation::{ERROR_SERVICE_DOES_NOT_EXIST, NO_ERROR};
use windows_sys::Win32::System::Services::{
    ChangeServiceConfig2W, CloseServiceHandle, ControlService, CreateServiceW, DeleteService,
    OpenSCManagerW, OpenServiceW, QueryServiceStatus, RegisterServiceCtrlHandlerW,
    SetServiceStatus, StartServiceCtrlDispatcherW, StartServiceW, ENUM_SERVICE_TYPE, SC_ACTION,
    SC_ACTION_RESTART, SC_MANAGER_ALL_ACCESS, SC_MANAGER_CONNECT, SERVICE_ACCEPT_SHUTDOWN,
    SERVICE_ACCEPT_STOP, SERVICE_ALL_ACCESS, SERVICE_AUTO_START, SERVICE_CONFIG_FAILURE_ACTIONS,
    SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_ERROR_NORMAL, SERVICE_FAILURE_ACTIONSW,
    SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS,
    SERVICE_STATUS_HANDLE, SERVICE_STOPPED, SERVICE_STOP_PENDING, SERVICE_TABLE_ENTRYW,
    SERVICE_WIN32_OWN_PROCESS,
};

use crate::windivert::WinDivert;

pub const SERVICE_NAME: &str = "MoleService";
pub const DISPLAY_NAME: &str = "Mole — local access-block bypass";

fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

// ── Shared state the C service callbacks reach through statics ────────────────
static STATUS_HANDLE: AtomicIsize = AtomicIsize::new(0);
static STOP: AtomicBool = AtomicBool::new(false);
static CHECKPOINT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
/// The live engine's stopper handle, so the control handler can unblock `recv`.
fn stopper_slot() -> &'static Mutex<Option<Arc<WinDivert>>> {
    static SLOT: OnceLock<Mutex<Option<Arc<WinDivert>>>> = OnceLock::new();
    SLOT.get_or_init(|| Mutex::new(None))
}

// ── Install / uninstall / control ────────────────────────────────────────────

/// Install the service pointing at this executable's `service-run`, set it to
/// start at boot, and ask Windows to restart it on failure.
pub fn install() -> Result<(), ServiceError> {
    let exe = std::env::current_exe().map_err(|_| ServiceError::NoExePath)?;
    let bin_path = format!("\"{}\" service-run", exe.display());

    unsafe {
        let scm = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_ALL_ACCESS);
        if scm.is_null() {
            return Err(ServiceError::last("OpenSCManager (are you elevated?)"));
        }
        let svc = CreateServiceW(
            scm,
            wide(SERVICE_NAME).as_ptr(),
            wide(DISPLAY_NAME).as_ptr(),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS as ENUM_SERVICE_TYPE,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            wide(&bin_path).as_ptr(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(), // LocalSystem
            std::ptr::null(),
        );
        if svc.is_null() {
            let e = ServiceError::last("CreateService");
            CloseServiceHandle(scm);
            return Err(e);
        }

        // Restart on crash: two restarts with a short delay, reset the counter
        // after a day. This is Windows' own self-healing, backing the engine's.
        let mut actions = [
            SC_ACTION {
                Type: SC_ACTION_RESTART,
                Delay: 5_000,
            },
            SC_ACTION {
                Type: SC_ACTION_RESTART,
                Delay: 10_000,
            },
        ];
        let mut fa: SERVICE_FAILURE_ACTIONSW = std::mem::zeroed();
        fa.dwResetPeriod = 86_400;
        fa.cActions = actions.len() as u32;
        fa.lpsaActions = actions.as_mut_ptr();
        ChangeServiceConfig2W(
            svc,
            SERVICE_CONFIG_FAILURE_ACTIONS,
            &mut fa as *mut _ as *mut _,
        );

        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
    }
    Ok(())
}

/// Start the installed service now (without waiting for a reboot).
pub fn start() -> Result<(), ServiceError> {
    with_service(SERVICE_ALL_ACCESS, |svc| unsafe {
        if StartServiceW(svc, 0, std::ptr::null()) == 0 {
            Err(ServiceError::last("StartService"))
        } else {
            Ok(())
        }
    })
}

/// Stop and delete the service. Returns Ok if it was already gone.
pub fn uninstall() -> Result<(), ServiceError> {
    unsafe {
        let scm = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_ALL_ACCESS);
        if scm.is_null() {
            return Err(ServiceError::last("OpenSCManager (are you elevated?)"));
        }
        let svc = OpenServiceW(scm, wide(SERVICE_NAME).as_ptr(), SERVICE_ALL_ACCESS);
        if svc.is_null() {
            let code = last_error();
            CloseServiceHandle(scm);
            if code == ERROR_SERVICE_DOES_NOT_EXIST {
                return Ok(()); // nothing to remove
            }
            return Err(ServiceError::from_code("OpenService", code));
        }
        // Best-effort stop, then delete.
        let mut status: SERVICE_STATUS = std::mem::zeroed();
        ControlService(svc, SERVICE_CONTROL_STOP, &mut status);
        let ok = DeleteService(svc) != 0;
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        if ok {
            Ok(())
        } else {
            Err(ServiceError::last("DeleteService"))
        }
    }
}

/// The service's current state code (SERVICE_RUNNING etc.), or None if absent.
/// Uses read-only access so `mole status` works without elevation.
pub fn query_state() -> Option<u32> {
    unsafe {
        let scm = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT);
        if scm.is_null() {
            return None;
        }
        let svc = OpenServiceW(scm, wide(SERVICE_NAME).as_ptr(), SERVICE_QUERY_STATUS);
        if svc.is_null() {
            CloseServiceHandle(scm);
            return None;
        }
        let mut status: SERVICE_STATUS = std::mem::zeroed();
        let ok = QueryServiceStatus(svc, &mut status);
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        if ok != 0 {
            Some(status.dwCurrentState)
        } else {
            None
        }
    }
}

fn with_service<T>(
    access: u32,
    f: impl FnOnce(*mut std::ffi::c_void) -> Result<T, ServiceError>,
) -> Result<T, ServiceError> {
    unsafe {
        let scm = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_ALL_ACCESS);
        if scm.is_null() {
            return Err(ServiceError::last("OpenSCManager (are you elevated?)"));
        }
        let svc = OpenServiceW(scm, wide(SERVICE_NAME).as_ptr(), access);
        if svc.is_null() {
            let e = ServiceError::last("OpenService");
            CloseServiceHandle(scm);
            return Err(e);
        }
        let r = f(svc);
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        r
    }
}

// ── The service entry point ──────────────────────────────────────────────────

/// The service body, supplied by the caller (mole-cli, where the probe lives).
/// It should run until `should_stop()` returns true. Stored so the C `ServiceMain`
/// callback can reach it.
static SERVE: OnceLock<fn()> = OnceLock::new();

/// True once the SCM has asked the service to stop.
pub fn should_stop() -> bool {
    STOP.load(Ordering::SeqCst)
}

/// Register (or clear) the live engine handle so a stop request can unblock it.
pub fn register_stopper(handle: Option<Arc<WinDivert>>) {
    if let Ok(mut slot) = stopper_slot().lock() {
        *slot = handle;
    }
}

/// Hand control to the SCM: it calls `service_main` on a service thread, which
/// runs `serve` until stop. Called from `mole service-run`, which the SCM launches.
pub fn run_dispatcher(serve: fn()) -> Result<(), ServiceError> {
    let _ = SERVE.set(serve);
    let name = wide(SERVICE_NAME);
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_ptr() as *mut u16,
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: std::ptr::null_mut(),
            lpServiceProc: None,
        },
    ];
    unsafe {
        if StartServiceCtrlDispatcherW(table.as_ptr()) == 0 {
            return Err(ServiceError::last("StartServiceCtrlDispatcher"));
        }
    }
    Ok(())
}

fn set_status(state: u32, accept: u32, wait_hint: u32) {
    let handle = STATUS_HANDLE.load(Ordering::SeqCst);
    if handle == 0 {
        return;
    }
    let cp = if state == SERVICE_RUNNING || state == SERVICE_STOPPED {
        0
    } else {
        CHECKPOINT.fetch_add(1, Ordering::SeqCst) + 1
    };
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS as ENUM_SERVICE_TYPE,
        dwCurrentState: state,
        dwControlsAccepted: accept,
        dwWin32ExitCode: 0,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: cp,
        dwWaitHint: wait_hint,
    };
    unsafe {
        SetServiceStatus(handle as SERVICE_STATUS_HANDLE, &status);
    }
}

/// Handles STOP/SHUTDOWN from the SCM: signal the loop and unblock the engine.
unsafe extern "system" fn control_handler(control: u32) {
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            set_status(SERVICE_STOP_PENDING, 0, 3000);
            STOP.store(true, Ordering::SeqCst);
            if let Ok(slot) = stopper_slot().lock() {
                if let Some(h) = slot.as_ref() {
                    h.shutdown();
                }
            }
        }
        _ => {}
    }
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
    let handle = RegisterServiceCtrlHandlerW(wide(SERVICE_NAME).as_ptr(), Some(control_handler));
    if handle.is_null() {
        return;
    }
    STATUS_HANDLE.store(handle as isize, Ordering::SeqCst);
    set_status(SERVICE_START_PENDING, 0, 3000);

    // Run the caller-supplied service body until it returns (on stop).
    let accept = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    set_status(SERVICE_RUNNING, accept, 0);
    if let Some(serve) = SERVE.get() {
        serve();
    } else {
        // No body was registered; just wait to be stopped.
        while !STOP.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
    }
    set_status(SERVICE_STOPPED, 0, 0);
}

// ── Errors ───────────────────────────────────────────────────────────────────

fn last_error() -> u32 {
    unsafe { windows_sys::Win32::Foundation::GetLastError() }
}

#[derive(Debug)]
pub enum ServiceError {
    NoExePath,
    Win32 { op: &'static str, code: u32 },
}

impl ServiceError {
    fn last(op: &'static str) -> ServiceError {
        ServiceError::Win32 {
            op,
            code: last_error(),
        }
    }
    fn from_code(op: &'static str, code: u32) -> ServiceError {
        ServiceError::Win32 { op, code }
    }
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceError::NoExePath => write!(f, "could not find this executable's path"),
            ServiceError::Win32 { op, code } => {
                let hint = match *code {
                    5 => " (access denied — run as administrator)",
                    1073 => " (the service already exists)",
                    _ if *code == NO_ERROR => "",
                    _ => "",
                };
                write!(f, "{op} failed (Windows error {code}){hint}")
            }
        }
    }
}

impl std::error::Error for ServiceError {}
