//! A read-only peek at the Windows service database.
//!
//! The probe needs one fact right now: is another DPI-bypass tool (a GoodByeDPI
//! service, say) already rewriting handshakes? If so, every measurement is
//! contaminated — the control would look "not blocked" because the other tool is
//! bypassing it. Phase 4's self-healing service will build on the same SCM calls;
//! this is the small, safe first slice of it.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use windows_sys::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_MANAGER_CONNECT,
    SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_STATUS,
};

fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

/// True if a service by this name exists and is currently running. False if it
/// is stopped, absent, or cannot be queried.
pub fn is_service_running(name: &str) -> bool {
    unsafe {
        let scm = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT);
        if scm.is_null() {
            return false;
        }
        let svc = OpenServiceW(scm, wide(name).as_ptr(), SERVICE_QUERY_STATUS);
        if svc.is_null() {
            CloseServiceHandle(scm);
            return false;
        }
        let mut status: SERVICE_STATUS = std::mem::zeroed();
        let ok = QueryServiceStatus(svc, &mut status);
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        ok != 0 && status.dwCurrentState == SERVICE_RUNNING
    }
}

/// Names of DPI-bypass tools that fight Mole for the same handshakes. If one of
/// these is running, the probe's numbers can't be trusted.
pub const KNOWN_CONFLICTING_SERVICES: &[&str] = &["GoodbyeDPI", "zapret", "winws", "ByeDPI"];

/// Return the first known conflicting DPI service that is running, if any.
pub fn conflicting_dpi_service() -> Option<&'static str> {
    KNOWN_CONFLICTING_SERVICES
        .iter()
        .copied()
        .find(|name| is_service_running(name))
}
