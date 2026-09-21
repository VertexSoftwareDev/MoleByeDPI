//! A safe handle over a WinDivert session.
//!
//! One `WinDivert` owns one open handle with one filter. `recv` blocks for the
//! next matching packet; `send` (re)injects one. Dropping the handle shuts the
//! session down cleanly, which is the backbone of Mole's fail-open promise: when
//! the process goes away the driver stops diverting and traffic flows normally
//! again, with nothing left behind.

use std::ffi::CString;
use std::sync::Arc;

use windows_sys::Win32::Foundation::GetLastError;

use crate::ffi::{
    WinDivertAddress, WinDivertApi, INVALID_HANDLE_VALUE, WINDIVERT_FLAG_DROP, WINDIVERT_FLAG_SNIFF,
    WINDIVERT_LAYER_NETWORK, WINDIVERT_SHUTDOWN_BOTH,
};

/// How a session treats the packets it matches.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Copy matching packets to us but leave them on the network stack. Nothing
    /// we do can break connectivity — the safe choice for measuring and probing.
    Sniff,
    /// Divert matching packets out of the stack. We must re-inject (`send`) each
    /// one or it is dropped. This is how the live filter engine rewrites traffic.
    Divert,
    /// Divert and drop: matching packets vanish. Used to hold back one leg of a
    /// connection (e.g. QUIC) so it falls back to a path we do handle.
    Drop,
}

/// A captured packet plus the address WinDivert needs to re-inject it.
pub struct Packet {
    pub data: Vec<u8>,
    pub addr: WinDivertAddress,
}

pub struct WinDivert {
    api: Arc<WinDivertApi>,
    handle: isize,
    mode: Mode,
}

impl WinDivert {
    /// Open a session for `filter` (WinDivert filter syntax, e.g.
    /// `"outbound and tcp.DstPort == 443"`). `priority` orders overlapping
    /// handles; higher runs first.
    pub fn open(
        api: Arc<WinDivertApi>,
        filter: &str,
        mode: Mode,
        priority: i16,
    ) -> Result<WinDivert, WinDivertError> {
        let c_filter = CString::new(filter).map_err(|_| WinDivertError::BadFilter)?;
        let flags = match mode {
            Mode::Sniff => WINDIVERT_FLAG_SNIFF,
            Mode::Divert => 0,
            Mode::Drop => WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_DROP,
        };

        let handle = unsafe {
            (api.open)(c_filter.as_ptr(), WINDIVERT_LAYER_NETWORK, priority, flags)
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(WinDivertError::from_last_error(filter));
        }
        Ok(WinDivert { api, handle, mode })
    }

    /// Block until the next matching packet, or `None` once the handle has been
    /// shut down and drained.
    pub fn recv(&self) -> Result<Option<Packet>, WinDivertError> {
        let mut buf = vec![0u8; 0xFFFF];
        let mut addr = WinDivertAddress::zeroed();
        let mut len: u32 = 0;
        let ok = unsafe {
            (self.api.recv)(
                self.handle,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut len,
                &mut addr,
            )
        };
        if ok == 0 {
            let code = unsafe { GetLastError() };
            // ERROR_NO_DATA (232): the handle was shut down and is drained.
            if code == 232 {
                return Ok(None);
            }
            return Err(WinDivertError::Recv(code));
        }
        buf.truncate(len as usize);
        Ok(Some(Packet { data: buf, addr }))
    }

    /// Re-inject (or inject) a packet. Recomputes checksums first so callers can
    /// hand back an edited packet without fixing them by hand.
    pub fn send(&self, packet: &mut Packet) -> Result<(), WinDivertError> {
        unsafe {
            (self.api.calc_checksums)(
                packet.data.as_mut_ptr(),
                packet.data.len() as u32,
                &mut packet.addr,
                0,
            );
        }
        let mut sent: u32 = 0;
        let ok = unsafe {
            (self.api.send)(
                self.handle,
                packet.data.as_ptr(),
                packet.data.len() as u32,
                &mut sent,
                &packet.addr,
            )
        };
        if ok == 0 {
            return Err(WinDivertError::Send(unsafe { GetLastError() }));
        }
        Ok(())
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Stop diverting and unblock any `recv`. Called automatically on drop; the
    /// caller can invoke it early to wind a capture loop down.
    pub fn shutdown(&self) {
        unsafe {
            (self.api.shutdown)(self.handle, WINDIVERT_SHUTDOWN_BOTH);
        }
    }
}

impl Drop for WinDivert {
    fn drop(&mut self) {
        unsafe {
            (self.api.shutdown)(self.handle, WINDIVERT_SHUTDOWN_BOTH);
            (self.api.close)(self.handle);
        }
    }
}

#[derive(Debug)]
pub enum WinDivertError {
    /// The filter string contained an interior NUL.
    BadFilter,
    /// `WinDivertOpen` failed. `code` is `GetLastError`.
    Open { code: u32, hint: &'static str },
    Recv(u32),
    Send(u32),
}

impl WinDivertError {
    fn from_last_error(_filter: &str) -> WinDivertError {
        let code = unsafe { GetLastError() };
        let hint = match code {
            2 => "the driver file WinDivert64.sys is missing next to WinDivert.dll",
            5 => "access denied — Mole must run as administrator",
            87 => "the filter string was rejected by the driver",
            577 => "the driver is not digitally signed / blocked by the OS or an antivirus",
            1275 => "the driver was blocked from loading (often an antivirus network shield)",
            _ => "see the Windows system error code",
        };
        WinDivertError::Open { code, hint }
    }
}

impl std::fmt::Display for WinDivertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WinDivertError::BadFilter => write!(f, "the filter string is not valid"),
            WinDivertError::Open { code, hint } => {
                write!(f, "could not open WinDivert (error {code}): {hint}")
            }
            WinDivertError::Recv(code) => write!(f, "WinDivertRecv failed (error {code})"),
            WinDivertError::Send(code) => write!(f, "WinDivertSend failed (error {code})"),
        }
    }
}

impl std::error::Error for WinDivertError {}
