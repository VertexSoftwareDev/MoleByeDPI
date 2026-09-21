//! The live filter engine: apply one chosen strategy to every outbound TLS
//! handshake, system-wide, for as long as Mole runs.
//!
//! This is the standing version of what the probe does for a single connection.
//! It diverts outbound TCP :443, reshapes each ClientHello with the strategy, and
//! reinjects everything else untouched. Reinjected packets are not recaptured, so
//! there is no loop. When the engine stops — cleanly, or because the process dies
//! — the handle closes and the driver stops diverting, so traffic flows again.
//! That is the fail-open guarantee, enforced by the OS closing the handle even if
//! Mole is killed.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use crate::ffi::WinDivertApi;
use crate::packet::{is_client_hello, TcpView};
use crate::strategy::Strategy;
use crate::windivert::{Mode, WinDivert, WinDivertError};

/// Blocks outbound QUIC (UDP :443) so browsers fall back to TLS-over-TCP, which
/// the filter engine does handle. This is the cheap first step for "the untouched
/// half" from the plan: it doesn't bypass QUIC, it sidesteps it. The cost is real
/// — QUIC to *unblocked* sites is forced onto TCP too, adding a little latency —
/// so it is opt-in. A full QUIC Initial desync can replace it later.
///
/// The handle drops matches in the driver; holding it open is all that's needed.
/// Dropping it (on stop or process exit) restores QUIC — fail-open here too.
pub struct QuicBlocker {
    _handle: WinDivert,
}

impl QuicBlocker {
    pub fn start(api: Arc<WinDivertApi>) -> Result<QuicBlocker, WinDivertError> {
        let handle = WinDivert::open(api, "outbound and udp.DstPort == 443", Mode::Drop, 1000)?;
        Ok(QuicBlocker { _handle: handle })
    }
}

/// Live counters, readable while the engine runs (for a status line or tray).
#[derive(Default)]
pub struct Stats {
    pub handshakes_shaped: AtomicU64,
    pub packets_passed: AtomicU64,
}

pub struct FilterEngine {
    handle: Arc<WinDivert>,
    strategy: Strategy,
    pub stats: Arc<Stats>,
}

impl FilterEngine {
    /// Open the system-wide handle and get ready to run. Priority 1000 puts Mole
    /// ahead of a lower-priority tool, though two handshake rewriters still
    /// conflict and Mole warns about that elsewhere.
    pub fn start(
        api: Arc<WinDivertApi>,
        strategy: Strategy,
    ) -> Result<FilterEngine, WinDivertError> {
        let handle = WinDivert::open(api, "outbound and tcp.DstPort == 443", Mode::Divert, 1000)?;
        Ok(FilterEngine {
            handle: Arc::new(handle),
            strategy,
            stats: Arc::new(Stats::default()),
        })
    }

    /// A handle to stop the engine from another thread (Ctrl+C, a service stop).
    pub fn stopper(&self) -> Arc<WinDivert> {
        self.handle.clone()
    }

    pub fn stats(&self) -> Arc<Stats> {
        self.stats.clone()
    }

    /// Run until stopped. Blocks the calling thread. `stop` lets the loop notice a
    /// shutdown even between packets; calling `shutdown` on the stopper handle
    /// also unblocks `recv`.
    pub fn run(&self, stop: &AtomicBool) {
        loop {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            match self.handle.recv() {
                Ok(Some(mut pkt)) => {
                    if let Some(view) = TcpView::parse(&pkt.data) {
                        if is_client_hello(view.payload(&pkt.data)) {
                            let mut sent_any = false;
                            for emit in self.strategy.apply(&pkt, &view).iter_mut() {
                                if self.handle.emit(emit).is_ok() {
                                    sent_any = true;
                                } else {
                                    // Nothing went out yet: send the original so
                                    // the handshake is never simply dropped. If a
                                    // later emit failed mid-way, we can't cleanly
                                    // recover, so just stop.
                                    if !sent_any {
                                        let _ = self.handle.send(&mut pkt);
                                    }
                                    break;
                                }
                            }
                            self.stats.handshakes_shaped.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                    }
                    let _ = self.handle.send(&mut pkt);
                    self.stats.packets_passed.fetch_add(1, Ordering::Relaxed);
                }
                Ok(None) => break, // shut down
                Err(_) => break,   // fail-open: stop diverting, let traffic flow
            }
        }
    }
}
