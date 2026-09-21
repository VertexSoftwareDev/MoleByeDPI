//! `mole-core` — the packet layer.
//!
//! It wraps WinDivert (load the DLL, open a filtered session, receive/inject
//! packets), parses just enough of IPv4/TCP/TLS to find a ClientHello's SNI, and
//! checks that Mole is running elevated. The measurement engine, the DoH client
//! and the live filter engine all build on top of this crate.
//!
//! Everything here upholds one rule from the plan: **fail-open**. A sniffing
//! session cannot drop a packet, and every diverting session shuts down cleanly
//! on drop, so if Mole stops, traffic flows.

pub mod admin;
pub mod checksum;
pub mod config;
pub mod engine;
pub mod ffi;
pub mod packet;
pub mod service;
pub mod strategy;
pub mod windivert;
pub mod winservice;

pub use config::Config;
pub use engine::{FilterEngine, QuicBlocker};
pub use ffi::{LoadError, WinDivertAddress, WinDivertApi};
pub use packet::{find_sni, is_client_hello, TcpView};
pub use strategy::{Cut, Decoy, Emit, Strategy};
pub use windivert::{Mode, Packet, WinDivert, WinDivertError};
