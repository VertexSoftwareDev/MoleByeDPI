//! The measurement engine — the heart of Mole.
//!
//! It answers one question for *this* line: which desync strategy gets a TLS
//! handshake to a blocked target through the filter? It resolves the target over
//! DoH (so a hijacked DNS can't mislead it), then attempts the handshake once with
//! no help (the control) and once per strategy, watching for the server's reply.
//!
//! The reply itself is the measurement: a real ClientHello goes out, the strategy
//! reshapes it on the wire via the same `mole-core` code the live engine uses, and
//! if any TLS record comes back the server name got through. The engine also tells
//! *failures* apart — a TCP that never opens is an IP-level block a local tool
//! can't fix; a TCP that opens but goes silent after the ClientHello is the DPI —
//! which is exactly the "say why" the plan promises.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use mole_core::service::conflicting_dpi_service;
use mole_core::{is_client_hello, Mode, Strategy, TcpView, WinDivert, WinDivertApi};
pub use mole_dns::Resolver;
use rustls::pki_types::ServerName;
use serde::Serialize;

/// What happened when we tried to reach the target.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reach {
    /// A TLS record came back — the server name got through.
    TlsReply,
    /// TCP opened but the server never replied to the ClientHello (dropped).
    Silent,
    /// The connection was reset (RST) right after the ClientHello (injected).
    Reset,
    /// TCP could not be opened at all — IP-level block or the host is down.
    TcpFailed,
    /// The handshake started but broke before completing — the strategy got the
    /// server name through but corrupted the stream (e.g. a bad-checksum decoy
    /// that checksum offload repaired on the way out). Not a usable bypass here.
    Broke,
}

/// One strategy's outcome, ready to print or serialize into a report file.
#[derive(Serialize, Clone)]
pub struct StrategyResult {
    pub strategy: String,
    pub passed: bool,
    pub detail: String,
    pub elapsed_ms: u128,
}

/// The overall reading, in plain terms.
#[derive(Serialize, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The target opened without any help — not blocked on this line.
    NotBlocked,
    /// A strategy got through; `winner` names it.
    BypassFound,
    /// TCP never opened — an IP-level block a local tool cannot pass.
    IpBlocked,
    /// The DPI blocks it and none of the strategies got through.
    NoBypass,
    /// The target's address could not be resolved.
    DnsFailed,
}

/// The full result of a probe run — the report file's shape too.
#[derive(Serialize, Clone)]
pub struct ProbeReport {
    pub target: String,
    pub resolver: String,
    pub resolved_ip: Option<String>,
    pub verdict: Verdict,
    pub winner: Option<String>,
    /// A conflicting DPI-bypass service that was running and skews the numbers.
    pub conflict: Option<String>,
    pub control_detail: String,
    pub results: Vec<StrategyResult>,
}

/// A shareable, privacy-preserving record of what worked on one line. Built for
/// the community map from the plan: pool these across operators and cities and a
/// picture of "what works where" emerges that no one has today. It carries only
/// technical facts — the strategies tried and the results, the blocked targets'
/// own public addresses, and an operator name *only if the user typed one*. It
/// never contains the user's public IP, any browsed site beyond the probe
/// targets, or anything identifying.
#[derive(Serialize, Clone)]
pub struct CommunityReport {
    pub schema: u32,
    pub generated_unix: u64,
    /// Operator/ISP name — present only if the user supplied it.
    pub operator: Option<String>,
    /// A rival DPI tool that was running and may have skewed results.
    pub conflict: Option<String>,
    /// A privacy statement describing exactly what is and isn't included.
    pub privacy: String,
    pub targets: Vec<ProbeReport>,
}

/// Run the full battery across `hosts` and assemble a community report.
pub fn community_report(
    hosts: &[String],
    api: Arc<WinDivertApi>,
    operator: Option<String>,
) -> CommunityReport {
    let opts = ProbeOptions {
        stop_on_first: false, // measure every strategy for the map
        ..ProbeOptions::default()
    };
    let targets: Vec<ProbeReport> = hosts.iter().map(|h| run(h, api.clone(), &opts)).collect();
    let conflict = mole_core::service::conflicting_dpi_service().map(|s| s.to_string());
    CommunityReport {
        schema: 1,
        generated_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        operator,
        conflict,
        privacy: "Contains only: strategies tried and their results, the blocked \
                  targets' own addresses, and an operator name if you supplied one. \
                  Contains no personal data — not your public IP, not any site you \
                  visited, nothing identifying."
            .to_string(),
        targets,
    }
}

/// Options for a run.
pub struct ProbeOptions {
    pub resolver: Resolver,
    pub strategies: Vec<Strategy>,
    pub timeout: Duration,
    /// Stop at the first strategy that gets through (fast). When false, every
    /// strategy is measured — richer for the community map, a little slower.
    pub stop_on_first: bool,
}

impl Default for ProbeOptions {
    fn default() -> Self {
        ProbeOptions {
            resolver: Resolver::cloudflare(),
            strategies: Strategy::probe_battery(),
            timeout: Duration::from_secs(4),
            stop_on_first: true,
        }
    }
}

/// Probe `host` and return a report. Never panics on network failure — every
/// failure becomes a verdict with a reason.
pub fn run(host: &str, api: Arc<WinDivertApi>, opts: &ProbeOptions) -> ProbeReport {
    let conflict = conflicting_dpi_service().map(|s| s.to_string());

    // 1. Resolve the true address over DoH.
    let ip = match opts.resolver.resolve_a(host) {
        Ok(ips) if !ips.is_empty() => ips[0],
        Ok(_) => {
            return dns_failed(host, opts, conflict, "the resolver returned no A records");
        }
        Err(e) => {
            return dns_failed(host, opts, conflict, &e.to_string());
        }
    };

    // 2. Control: reach the target with no help at all.
    let (control, control_detail) = attempt(&api, ip, host, &Strategy::Passthrough, opts.timeout);

    let mut report = ProbeReport {
        target: host.to_string(),
        resolver: opts.resolver.name.clone(),
        resolved_ip: Some(ip.to_string()),
        verdict: Verdict::NoBypass,
        winner: None,
        conflict,
        control_detail: control_detail.clone(),
        results: Vec::new(),
    };

    match control {
        Reach::TlsReply => {
            report.verdict = Verdict::NotBlocked;
            return report;
        }
        Reach::TcpFailed => {
            report.verdict = Verdict::IpBlocked;
            return report;
        }
        // Silent / Reset / NotTls: a DPI block worth trying strategies against.
        _ => {}
    }

    // 3. Try each strategy.
    for strat in &opts.strategies {
        let start = Instant::now();
        let (reach, detail) = attempt(&api, ip, host, strat, opts.timeout);
        let passed = reach == Reach::TlsReply;
        report.results.push(StrategyResult {
            strategy: strat.label(),
            passed,
            detail,
            elapsed_ms: start.elapsed().as_millis(),
        });
        if passed {
            // Keep the first (cheapest, listed-earliest) winner even when we go on
            // to measure the rest for the map — a TTL-independent fake beats a
            // guessed TTL that only happens to match this hop today.
            if report.winner.is_none() {
                report.winner = Some(strat.label());
            }
            report.verdict = Verdict::BypassFound;
            if opts.stop_on_first {
                break;
            }
        }
    }

    report
}

/// Whether a host is reachable *right now*, over the line as it currently stands.
/// Needs no driver and no elevation — it resolves over DoH and tries a full TLS
/// handshake. The GUI uses it to show, live, whether a site is blocked before
/// protection and open after.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reachable {
    /// The handshake completed — the site is open on this line.
    Yes,
    /// TCP opened but the handshake was reset or dropped — a DPI block.
    Blocked(String),
    /// TCP could not be opened — an IP-level block a local tool cannot pass.
    IpBlocked,
    /// The name could not be resolved.
    DnsFailed(String),
}

/// Resolve `host` over `resolver` and check whether a TLS handshake completes.
pub fn check_reachable(host: &str, resolver: &Resolver) -> Reachable {
    let ip = match resolver.resolve_a(host) {
        Ok(ips) if !ips.is_empty() => ips[0],
        Ok(_) => return Reachable::DnsFailed("no A records".into()),
        Err(e) => return Reachable::DnsFailed(e.to_string()),
    };
    match tls_probe(ip, host, Duration::from_secs(5)) {
        Reach::TlsReply => Reachable::Yes,
        Reach::TcpFailed => Reachable::IpBlocked,
        Reach::Reset => Reachable::Blocked("connection reset (DPI)".into()),
        Reach::Silent => Reachable::Blocked("no reply (dropped)".into()),
        Reach::Broke => Reachable::Blocked("handshake broke".into()),
    }
}

fn dns_failed(
    host: &str,
    opts: &ProbeOptions,
    conflict: Option<String>,
    detail: &str,
) -> ProbeReport {
    ProbeReport {
        target: host.to_string(),
        resolver: opts.resolver.name.clone(),
        resolved_ip: None,
        verdict: Verdict::DnsFailed,
        winner: None,
        conflict,
        control_detail: format!("DNS resolution failed: {detail}"),
        results: Vec::new(),
    }
}

/// Attempt one handshake under `strategy`, returning how far it got and why.
fn attempt(
    api: &Arc<WinDivertApi>,
    ip: Ipv4Addr,
    host: &str,
    strategy: &Strategy,
    timeout: Duration,
) -> (Reach, String) {
    // Passthrough needs no filter — measure the raw line.
    let filter_handle = if *strategy == Strategy::Passthrough {
        None
    } else {
        let filter = format!("outbound and tcp.DstPort == 443 and ip.DstAddr == {ip}");
        match WinDivert::open(api.clone(), &filter, Mode::Divert, 1000) {
            Ok(h) => Some(Arc::new(h)),
            Err(e) => return (Reach::TcpFailed, format!("could not open filter: {e}")),
        }
    };

    // Run the strategy on this connection's ClientHello in a worker.
    let worker = filter_handle.as_ref().map(|h| {
        let h = h.clone();
        let s = strategy.clone();
        std::thread::spawn(move || run_filter(h, s))
    });

    // Give the filter a moment to be blocked in recv before we send.
    if filter_handle.is_some() {
        std::thread::sleep(Duration::from_millis(60));
    }

    let outcome = tls_probe(ip, host, timeout);

    // Tear the filter down: shutdown unblocks recv, the worker returns.
    if let Some(h) = &filter_handle {
        h.shutdown();
    }
    if let Some(w) = worker {
        let _ = w.join();
    }

    match outcome {
        Reach::TlsReply => (outcome, "server replied — the handshake got through".into()),
        Reach::Silent => (
            outcome,
            "TCP opened but the server never replied after the ClientHello (dropped by the filter)"
                .into(),
        ),
        Reach::Reset => (
            outcome,
            "the connection was reset right after the ClientHello (filter injected a RST)".into(),
        ),
        Reach::TcpFailed => (
            outcome,
            "could not open TCP to the address — an IP-level block or the host is down".into(),
        ),
        Reach::Broke => (
            outcome,
            "the SNI got through but the handshake broke — the strategy corrupts the \
             stream on this system (e.g. checksum offload repairs a bad-checksum decoy)"
                .into(),
        ),
    }
}

/// The filter loop for one probe connection: reshape the first ClientHello with
/// `strategy`, pass everything else straight through. Reinjection keeps traffic
/// flowing; on shutdown `recv` returns `None` and the loop ends.
fn run_filter(handle: Arc<WinDivert>, strategy: Strategy) {
    let debug = std::env::var("MOLE_DEBUG").is_ok();
    let mut done = false;
    let mut seen = 0u32;
    loop {
        match handle.recv() {
            Ok(Some(mut pkt)) => {
                seen += 1;
                if !done {
                    if let Some(view) = TcpView::parse(&pkt.data) {
                        let payload = view.payload(&pkt.data);
                        if is_client_hello(payload) {
                            done = true;
                            let emits = strategy.apply(&pkt, &view);
                            if debug {
                                eprintln!(
                                    "[filter] ClientHello caught (pkt #{seen}, {} payload bytes) → {} emit(s)",
                                    payload.len(),
                                    emits.len()
                                );
                            }
                            for (i, emit) in emits.into_iter().enumerate() {
                                let mut emit = emit;
                                match handle.emit(&mut emit) {
                                    Ok(()) if debug => eprintln!(
                                        "[filter]   emit {i}: sent {} bytes (fix_checksums={})",
                                        emit.packet.data.len(),
                                        emit.fix_checksums
                                    ),
                                    Err(e) => eprintln!("[filter]   emit {i}: FAILED: {e}"),
                                    _ => {}
                                }
                            }
                            continue;
                        }
                    }
                }
                if let Err(e) = handle.send(&mut pkt) {
                    if debug {
                        eprintln!("[filter] passthrough send failed: {e}");
                    }
                }
            }
            Ok(None) => break,
            Err(_) => break,
        }
    }
    if debug {
        eprintln!("[filter] loop ended, saw {seen} packet(s), transformed={done}");
    }
}

/// Drive a *full* TLS handshake for `host` to `ip:443` and classify how it went.
///
/// Completing the handshake — not just getting one reply — is the real test: a
/// strategy can get a ServerHello back yet still corrupt the stream so the
/// handshake breaks (a bad-checksum decoy that a NIC's checksum offload "fixes"
/// on the way out does exactly this). Only a completed handshake is a usable
/// bypass, so that is what we require. The cert is accepted without checking,
/// because we connect by IP and only care that the bytes flowed end to end.
fn tls_probe(ip: Ipv4Addr, host: &str, timeout: Duration) -> Reach {
    let config = match dangerous_config() {
        Some(c) => c,
        None => return Reach::TcpFailed,
    };
    let name = match ServerName::try_from(host.to_string()) {
        Ok(n) => n,
        Err(_) => return Reach::TcpFailed,
    };
    let mut conn = match rustls::ClientConnection::new(Arc::new(config), name) {
        Ok(c) => c,
        Err(_) => return Reach::TcpFailed,
    };
    let addr = SocketAddr::new(IpAddr::V4(ip), 443);
    let mut sock = match TcpStream::connect_timeout(&addr, timeout) {
        Ok(s) => s,
        Err(_) => return Reach::TcpFailed,
    };
    sock.set_nodelay(true).ok(); // one segment, so the filter sees the whole hello
    sock.set_read_timeout(Some(timeout)).ok();
    sock.set_write_timeout(Some(timeout)).ok();

    loop {
        // Flush anything the handshake wants to send.
        while conn.wants_write() {
            if conn.write_tls(&mut sock).is_err() {
                return Reach::Reset;
            }
        }
        // Done? A completed handshake is the only real pass.
        if !conn.is_handshaking() {
            return Reach::TlsReply;
        }
        // Read the next flight.
        match conn.read_tls(&mut sock) {
            Ok(0) => return Reach::Reset, // peer closed mid-handshake
            Ok(_) => {}
            Err(e) => {
                return match e.kind() {
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => Reach::Silent,
                    std::io::ErrorKind::ConnectionReset => Reach::Reset,
                    _ => Reach::Silent,
                };
            }
        }
        // Process it. An error here means bytes flowed but the handshake broke —
        // the strategy corrupted the stream on this system.
        if conn.process_new_packets().is_err() {
            return Reach::Broke;
        }
    }
}

/// A rustls client config that accepts any certificate. We reach servers by IP
/// with the real SNI and only measure whether the handshake completes, so cert
/// identity is irrelevant here — never use this config for real traffic.
fn dangerous_config() -> Option<rustls::ClientConfig> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(danger::AcceptAny))
        .with_no_client_auth();
    Some(config)
}

/// A certificate verifier that accepts everything — only for the probe, whose job
/// is to measure reachability, not to trust a peer.
mod danger {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, Error, SignatureScheme};

    #[derive(Debug)]
    pub struct AcceptAny;

    impl ServerCertVerifier for AcceptAny {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::ED25519,
            ]
        }
    }
}
