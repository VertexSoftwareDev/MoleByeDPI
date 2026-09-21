//! `mole` command line.
//!
//! Phase 0 ships two commands:
//!   * `doctor`  — is the ground ready? admin rights, the WinDivert DLL/driver,
//!                 and a live capture that proves packets can be intercepted.
//!   * `capture` — sniff TLS ClientHello packets and print who they are going to,
//!                 including the SNI, without touching the traffic (SNIFF mode).
//!
//! Later phases add `probe`, `apply` and `service`. The arg handling is hand
//! rolled to keep the binary lean and dependency-free.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use mole_core::admin::is_elevated;
use mole_core::packet::find_sni;
use mole_core::service::conflicting_dpi_service;
use mole_core::{Config, FilterEngine, Mode, QuicBlocker, Strategy, TcpView, WinDivert, WinDivertApi};
use mole_dns::Resolver;
use mole_probe::{ProbeOptions, ProbeReport, Verdict};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("help");
    let rest = &args[args.len().min(1)..];

    let code = match cmd {
        "doctor" => cmd_doctor(),
        "capture" => cmd_capture(rest),
        "dns" => cmd_dns(rest),
        "probe" => cmd_probe(rest),
        "apply" => cmd_apply(rest),
        "install" => cmd_install(rest),
        "uninstall" => cmd_uninstall(),
        "status" => cmd_status(),
        "report" => cmd_report(rest),
        "service-run" => cmd_service_run(),
        "help" | "--help" | "-h" => {
            print_help();
            0
        }
        other => {
            eprintln!("mole: unknown command '{other}'\n");
            print_help();
            2
        }
    };
    std::process::exit(code);
}

fn print_help() {
    println!(
        "mole — find and hold the bypass that works on your line\n\
         \n\
         USAGE:\n\
         \x20 mole doctor              check admin, driver and packet capture\n\
         \x20 mole capture [--port P] [--count N] [--seconds S]\n\
         \x20                          sniff TLS ClientHellos and show their SNI\n\
         \x20 mole dns <host> [--google]\n\
         \x20                          resolve a name over DoH (bypasses DNS hijacking)\n\
         \x20 mole probe [host ...] [--google] [--all] [--json FILE]\n\
         \x20                          measure which bypass strategy works on this line\n\
         \x20 mole apply [<strategy> | --auto [host ...]] [--block-quic]\n\
         \x20                          apply a strategy system-wide until stopped\n\
         \x20 mole install [<strategy> | --auto [host ...]] [--block-quic]\n\
         \x20                          install and start the self-healing service\n\
         \x20 mole uninstall           stop and remove the service, clean up\n\
         \x20 mole status              show the service state and saved strategy\n\
         \x20 mole report [--operator NAME] [--out FILE] [host ...]\n\
         \x20                          measure everything and write a shareable,\n\
         \x20                          privacy-preserving report for the community map\n\
         \n\
         `probe` with no host uses a small set of commonly-blocked targets.\n\
         --all measures every strategy (for the community map); default stops at\n\
         the first that works. --json writes a machine-readable report.\n\
         `apply --auto` probes first, then applies and saves the winner. `apply`\n\
         with no argument reuses the saved strategy. Ctrl+C stops and restores\n\
         normal traffic (fail-open)."
    );
}

/// A pass/fail line in the doctor report.
fn check(ok: bool, label: &str, detail: &str) -> bool {
    let mark = if ok { "[ok]  " } else { "[fail]" };
    if detail.is_empty() {
        println!("{mark} {label}");
    } else {
        println!("{mark} {label} — {detail}");
    }
    ok
}

fn cmd_doctor() -> i32 {
    println!("Mole doctor — is this line ready for Mole?\n");
    let mut all_ok = true;

    // 1. Elevation.
    let elevated = is_elevated();
    all_ok &= check(
        elevated,
        "administrator",
        if elevated {
            "running elevated"
        } else {
            "NOT elevated — WinDivert's driver needs administrator rights"
        },
    );

    // 2. WinDivert DLL + driver load.
    let api = match WinDivertApi::load() {
        Ok(api) => {
            check(true, "WinDivert.dll", "loaded");
            Some(Arc::new(api))
        }
        Err(e) => {
            all_ok &= check(false, "WinDivert.dll", &e.to_string());
            None
        }
    };

    // 3. Open a real (sniffing) session — this installs and starts the driver.
    if let Some(api) = api {
        match WinDivert::open(api, "tcp.DstPort == 443", Mode::Sniff, 0) {
            Ok(handle) => {
                check(true, "driver", "installed and capturing");
                // 4. Prove capture: wait briefly for one packet.
                let handle = Arc::new(handle);
                let got = wait_one(handle, Duration::from_secs(8));
                match got {
                    Some(desc) => check(true, "packet capture", &desc),
                    None => check(
                        true,
                        "packet capture",
                        "no HTTPS packet in 8s (line idle?) — driver is fine",
                    ),
                };
            }
            Err(e) => {
                all_ok &= check(false, "driver", &e.to_string());
            }
        }
    }

    // AV / rival-tool notes: name likely sources of friction rather than fail.
    if let Some(av) = mole_core::service::interfering_antivirus() {
        check(
            true,
            "antivirus",
            &format!("{av} is running — its network shield can intercept TLS or block the driver; if Mole misbehaves, exclude it or pause the shield"),
        );
    }
    if let Some(svc) = conflicting_dpi_service() {
        check(
            true,
            "rival tool",
            &format!("the '{svc}' service is running — it and Mole rewrite the same handshakes; keep only one"),
        );
    }

    println!();
    if all_ok {
        println!("Ready. The packet layer works on this line.");
        0
    } else {
        println!("Not ready — fix the [fail] lines above.");
        1
    }
}

/// Wait up to `budget` for one captured packet and describe it. `recv` blocks, so
/// a timer thread shuts the handle down when the budget runs out — on an idle
/// line `recv` then returns `None` and we report cleanly instead of hanging.
fn wait_one(handle: Arc<WinDivert>, budget: Duration) -> Option<String> {
    {
        let handle = handle.clone();
        std::thread::spawn(move || {
            std::thread::sleep(budget);
            handle.shutdown();
        });
    }
    loop {
        match handle.recv() {
            Ok(Some(pkt)) => {
                let Some(view) = TcpView::parse(&pkt.data) else {
                    return Some("captured a non-IPv4 packet".to_string());
                };
                // Prefer a packet we can describe by SNI; keep waiting past bare
                // ACKs until the budget's shutdown ends the loop.
                if let Some((host, _)) = find_sni(view.payload(&pkt.data)) {
                    let d = view.dst;
                    return Some(format!(
                        "{}.{}.{}.{}:{}  SNI {host}",
                        d[0], d[1], d[2], d[3], view.dst_port
                    ));
                }
                let d = view.dst;
                return Some(format!("{}.{}.{}.{}:{}", d[0], d[1], d[2], d[3], view.dst_port));
            }
            Ok(None) => return None, // budget elapsed, handle shut down
            Err(_) => return None,
        }
    }
}

struct CaptureOpts {
    port: u16,
    count: usize,
    seconds: u64,
}

fn cmd_capture(args: &[String]) -> i32 {
    let mut opts = CaptureOpts {
        port: 443,
        count: 10,
        seconds: 60,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--port" => {
                i += 1;
                opts.port = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(opts.port);
            }
            "--count" => {
                i += 1;
                opts.count = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(opts.count);
            }
            "--seconds" => {
                i += 1;
                opts.seconds = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(opts.seconds);
            }
            other => {
                eprintln!("mole capture: unknown option '{other}'");
                return 2;
            }
        }
        i += 1;
    }

    if !is_elevated() {
        eprintln!("mole capture: needs administrator rights (WinDivert driver).");
        return 1;
    }

    let api = match WinDivertApi::load() {
        Ok(api) => Arc::new(api),
        Err(e) => {
            eprintln!("mole capture: {e}");
            return 1;
        }
    };

    let filter = format!("outbound and tcp.DstPort == {}", opts.port);
    let handle = match WinDivert::open(api, &filter, Mode::Sniff, 0) {
        Ok(h) => Arc::new(h),
        Err(e) => {
            eprintln!("mole capture: {e}");
            return 1;
        }
    };

    println!(
        "Sniffing outbound TCP :{} (copy only, traffic untouched). Ctrl+C to stop.\n",
        opts.port
    );

    // Ctrl+C shuts the handle down so recv unblocks and we exit cleanly.
    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = stop.clone();
        let handle = handle.clone();
        let _ = ctrlc(move || {
            stop.store(true, Ordering::SeqCst);
            handle.shutdown();
        });
    }

    // A timer thread enforces --seconds the same way: shut the handle down.
    {
        let handle = handle.clone();
        let secs = opts.seconds;
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(secs));
            handle.shutdown();
        });
    }

    let mut seen = 0usize;
    while seen < opts.count {
        match handle.recv() {
            Ok(Some(pkt)) => {
                let Some(view) = TcpView::parse(&pkt.data) else {
                    continue;
                };
                let payload = view.payload(&pkt.data);
                let sni = find_sni(payload);
                // Only report handshake-bearing packets; skip pure ACKs so the
                // output shows destinations, not noise.
                if sni.is_none() && payload.len() < 8 {
                    continue;
                }
                seen += 1;
                let d = view.dst;
                match sni {
                    Some((host, off)) => println!(
                        "{seen:>3}. {}.{}.{}.{}:{}  SNI {host}  (name at payload offset {off})",
                        d[0], d[1], d[2], d[3], view.dst_port
                    ),
                    None => println!(
                        "{seen:>3}. {}.{}.{}.{}:{}  ({} payload bytes, no SNI)",
                        d[0], d[1], d[2], d[3], view.dst_port, payload.len()
                    ),
                }
            }
            Ok(None) => break, // shut down
            Err(e) => {
                eprintln!("mole capture: {e}");
                return 1;
            }
        }
    }

    println!("\nCaptured {seen} handshake packet(s). Traffic was never touched.");
    0
}

fn cmd_dns(args: &[String]) -> i32 {
    let mut host = None;
    let mut resolver = Resolver::cloudflare();
    for a in args {
        match a.as_str() {
            "--google" => resolver = Resolver::google(),
            "--cloudflare" => resolver = Resolver::cloudflare(),
            other if !other.starts_with("--") => host = Some(other.to_string()),
            other => {
                eprintln!("mole dns: unknown option '{other}'");
                return 2;
            }
        }
    }
    let Some(host) = host else {
        eprintln!("mole dns: give a host name, e.g. `mole dns example.com`");
        return 2;
    };
    println!("Resolving {host} over DoH via {}...", resolver.name);
    match resolver.resolve_a(&host) {
        Ok(ips) if ips.is_empty() => {
            println!("No A records returned.");
            1
        }
        Ok(ips) => {
            for ip in ips {
                println!("  {ip}");
            }
            0
        }
        Err(e) => {
            eprintln!("Failed: {e}");
            1
        }
    }
}

/// A few targets commonly blocked in Turkey, used when the user names none.
const DEFAULT_TARGETS: &[&str] = &["www.roblox.com", "discord.com", "www.wikipedia.org"];

fn cmd_probe(args: &[String]) -> i32 {
    let mut hosts: Vec<String> = Vec::new();
    let mut opts = ProbeOptions::default();
    let mut json_path: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--google" => opts.resolver = Resolver::google(),
            "--cloudflare" => opts.resolver = Resolver::cloudflare(),
            "--all" => opts.stop_on_first = false,
            "--json" => {
                i += 1;
                json_path = args.get(i).cloned();
                if json_path.is_none() {
                    eprintln!("mole probe: --json needs a file path");
                    return 2;
                }
            }
            other if !other.starts_with("--") => hosts.push(other.to_string()),
            other => {
                eprintln!("mole probe: unknown option '{other}'");
                return 2;
            }
        }
        i += 1;
    }
    if hosts.is_empty() {
        hosts = DEFAULT_TARGETS.iter().map(|s| s.to_string()).collect();
    }

    if !is_elevated() {
        eprintln!("mole probe: needs administrator rights (WinDivert driver).");
        return 1;
    }
    let api = match WinDivertApi::load() {
        Ok(api) => Arc::new(api),
        Err(e) => {
            eprintln!("mole probe: {e}");
            return 1;
        }
    };

    // A running rival DPI tool makes every number a lie; say so loudly up front.
    if let Some(svc) = conflicting_dpi_service() {
        println!(
            "WARNING: the '{svc}' service is running. It rewrites the same handshakes\n\
             Mole is testing, so these results are unreliable. Stop it first:\n\
             \x20   sc stop {svc}\n"
        );
    }

    let mut reports = Vec::new();
    for host in &hosts {
        println!("── Probing {host} ──");
        let report = mole_probe::run(host, api.clone(), &opts);
        print_report(&report);
        println!();
        reports.push(report);
    }

    if let Some(path) = json_path {
        match serde_json::to_string_pretty(&reports) {
            Ok(s) => {
                if let Err(e) = std::fs::write(&path, s) {
                    eprintln!("mole probe: could not write {path}: {e}");
                } else {
                    println!("Report written to {path}");
                }
            }
            Err(e) => eprintln!("mole probe: could not serialize report: {e}"),
        }
    }

    // Exit non-zero only if every target is blocked with no bypass found.
    let any_ok = reports
        .iter()
        .any(|r| matches!(r.verdict, Verdict::BypassFound | Verdict::NotBlocked));
    if any_ok {
        0
    } else {
        1
    }
}

fn cmd_apply(args: &[String]) -> i32 {
    let mut auto = false;
    let mut block_quic = false;
    let mut hosts: Vec<String> = Vec::new();
    let mut label: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--auto" => auto = true,
            "--block-quic" => block_quic = true,
            other if other.starts_with("--") => {
                eprintln!("mole apply: unknown option '{other}'");
                return 2;
            }
            other if auto => hosts.push(other.to_string()),
            other => label = Some(other.to_string()),
        }
        i += 1;
    }

    if !is_elevated() {
        eprintln!("mole apply: needs administrator rights (WinDivert driver).");
        return 1;
    }
    let api = match WinDivertApi::load() {
        Ok(api) => Arc::new(api),
        Err(e) => {
            eprintln!("mole apply: {e}");
            return 1;
        }
    };

    if let Some(svc) = conflicting_dpi_service() {
        eprintln!(
            "mole apply: the '{svc}' service is running and rewrites the same handshakes.\n\
             Stop it first (`sc stop {svc}`), or the two tools will fight."
        );
        return 1;
    }

    // Decide which strategy to apply, and remember it so a later bare `apply`
    // (or the service) reuses it.
    let (strategy, label) = match pick_strategy(&api, auto, &hosts, label, "apply") {
        Some(pair) => pair,
        None => return 1,
    };
    if let Err(e) = Config::new(&label, "Cloudflare").quic(block_quic).save() {
        eprintln!("  (could not save choice: {e})");
    }

    run_engine(api, strategy, block_quic)
}

/// Resolve the strategy for an `apply`/`install`: `--auto` probes for a winner, a
/// label is parsed, and neither reuses the saved config. Returns the strategy and
/// its label, or prints why it couldn't and returns None.
fn pick_strategy(
    api: &Arc<WinDivertApi>,
    auto: bool,
    hosts: &[String],
    label: Option<String>,
    cmd: &str,
) -> Option<(Strategy, String)> {
    if auto {
        return choose_by_probe(api, hosts, cmd);
    }
    if let Some(l) = label {
        return match Strategy::from_label(&l) {
            Some(s) => Some((s, l)),
            None => {
                eprintln!("mole {cmd}: '{l}' is not a known strategy (e.g. split:sni, fakesplit:ttl6:sni).");
                None
            }
        };
    }
    match Config::load().and_then(|c| Strategy::from_label(&c.strategy).map(|s| (s, c.strategy))) {
        Some((s, l)) => {
            println!("Using saved strategy: {l}");
            Some((s, l))
        }
        None => {
            eprintln!("mole {cmd}: no strategy given and none saved. Try `mole {cmd} --auto`.");
            None
        }
    }
}

/// Probe the targets and pick the first strategy that works anywhere.
fn choose_by_probe(api: &Arc<WinDivertApi>, hosts: &[String], cmd: &str) -> Option<(Strategy, String)> {
    let opts = ProbeOptions::default();
    let targets: Vec<String> = if hosts.is_empty() {
        DEFAULT_TARGETS.iter().map(|s| s.to_string()).collect()
    } else {
        hosts.to_vec()
    };
    println!("Measuring this line to pick a strategy...");
    for host in &targets {
        let report = mole_probe::run(host, api.clone(), &opts);
        if let Some(winner) = &report.winner {
            println!("  {host}: '{winner}' works.");
            return Strategy::from_label(winner).map(|s| (s, winner.clone()));
        }
        println!("  {host}: no strategy got through ({}).", verdict_word(&report.verdict));
    }
    eprintln!(
        "mole {cmd} --auto: none of the strategies got through on the tested targets.\n\
         This line may need a technique Mole doesn't have yet, or the block is IP-level."
    );
    None
}

fn verdict_word(v: &Verdict) -> &'static str {
    match v {
        Verdict::NotBlocked => "not blocked",
        Verdict::BypassFound => "bypass found",
        Verdict::IpBlocked => "IP-level block",
        Verdict::NoBypass => "DPI block, no bypass",
        Verdict::DnsFailed => "DNS failed",
    }
}

/// Run the live engine until Ctrl+C, then stop and restore normal traffic.
fn run_engine(api: Arc<WinDivertApi>, strategy: Strategy, block_quic: bool) -> i32 {
    let engine = match FilterEngine::start(api.clone(), strategy.clone()) {
        Ok(e) => Arc::new(e),
        Err(e) => {
            eprintln!("mole apply: {e}");
            return 1;
        }
    };

    // Optionally hold QUIC back so browsers fall onto TCP, which we shape. Kept
    // alive for the run; dropped on exit, which restores QUIC.
    let _quic = if block_quic {
        match QuicBlocker::start(api) {
            Ok(q) => {
                println!("Blocking outbound QUIC (UDP :443) — browsers will use TCP.");
                Some(q)
            }
            Err(e) => {
                eprintln!("mole apply: could not block QUIC: {e}");
                return 1;
            }
        }
    } else {
        None
    };

    println!(
        "Applying '{}' to all outbound HTTPS. Ctrl+C to stop (traffic then flows normally).\n",
        strategy.label()
    );

    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = stop.clone();
        let stopper = engine.stopper();
        let _ = ctrlc(move || {
            stop.store(true, Ordering::SeqCst);
            stopper.shutdown();
        });
    }

    // A small reporter thread prints live counters until we stop.
    let stats = engine.stats();
    {
        let stop = stop.clone();
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_secs(3));
                let shaped = stats.handshakes_shaped.load(Ordering::Relaxed);
                let passed = stats.packets_passed.load(Ordering::Relaxed);
                print!("\r  shaped {shaped} handshake(s), passed {passed} packet(s)   ");
                use std::io::Write;
                let _ = std::io::stdout().flush();
            }
        });
    }

    engine.run(&stop);
    println!("\nStopped. Traffic restored.");
    0
}

fn cmd_install(args: &[String]) -> i32 {
    let mut auto = false;
    let mut block_quic = false;
    let mut hosts: Vec<String> = Vec::new();
    let mut label: Option<String> = None;
    for a in args {
        match a.as_str() {
            "--auto" => auto = true,
            "--block-quic" => block_quic = true,
            other if other.starts_with("--") => {
                eprintln!("mole install: unknown option '{other}'");
                return 2;
            }
            other if auto => hosts.push(other.to_string()),
            other => label = Some(other.to_string()),
        }
    }
    if !is_elevated() {
        eprintln!("mole install: needs administrator rights.");
        return 1;
    }
    let api = match WinDivertApi::load() {
        Ok(api) => Arc::new(api),
        Err(e) => {
            eprintln!("mole install: {e}");
            return 1;
        }
    };
    if let Some(svc) = conflicting_dpi_service() {
        eprintln!(
            "mole install: the '{svc}' service is running and would fight Mole.\n\
             Remove or stop it first (`sc stop {svc}`)."
        );
        return 1;
    }

    let (_strategy, label) = match pick_strategy(&api, auto, &hosts, label, "install") {
        Some(pair) => pair,
        None => return 1,
    };
    let cfg = Config::new(&label, "Cloudflare").quic(block_quic);
    if let Err(e) = cfg.save() {
        eprintln!("mole install: could not save config: {e}");
        return 1;
    }
    println!("Saved strategy '{label}'{}.", if block_quic { " (QUIC blocked)" } else { "" });

    use mole_core::winservice;
    if let Err(e) = winservice::install() {
        eprintln!("mole install: {e}");
        return 1;
    }
    match winservice::start() {
        Ok(()) => {
            println!("Service installed and started. It will run at boot and heal itself if it drops.");
            0
        }
        Err(e) => {
            eprintln!("mole install: installed, but could not start now: {e}");
            1
        }
    }
}

fn cmd_uninstall() -> i32 {
    if !is_elevated() {
        eprintln!("mole uninstall: needs administrator rights.");
        return 1;
    }
    use mole_core::winservice;
    match winservice::uninstall() {
        Ok(()) => {
            // Leave nothing behind: remove the saved config too.
            let _ = std::fs::remove_file(Config::path());
            println!("Service stopped and removed. Nothing left behind; traffic flows normally.");
            0
        }
        Err(e) => {
            eprintln!("mole uninstall: {e}");
            1
        }
    }
}

fn cmd_status() -> i32 {
    use mole_core::winservice;
    match winservice::query_state() {
        Some(state) => println!("Service: {}", service_state_word(state)),
        None => println!("Service: not installed"),
    }
    match Config::load() {
        Some(c) => {
            println!("Strategy: {}", c.strategy);
            println!("Resolver: {}", c.resolver);
            println!("Block QUIC: {}", if c.block_quic { "yes" } else { "no" });
        }
        None => println!("Strategy: none saved"),
    }
    if let Some(svc) = conflicting_dpi_service() {
        println!("Note: '{svc}' is also running — it will fight Mole; keep only one.");
    }
    0
}

fn cmd_report(args: &[String]) -> i32 {
    let mut operator: Option<String> = None;
    let mut out = "mole-report.json".to_string();
    let mut hosts: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--operator" => {
                i += 1;
                operator = args.get(i).cloned();
            }
            "--out" => {
                i += 1;
                match args.get(i) {
                    Some(p) => out = p.clone(),
                    None => {
                        eprintln!("mole report: --out needs a file path");
                        return 2;
                    }
                }
            }
            other if other.starts_with("--") => {
                eprintln!("mole report: unknown option '{other}'");
                return 2;
            }
            other => hosts.push(other.to_string()),
        }
        i += 1;
    }
    if hosts.is_empty() {
        hosts = DEFAULT_TARGETS.iter().map(|s| s.to_string()).collect();
    }
    if !is_elevated() {
        eprintln!("mole report: needs administrator rights (WinDivert driver).");
        return 1;
    }
    let api = match WinDivertApi::load() {
        Ok(api) => Arc::new(api),
        Err(e) => {
            eprintln!("mole report: {e}");
            return 1;
        }
    };
    if let Some(svc) = conflicting_dpi_service() {
        println!("WARNING: '{svc}' is running and will skew results; stop it first (`sc stop {svc}`).\n");
    }

    println!("Measuring every strategy across {} target(s)...", hosts.len());
    let report = mole_probe::community_report(&hosts, api, operator);
    match serde_json::to_string_pretty(&report) {
        Ok(s) => {
            if let Err(e) = std::fs::write(&out, s) {
                eprintln!("mole report: could not write {out}: {e}");
                return 1;
            }
            let bypassed = report
                .targets
                .iter()
                .filter(|t| t.winner.is_some())
                .count();
            println!(
                "Wrote {out}. {} of {} target(s) bypassed. It contains only technical data — \n\
                 safe to share for the community map.",
                bypassed,
                report.targets.len()
            );
            0
        }
        Err(e) => {
            eprintln!("mole report: could not serialize: {e}");
            1
        }
    }
}

/// The SCM entry point (internal). Fails loudly only to the event log path; here
/// we just hand control to the dispatcher.
fn cmd_service_run() -> i32 {
    use mole_core::winservice;
    match winservice::run_dispatcher() {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn service_state_word(state: u32) -> &'static str {
    // Values from Win32 Services (SERVICE_*).
    match state {
        1 => "stopped",
        2 => "start pending",
        3 => "stop pending",
        4 => "running",
        5 => "continue pending",
        6 => "pause pending",
        7 => "paused",
        _ => "unknown",
    }
}

fn print_report(r: &ProbeReport) {
    match &r.resolved_ip {
        Some(ip) => println!("  resolved ({}) → {ip}", r.resolver),
        None => println!("  resolved ({}) → failed", r.resolver),
    }
    match r.verdict {
        Verdict::NotBlocked => {
            println!("  verdict: NOT blocked on this line — the target opened with no help.");
            println!("           ({})", r.control_detail);
        }
        Verdict::IpBlocked => {
            println!("  verdict: IP-level block — a local tool cannot pass this.");
            println!("           {}", r.control_detail);
        }
        Verdict::DnsFailed => {
            println!("  verdict: could not resolve the target.");
            println!("           {}", r.control_detail);
        }
        Verdict::BypassFound => {
            for res in &r.results {
                let mark = if res.passed { "✓" } else { "·" };
                println!("    {mark} {:<22} {} ({} ms)", res.strategy, res.detail, res.elapsed_ms);
            }
            if let Some(w) = &r.winner {
                println!("  verdict: BYPASS FOUND — use `{w}` on this line.");
            }
        }
        Verdict::NoBypass => {
            for res in &r.results {
                println!("    · {:<22} {} ({} ms)", res.strategy, res.detail, res.elapsed_ms);
            }
            println!("  verdict: DPI blocks it and none of the strategies got through.");
            println!("           control: {}", r.control_detail);
        }
    }
    if let Some(c) = &r.conflict {
        println!("  note: '{c}' service was running — results may be skewed.");
    }
}

/// Minimal Ctrl+C handler via the Win32 console control API, so we do not pull in
/// a crate for one callback.
fn ctrlc<F: Fn() + Send + Sync + 'static>(f: F) -> Result<(), ()> {
    use std::sync::OnceLock;
    static HANDLER: OnceLock<Box<dyn Fn() + Send + Sync>> = OnceLock::new();
    // We can only install one; wrap the Fn so the C callback can reach it.
    let boxed: Box<dyn Fn() + Send + Sync> = Box::new(f);
    if HANDLER.set(boxed).is_err() {
        return Err(());
    }

    unsafe extern "system" fn handler(_ctrl_type: u32) -> i32 {
        if let Some(f) = HANDLER.get() {
            f();
        }
        1 // handled
    }

    let ok = unsafe {
        windows_sys::Win32::System::Console::SetConsoleCtrlHandler(Some(handler), 1)
    };
    if ok == 0 {
        Err(())
    } else {
        Ok(())
    }
}
