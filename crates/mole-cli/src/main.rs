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
use mole_core::{Mode, TcpView, WinDivert, WinDivertApi};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("help");
    let rest = &args[args.len().min(1)..];

    let code = match cmd {
        "doctor" => cmd_doctor(),
        "capture" => cmd_capture(rest),
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
         \n\
         Phase 0. Measurement (probe) and the live filter engine come next."
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
