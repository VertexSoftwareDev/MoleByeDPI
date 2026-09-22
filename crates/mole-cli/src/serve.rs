//! The service body: run the chosen strategy, watch that it still works, and
//! re-measure when it stops — the plan's "if the operator changes, it finds the
//! new working setting" without the user touching a thing.
//!
//! It lives here, in the CLI, because re-measuring needs `mole-probe`, which
//! depends on `mole-core` (where the SCM plumbing is) — so the service body can't
//! live down there. `mole-core::winservice` calls this over a function pointer.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use mole_core::{
    servicelog, winservice, Config, FilterEngine, QuicBlocker, Strategy, WinDivertApi,
};
use mole_probe::{check_reachable, ProbeOptions, Reachable};

/// Fallback canary if the config doesn't name the site the winner was found on.
const DEFAULT_CANARY: &str = "www.roblox.com";

/// The site the health monitor watches: the one the winning strategy was found
/// blocked-then-open on at install, so self-healing works on any line — not just
/// where the default happens to be blocked.
fn canary_for(cfg: &Config) -> String {
    if cfg.canary.trim().is_empty() {
        DEFAULT_CANARY.to_string()
    } else {
        cfg.canary.clone()
    }
}

fn health_interval() -> Duration {
    let secs = std::env::var("MOLE_HEALTH_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(180);
    Duration::from_secs(secs.max(3))
}

fn fail_threshold() -> u32 {
    std::env::var("MOLE_HEALTH_FAILS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3)
        .max(1)
}

enum Outcome {
    Stopped,
    Remeasured,
    Failed,
}

/// Entry point handed to the SCM dispatcher.
pub fn serve() {
    let mut attempts = 0u32;
    while !winservice::should_stop() {
        match run_once() {
            Outcome::Stopped => break,
            Outcome::Remeasured => attempts = 0,
            Outcome::Failed => {
                attempts += 1;
                if attempts >= 5 {
                    // Give up in-process; the SCM's failure actions restart us.
                    std::process::exit(1);
                }
                std::thread::sleep(Duration::from_millis(500 * attempts as u64));
            }
        }
    }
}

fn run_once() -> Outcome {
    let Some(cfg) = Config::load() else {
        return wait_for_stop();
    };
    let Some(strategy) = Strategy::from_label(&cfg.strategy) else {
        return wait_for_stop();
    };
    let api = match WinDivertApi::load() {
        Ok(a) => Arc::new(a),
        Err(e) => {
            servicelog::log(&format!("could not load WinDivert: {e}"));
            return Outcome::Failed;
        }
    };
    let engine = match FilterEngine::start(api.clone(), strategy) {
        Ok(e) => Arc::new(e),
        Err(e) => {
            // Usually an antivirus network shield blocking the driver.
            servicelog::log(&format!(
                "could not start the filter engine: {e} — an antivirus shield may be blocking WinDivert (you are unprotected)"
            ));
            return Outcome::Failed;
        }
    };
    servicelog::log(&format!(
        "protecting with '{}' (watching {})",
        cfg.strategy,
        canary_for(&cfg)
    ));
    let quic = if cfg.block_quic {
        QuicBlocker::start(api.clone()).ok()
    } else {
        None
    };

    let stopper = engine.stopper();
    winservice::register_stopper(Some(stopper.clone()));

    // Health monitor: watch this line's own blocked site; on repeated failure,
    // break the engine loop and ask for a re-measure.
    let canary = canary_for(&cfg);
    let remeasure = Arc::new(AtomicBool::new(false));
    let health_active = Arc::new(AtomicBool::new(true));
    let health = {
        let stopper = stopper.clone();
        let remeasure = remeasure.clone();
        let active = health_active.clone();
        let canary = canary.clone();
        std::thread::spawn(move || health_loop(canary, stopper, remeasure, active))
    };

    // Run until the handle is shut down (by the SCM stop, or by the health monitor).
    let local_stop = AtomicBool::new(false);
    engine.run(&local_stop);

    // Wind the health thread down and release the engine so the driver handle
    // closes before any re-measure runs on a clean line.
    health_active.store(false, Ordering::SeqCst);
    let _ = health.join();
    winservice::register_stopper(None);
    let want_remeasure = remeasure.load(Ordering::SeqCst);
    drop(stopper);
    drop(quic);
    drop(engine);

    if winservice::should_stop() {
        Outcome::Stopped
    } else if want_remeasure {
        remeasure_and_save(&api, &cfg, &canary);
        Outcome::Remeasured
    } else {
        Outcome::Failed
    }
}

/// Periodically check the canary through the running engine. Count consecutive
/// blocks (a strategy that stopped working); a success resets the count. On the
/// threshold, flag a re-measure and unblock the engine loop.
fn health_loop(
    canary: String,
    stopper: Arc<mole_core::WinDivert>,
    remeasure: Arc<AtomicBool>,
    active: Arc<AtomicBool>,
) {
    let interval = health_interval();
    let threshold = fail_threshold();
    let mut fails = 0u32;
    loop {
        // Sleep the interval in small steps so a stop is noticed quickly.
        let steps = (interval.as_millis() / 250).max(1);
        for _ in 0..steps {
            if !active.load(Ordering::SeqCst) || winservice::should_stop() {
                return;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        if !active.load(Ordering::SeqCst) || winservice::should_stop() {
            return;
        }
        match check_reachable(&canary) {
            Reachable::Yes => fails = 0,
            Reachable::Blocked(_) => {
                fails += 1;
                if fails >= threshold {
                    remeasure.store(true, Ordering::SeqCst);
                    stopper.shutdown(); // break the engine loop
                    return;
                }
            }
            // DNS or IP-level issues aren't a strategy failure; don't count them.
            Reachable::DnsFailed(_) | Reachable::IpBlocked => {}
        }
    }
}

/// Re-measure on the (now clean) line and save a new strategy if one is found,
/// keeping the same canary so the monitor keeps watching this line's blocked site.
fn remeasure_and_save(api: &Arc<WinDivertApi>, cfg: &Config, canary: &str) {
    servicelog::log(&format!(
        "'{}' stopped working on {canary}; re-measuring",
        cfg.strategy
    ));
    let opts = ProbeOptions::default();
    let report = mole_probe::run(canary, api.clone(), &opts);
    match report.winner {
        Some(winner) if winner != cfg.strategy => {
            let _ = Config::new(&winner, &cfg.resolver)
                .quic(cfg.block_quic)
                .canary(canary)
                .save();
            servicelog::log(&format!("switched to '{winner}'"));
        }
        Some(_) => servicelog::log("re-measured; the same strategy still wins"),
        None => {
            servicelog::log("re-measured; no strategy got through (line may need a new technique)")
        }
    }
}

fn wait_for_stop() -> Outcome {
    while !winservice::should_stop() {
        std::thread::sleep(Duration::from_millis(500));
    }
    Outcome::Stopped
}
