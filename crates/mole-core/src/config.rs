//! Mole's on-disk choice: which strategy to apply, and which resolver to use.
//!
//! The probe writes it once it finds a winner; `apply` and the Windows service
//! read it. It lives in `%ProgramData%\Mole` so the service (LocalSystem) and a
//! user-run `apply` see the same file. Nothing here is secret — no browsing data,
//! no identity, just the technique name and a resolver.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// A `Strategy::label()`, e.g. `"fakesplit:ttl6:sni"`.
    pub strategy: String,
    /// Resolver name: `"Cloudflare"` or `"Google"`.
    pub resolver: String,
    /// Hold QUIC back so browsers fall onto TCP. Off unless the user asked.
    #[serde(default)]
    pub block_quic: bool,
    /// The blocked site the winning strategy was found on. The service watches
    /// exactly this one, so self-healing works on any line — not just where the
    /// hardcoded default happens to be blocked. Empty falls back to a default.
    #[serde(default)]
    pub canary: String,
}

impl Config {
    pub fn new(strategy: &str, resolver: &str) -> Config {
        Config {
            strategy: strategy.to_string(),
            resolver: resolver.to_string(),
            block_quic: false,
            canary: String::new(),
        }
    }

    /// Set whether the service should also block QUIC.
    pub fn quic(mut self, on: bool) -> Config {
        self.block_quic = on;
        self
    }

    /// Set the blocked site the health monitor should watch.
    pub fn canary(mut self, host: &str) -> Config {
        self.canary = host.to_string();
        self
    }

    /// `%ProgramData%\Mole\config.json`, falling back to the executable's folder
    /// if ProgramData is somehow unset.
    pub fn path() -> PathBuf {
        if let Ok(pd) = std::env::var("ProgramData") {
            return PathBuf::from(pd).join("Mole").join("config.json");
        }
        std::env::current_exe()
            .ok()
            .and_then(|e| e.parent().map(|p| p.to_path_buf()))
            .unwrap_or_else(|| PathBuf::from("."))
            .join("mole-config.json")
    }

    pub fn load() -> Option<Config> {
        let text = std::fs::read_to_string(Self::path()).ok()?;
        serde_json::from_str(&text).ok()
    }

    pub fn save(&self) -> std::io::Result<()> {
        let path = Self::path();
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let text = serde_json::to_string_pretty(self).map_err(std::io::Error::other)?;
        std::fs::write(path, text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_json() {
        let c = Config::new("fakesplit:ttl6:sni", "Cloudflare");
        let text = serde_json::to_string(&c).unwrap();
        let back: Config = serde_json::from_str(&text).unwrap();
        assert_eq!(c, back);
    }
}
