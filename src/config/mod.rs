//! Firewall daemon runtime configuration.

use std::path::PathBuf;
use std::time::Duration;

const DEFAULT_RUNTIME_CONFIG_PATH: &str = "/etc/idd/idps.yaml";
const DEFAULT_SQLITE_PATH: &str = "/data/idd/firewalld.sqlite3";
const DEFAULT_SHUTDOWN_TIMEOUT_SECS: u64 = 30;
const DEFAULT_RECONNECT_DELAY_SECS: u64 = 1;

/// Firewall daemon configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallConfig {
    /// IDPS runtime configuration path used by `idps-client`.
    pub runtime_config_path: PathBuf,
    /// Local `SQLite` database path.
    pub sqlite_path: PathBuf,
    /// Graceful shutdown timeout.
    pub shutdown_timeout: Duration,
    /// Delay between recoverable reconnect attempts.
    pub reconnect_delay: Duration,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            runtime_config_path: PathBuf::from(DEFAULT_RUNTIME_CONFIG_PATH),
            sqlite_path: PathBuf::from(DEFAULT_SQLITE_PATH),
            shutdown_timeout: Duration::from_secs(DEFAULT_SHUTDOWN_TIMEOUT_SECS),
            reconnect_delay: Duration::from_secs(DEFAULT_RECONNECT_DELAY_SECS),
        }
    }
}

impl FirewallConfig {
    /// Load the daemon configuration from environment variables and defaults.
    #[must_use]
    pub fn load() -> Self {
        let mut config = Self::default();
        if let Ok(path) = std::env::var("IDPS_FIREWALLD_CONFIG") {
            config.runtime_config_path = PathBuf::from(path);
        }
        if let Ok(path) = std::env::var("IDPS_FIREWALLD_DB") {
            config.sqlite_path = PathBuf::from(path);
        }
        config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_uses_runtime_paths() {
        let config = FirewallConfig::default();
        assert_eq!(config.sqlite_path, PathBuf::from(DEFAULT_SQLITE_PATH));
        assert_eq!(config.shutdown_timeout, Duration::from_secs(30));
    }
}
