//! Firewall daemon runtime configuration.

use std::path::PathBuf;
use std::time::Duration;

const DEFAULT_RUNTIME_CONFIG_PATH: &str = "/etc/idd/idps.yaml";
const DEFAULT_SQLITE_PATH: &str = "/data/idd/firewalld.sqlite3";
const DEFAULT_EBPF_OBJECT_PATH: &str = "target/bpfel-unknown-none/release/idps-firewalld-ebpf";
const DEFAULT_ANDROID_PACKAGES_LIST_PATH: &str = "/data/system/packages.list";
const DEFAULT_SHUTDOWN_TIMEOUT_SECS: u64 = 30;
const DEFAULT_RECONNECT_DELAY_SECS: u64 = 1;
const DEFAULT_SMOKE_RULESET_VERSION: &str = "smoke-v1";
const DEFAULT_SMOKE_POLL_INTERVAL_MS: u64 = 250;
const DEFAULT_RUNTIME_POLL_INTERVAL_MS: u64 = 250;
const DEFAULT_RUNTIME_REPORT_INTERVAL_MS: u64 = 250;
const DEFAULT_RETENTION_CLEANUP_INTERVAL_SECS: u64 = 3600;
const DEFAULT_FIREWALL_EVENT_RETENTION_SECS: u64 = 7 * 24 * 60 * 60;
const DEFAULT_TRAFFIC_WINDOW_RETENTION_SECS: u64 = 7 * 24 * 60 * 60;
const DEFAULT_SUCCEEDED_OUTBOX_RETENTION_SECS: u64 = 24 * 60 * 60;

/// Data-plane backend mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataplaneMode {
    /// In-memory mock backend.
    Mock,
    /// Real Aya tc backend.
    Ebpf,
}

/// Firewall daemon configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallConfig {
    /// IDPS runtime configuration path used by `idps-client`.
    pub runtime_config_path: PathBuf,
    /// Local `SQLite` database path.
    pub sqlite_path: PathBuf,
    /// Active data-plane mode.
    pub dataplane_mode: DataplaneMode,
    /// eBPF object path when `DataplaneMode::Ebpf` is enabled.
    pub ebpf_object_path: PathBuf,
    /// Android package-to-UID registry used for package policy compilation.
    pub android_packages_list_path: PathBuf,
    /// Interfaces to attach tc ingress/egress programs to.
    pub attach_ifaces: Vec<String>,
    /// Optional smoke-only bootstrap firewall rules.
    pub smoke_firewall_rules: Option<String>,
    /// Optional smoke-only traffic policy payload.
    pub smoke_traffic_policy: Option<String>,
    /// Smoke ruleset version.
    pub smoke_ruleset_version: String,
    /// Poll interval for smoke dataplane sampling.
    pub smoke_poll_interval: Duration,
    /// Poll interval for managed runtime dataplane sampling.
    pub runtime_poll_interval: Duration,
    /// Poll interval for managed runtime report uploads.
    pub runtime_report_interval: Duration,
    /// Periodic retention cleanup interval.
    pub retention_cleanup_interval: Duration,
    /// How long firewall events should be retained.
    pub firewall_event_retention: Duration,
    /// How long traffic windows should be retained.
    pub traffic_window_retention: Duration,
    /// How long succeeded outbox rows should be retained.
    pub succeeded_outbox_retention: Duration,
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
            dataplane_mode: DataplaneMode::Mock,
            ebpf_object_path: PathBuf::from(DEFAULT_EBPF_OBJECT_PATH),
            android_packages_list_path: PathBuf::from(DEFAULT_ANDROID_PACKAGES_LIST_PATH),
            attach_ifaces: Vec::new(),
            smoke_firewall_rules: None,
            smoke_traffic_policy: None,
            smoke_ruleset_version: DEFAULT_SMOKE_RULESET_VERSION.to_string(),
            smoke_poll_interval: Duration::from_millis(DEFAULT_SMOKE_POLL_INTERVAL_MS),
            runtime_poll_interval: Duration::from_millis(DEFAULT_RUNTIME_POLL_INTERVAL_MS),
            runtime_report_interval: Duration::from_millis(DEFAULT_RUNTIME_REPORT_INTERVAL_MS),
            retention_cleanup_interval: Duration::from_secs(
                DEFAULT_RETENTION_CLEANUP_INTERVAL_SECS,
            ),
            firewall_event_retention: Duration::from_secs(DEFAULT_FIREWALL_EVENT_RETENTION_SECS),
            traffic_window_retention: Duration::from_secs(DEFAULT_TRAFFIC_WINDOW_RETENTION_SECS),
            succeeded_outbox_retention: Duration::from_secs(
                DEFAULT_SUCCEEDED_OUTBOX_RETENTION_SECS,
            ),
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
        if let Ok(mode) = std::env::var("IDPS_FIREWALLD_DATAPLANE") {
            config.dataplane_mode = match mode.as_str() {
                "ebpf" => DataplaneMode::Ebpf,
                _ => DataplaneMode::Mock,
            };
        }
        if let Ok(path) = std::env::var("IDPS_FIREWALLD_EBPF_OBJECT") {
            config.ebpf_object_path = PathBuf::from(path);
        }
        if let Ok(path) = std::env::var("IDPS_FIREWALLD_ANDROID_PACKAGES_LIST") {
            config.android_packages_list_path = PathBuf::from(path);
        }
        if let Ok(ifaces) = std::env::var("IDPS_FIREWALLD_ATTACH_IFACES") {
            config.attach_ifaces = ifaces
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .collect();
        }
        if let Ok(rules) = std::env::var("IDPS_FIREWALLD_SMOKE_FIREWALL_RULES")
            && !rules.trim().is_empty()
        {
            config.smoke_firewall_rules = Some(rules);
        }
        if let Ok(policy) = std::env::var("IDPS_FIREWALLD_SMOKE_TRAFFIC_POLICY")
            && !policy.trim().is_empty()
        {
            config.smoke_traffic_policy = Some(policy);
        }
        if let Ok(version) = std::env::var("IDPS_FIREWALLD_SMOKE_RULESET_VERSION")
            && !version.trim().is_empty()
        {
            config.smoke_ruleset_version = version;
        }
        if let Ok(interval) = std::env::var("IDPS_FIREWALLD_SMOKE_POLL_INTERVAL_MS")
            && let Ok(interval_ms) = interval.parse::<u64>()
        {
            config.smoke_poll_interval = Duration::from_millis(interval_ms);
        }
        if let Ok(interval) = std::env::var("IDPS_FIREWALLD_RUNTIME_POLL_INTERVAL_MS")
            && let Ok(interval_ms) = interval.parse::<u64>()
        {
            config.runtime_poll_interval = Duration::from_millis(interval_ms);
        }
        if let Ok(interval) = std::env::var("IDPS_FIREWALLD_RUNTIME_REPORT_INTERVAL_MS")
            && let Ok(interval_ms) = interval.parse::<u64>()
        {
            config.runtime_report_interval = Duration::from_millis(interval_ms);
        }
        if let Ok(interval) = std::env::var("IDPS_FIREWALLD_RETENTION_CLEANUP_INTERVAL_SECS")
            && let Ok(interval_secs) = interval.parse::<u64>()
        {
            config.retention_cleanup_interval = Duration::from_secs(interval_secs);
        }
        if let Ok(interval) = std::env::var("IDPS_FIREWALLD_FIREWALL_EVENT_RETENTION_SECS")
            && let Ok(interval_secs) = interval.parse::<u64>()
        {
            config.firewall_event_retention = Duration::from_secs(interval_secs);
        }
        if let Ok(interval) = std::env::var("IDPS_FIREWALLD_TRAFFIC_WINDOW_RETENTION_SECS")
            && let Ok(interval_secs) = interval.parse::<u64>()
        {
            config.traffic_window_retention = Duration::from_secs(interval_secs);
        }
        if let Ok(interval) = std::env::var("IDPS_FIREWALLD_SUCCEEDED_OUTBOX_RETENTION_SECS")
            && let Ok(interval_secs) = interval.parse::<u64>()
        {
            config.succeeded_outbox_retention = Duration::from_secs(interval_secs);
        }
        config
    }

    /// Return whether explicit smoke bootstrap configuration is present.
    #[must_use]
    pub fn smoke_mode_requested(&self) -> bool {
        self.smoke_firewall_rules.is_some() || self.smoke_traffic_policy.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_uses_runtime_paths() {
        let config = FirewallConfig::default();
        assert_eq!(config.sqlite_path, PathBuf::from(DEFAULT_SQLITE_PATH));
        assert_eq!(
            config.ebpf_object_path,
            PathBuf::from(DEFAULT_EBPF_OBJECT_PATH)
        );
        assert_eq!(
            config.android_packages_list_path,
            PathBuf::from(DEFAULT_ANDROID_PACKAGES_LIST_PATH)
        );
        assert_eq!(config.dataplane_mode, DataplaneMode::Mock);
        assert_eq!(config.smoke_ruleset_version, DEFAULT_SMOKE_RULESET_VERSION);
        assert_eq!(
            config.smoke_poll_interval,
            Duration::from_millis(DEFAULT_SMOKE_POLL_INTERVAL_MS)
        );
        assert_eq!(
            config.runtime_poll_interval,
            Duration::from_millis(DEFAULT_RUNTIME_POLL_INTERVAL_MS)
        );
        assert_eq!(
            config.runtime_report_interval,
            Duration::from_millis(DEFAULT_RUNTIME_REPORT_INTERVAL_MS)
        );
        assert_eq!(
            config.retention_cleanup_interval,
            Duration::from_secs(DEFAULT_RETENTION_CLEANUP_INTERVAL_SECS)
        );
        assert_eq!(
            config.firewall_event_retention,
            Duration::from_secs(DEFAULT_FIREWALL_EVENT_RETENTION_SECS)
        );
        assert_eq!(
            config.traffic_window_retention,
            Duration::from_secs(DEFAULT_TRAFFIC_WINDOW_RETENTION_SECS)
        );
        assert_eq!(
            config.succeeded_outbox_retention,
            Duration::from_secs(DEFAULT_SUCCEEDED_OUTBOX_RETENTION_SECS)
        );
        assert_eq!(config.shutdown_timeout, Duration::from_secs(30));
    }

    #[test]
    fn smoke_mode_requires_explicit_smoke_inputs() {
        let mut config = FirewallConfig::default();
        assert!(!config.smoke_mode_requested());

        config.smoke_firewall_rules = Some("prog=test,allow=true".to_string());
        assert!(config.smoke_mode_requested());
    }
}
