//! Health reporting for the firewall daemon.

use std::path::Path;

use anyhow::{Context, Result};
use serde_json::json;

use crate::persistence::db::FirewallDb;
use crate::reporter::pending_reports;
use crate::runtime::RuntimePhase;

/// Top-level daemon health snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthSnapshot {
    /// Runtime lifecycle phase.
    pub phase: RuntimePhase,
    /// Whether the transport is currently connected.
    pub connected: bool,
    /// Whether registration has completed for the current session.
    pub registered: bool,
    /// Active rule version.
    pub rule_version: Option<String>,
    /// Active traffic cycle.
    pub traffic_cycle_secs: Option<u64>,
    /// Pending outbox count.
    pub pending_reports: i64,
    /// Last successfully acknowledged report time in seconds.
    pub last_report_succeeded_at: Option<u64>,
    /// Last failed report time in seconds.
    pub last_report_failed_at: Option<u64>,
    /// Current traffic window start time in seconds.
    pub current_window_started_at: Option<u64>,
    /// Number of buffered fact-event buckets waiting for flush.
    pub buffered_fact_windows: usize,
    /// Dataplane readiness/status string.
    pub dataplane_status: String,
    /// Active dataplane checksum.
    pub dataplane_checksum: Option<String>,
    /// Dataplane event loss counter.
    pub dataplane_lost_events: usize,
}

impl HealthSnapshot {
    /// Build the default detached snapshot used before the daemon has reported
    /// any live state.
    #[must_use]
    pub fn default_detached() -> Self {
        Self {
            phase: RuntimePhase::Init,
            connected: false,
            registered: false,
            rule_version: None,
            traffic_cycle_secs: None,
            pending_reports: 0,
            last_report_succeeded_at: None,
            last_report_failed_at: None,
            current_window_started_at: None,
            buffered_fact_windows: 0,
            dataplane_status: "detached".to_string(),
            dataplane_checksum: None,
            dataplane_lost_events: 0,
        }
    }

    /// Load the latest persisted runtime health snapshot from the daemon
    /// database.
    ///
    /// Missing databases or missing snapshot rows return a detached default.
    ///
    /// # Errors
    ///
    /// Returns an error when the existing database cannot be opened or queried.
    pub fn load_latest(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default_detached());
        }

        let db = FirewallDb::open(path).with_context(|| {
            format!(
                "failed to open firewalld health database {}",
                path.display()
            )
        })?;
        let mut snapshot = db
            .latest_health_snapshot()?
            .unwrap_or_else(Self::default_detached);
        snapshot.pending_reports = pending_reports(db.connection())?;
        snapshot.current_window_started_at = db
            .traffic_window_cursor("default")?
            .and_then(|cursor| cursor.window_start)
            .and_then(|value| u64::try_from(value).ok());
        Ok(snapshot)
    }

    /// Render a stable JSON value for diagnostics endpoints and CLI output.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "phase": self.phase.as_str(),
            "connected": self.connected,
            "registered": self.registered,
            "rule_version": self.rule_version,
            "traffic_cycle_secs": self.traffic_cycle_secs,
            "pending_reports": self.pending_reports,
            "last_report_succeeded_at": self.last_report_succeeded_at,
            "last_report_failed_at": self.last_report_failed_at,
            "current_window_started_at": self.current_window_started_at,
            "buffered_fact_windows": self.buffered_fact_windows,
            "dataplane": {
                "status": self.dataplane_status,
                "checksum": self.dataplane_checksum,
                "lost_events": self.dataplane_lost_events,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::{HealthSnapshot, RuntimePhase};
    use crate::persistence::db::FirewallDb;

    #[test]
    fn renders_health_snapshot_as_json() {
        let snapshot = HealthSnapshot {
            phase: RuntimePhase::Running,
            connected: true,
            registered: true,
            rule_version: Some("v1".to_string()),
            traffic_cycle_secs: Some(10),
            pending_reports: 1,
            last_report_succeeded_at: Some(2),
            last_report_failed_at: None,
            current_window_started_at: Some(1),
            buffered_fact_windows: 0,
            dataplane_status: "ready".to_string(),
            dataplane_checksum: Some("abc".to_string()),
            dataplane_lost_events: 3,
        };
        let value = snapshot.to_json();
        assert_eq!(value["dataplane"]["lost_events"], 3);
        assert_eq!(value["phase"], "Running");
    }

    #[test]
    fn loads_default_snapshot_when_db_is_missing() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("missing.sqlite3");
        let snapshot = HealthSnapshot::load_latest(&path).expect("snapshot loaded");
        assert_eq!(snapshot, HealthSnapshot::default_detached());
    }

    #[test]
    fn loads_latest_snapshot_and_refreshes_live_counts() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("firewalld.sqlite3");
        let db = FirewallDb::open(&path).expect("db opened");
        db.upsert_health_snapshot(&HealthSnapshot {
            phase: RuntimePhase::Running,
            connected: true,
            registered: true,
            rule_version: Some("v1".to_string()),
            traffic_cycle_secs: Some(30),
            pending_reports: 0,
            last_report_succeeded_at: Some(11),
            last_report_failed_at: None,
            current_window_started_at: Some(10),
            buffered_fact_windows: 2,
            dataplane_status: "ready".to_string(),
            dataplane_checksum: Some("abc".to_string()),
            dataplane_lost_events: 1,
        })
        .expect("snapshot stored");
        db.upsert_traffic_window_cursor("default", Some(44), Some(30))
            .expect("cursor stored");
        crate::persistence::outbox::enqueue_report(
            db.connection(),
            "report-1",
            "firewall_event",
            "{}",
            1,
        )
        .expect("report enqueued");

        let snapshot = HealthSnapshot::load_latest(&path).expect("snapshot loaded");
        assert_eq!(snapshot.pending_reports, 1);
        assert_eq!(snapshot.current_window_started_at, Some(44));
        assert_eq!(snapshot.dataplane_status, "ready");
    }
}
