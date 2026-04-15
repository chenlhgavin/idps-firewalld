//! Local statistics view for firewalld diagnostics.

use std::path::Path;

use anyhow::{Context, Result};
use serde_json::json;

use crate::dataplane::stats::GlobalStats;
use crate::persistence::db::FirewallDb;

/// Read-only traffic statistics snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatisticsSnapshot {
    /// Persisted plus in-flight ingress bytes.
    pub ingress_bytes: u64,
    /// Persisted plus in-flight egress bytes.
    pub egress_bytes: u64,
    /// Persisted plus in-flight ingress packets.
    pub ingress_packets: u64,
    /// Persisted plus in-flight egress packets.
    pub egress_packets: u64,
    /// Current in-flight window start, if any.
    pub current_window_started_at: Option<u64>,
}

impl StatisticsSnapshot {
    /// Return a detached empty snapshot.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            ingress_bytes: 0,
            egress_bytes: 0,
            ingress_packets: 0,
            egress_packets: 0,
            current_window_started_at: None,
        }
    }

    /// Load the latest local statistics from the SQLite cache.
    pub fn load_latest(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::empty());
        }

        let db = FirewallDb::open(path).with_context(|| {
            format!(
                "failed to open firewalld statistics database {}",
                path.display()
            )
        })?;
        let persisted = db.sum_global_traffic()?;
        let inflight = db.traffic_window_state("default")?;
        let inflight_stats = inflight
            .as_ref()
            .map_or(GlobalStats::default(), |state| state.global);
        let current_window_started_at = inflight
            .and_then(|state| state.window_start)
            .and_then(|value| u64::try_from(value).ok());

        Ok(Self {
            ingress_bytes: persisted
                .ingress_bytes
                .saturating_add(inflight_stats.ingress_bytes),
            egress_bytes: persisted
                .egress_bytes
                .saturating_add(inflight_stats.egress_bytes),
            ingress_packets: persisted
                .ingress_packets
                .saturating_add(inflight_stats.ingress_packets),
            egress_packets: persisted
                .egress_packets
                .saturating_add(inflight_stats.egress_packets),
            current_window_started_at,
        })
    }

    /// Render a stable JSON payload for CLI diagnostics.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "global": {
                "ingress_bytes": self.ingress_bytes,
                "egress_bytes": self.egress_bytes,
                "ingress_packets": self.ingress_packets,
                "egress_packets": self.egress_packets,
            },
            "current_window_started_at": self.current_window_started_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::StatisticsSnapshot;
    use crate::dataplane::stats::GlobalStats;
    use crate::persistence::db::{FirewallDb, TrafficWindowStateRow};
    use crate::traffic::aggregate::AppTrafficSummary;

    #[test]
    fn returns_empty_when_db_is_missing() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("missing.sqlite3");
        let snapshot = StatisticsSnapshot::load_latest(&path).expect("stats loaded");
        assert_eq!(snapshot, StatisticsSnapshot::empty());
    }

    #[test]
    fn combines_persisted_and_inflight_global_counters() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("firewalld.sqlite3");
        let db = FirewallDb::open(&path).expect("db opened");
        db.insert_global_window(
            1,
            2,
            &GlobalStats {
                ingress_bytes: 10,
                egress_bytes: 20,
                ingress_packets: 1,
                egress_packets: 2,
            },
        )
        .expect("window inserted");
        db.upsert_traffic_window_state(&TrafficWindowStateRow {
            cursor_key: "default".to_string(),
            window_start: Some(3),
            cycle_secs: Some(10),
            global: GlobalStats {
                ingress_bytes: 5,
                egress_bytes: 6,
                ingress_packets: 1,
                egress_packets: 1,
            },
            apps: vec![AppTrafficSummary {
                app_id: "pkg:demo".to_string(),
                wifi_bytes: 10,
                mobile_bytes: 0,
            }],
            updated_at: 3,
        })
        .expect("state inserted");

        let snapshot = StatisticsSnapshot::load_latest(&path).expect("stats loaded");
        assert_eq!(snapshot.ingress_bytes, 15);
        assert_eq!(snapshot.egress_packets, 3);
        assert_eq!(snapshot.current_window_started_at, Some(3));
    }
}
