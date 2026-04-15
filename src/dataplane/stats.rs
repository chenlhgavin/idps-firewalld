//! Data-plane statistics snapshots.

use serde::{Deserialize, Serialize};

use crate::dataplane::maps::aggregate_global_counters;

/// Global traffic counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct GlobalStats {
    /// Total ingress bytes.
    pub ingress_bytes: u64,
    /// Total egress bytes.
    pub egress_bytes: u64,
    /// Total ingress packets.
    pub ingress_packets: u64,
    /// Total egress packets.
    pub egress_packets: u64,
}

/// Per-app and per-interface traffic sample.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppTrafficSample {
    /// Internal app id.
    pub app_id: String,
    /// Optional thread id.
    pub pid: Option<u32>,
    /// Optional process id.
    pub tgid: Option<u32>,
    /// Optional uid.
    pub uid: Option<u32>,
    /// Optional task command.
    pub comm: Option<String>,
    /// Interface index.
    pub ifindex: u32,
    /// Total bytes.
    pub bytes: u64,
    /// Total packets.
    pub packets: u64,
}

impl AppTrafficSample {
    /// Return the best process identifier for userspace enrichment.
    #[must_use]
    pub fn process_id(&self) -> Option<u32> {
        self.tgid.or(self.pid)
    }
}

/// Aggregate a per-cpu global snapshot into a single global view.
#[must_use]
pub fn snapshot_global_stats(values: &[GlobalStats]) -> GlobalStats {
    aggregate_global_counters(values)
}

#[cfg(test)]
mod tests {
    use super::{GlobalStats, snapshot_global_stats};

    #[test]
    fn snapshots_per_cpu_stats() {
        let snapshot = snapshot_global_stats(&[
            GlobalStats {
                ingress_bytes: 1,
                egress_bytes: 2,
                ingress_packets: 3,
                egress_packets: 4,
            },
            GlobalStats {
                ingress_bytes: 10,
                egress_bytes: 20,
                ingress_packets: 30,
                egress_packets: 40,
            },
        ]);
        assert_eq!(snapshot.ingress_bytes, 11);
        assert_eq!(snapshot.egress_packets, 44);
    }
}
