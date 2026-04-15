//! Traffic aggregation over data-plane samples.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::dataplane::stats::{AppTrafficSample, GlobalStats};
use crate::identity::interface_map::NetworkClass;

/// Application traffic summary grouped by app id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppTrafficSummary {
    /// Internal app id.
    pub app_id: String,
    /// Wi-Fi bytes.
    pub wifi_bytes: u64,
    /// Mobile bytes.
    pub mobile_bytes: u64,
}

/// Aggregate app samples into app-level Wi-Fi/mobile totals.
#[must_use]
pub fn aggregate_app_traffic(
    samples: &[AppTrafficSample],
    classify_ifindex: impl Fn(u32) -> NetworkClass,
) -> Vec<AppTrafficSummary> {
    let mut totals: BTreeMap<String, AppTrafficSummary> = BTreeMap::new();
    for sample in samples {
        let entry = totals
            .entry(sample.app_id.clone())
            .or_insert_with(|| AppTrafficSummary {
                app_id: sample.app_id.clone(),
                wifi_bytes: 0,
                mobile_bytes: 0,
            });
        match classify_ifindex(sample.ifindex) {
            NetworkClass::Wifi => entry.wifi_bytes += sample.bytes,
            NetworkClass::Mobile => entry.mobile_bytes += sample.bytes,
            NetworkClass::Other => {}
        }
    }
    totals.into_values().collect()
}

/// Copy the global stats snapshot into a reportable value.
#[must_use]
pub const fn aggregate_global_traffic(stats: GlobalStats) -> GlobalStats {
    stats
}

#[cfg(test)]
mod tests {
    use crate::dataplane::stats::{AppTrafficSample, GlobalStats};
    use crate::identity::interface_map::NetworkClass;

    use super::{aggregate_app_traffic, aggregate_global_traffic};

    #[test]
    fn aggregates_wifi_and_mobile_bytes() {
        let samples = [
            AppTrafficSample {
                app_id: "app-1".to_string(),
                pid: None,
                tgid: None,
                uid: None,
                comm: None,
                ifindex: 1,
                bytes: 100,
                packets: 1,
            },
            AppTrafficSample {
                app_id: "app-1".to_string(),
                pid: None,
                tgid: None,
                uid: None,
                comm: None,
                ifindex: 2,
                bytes: 50,
                packets: 1,
            },
        ];
        let summaries = aggregate_app_traffic(&samples, |ifindex| match ifindex {
            1 => NetworkClass::Wifi,
            2 => NetworkClass::Mobile,
            _ => NetworkClass::Other,
        });
        assert_eq!(summaries[0].wifi_bytes, 100);
        assert_eq!(summaries[0].mobile_bytes, 50);
    }

    #[test]
    fn preserves_global_stats() {
        let stats = GlobalStats {
            ingress_bytes: 10,
            egress_bytes: 20,
            ingress_packets: 1,
            egress_packets: 2,
        };
        assert_eq!(aggregate_global_traffic(stats), stats);
    }
}
