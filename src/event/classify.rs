//! Business classification for fact events.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::dataplane::events::{FactEvent, FactEventKind};

/// Business event type derived from fact events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BusinessEventType {
    /// Generic blocked network event.
    NetworkBlock,
    /// Multi-port scan detected on ingress.
    PortScan,
    /// Repeated same-port anomaly detected on ingress.
    ConnectionStateAnomaly,
    /// Application connectivity denial.
    AppPolicyDeny,
}

/// Classify ingress-window fact events into a final business event type.
#[must_use]
pub fn classify_fact_window(events: &[FactEvent]) -> BusinessEventType {
    if events
        .iter()
        .any(|event| event.kind == FactEventKind::PolicyDeny)
    {
        return BusinessEventType::AppPolicyDeny;
    }

    let ingress: Vec<&FactEvent> = events
        .iter()
        .filter(|event| event.kind == FactEventKind::IngressRuleMatch)
        .collect();
    if ingress.is_empty() {
        return BusinessEventType::NetworkBlock;
    }

    let unique_ports: BTreeSet<u16> = ingress.iter().map(|event| event.dst_port).collect();
    if unique_ports.len() >= 3 {
        return BusinessEventType::PortScan;
    }

    let first_port = ingress.first().map_or(0, |event| event.dst_port);
    let same_port_hits = ingress
        .iter()
        .filter(|event| event.dst_port == first_port)
        .count();
    if same_port_hits >= 4 {
        return BusinessEventType::ConnectionStateAnomaly;
    }

    BusinessEventType::NetworkBlock
}

#[cfg(test)]
mod tests {
    use crate::dataplane::events::{FactAction, FactEvent, FactEventKind};

    use super::{BusinessEventType, classify_fact_window};

    fn ingress_event(id: &str, port: u16) -> FactEvent {
        FactEvent {
            event_id: id.to_string(),
            event_time_secs: 1,
            kind: FactEventKind::IngressRuleMatch,
            action: FactAction::Block,
            src_ip: "1.1.1.1".to_string(),
            src_port: 1000,
            dst_ip: "2.2.2.2".to_string(),
            dst_port: port,
            proto: "tcp".to_string(),
            ifindex: 1,
            pid: None,
            tgid: None,
            uid: None,
            comm: None,
            app_id: None,
            rule_id: None,
        }
    }

    #[test]
    fn classifies_port_scan() {
        let events = [
            ingress_event("1", 80),
            ingress_event("2", 81),
            ingress_event("3", 82),
        ];
        assert_eq!(classify_fact_window(&events), BusinessEventType::PortScan);
    }

    #[test]
    fn classifies_connection_state_anomaly() {
        let events = [
            ingress_event("1", 443),
            ingress_event("2", 443),
            ingress_event("3", 443),
            ingress_event("4", 443),
        ];
        assert_eq!(
            classify_fact_window(&events),
            BusinessEventType::ConnectionStateAnomaly
        );
    }
}
