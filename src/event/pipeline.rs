//! Fact-event enrichment into business events.

use crate::dataplane::events::FactAction;
use crate::dataplane::events::FactEvent;
use crate::event::classify::{BusinessEventType, classify_fact_window};

/// Final business event produced by the control-plane event pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BusinessEvent {
    /// Event id.
    pub event_id: String,
    /// Event time in seconds.
    pub event_time_secs: u64,
    /// Final business event type.
    pub event_type: BusinessEventType,
    /// Effective enforcement action.
    pub action: FactAction,
    /// Event detail string.
    pub detail: String,
    /// Source address.
    pub src_ip: String,
    /// Source port.
    pub src_port: u16,
    /// Destination address.
    pub dst_ip: String,
    /// Destination port.
    pub dst_port: u16,
    /// Transport protocol.
    pub proto: String,
    /// Optional app id.
    pub app_id: Option<String>,
    /// Optional app display name.
    pub app_name: Option<String>,
    /// Optional package name.
    pub pkgname: Option<String>,
    /// Optional rule id.
    pub rule_id: Option<String>,
    /// Stable detail length.
    pub detail_len: usize,
}

/// Convert a fact-event window into a single business event.
#[must_use]
pub fn build_business_event(events: &[FactEvent]) -> Option<BusinessEvent> {
    let first = events.first()?;
    let event_type = classify_fact_window(events);
    let detail = describe_business_event(event_type, &first.proto);
    Some(BusinessEvent {
        event_id: first.event_id.clone(),
        event_time_secs: first.event_time_secs,
        event_type,
        action: first.action,
        detail_len: detail.len(),
        detail,
        src_ip: first.src_ip.clone(),
        src_port: first.src_port,
        dst_ip: first.dst_ip.clone(),
        dst_port: first.dst_port,
        proto: first.proto.clone(),
        app_id: first.app_id.clone(),
        app_name: None,
        pkgname: None,
        rule_id: first.rule_id.clone(),
    })
}

fn describe_business_event(event_type: BusinessEventType, proto: &str) -> String {
    match event_type {
        BusinessEventType::NetworkBlock => "connection blocked by firewall rule".to_string(),
        BusinessEventType::PortScan => match proto {
            "udp" => "udp portscan attack".to_string(),
            _ => "tcp portscan attack".to_string(),
        },
        BusinessEventType::ConnectionStateAnomaly => match proto {
            "udp" => "transport layer --udp unnormal".to_string(),
            _ => "transport layer --tcp unnormal".to_string(),
        },
        BusinessEventType::AppPolicyDeny => "application network access denied".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use crate::dataplane::events::{FactAction, FactEvent, FactEventKind};
    use crate::event::classify::BusinessEventType;

    use super::build_business_event;

    #[test]
    fn builds_business_event_from_fact_window() {
        let event = FactEvent {
            event_id: "evt-1".to_string(),
            event_time_secs: 1,
            kind: FactEventKind::EgressRuleMatch,
            action: FactAction::Block,
            src_ip: "10.0.0.1".to_string(),
            src_port: 1234,
            dst_ip: "8.8.8.8".to_string(),
            dst_port: 53,
            proto: "udp".to_string(),
            ifindex: 2,
            pid: None,
            tgid: None,
            uid: None,
            comm: None,
            app_id: Some("app-1".to_string()),
            rule_id: Some("rule-1".to_string()),
        };
        let business = build_business_event(&[event]).expect("business event");
        assert_eq!(business.event_type, BusinessEventType::NetworkBlock);
        assert_eq!(business.app_id.as_deref(), Some("app-1"));
        assert_eq!(business.detail, "connection blocked by firewall rule");
        assert_eq!(business.detail_len, business.detail.len());
        assert_eq!(business.dst_port, 53);
    }
}
