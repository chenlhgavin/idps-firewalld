//! Fact events emitted by the data plane.

use crate::dataplane::maps::WireFactEvent;
use crate::identity::provider::AndroidPackageMap;

/// Data-plane fact event kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactEventKind {
    /// Tuple-rule match on ingress.
    IngressRuleMatch,
    /// Tuple-rule match on egress.
    EgressRuleMatch,
    /// Application or program policy denial.
    PolicyDeny,
}

/// Data-plane action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactAction {
    /// Allow traffic.
    Allow,
    /// Alert on traffic.
    Alert,
    /// Block traffic.
    Block,
}

/// Stable fact event emitted by the data plane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactEvent {
    /// Unique event identifier.
    pub event_id: String,
    /// Event timestamp in seconds.
    pub event_time_secs: u64,
    /// Event kind.
    pub kind: FactEventKind,
    /// Data-plane action.
    pub action: FactAction,
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
    /// Interface index.
    pub ifindex: u32,
    /// Optional thread id.
    pub pid: Option<u32>,
    /// Optional process id.
    pub tgid: Option<u32>,
    /// Optional uid.
    pub uid: Option<u32>,
    /// Optional task command.
    pub comm: Option<String>,
    /// Optional app id.
    pub app_id: Option<String>,
    /// Optional rule id.
    pub rule_id: Option<String>,
}

impl FactEvent {
    /// Return the best process identifier for userspace enrichment.
    #[must_use]
    pub fn process_id(&self) -> Option<u32> {
        self.tgid.or(self.pid)
    }
}

/// Decode a wire event into the userspace event model.
#[must_use]
pub fn decode_wire_event(
    checksum: &str,
    event: WireFactEvent,
    packages: Option<&AndroidPackageMap>,
) -> FactEvent {
    event.into_fact_event(checksum, packages)
}

#[cfg(test)]
mod tests {
    use crate::dataplane::events::{FactAction, FactEventKind};
    use crate::dataplane::maps::WireFactEvent;

    use super::decode_wire_event;

    #[test]
    fn decodes_wire_event() {
        let fact = decode_wire_event(
            "abc",
            WireFactEvent {
                event_time_secs: 42,
                rule_id_hash: 0x42,
                ifindex: 1,
                app_uid: 1000,
                app_pid: 1001,
                app_tgid: 1000,
                src_ip: u32::from(std::net::Ipv4Addr::new(1, 1, 1, 1)),
                dst_ip: u32::from(std::net::Ipv4Addr::new(2, 2, 2, 2)),
                rule_index: 3,
                bytes: 64,
                src_port: 100,
                dst_port: 200,
                event_kind: 0,
                action: 1,
                proto: 6,
                reserved: [0; 5],
                app_comm: *b"curl\0\0\0\0\0\0\0\0\0\0\0\0",
            },
            None,
        );
        assert_eq!(fact.kind, FactEventKind::IngressRuleMatch);
        assert_eq!(fact.action, FactAction::Alert);
        assert_eq!(fact.event_time_secs, 42);
        assert_eq!(fact.uid, Some(1000));
        assert_eq!(fact.pid, Some(1001));
        assert_eq!(fact.tgid, Some(1000));
        assert_eq!(fact.rule_id.as_deref(), Some("rule-0000000000000042"));
    }
}
