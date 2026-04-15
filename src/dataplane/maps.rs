//! Compiled data-plane state derived from normalized rules.

use std::fs;
use std::hash::Hasher;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use anyhow::{Result, anyhow, bail};
#[cfg(feature = "ebpf")]
use bytemuck::{Pod, Zeroable};

use crate::dataplane::events::{FactAction, FactEvent, FactEventKind};
use crate::dataplane::stats::GlobalStats;
use crate::identity::interface_map::classify_interface;
use crate::identity::provider::AndroidPackageMap;
use crate::identity::resolve::resolve_observed_identity;
use crate::rule::model::{
    AddressMatch, AppPolicyRule, FirewallRule, InterfaceScope, NetworkScope, PolicyAction,
    PortMatch, ProgramPolicyRule, Protocol, TupleAction,
};

/// Maximum task command length returned by `bpf_get_current_comm`.
pub const TASK_COMM_LEN: usize = 16;
/// Maximum number of tuple rules programmed in one active slot.
pub const MAX_RULE_ENTRIES: usize = 1024;
/// Maximum number of app/program policies programmed into the dataplane.
pub const MAX_POLICY_ENTRIES: usize = 1024;
/// Number of active dataplane configuration slots.
pub const ACTIVE_CONFIG_SLOTS: usize = 2;
/// Total tuple-rule capacity across all configuration slots.
pub const TOTAL_RULE_ENTRIES: usize = MAX_RULE_ENTRIES * ACTIVE_CONFIG_SLOTS;
/// Total app-policy capacity across all configuration slots.
pub const TOTAL_POLICY_ENTRIES: usize = MAX_POLICY_ENTRIES * ACTIVE_CONFIG_SLOTS;
/// Maximum number of tracked flow-ownership entries.
pub const FLOW_OWNERSHIP_ENTRIES: usize = 4096;
/// Maximum number of interface classes written into the dataplane map.
pub const MAX_INTERFACE_CLASS_ENTRIES: usize = 64;

/// Package-policy selector kind.
pub const POLICY_KIND_APP: u8 = 1;
/// Program-policy selector kind.
pub const POLICY_KIND_PROGRAM: u8 = 2;
/// Match any network class.
pub const NETWORK_SCOPE_ALL: u8 = 0;
/// Match Wi-Fi interfaces.
pub const NETWORK_SCOPE_WIFI: u8 = 1;
/// Match mobile/cellular interfaces.
pub const NETWORK_SCOPE_MOBILE: u8 = 2;

/// Userspace/kernel-compatible IPv4 tuple rule.
#[repr(C)]
#[cfg_attr(feature = "ebpf", derive(Pod, Zeroable))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RuleV4 {
    /// Stable rule id hash for event correlation.
    pub rule_id_hash: u64,
    /// Source IPv4 address.
    pub src_addr: u32,
    /// Source prefix mask.
    pub src_mask: u32,
    /// Destination IPv4 address.
    pub dst_addr: u32,
    /// Destination prefix mask.
    pub dst_mask: u32,
    /// Source port range start.
    pub src_port_start: u16,
    /// Source port range end.
    pub src_port_end: u16,
    /// Destination port range start.
    pub dst_port_start: u16,
    /// Destination port range end.
    pub dst_port_end: u16,
    /// Encoded transport protocol: 0 any, 6 tcp, 17 udp.
    pub proto: u8,
    /// Encoded action:
    /// 0 allow, 1 alert, 2 block/report, 3 ingress observe, 4 block/silent.
    pub action: u8,
    /// Encoded direction: 0 ingress, 1 egress.
    pub direction: u8,
    /// Enabled flag.
    pub enabled: u8,
    /// Reserved padding.
    pub reserved: u32,
}

/// Userspace/kernel-compatible app/program policy entry.
#[repr(C)]
#[cfg_attr(feature = "ebpf", derive(Pod, Zeroable))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AppPolicyEntry {
    /// Stable policy id hash for event correlation.
    pub policy_id_hash: u64,
    /// Scope ifindex when non-zero.
    pub scope_ifindex: u32,
    /// UID selector used for package policies.
    pub match_uid: u32,
    /// Truncated program identity used for task matching.
    pub identity: [u8; TASK_COMM_LEN],
    /// Encoded allow/deny action: 1 allow, 2 deny.
    pub action: u8,
    /// Encoded identity kind: 1 app, 2 program.
    pub kind: u8,
    /// Encoded network scope: 0 all, 1 wifi, 2 mobile.
    pub network_scope: u8,
    /// Reserved padding to keep the struct `Pod`-compatible.
    pub reserved: [u8; 5],
}

/// Userspace/kernel-compatible traffic policy entry.
#[repr(C)]
#[cfg_attr(feature = "ebpf", derive(Pod, Zeroable))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TrafficPolicyEntry {
    /// Stable traffic policy id hash.
    pub policy_id_hash: u64,
    /// Reporting cycle in seconds.
    pub cycle_secs: u64,
}

/// Userspace/kernel-compatible rule config.
#[repr(C)]
#[cfg_attr(feature = "ebpf", derive(Pod, Zeroable))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RuleConfig {
    /// Lower 64 bits of the ruleset checksum.
    pub checksum_low: u64,
    /// Active slot consumed by the dataplane.
    pub active_slot: u32,
    /// Number of active tuple rules.
    pub rule_count: u32,
    /// Number of active app/program policies.
    pub policy_count: u32,
    /// Reserved padding.
    pub reserved: u32,
}

/// Userspace/kernel-compatible fact event.
#[repr(C)]
#[cfg_attr(feature = "ebpf", derive(Pod, Zeroable))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WireFactEvent {
    /// Event timestamp in seconds.
    pub event_time_secs: u64,
    /// Stable matched rule or policy id hash.
    pub rule_id_hash: u64,
    /// Packet bytes.
    pub bytes: u64,
    /// Interface index.
    pub ifindex: u32,
    /// Current task uid when available.
    pub app_uid: u32,
    /// Current task thread id when available.
    pub app_pid: u32,
    /// Current task process id when available.
    pub app_tgid: u32,
    /// Source IPv4 address.
    pub src_ip: u32,
    /// Destination IPv4 address.
    pub dst_ip: u32,
    /// Matched rule or policy index.
    pub rule_index: u32,
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
    /// Encoded event kind.
    pub event_kind: u8,
    /// Encoded action.
    pub action: u8,
    /// Encoded transport protocol.
    pub proto: u8,
    /// Reserved padding to keep the struct `Pod`-compatible.
    pub reserved: [u8; 5],
    /// Current task command when available.
    pub app_comm: [u8; TASK_COMM_LEN],
}

/// Key used for per-app/per-interface traffic counters.
#[repr(C)]
#[cfg_attr(feature = "ebpf", derive(Pod, Zeroable))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AppTrafficKey {
    /// Current task uid.
    pub uid: u32,
    /// Current task thread id.
    pub pid: u32,
    /// Current task process id.
    pub tgid: u32,
    /// Interface index.
    pub ifindex: u32,
    /// Current task command.
    pub comm: [u8; TASK_COMM_LEN],
}

/// Value stored in the per-app traffic map.
#[repr(C)]
#[cfg_attr(feature = "ebpf", derive(Pod, Zeroable))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AppTrafficValue {
    /// Total bytes.
    pub bytes: u64,
    /// Total packets.
    pub packets: u64,
}

/// Flow ownership key reused across packet path lookups.
#[repr(C)]
#[cfg_attr(feature = "ebpf", derive(Pod, Zeroable))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FlowOwnershipKey {
    /// Source IPv4 address.
    pub src_ip: u32,
    /// Destination IPv4 address.
    pub dst_ip: u32,
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
    /// Protocol.
    pub proto: u8,
    /// Reserved padding.
    pub reserved: [u8; 3],
}

/// Flow ownership value storing resolved identity.
#[repr(C)]
#[cfg_attr(feature = "ebpf", derive(Pod, Zeroable))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FlowOwnershipValue {
    /// Identity uid.
    pub uid: u32,
    /// Identity thread id.
    pub pid: u32,
    /// Identity process id.
    pub tgid: u32,
    /// Identity comm.
    pub comm: [u8; TASK_COMM_LEN],
}

/// Userspace/kernel-compatible interface classification entry.
#[repr(C)]
#[cfg_attr(feature = "ebpf", derive(Pod, Zeroable))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct InterfaceClassValue {
    /// Encoded network class: 0 all/other, 1 wifi, 2 mobile.
    pub network_scope: u8,
    /// Reserved padding.
    pub reserved: [u8; 3],
}

/// Summary of the active compiled data-plane state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledDataplaneState {
    /// Active ruleset checksum.
    pub checksum: String,
    /// Number of tuple rules.
    pub tuple_rule_count: usize,
    /// Number of policy rules compiled into the dataplane.
    pub policy_rule_count: usize,
    /// Whether flow ownership support is expected by the userspace/kernel contract.
    pub flow_ownership_enabled: bool,
    /// Traffic cycle in seconds, if configured.
    pub traffic_cycle_secs: Option<u64>,
}

impl CompiledDataplaneState {
    /// Build a data-plane summary from compiled vectors.
    #[must_use]
    pub fn new(
        checksum: String,
        tuple_rule_count: usize,
        policy_rule_count: usize,
        traffic_cycle_secs: Option<u64>,
    ) -> Self {
        Self {
            checksum,
            tuple_rule_count,
            policy_rule_count,
            flow_ownership_enabled: policy_rule_count != 0,
            traffic_cycle_secs,
        }
    }
}

impl RuleV4 {
    /// Convert a normalized tuple rule into a wire rule when it is representable
    /// as IPv4.
    #[must_use]
    pub fn from_firewall_rule(rule: &FirewallRule) -> Option<Self> {
        let FirewallRule::Tuple(rule) = rule else {
            return None;
        };
        Some(Self {
            rule_id_hash: stable_id_hash(&rule.metadata.rule_id),
            src_addr: encode_addr(&rule.src_addr)?.0,
            src_mask: encode_addr(&rule.src_addr)?.1,
            dst_addr: encode_addr(&rule.dst_addr)?.0,
            dst_mask: encode_addr(&rule.dst_addr)?.1,
            src_port_start: encode_port_start(&rule.src_port),
            src_port_end: encode_port_end(&rule.src_port),
            dst_port_start: encode_port_start(&rule.dst_port),
            dst_port_end: encode_port_end(&rule.dst_port),
            proto: encode_protocol(rule.protocol),
            action: encode_action(rule.action),
            direction: encode_direction(rule.direction),
            enabled: 1,
            reserved: 0,
        })
    }
}

impl AppPolicyEntry {
    /// Compile one package policy into dataplane entries.
    ///
    /// Package policies are expanded to every resolved Android UID.
    pub fn from_app_rule(
        rule: &AppPolicyRule,
        packages: Option<&AndroidPackageMap>,
    ) -> Result<Vec<Self>> {
        let Some(packages) = packages else {
            bail!(
                "package policy {} requires Android package mapping to compile",
                rule.package
            );
        };
        let Some(uids) = packages.uids_for_package(&rule.package) else {
            bail!("package policy {} has no Android UID mapping", rule.package);
        };

        let (scope_ifindex, network_scope) = encode_interface_scope(&rule.interface_scope)?;
        Ok(uids
            .iter()
            .copied()
            .map(|uid| Self {
                policy_id_hash: stable_id_hash(
                    rule.metadata
                        .policy_id
                        .as_deref()
                        .unwrap_or(&rule.metadata.rule_id),
                ),
                scope_ifindex,
                match_uid: uid,
                identity: [0; TASK_COMM_LEN],
                action: encode_policy_action(rule.action),
                kind: POLICY_KIND_APP,
                network_scope,
                reserved: [0; 5],
            })
            .collect())
    }

    /// Convert one normalized program rule into a dataplane policy entry.
    pub fn from_program_rule(rule: &ProgramPolicyRule) -> Result<Self> {
        let (scope_ifindex, network_scope) = encode_interface_scope(&rule.interface_scope)?;
        Ok(Self {
            policy_id_hash: stable_id_hash(
                rule.metadata
                    .policy_id
                    .as_deref()
                    .unwrap_or(&rule.metadata.rule_id),
            ),
            scope_ifindex,
            match_uid: 0,
            identity: encode_identity(&rule.program),
            action: encode_policy_action(rule.action),
            kind: POLICY_KIND_PROGRAM,
            network_scope,
            reserved: [0; 5],
        })
    }

    /// Return whether this entry can match the provided task identity.
    #[must_use]
    pub fn matches_identity(&self, uid: u32, comm: &[u8; TASK_COMM_LEN]) -> bool {
        match self.kind {
            POLICY_KIND_APP => self.match_uid != 0 && self.match_uid == uid,
            POLICY_KIND_PROGRAM => self.identity == *comm,
            _ => false,
        }
    }
}

impl WireFactEvent {
    /// Convert a wire fact event into the userspace event model.
    #[must_use]
    pub fn into_fact_event(
        self,
        checksum: &str,
        packages: Option<&AndroidPackageMap>,
    ) -> FactEvent {
        let app_id = decode_app_id(self.app_uid, &self.app_comm, packages);
        let stable_rule_id = match self.event_kind {
            2 => format!("policy-{:016x}", self.rule_id_hash),
            _ => format!("rule-{:016x}", self.rule_id_hash),
        };
        FactEvent {
            event_id: format!("{checksum}:{stable_rule_id}:{}", self.rule_index),
            event_time_secs: self.event_time_secs,
            kind: match self.event_kind {
                0 => FactEventKind::IngressRuleMatch,
                1 => FactEventKind::EgressRuleMatch,
                _ => FactEventKind::PolicyDeny,
            },
            action: match self.action {
                0 => FactAction::Allow,
                1 => FactAction::Alert,
                _ => FactAction::Block,
            },
            src_ip: Ipv4Addr::from(self.src_ip).to_string(),
            src_port: self.src_port,
            dst_ip: Ipv4Addr::from(self.dst_ip).to_string(),
            dst_port: self.dst_port,
            proto: match self.proto {
                6 => "tcp".to_string(),
                17 => "udp".to_string(),
                _ => "any".to_string(),
            },
            ifindex: self.ifindex,
            pid: (self.app_pid != 0).then_some(self.app_pid),
            tgid: (self.app_tgid != 0).then_some(self.app_tgid),
            uid: (self.app_uid != 0).then_some(self.app_uid),
            comm: {
                let comm = decode_task_comm(&self.app_comm);
                (!comm.is_empty()).then_some(comm)
            },
            app_id,
            rule_id: Some(stable_rule_id),
        }
    }
}

/// Hash one stable rule or policy identifier into the dataplane wire format.
#[must_use]
pub fn stable_id_hash(value: &str) -> u64 {
    let mut hasher = std::hash::DefaultHasher::new();
    std::hash::Hash::hash(&value, &mut hasher);
    hasher.finish()
}

/// Decode a stable userspace app id from dataplane task identity fields.
#[must_use]
pub fn decode_app_id(
    uid: u32,
    comm: &[u8; TASK_COMM_LEN],
    packages: Option<&AndroidPackageMap>,
) -> Option<String> {
    let comm = decode_task_comm(comm);
    let identity = resolve_observed_identity(
        packages,
        (!comm.is_empty()).then_some(comm.as_str()),
        (uid != 0).then_some(uid),
    );
    (identity.identity_type != crate::identity::model::IdentityType::Unknown)
        .then_some(identity.app_id)
}

/// Decode a zero-padded task command into a string.
#[must_use]
pub fn decode_task_comm(comm: &[u8; TASK_COMM_LEN]) -> String {
    let end = comm
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(TASK_COMM_LEN);
    String::from_utf8_lossy(&comm[..end]).trim().to_string()
}

fn encode_addr(value: &AddressMatch) -> Option<(u32, u32)> {
    match value {
        AddressMatch::Any => Some((0, 0)),
        AddressMatch::Ip(IpAddr::V4(ip)) => Some((u32::from(*ip), u32::MAX)),
        AddressMatch::Ip(IpAddr::V6(_)) => None,
        AddressMatch::Cidr(cidr) => parse_ipv4_cidr(cidr),
    }
}

fn parse_ipv4_cidr(cidr: &str) -> Option<(u32, u32)> {
    let (addr, prefix) = cidr.split_once('/')?;
    let addr = addr.parse::<Ipv4Addr>().ok()?;
    let prefix = prefix.parse::<u32>().ok()?;
    if prefix > 32 {
        return None;
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Some((u32::from(addr), mask))
}

fn encode_port_start(value: &PortMatch) -> u16 {
    match value {
        PortMatch::Any => 0,
        PortMatch::Single(port) => *port,
        PortMatch::Range(range) => *range.start(),
    }
}

fn encode_port_end(value: &PortMatch) -> u16 {
    match value {
        PortMatch::Any => 0,
        PortMatch::Single(port) => *port,
        PortMatch::Range(range) => *range.end(),
    }
}

fn encode_protocol(proto: Protocol) -> u8 {
    match proto {
        Protocol::Any => 0,
        Protocol::Tcp => 6,
        Protocol::Udp => 17,
    }
}

fn encode_action(action: TupleAction) -> u8 {
    match action {
        TupleAction::Allow => 0,
        TupleAction::Alert => 1,
        TupleAction::Block => 2,
        TupleAction::IngressObserve => 3,
        TupleAction::BlockSilent => 4,
    }
}

fn encode_policy_action(action: PolicyAction) -> u8 {
    match action {
        PolicyAction::Allow => 1,
        PolicyAction::Deny => 2,
    }
}

fn encode_direction(direction: crate::rule::model::Direction) -> u8 {
    match direction {
        crate::rule::model::Direction::Ingress => 0,
        crate::rule::model::Direction::Egress => 1,
    }
}

fn encode_identity(value: &str) -> [u8; TASK_COMM_LEN] {
    let mut encoded = [0; TASK_COMM_LEN];
    let bytes = value.as_bytes();
    let len = bytes.len().min(TASK_COMM_LEN);
    encoded[..len].copy_from_slice(&bytes[..len]);
    encoded
}

fn encode_interface_scope(scope: &InterfaceScope) -> Result<(u32, u8)> {
    match scope {
        InterfaceScope::All => Ok((0, NETWORK_SCOPE_ALL)),
        InterfaceScope::Device(device) => {
            let ifindex = interface_ifindex(device)
                .ok_or_else(|| anyhow!("interface scope {device} could not be resolved"))?;
            Ok((ifindex, encode_network_scope_from_name(device)))
        }
        InterfaceScope::Network(scope) => Ok((0, encode_network_scope(*scope))),
    }
}

fn encode_network_scope(scope: NetworkScope) -> u8 {
    match scope {
        NetworkScope::All => NETWORK_SCOPE_ALL,
        NetworkScope::Wifi => NETWORK_SCOPE_WIFI,
        NetworkScope::Mobile => NETWORK_SCOPE_MOBILE,
    }
}

fn encode_network_scope_from_name(name: &str) -> u8 {
    match classify_interface(name) {
        crate::identity::interface_map::NetworkClass::Wifi => NETWORK_SCOPE_WIFI,
        crate::identity::interface_map::NetworkClass::Mobile => NETWORK_SCOPE_MOBILE,
        crate::identity::interface_map::NetworkClass::Other => NETWORK_SCOPE_ALL,
    }
}

fn interface_ifindex(name: &str) -> Option<u32> {
    let path = PathBuf::from("/sys/class/net").join(name).join("ifindex");
    let value = fs::read_to_string(path).ok()?;
    value.trim().parse::<u32>().ok()
}

#[cfg(feature = "ebpf")]
unsafe impl aya::Pod for RuleV4 {}
#[cfg(feature = "ebpf")]
unsafe impl aya::Pod for AppPolicyEntry {}
#[cfg(feature = "ebpf")]
unsafe impl aya::Pod for TrafficPolicyEntry {}
#[cfg(feature = "ebpf")]
unsafe impl aya::Pod for RuleConfig {}
#[cfg(feature = "ebpf")]
unsafe impl aya::Pod for WireFactEvent {}
#[cfg(feature = "ebpf")]
unsafe impl aya::Pod for GlobalStats {}
#[cfg(feature = "ebpf")]
unsafe impl aya::Pod for AppTrafficKey {}
#[cfg(feature = "ebpf")]
unsafe impl aya::Pod for AppTrafficValue {}
#[cfg(feature = "ebpf")]
unsafe impl aya::Pod for FlowOwnershipKey {}
#[cfg(feature = "ebpf")]
unsafe impl aya::Pod for FlowOwnershipValue {}
#[cfg(feature = "ebpf")]
unsafe impl aya::Pod for InterfaceClassValue {}

/// Aggregate per-cpu global counters into a single snapshot.
#[must_use]
pub fn aggregate_global_counters(values: &[GlobalStats]) -> GlobalStats {
    values
        .iter()
        .copied()
        .fold(GlobalStats::default(), |mut acc, item| {
            acc.ingress_bytes = acc.ingress_bytes.saturating_add(item.ingress_bytes);
            acc.egress_bytes = acc.egress_bytes.saturating_add(item.egress_bytes);
            acc.ingress_packets = acc.ingress_packets.saturating_add(item.ingress_packets);
            acc.egress_packets = acc.egress_packets.saturating_add(item.egress_packets);
            acc
        })
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use crate::dataplane::events::{FactAction, FactEventKind};
    use crate::dataplane::stats::GlobalStats;
    use crate::identity::provider::AndroidPackageMap;
    use crate::rule::normalize::build_rule_set;

    use super::{
        AppPolicyEntry, CompiledDataplaneState, RuleV4, TASK_COMM_LEN, WireFactEvent,
        aggregate_global_counters, decode_app_id, decode_task_comm,
    };

    #[test]
    fn builds_compiled_ruleset_summary() {
        let compiled = CompiledDataplaneState::new("abc".to_string(), 1, 2, Some(10));
        assert_eq!(compiled.policy_rule_count, 2);
        assert_eq!(compiled.tuple_rule_count, 1);
        assert!(compiled.flow_ownership_enabled);
        assert_eq!(compiled.traffic_cycle_secs, Some(10));
    }

    #[test]
    fn converts_tuple_rule_to_wire_rule() {
        let ruleset = build_rule_set(
            "v1",
            "name=block,dip=10.0.0.1,dport=443,chain=output,action=block",
            None,
        )
        .expect("ruleset");
        let wire = RuleV4::from_firewall_rule(&ruleset.firewall_rules[0]).expect("wire rule");
        assert_ne!(wire.rule_id_hash, 0);
        assert_eq!(wire.dst_addr, u32::from(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(wire.dst_mask, u32::MAX);
        assert_eq!(wire.dst_port_start, 443);
        assert_eq!(wire.dst_port_end, 443);
        assert_eq!(wire.action, 2);
        assert_eq!(wire.direction, 1);
    }

    #[test]
    fn converts_program_policy_to_policy_entry() {
        let ruleset = build_rule_set("v1", "prog=test-client,allow=false", None).expect("ruleset");
        let crate::rule::model::FirewallRule::Program(rule) = &ruleset.firewall_rules[0] else {
            panic!("expected program rule");
        };
        let policy = AppPolicyEntry::from_program_rule(rule).expect("policy");
        let mut expected = [0; TASK_COMM_LEN];
        expected[..11].copy_from_slice(b"test-client");
        assert_ne!(policy.policy_id_hash, 0);
        assert_eq!(policy.match_uid, 0);
        assert_eq!(policy.identity, expected);
        assert_eq!(policy.network_scope, 0);
        assert_eq!(policy.scope_ifindex, 0);
        assert_eq!(policy.action, 2);
    }

    #[test]
    fn compiles_package_policy_to_uid_entries() {
        let ruleset = build_rule_set(
            "v1",
            "app_name=Browser,pkg=com.demo.browser,allow=false",
            None,
        )
        .expect("ruleset");
        let packages = AndroidPackageMap::parse_packages_list(
            "com.demo.browser 10123 0 /data/user/0/com.demo.browser default\n",
        )
        .expect("package list parsed");
        let crate::rule::model::FirewallRule::App(rule) = &ruleset.firewall_rules[0] else {
            panic!("expected app rule");
        };
        let policies = AppPolicyEntry::from_app_rule(rule, Some(&packages)).expect("policies");
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].match_uid, 10123);
        assert_eq!(policies[0].kind, super::POLICY_KIND_APP);
    }

    #[test]
    fn package_policy_requires_android_uid_mapping() {
        let ruleset = build_rule_set(
            "v1",
            "app_name=Browser,pkg=com.demo.browser,allow=false",
            None,
        )
        .expect("ruleset");
        let crate::rule::model::FirewallRule::App(rule) = &ruleset.firewall_rules[0] else {
            panic!("expected app rule");
        };
        let error = AppPolicyEntry::from_app_rule(rule, None).expect_err("missing mapping");
        assert!(
            error
                .to_string()
                .contains("requires Android package mapping")
        );
    }

    #[test]
    fn converts_wire_event_to_fact_event() {
        let mut comm = [0; TASK_COMM_LEN];
        comm[..4].copy_from_slice(b"curl");
        let event = WireFactEvent {
            event_time_secs: 42,
            rule_id_hash: 0xabc,
            bytes: 64,
            event_kind: 1,
            action: 2,
            proto: 6,
            reserved: [0; 5],
            ifindex: 2,
            app_uid: 1000,
            app_pid: 1001,
            app_tgid: 1000,
            src_ip: u32::from(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: u32::from(Ipv4Addr::new(8, 8, 8, 8)),
            src_port: 1234,
            dst_port: 443,
            rule_index: 7,
            app_comm: comm,
        };
        let fact = event.into_fact_event("abcd", None);
        assert_eq!(fact.kind, FactEventKind::EgressRuleMatch);
        assert_eq!(fact.action, FactAction::Block);
        assert_eq!(fact.event_time_secs, 42);
        assert_eq!(fact.rule_id.as_deref(), Some("rule-0000000000000abc"));
        assert_eq!(fact.pid, Some(1001));
        assert_eq!(fact.tgid, Some(1000));
        assert_eq!(fact.app_id.as_deref(), Some("prog:curl"));
    }

    #[test]
    fn converts_policy_deny_wire_event_to_fact_event() {
        let mut comm = [0; TASK_COMM_LEN];
        comm[..4].copy_from_slice(b"curl");
        let event = WireFactEvent {
            event_time_secs: 42,
            rule_id_hash: 0xdef,
            bytes: 64,
            event_kind: 2,
            action: 2,
            proto: 6,
            reserved: [0; 5],
            ifindex: 2,
            app_uid: 1000,
            app_pid: 1001,
            app_tgid: 1000,
            src_ip: u32::from(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: u32::from(Ipv4Addr::new(8, 8, 8, 8)),
            src_port: 1234,
            dst_port: 443,
            rule_index: 3,
            app_comm: comm,
        };
        let fact = event.into_fact_event("abcd", None);
        assert_eq!(fact.kind, FactEventKind::PolicyDeny);
        assert_eq!(fact.rule_id.as_deref(), Some("policy-0000000000000def"));
        assert_eq!(fact.app_id.as_deref(), Some("prog:curl"));
    }

    #[cfg(feature = "ebpf")]
    #[test]
    fn flow_ownership_types_are_pod_compatible() {
        let key = super::FlowOwnershipKey {
            src_ip: 1,
            dst_ip: 2,
            src_port: 3,
            dst_port: 4,
            proto: 6,
            reserved: [0; 3],
        };
        let value = super::FlowOwnershipValue {
            uid: 1000,
            pid: 1001,
            tgid: 1000,
            comm: [0; TASK_COMM_LEN],
        };
        let _: &[u8] = bytemuck::bytes_of(&key);
        let _: &[u8] = bytemuck::bytes_of(&value);
    }

    #[test]
    fn decodes_zero_padded_comm() {
        let mut comm = [0; TASK_COMM_LEN];
        comm[..3].copy_from_slice(b"ipm");
        assert_eq!(decode_task_comm(&comm), "ipm");
    }

    #[test]
    fn falls_back_to_uid_when_comm_missing() {
        assert_eq!(
            decode_app_id(1001, &[0; TASK_COMM_LEN], None),
            Some("uid:1001".to_string())
        );
    }

    #[test]
    fn prefers_package_from_android_uid_mapping_when_decoding() {
        let packages = AndroidPackageMap::parse_packages_list(
            "com.demo.browser 10123 0 /data/user/0/com.demo.browser default\n",
        )
        .expect("package list parsed");
        let mut comm = [0; TASK_COMM_LEN];
        comm[..4].copy_from_slice(b"curl");
        assert_eq!(
            decode_app_id(10123, &comm, Some(&packages)),
            Some("pkg:com.demo.browser".to_string())
        );
    }

    #[test]
    fn aggregates_per_cpu_counters() {
        let values = [
            GlobalStats {
                ingress_bytes: 10,
                egress_bytes: 20,
                ingress_packets: 1,
                egress_packets: 2,
            },
            GlobalStats {
                ingress_bytes: 1,
                egress_bytes: 2,
                ingress_packets: 3,
                egress_packets: 4,
            },
        ];
        let combined = aggregate_global_counters(&values);
        assert_eq!(combined.ingress_bytes, 11);
        assert_eq!(combined.egress_packets, 6);
    }
}
