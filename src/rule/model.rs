//! Normalized firewall and traffic rule models.

use std::net::IpAddr;
use std::ops::RangeInclusive;

/// Stable rule metadata shared by every normalized rule variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleMetadata {
    /// Stable business rule id.
    pub rule_id: String,
    /// Stable policy id used by app/program policy rules.
    pub policy_id: Option<String>,
    /// External rule status.
    pub status: RuleStatus,
    /// Rule priority, lower values are evaluated first when supported.
    pub priority: i32,
    /// Load timestamp in seconds.
    pub loaded_at: u64,
}

/// Normalized rule status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleStatus {
    /// Rule is active.
    Active,
    /// Rule is disabled.
    Disabled,
}

impl RuleStatus {
    /// Return the stable storage representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
        }
    }
}

/// Parsed firewall rule variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirewallRule {
    /// Application allow/deny policy.
    App(AppPolicyRule),
    /// Program allow/deny policy.
    Program(ProgramPolicyRule),
    /// Five-tuple access control rule.
    Tuple(TupleRule),
}

/// Internal action for allow/deny style policies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyAction {
    /// Permit traffic.
    Allow,
    /// Deny traffic.
    Deny,
}

/// Scope used by app/program connectivity policies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterfaceScope {
    /// Match all interfaces.
    All,
    /// Match one concrete device name.
    Device(String),
    /// Match one logical network class.
    Network(NetworkScope),
}

/// Logical network class used by policy scopes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkScope {
    /// Match any network type.
    All,
    /// Match Wi-Fi interfaces.
    Wifi,
    /// Match mobile/cellular interfaces.
    Mobile,
}

/// Internal action for tuple rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TupleAction {
    /// Permit traffic.
    Allow,
    /// Alert but allow traffic.
    Alert,
    /// Record an ingress detection event but allow the packet.
    IngressObserve,
    /// Block traffic and emit a business-visible event.
    Block,
    /// Block traffic without emitting a normal fact event.
    BlockSilent,
}

/// Normalized packet direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Inbound traffic.
    Ingress,
    /// Outbound traffic.
    Egress,
}

/// Normalized transport protocol selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// TCP traffic.
    Tcp,
    /// UDP traffic.
    Udp,
    /// Any protocol.
    Any,
}

/// Normalized address selector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressMatch {
    /// Match any address.
    Any,
    /// Match a concrete IP address.
    Ip(IpAddr),
    /// Match a CIDR prefix represented as the original string.
    Cidr(String),
}

/// Normalized port selector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortMatch {
    /// Match any port.
    Any,
    /// Match a concrete port.
    Single(u16),
    /// Match an inclusive port range.
    Range(RangeInclusive<u16>),
}

/// Application policy rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppPolicyRule {
    /// Stable metadata.
    pub metadata: RuleMetadata,
    /// Optional display name.
    pub app_name: String,
    /// Unique package identifier.
    pub package: String,
    /// Interface scope for the policy.
    pub interface_scope: InterfaceScope,
    /// Allow or deny behavior.
    pub action: PolicyAction,
}

/// Program policy rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramPolicyRule {
    /// Stable metadata.
    pub metadata: RuleMetadata,
    /// Executable or program name.
    pub program: String,
    /// Interface scope for the policy.
    pub interface_scope: InterfaceScope,
    /// Allow or deny behavior.
    pub action: PolicyAction,
}

/// Five-tuple firewall rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TupleRule {
    /// Stable metadata.
    pub metadata: RuleMetadata,
    /// Optional display name.
    pub name: Option<String>,
    /// Optional display description.
    pub description: Option<String>,
    /// Direction selector.
    pub direction: Direction,
    /// Source address selector.
    pub src_addr: AddressMatch,
    /// Destination address selector.
    pub dst_addr: AddressMatch,
    /// Source port selector.
    pub src_port: PortMatch,
    /// Destination port selector.
    pub dst_port: PortMatch,
    /// Transport protocol selector.
    pub protocol: Protocol,
    /// Enforcement action.
    pub action: TupleAction,
}

/// Normalized traffic reporting policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrafficPolicy {
    /// Stable metadata.
    pub metadata: RuleMetadata,
    /// Reporting cycle in seconds.
    pub cycle_secs: u64,
}

/// Active normalized rule set with version metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedRuleSet {
    /// Logical ruleset version.
    pub version: String,
    /// Human-readable checksum over the raw payload.
    pub checksum: String,
    /// Parsed firewall rules.
    pub firewall_rules: Vec<FirewallRule>,
    /// Parsed traffic policy, if present.
    pub traffic_policy: Option<TrafficPolicy>,
}
