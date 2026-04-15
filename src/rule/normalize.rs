//! Parsing and normalization for `firewall(fun=1)` and `traffic(fun=4)` rules.

use std::collections::BTreeMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::net::IpAddr;

use anyhow::{Result, anyhow, bail};

use crate::rule::model::{
    AddressMatch, AppPolicyRule, Direction, FirewallRule, InterfaceScope, NetworkScope,
    NormalizedRuleSet, PolicyAction, PortMatch, ProgramPolicyRule, Protocol, RuleMetadata,
    RuleStatus, TrafficPolicy, TupleAction, TupleRule,
};

const MIN_TRAFFIC_CYCLE_SECS: u64 = 5;

/// Normalize a raw firewall payload into internal firewall rules.
///
/// # Errors
///
/// Returns an error when any line is malformed or contains unsupported values.
pub fn normalize_firewall_rules(payload: &str) -> Result<Vec<FirewallRule>> {
    payload
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(index, line)| parse_firewall_line(line, index))
        .filter_map(|rule| match rule {
            Ok(Some(rule)) => Some(Ok(rule)),
            Ok(None) => None,
            Err(error) => Some(Err(error)),
        })
        .collect()
}

/// Normalize a raw traffic payload into an internal traffic policy.
///
/// # Errors
///
/// Returns an error when the payload does not contain a valid `cycle` field.
pub fn normalize_traffic_policy(payload: &str) -> Result<TrafficPolicy> {
    let cycle = extract_cycle(payload)?;
    if cycle < MIN_TRAFFIC_CYCLE_SECS {
        bail!("traffic cycle must be at least {MIN_TRAFFIC_CYCLE_SECS} seconds");
    }
    Ok(TrafficPolicy {
        metadata: build_rule_metadata(payload, 0, true),
        cycle_secs: cycle,
    })
}

/// Build a normalized rule set with version metadata.
///
/// # Errors
///
/// Returns an error when firewall or traffic normalization fails.
pub fn build_rule_set(
    version: impl Into<String>,
    firewall_payload: &str,
    traffic_payload: Option<&str>,
) -> Result<NormalizedRuleSet> {
    let firewall_rules = normalize_firewall_rules(firewall_payload)?;
    let traffic_policy = traffic_payload.map(normalize_traffic_policy).transpose()?;
    let checksum = checksum_parts(firewall_payload, traffic_payload.unwrap_or_default());
    Ok(NormalizedRuleSet {
        version: version.into(),
        checksum,
        firewall_rules,
        traffic_policy,
    })
}

fn parse_firewall_line(line: &str, index: usize) -> Result<Option<FirewallRule>> {
    let fields = parse_key_values(line)?;
    let metadata = build_rule_metadata(line, index, false);
    if fields.contains_key("pkg") {
        let Some(action) = parse_policy_action(required(&fields, "allow")?)? else {
            return Ok(None);
        };
        return Ok(Some(FirewallRule::App(AppPolicyRule {
            metadata: metadata.clone(),
            app_name: fields.get("app_name").cloned().unwrap_or_default(),
            package: required(&fields, "pkg")?.to_string(),
            interface_scope: parse_interface_scope(&fields)?,
            action,
        })));
    }

    if fields.contains_key("prog") && fields.contains_key("allow") && !fields.contains_key("chain")
    {
        let Some(action) = parse_policy_action(required(&fields, "allow")?)? else {
            return Ok(None);
        };
        return Ok(Some(FirewallRule::Program(ProgramPolicyRule {
            metadata: metadata.clone(),
            program: required(&fields, "prog")?.to_string(),
            interface_scope: parse_interface_scope(&fields)?,
            action,
        })));
    }

    let Some(action) = parse_tuple_action(required(&fields, "action")?)? else {
        return Ok(None);
    };

    Ok(Some(FirewallRule::Tuple(TupleRule {
        metadata,
        name: fields.get("name").cloned(),
        description: fields.get("desc").cloned(),
        direction: parse_direction(required(&fields, "chain")?)?,
        src_addr: parse_address(fields.get("sip").map_or("*", String::as_str))?,
        dst_addr: parse_address(fields.get("dip").map_or("*", String::as_str))?,
        src_port: parse_port(fields.get("sport").map_or("*", String::as_str))?,
        dst_port: parse_port(fields.get("dport").map_or("*", String::as_str))?,
        protocol: parse_protocol(fields.get("proto").map_or("*", String::as_str))?,
        action,
    })))
}

fn parse_key_values(line: &str) -> Result<BTreeMap<String, String>> {
    let mut fields = BTreeMap::new();
    for token in line.split(',') {
        let token = token.trim().trim_start_matches('!');
        let (key, value) = token
            .split_once('=')
            .ok_or_else(|| anyhow!("rule token is missing '=': {token}"))?;
        fields.insert(key.trim().to_string(), value.trim().to_string());
    }
    Ok(fields)
}

fn required<'a>(fields: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str> {
    fields
        .get(key)
        .map(String::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow!("missing required field '{key}'"))
}

fn parse_policy_action(value: &str) -> Result<Option<PolicyAction>> {
    match value {
        "true" | "allow" => Ok(Some(PolicyAction::Allow)),
        "false" | "deny" => Ok(Some(PolicyAction::Deny)),
        "delete" | "NULL" | "null" => Ok(None),
        _ => bail!("unsupported policy allow value: {value}"),
    }
}

fn parse_tuple_action(value: &str) -> Result<Option<TupleAction>> {
    match value {
        "allow" | "P" => Ok(Some(TupleAction::Allow)),
        "LP" => Ok(Some(TupleAction::IngressObserve)),
        "alert" => Ok(Some(TupleAction::Alert)),
        "block" | "LD" => Ok(Some(TupleAction::Block)),
        "NLD" => Ok(Some(TupleAction::BlockSilent)),
        "delete" | "NULL" | "null" => Ok(None),
        _ => bail!("unsupported tuple action: {value}"),
    }
}

fn parse_interface_scope(fields: &BTreeMap<String, String>) -> Result<InterfaceScope> {
    let device = fields
        .get("dev")
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty() && *value != "*");
    let network = fields
        .get("network")
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty() && *value != "*");

    if device.is_some() && network.is_some() {
        bail!("policy rule cannot define both dev and network scope");
    }

    if let Some(device) = device {
        return Ok(InterfaceScope::Device(device.to_string()));
    }

    if let Some(network) = network {
        return Ok(InterfaceScope::Network(parse_network_scope(network)?));
    }

    Ok(InterfaceScope::All)
}

fn parse_network_scope(value: &str) -> Result<NetworkScope> {
    match value.to_ascii_lowercase().as_str() {
        "all" => Ok(NetworkScope::All),
        "wifi" => Ok(NetworkScope::Wifi),
        "mobile" | "cellular" => Ok(NetworkScope::Mobile),
        _ => bail!("unsupported network scope: {value}"),
    }
}

fn parse_direction(value: &str) -> Result<Direction> {
    match value {
        "localin" | "input" => Ok(Direction::Ingress),
        "output" | "localout" => Ok(Direction::Egress),
        _ => bail!("unsupported chain value: {value}"),
    }
}

fn parse_protocol(value: &str) -> Result<Protocol> {
    match value {
        "*" | "any" | "" => Ok(Protocol::Any),
        "tcp" => Ok(Protocol::Tcp),
        "udp" => Ok(Protocol::Udp),
        _ => bail!("unsupported protocol: {value}"),
    }
}

fn parse_address(value: &str) -> Result<AddressMatch> {
    if value == "*" || value.is_empty() {
        return Ok(AddressMatch::Any);
    }
    if value.contains('/') {
        return Ok(AddressMatch::Cidr(value.to_string()));
    }
    let ip = value
        .parse::<IpAddr>()
        .map_err(|error| anyhow!("invalid IP address '{value}': {error}"))?;
    Ok(AddressMatch::Ip(ip))
}

fn parse_port(value: &str) -> Result<PortMatch> {
    if value == "*" || value.is_empty() {
        return Ok(PortMatch::Any);
    }
    if let Some((start, end)) = value.split_once('-') {
        let start = parse_port_number(start)?;
        let end = parse_port_number(end)?;
        if start > end {
            bail!("invalid port range: {value}");
        }
        return Ok(PortMatch::Range(start..=end));
    }
    Ok(PortMatch::Single(parse_port_number(value)?))
}

fn parse_port_number(value: &str) -> Result<u16> {
    value
        .parse::<u16>()
        .map_err(|error| anyhow!("invalid port '{value}': {error}"))
}

fn extract_cycle(payload: &str) -> Result<u64> {
    let digits = payload
        .split(|ch: char| !ch.is_ascii_digit())
        .find(|part| !part.is_empty())
        .ok_or_else(|| anyhow!("traffic payload is missing cycle"))?;
    digits
        .parse::<u64>()
        .map_err(|error| anyhow!("invalid traffic cycle '{digits}': {error}"))
}

fn checksum_parts(firewall_payload: &str, traffic_payload: &str) -> String {
    let mut hasher = DefaultHasher::new();
    firewall_payload.hash(&mut hasher);
    traffic_payload.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

fn build_rule_metadata(seed: &str, index: usize, traffic_policy: bool) -> RuleMetadata {
    let mut hasher = DefaultHasher::new();
    seed.hash(&mut hasher);
    index.hash(&mut hasher);
    traffic_policy.hash(&mut hasher);
    let hash = format!("{:016x}", hasher.finish());
    let kind = if traffic_policy {
        "traffic"
    } else if seed.contains("pkg=") || seed.contains("prog=") {
        "policy"
    } else {
        "tuple"
    };
    RuleMetadata {
        rule_id: format!("{kind}-{hash}"),
        policy_id: (kind == "policy").then(|| format!("policy-{hash}")),
        status: RuleStatus::Active,
        priority: i32::try_from(index).unwrap_or(i32::MAX),
        loaded_at: 0,
    }
}

#[cfg(test)]
mod tests {
    use crate::rule::model::{
        AddressMatch, Direction, FirewallRule, InterfaceScope, PolicyAction, PortMatch, Protocol,
        TupleAction,
    };

    use super::{build_rule_set, normalize_firewall_rules, normalize_traffic_policy};

    #[test]
    fn parses_app_rule() {
        let rules = normalize_firewall_rules("app_name=Browser,pkg=com.demo.browser,allow=true")
            .expect("parsed app rule");
        assert!(matches!(
            &rules[0],
            FirewallRule::App(rule)
                if rule.app_name == "Browser"
                    && rule.package == "com.demo.browser"
                    && rule.interface_scope == InterfaceScope::All
                    && rule.action == PolicyAction::Allow
        ));
    }

    #[test]
    fn parses_program_rule() {
        let rules =
            normalize_firewall_rules("prog=test-client,allow=false").expect("parsed program rule");
        assert!(matches!(
            &rules[0],
            FirewallRule::Program(rule)
                if rule.program == "test-client"
                    && rule.interface_scope == InterfaceScope::All
                    && rule.action == PolicyAction::Deny
        ));
    }

    #[test]
    fn parses_tuple_rule() {
        let rules = normalize_firewall_rules(
            "name=block-risk,desc=block risky connect,sip=*,sport=*,dip=172.16.1.100,dport=443,chain=output,action=block",
        )
        .expect("parsed tuple rule");
        assert!(matches!(
            &rules[0],
            FirewallRule::Tuple(rule)
                if rule.direction == Direction::Egress
                    && rule.dst_addr == AddressMatch::Ip("172.16.1.100".parse().expect("ip"))
                    && rule.dst_port == PortMatch::Single(443)
                    && rule.protocol == Protocol::Any
                    && rule.action == TupleAction::Block
        ));
    }

    #[test]
    fn parses_interface_scoped_program_rule() {
        let rules =
            normalize_firewall_rules("prog=test-client,dev=lo,allow=true").expect("parsed rule");
        assert!(matches!(
            &rules[0],
            FirewallRule::Program(rule)
                if rule.interface_scope == InterfaceScope::Device("lo".to_string())
        ));
    }

    #[test]
    fn skips_deleted_rules() {
        let rules = normalize_firewall_rules(
            "prog=test-client,allow=delete\nchain=output,dip=10.0.0.1,dport=53,action=NULL",
        )
        .expect("deleted rules skipped");
        assert!(rules.is_empty());
    }

    #[test]
    fn rejects_invalid_port_range() {
        let error = normalize_firewall_rules(
            "sip=*,sport=*,dip=*,dport=5001-5000,chain=output,action=allow",
        )
        .expect_err("invalid port range rejected");
        assert!(error.to_string().contains("invalid port range"));
    }

    #[test]
    fn parses_traffic_cycle() {
        let policy = normalize_traffic_policy("{\"cycle\": 1800}").expect("parsed traffic");
        assert_eq!(policy.cycle_secs, 1800);
    }

    #[test]
    fn rejects_traffic_cycle_below_minimum() {
        let error = normalize_traffic_policy("{\"cycle\": 4}").expect_err("cycle rejected");
        assert!(error.to_string().contains("at least 5 seconds"));
    }

    #[test]
    fn builds_versioned_rule_set() {
        let ruleset = build_rule_set("v1", "prog=test-client,allow=true", Some("{\"cycle\": 10}"))
            .expect("built ruleset");
        assert_eq!(ruleset.version, "v1");
        assert_eq!(ruleset.firewall_rules.len(), 1);
        assert_eq!(
            ruleset.traffic_policy.expect("traffic policy").cycle_secs,
            10
        );
        match &ruleset.firewall_rules[0] {
            FirewallRule::Program(rule) => {
                assert!(rule.metadata.rule_id.starts_with("policy-"));
                assert_eq!(rule.metadata.status, crate::rule::model::RuleStatus::Active);
            }
            _ => panic!("expected program rule"),
        }
        assert!(!ruleset.checksum.is_empty());
    }
}
