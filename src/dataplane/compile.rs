//! Compile normalized rules into dataplane-ready summaries.

use anyhow::{Result, bail};

use crate::dataplane::maps::{
    AppPolicyEntry, CompiledDataplaneState, MAX_POLICY_ENTRIES, MAX_RULE_ENTRIES, RuleConfig,
    RuleV4, TrafficPolicyEntry, stable_id_hash,
};
use crate::identity::provider::AndroidPackageMap;
use crate::rule::model::{FirewallRule, NormalizedRuleSet};

/// Compiled rule payload ready to program into the dataplane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledRuleSet {
    /// Summary of the compiled ruleset.
    pub summary: CompiledDataplaneState,
    /// Active tuple rules encoded for the dataplane.
    pub rules_v4: Vec<RuleV4>,
    /// Active app/program policies encoded for the dataplane.
    pub app_policies: Vec<AppPolicyEntry>,
    /// Stable rule ids by dataplane tuple-rule slot.
    pub tuple_rule_ids: Vec<String>,
    /// Stable policy ids by dataplane policy slot.
    pub policy_ids: Vec<String>,
    /// Encoded traffic policy entry when available.
    pub traffic_policy: Option<TrafficPolicyEntry>,
    /// Loader rule config.
    pub config: RuleConfig,
}

/// Compile a normalized ruleset into the dataplane summary used by the loader.
///
/// Package policies are resolved through the Android package registry when
/// available. Package rules without authoritative UID mappings are rejected.
pub fn compile_ruleset(
    ruleset: &NormalizedRuleSet,
    packages: Option<&AndroidPackageMap>,
) -> Result<CompiledRuleSet> {
    let rules_v4: Vec<RuleV4> = ruleset
        .firewall_rules
        .iter()
        .filter_map(RuleV4::from_firewall_rule)
        .collect();

    let mut app_policies = Vec::new();
    let mut policy_ids = Vec::new();
    for rule in &ruleset.firewall_rules {
        match rule {
            FirewallRule::App(rule) => {
                let policy_id = rule
                    .metadata
                    .policy_id
                    .clone()
                    .unwrap_or_else(|| rule.metadata.rule_id.clone());
                let entries = AppPolicyEntry::from_app_rule(rule, packages)?;
                policy_ids.extend(std::iter::repeat_n(policy_id, entries.len()));
                app_policies.extend(entries);
            }
            FirewallRule::Program(rule) => {
                let policy_id = rule
                    .metadata
                    .policy_id
                    .clone()
                    .unwrap_or_else(|| rule.metadata.rule_id.clone());
                app_policies.push(AppPolicyEntry::from_program_rule(rule)?);
                policy_ids.push(policy_id);
            }
            FirewallRule::Tuple(_) => {}
        }
    }

    if rules_v4.len() > MAX_RULE_ENTRIES {
        bail!(
            "ruleset contains {} tuple rules but dataplane supports at most {}",
            rules_v4.len(),
            MAX_RULE_ENTRIES
        );
    }
    if app_policies.len() > MAX_POLICY_ENTRIES {
        bail!(
            "ruleset contains {} app policies but dataplane supports at most {}",
            app_policies.len(),
            MAX_POLICY_ENTRIES
        );
    }

    let tuple_rule_ids = ruleset
        .firewall_rules
        .iter()
        .filter_map(|rule| match rule {
            FirewallRule::Tuple(rule) => Some(rule.metadata.rule_id.clone()),
            FirewallRule::App(_) | FirewallRule::Program(_) => None,
        })
        .collect();

    let traffic_policy = ruleset
        .traffic_policy
        .as_ref()
        .map(|policy| TrafficPolicyEntry {
            policy_id_hash: stable_id_hash(&policy.metadata.rule_id),
            cycle_secs: policy.cycle_secs,
        });

    let policy_count = app_policies.len().try_into().unwrap_or(u32::MAX);
    let checksum_low = ruleset.checksum.chars().take(16).collect::<String>();
    let checksum_low = u64::from_str_radix(&checksum_low, 16).unwrap_or(0);

    Ok(CompiledRuleSet {
        summary: CompiledDataplaneState::new(
            ruleset.checksum.clone(),
            rules_v4.len(),
            app_policies.len(),
            ruleset
                .traffic_policy
                .as_ref()
                .map(|policy| policy.cycle_secs),
        ),
        app_policies,
        tuple_rule_ids,
        policy_ids,
        traffic_policy,
        config: RuleConfig {
            checksum_low,
            active_slot: 0,
            rule_count: rules_v4.len().try_into().unwrap_or(u32::MAX),
            policy_count,
            reserved: 0,
        },
        rules_v4,
    })
}

#[cfg(test)]
mod tests {
    use crate::identity::provider::AndroidPackageMap;
    use crate::rule::normalize::build_rule_set;

    use super::compile_ruleset;

    #[test]
    fn compiles_tuple_and_program_rules_for_dataplane() {
        let ruleset = build_rule_set(
            "v1",
            "prog=test-client,allow=true\nname=allow,dip=10.0.0.1,dport=53,chain=output,action=allow",
            Some("{\"cycle\": 10}"),
        )
        .expect("ruleset");
        let compiled = compile_ruleset(&ruleset, None).expect("compiled ruleset");
        assert_eq!(compiled.rules_v4.len(), 1);
        assert_eq!(compiled.app_policies.len(), 1);
        assert_eq!(compiled.app_policies[0].network_scope, 0);
        assert_eq!(compiled.app_policies[0].scope_ifindex, 0);
        assert!(compiled.summary.flow_ownership_enabled);
        assert_eq!(
            compiled.traffic_policy.expect("traffic policy").cycle_secs,
            10
        );
        assert_eq!(compiled.tuple_rule_ids.len(), 1);
        assert_eq!(compiled.policy_ids.len(), 1);
        assert!(compiled.tuple_rule_ids[0].starts_with("tuple-"));
        assert!(compiled.policy_ids[0].starts_with("policy-"));
        assert_eq!(compiled.config.rule_count, 1);
        assert_eq!(compiled.config.policy_count, 1);
    }

    #[test]
    fn compiles_package_policies_to_uid_matches() {
        let ruleset = build_rule_set(
            "v1",
            "app_name=Browser,pkg=com.demo.browser,allow=false\nprog=test-client,allow=true",
            None,
        )
        .expect("ruleset");
        let packages = AndroidPackageMap::parse_packages_list(
            "com.demo.browser 10123 0 /data/user/0/com.demo.browser default\n",
        )
        .expect("package list parsed");

        let compiled = compile_ruleset(&ruleset, Some(&packages)).expect("compiled ruleset");
        assert_eq!(compiled.app_policies.len(), 2);
        assert_eq!(compiled.policy_ids.len(), 2);
        assert_eq!(compiled.app_policies[0].match_uid, 10123);
        assert_eq!(compiled.config.policy_count, 2);
    }

    #[test]
    fn rejects_package_policies_without_android_mapping() {
        let ruleset = build_rule_set(
            "v1",
            "app_name=Browser,pkg=com.demo.browser,allow=false",
            None,
        )
        .expect("ruleset");

        let error = compile_ruleset(&ruleset, None).expect_err("compile rejected");
        assert!(
            error
                .to_string()
                .contains("requires Android package mapping")
        );
    }
}
