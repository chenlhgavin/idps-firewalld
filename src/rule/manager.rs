//! Rule manager for normalized active rule versions.

use anyhow::{Result, bail};

use crate::rule::model::NormalizedRuleSet;
use crate::rule::normalize::build_rule_set;

/// Active normalized rules with last-good fallback semantics.
#[derive(Debug, Default)]
pub struct RuleManager {
    current: Option<NormalizedRuleSet>,
}

impl RuleManager {
    /// Return the current active rule set.
    #[must_use]
    pub fn current(&self) -> Option<&NormalizedRuleSet> {
        self.current.as_ref()
    }

    /// Load a new candidate ruleset and promote it if valid.
    ///
    /// # Errors
    ///
    /// Returns an error when normalization fails or the version is empty.
    ///
    /// # Panics
    ///
    /// Panics only if the freshly stored ruleset cannot be read back from the
    /// in-memory manager, which would indicate internal state corruption.
    pub fn load_candidate(
        &mut self,
        version: impl Into<String>,
        firewall_payload: &str,
        traffic_payload: Option<&str>,
    ) -> Result<&NormalizedRuleSet> {
        let version = version.into();
        if version.trim().is_empty() {
            bail!("ruleset version must not be empty");
        }
        let ruleset = build_rule_set(version, firewall_payload, traffic_payload)?;
        self.current = Some(ruleset);
        Ok(self.current.as_ref().expect("ruleset stored"))
    }
}

#[cfg(test)]
mod tests {
    use super::RuleManager;

    #[test]
    fn preserves_last_good_ruleset_on_failure() {
        let mut manager = RuleManager::default();
        manager
            .load_candidate("v1", "prog=test-client,allow=true", Some("{\"cycle\": 10}"))
            .expect("initial ruleset");

        let error = manager
            .load_candidate(
                "v2",
                "prog=test-client,allow=maybe",
                Some("{\"cycle\": 10}"),
            )
            .expect_err("invalid ruleset rejected");
        assert!(error.to_string().contains("unsupported policy allow value"));
        assert_eq!(manager.current().expect("last good").version, "v1");
    }

    #[test]
    fn rejects_empty_version() {
        let mut manager = RuleManager::default();
        let error = manager
            .load_candidate("", "prog=test-client,allow=true", None)
            .expect_err("empty version rejected");
        assert!(error.to_string().contains("must not be empty"));
    }
}
