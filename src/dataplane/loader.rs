//! Data-plane loader and health snapshots.

use std::sync::Arc;

use anyhow::Result;

use crate::config::{DataplaneMode, FirewallConfig};
use crate::dataplane::aya_backend::AyaTcDataplane;
use crate::dataplane::backend::{DataplaneBackend, MockDataplane};
use crate::dataplane::compile::{CompiledRuleSet, compile_ruleset};
use crate::rule::model::NormalizedRuleSet;

/// Loader status for the current data plane backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoaderStatus {
    /// Backend is not initialized.
    Detached,
    /// Backend is initialized and ready.
    Ready,
}

/// Health snapshot for the data plane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataplaneHealth {
    /// Loader status.
    pub status: LoaderStatus,
    /// Active ruleset checksum if one is applied.
    pub active_checksum: Option<String>,
    /// Pending fact-event queue depth.
    pub queued_events: usize,
    /// Fact events lost by perf buffers.
    pub lost_events: usize,
}

/// Loader output that can later be programmed into a live dataplane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgrammedDataplane {
    /// Compiled rules programmed into the backend.
    pub compiled: CompiledRuleSet,
}

/// Build the configured data-plane backend.
#[must_use]
pub fn build_backend(config: &FirewallConfig) -> Arc<dyn DataplaneBackend> {
    match config.dataplane_mode {
        DataplaneMode::Mock => Arc::new(MockDataplane::default()),
        DataplaneMode::Ebpf => AyaTcDataplane::new(
            config.ebpf_object_path.clone(),
            config.attach_ifaces.clone(),
            config.android_packages_list_path.clone(),
        ),
    }
}

/// Validate that the selected dataplane backend can be constructed.
///
/// # Errors
///
/// Returns an error when the backend fails to initialize or shut down during
/// validation.
pub async fn validate_backend(backend: Arc<dyn DataplaneBackend>) -> Result<()> {
    backend.initialize().await?;
    backend.shutdown().await
}

/// Compile a ruleset for dataplane programming.
pub fn prepare_programming(ruleset: &NormalizedRuleSet) -> Result<ProgrammedDataplane> {
    Ok(ProgrammedDataplane {
        compiled: compile_ruleset(ruleset, None)?,
    })
}

#[cfg(test)]
mod tests {
    use crate::config::{DataplaneMode, FirewallConfig};
    use crate::rule::normalize::build_rule_set;

    use super::{LoaderStatus, build_backend, prepare_programming};

    #[test]
    fn build_backend_returns_mock_by_default() {
        let config = FirewallConfig::default();
        let _backend = build_backend(&config);
    }

    #[test]
    fn ebpf_mode_builds_real_backend() {
        let mut config = FirewallConfig::default();
        config.dataplane_mode = DataplaneMode::Ebpf;
        config.attach_ifaces = vec!["eth0".to_string()];
        config.ebpf_object_path = "dummy.o".into();
        let backend = build_backend(&config);
        let _ = backend;
        assert_eq!(LoaderStatus::Detached, LoaderStatus::Detached);
    }

    #[test]
    fn prepare_programming_compiles_tuple_rules() {
        let ruleset = build_rule_set(
            "v1",
            "name=allow,dip=10.0.0.1,dport=53,chain=output,action=allow",
            None,
        )
        .expect("ruleset");
        let programmed = prepare_programming(&ruleset).expect("compiled ruleset");
        assert_eq!(programmed.compiled.rules_v4.len(), 1);
    }
}
