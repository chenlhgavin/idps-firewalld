//! Data plane backend abstraction.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Result, bail};

use crate::dataplane::events::FactEvent;
use crate::dataplane::loader::{DataplaneHealth, LoaderStatus};
use crate::dataplane::stats::{AppTrafficSample, GlobalStats};
use crate::rule::model::NormalizedRuleSet;

/// Boxed future returned by data plane trait methods.
pub type DataplaneFuture<'a, T = ()> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

/// Data plane lifecycle backend.
pub trait DataplaneBackend: Send + Sync {
    /// Initialize and attach the backend.
    fn initialize(&self) -> DataplaneFuture<'_>;

    /// Shut the backend down and release resources.
    fn shutdown(&self) -> DataplaneFuture<'_>;

    /// Apply a normalized ruleset to the backend.
    fn apply_ruleset(&self, ruleset: &NormalizedRuleSet) -> DataplaneFuture<'_>;

    /// Read the latest global traffic counters.
    fn read_global_stats(&self) -> DataplaneFuture<'_, GlobalStats>;

    /// Read the latest per-app traffic samples.
    fn read_app_samples(&self) -> DataplaneFuture<'_, Vec<AppTrafficSample>>;

    /// Drain currently available fact events.
    fn drain_events(&self) -> DataplaneFuture<'_, Vec<FactEvent>>;

    /// Return dataplane health.
    fn health(&self) -> DataplaneHealth;
}

/// Mock data plane used before privileged eBPF support is available.
#[derive(Debug, Default)]
pub struct MockDataplane {
    initialized: AtomicBool,
    fail_apply: AtomicBool,
}

impl MockDataplane {
    /// Return whether the mock backend has been initialized.
    #[must_use]
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    /// Configure whether `apply_ruleset` should fail.
    pub fn set_fail_apply(&self, enabled: bool) {
        self.fail_apply.store(enabled, Ordering::SeqCst);
    }
}

impl DataplaneBackend for MockDataplane {
    fn initialize(&self) -> DataplaneFuture<'_> {
        Box::pin(async move {
            self.initialized.store(true, Ordering::SeqCst);
            Ok(())
        })
    }

    fn shutdown(&self) -> DataplaneFuture<'_> {
        Box::pin(async move {
            self.initialized.store(false, Ordering::SeqCst);
            Ok(())
        })
    }

    fn apply_ruleset(&self, _ruleset: &NormalizedRuleSet) -> DataplaneFuture<'_> {
        Box::pin(async move {
            if !self.is_initialized() {
                bail!("mock dataplane must be initialized before applying rules");
            }
            if self.fail_apply.load(Ordering::SeqCst) {
                bail!("mock dataplane apply failure");
            }
            Ok(())
        })
    }

    fn read_global_stats(&self) -> DataplaneFuture<'_, GlobalStats> {
        Box::pin(async move { Ok(GlobalStats::default()) })
    }

    fn read_app_samples(&self) -> DataplaneFuture<'_, Vec<AppTrafficSample>> {
        Box::pin(async move { Ok(Vec::new()) })
    }

    fn drain_events(&self) -> DataplaneFuture<'_, Vec<FactEvent>> {
        Box::pin(async move { Ok(Vec::new()) })
    }

    fn health(&self) -> DataplaneHealth {
        DataplaneHealth {
            status: if self.is_initialized() {
                LoaderStatus::Ready
            } else {
                LoaderStatus::Detached
            },
            active_checksum: None,
            queued_events: 0,
            lost_events: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DataplaneBackend, MockDataplane};

    #[tokio::test]
    async fn mock_dataplane_tracks_lifecycle() {
        let backend = MockDataplane::default();
        assert!(!backend.is_initialized());
        backend.initialize().await.expect("initialize");
        assert!(backend.is_initialized());
        backend.shutdown().await.expect("shutdown");
        assert!(!backend.is_initialized());
    }
}
