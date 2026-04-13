//! Shared application state for the firewall daemon.

use std::sync::Arc;

use tokio::sync::{Notify, RwLock};
use tokio_util::sync::CancellationToken;

use crate::config::FirewallConfig;
use crate::runtime::RuntimePhase;

/// Shared daemon state owned across runtime actors.
#[derive(Debug)]
pub struct FirewallAppState {
    /// Loaded daemon configuration.
    pub config: FirewallConfig,
    /// Lifecycle phase.
    pub phase: RwLock<RuntimePhase>,
    /// Notification emitted after each phase change.
    pub phase_notify: Arc<Notify>,
    /// Coordinated graceful-shutdown token.
    pub shutdown: CancellationToken,
}

impl FirewallAppState {
    /// Build a new shared application state.
    pub fn new(config: FirewallConfig) -> Arc<Self> {
        Arc::new(Self {
            config,
            phase: RwLock::new(RuntimePhase::Init),
            phase_notify: Arc::new(Notify::new()),
            shutdown: CancellationToken::new(),
        })
    }

    /// Return the current lifecycle phase.
    pub async fn current_phase(&self) -> RuntimePhase {
        *self.phase.read().await
    }

    /// Wait until the daemon reaches the requested lifecycle phase.
    pub async fn wait_for_phase(&self, target: RuntimePhase) {
        loop {
            if self.current_phase().await == target {
                return;
            }
            self.phase_notify.notified().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::FirewallAppState;
    use crate::config::FirewallConfig;
    use crate::runtime::{RuntimePhase, transition};

    #[tokio::test]
    async fn wait_for_phase_returns_after_transition() {
        let state = FirewallAppState::new(FirewallConfig::default());
        let waiter = {
            let state = state.clone();
            tokio::spawn(async move {
                state.wait_for_phase(RuntimePhase::Bootstrap).await;
            })
        };
        transition(&state, RuntimePhase::Bootstrap)
            .await
            .expect("phase transition succeeded");
        waiter.await.expect("waiter joined");
    }
}
