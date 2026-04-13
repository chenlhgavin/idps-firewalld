//! Runtime orchestration for the firewall daemon.

pub mod state;
pub mod tasks;

use anyhow::{Result, bail};
use tracing::info;

use crate::app::FirewallAppState;
use crate::dataplane::backend::DataplaneBackend;

pub use state::RuntimePhase;

/// Run the stage-1 lifecycle with the provided data plane backend.
///
/// # Errors
///
/// Returns an error when a lifecycle transition is invalid or the data plane
/// backend fails to initialize or shut down.
pub async fn run_with_backend<B>(state: &FirewallAppState, backend: &B) -> Result<()>
where
    B: DataplaneBackend + ?Sized,
{
    transition(state, RuntimePhase::Bootstrap).await?;
    transition(state, RuntimePhase::Registering).await?;
    transition(state, RuntimePhase::RuleSyncing).await?;
    backend.initialize().await?;
    transition(state, RuntimePhase::DataPlaneReady).await?;
    transition(state, RuntimePhase::Running).await?;
    state.shutdown.cancelled().await;
    backend.shutdown().await?;
    transition(state, RuntimePhase::Shutdown).await
}

/// Move to a new lifecycle phase.
///
/// # Errors
///
/// Returns an error when the requested transition is not permitted by the
/// runtime lifecycle model.
pub async fn transition(state: &FirewallAppState, next: RuntimePhase) -> Result<()> {
    let mut phase = state.phase.write().await;
    if !phase.can_transition_to(next) {
        bail!("invalid firewalld phase transition: {phase:?} -> {next:?}");
    }
    info!(from = ?*phase, to = ?next, "firewalld phase transition");
    *phase = next;
    state.phase_notify.notify_waiters();
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::config::FirewallConfig;
    use crate::dataplane::backend::MockDataplane;

    #[tokio::test]
    async fn run_with_backend_reaches_shutdown_after_cancel() {
        let state = FirewallAppState::new(FirewallConfig::default());
        let backend = MockDataplane::default();
        let run_state = Arc::clone(&state);
        let handle = tokio::spawn(async move { run_with_backend(&run_state, &backend).await });
        state.wait_for_phase(RuntimePhase::Running).await;
        state.shutdown.cancel();
        handle
            .await
            .expect("runtime task joined")
            .expect("runtime completed");
        assert_eq!(state.current_phase().await, RuntimePhase::Shutdown);
    }

    #[tokio::test]
    async fn transition_rejects_invalid_phase_skip() {
        let state = FirewallAppState::new(FirewallConfig::default());
        let error = transition(&state, RuntimePhase::Running)
            .await
            .expect_err("transition failed");
        assert!(
            error
                .to_string()
                .contains("invalid firewalld phase transition")
        );
    }
}
