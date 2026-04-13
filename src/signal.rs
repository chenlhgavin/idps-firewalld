//! Unix signal handling for graceful shutdown.

use anyhow::{Context, Result};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

/// Spawn a signal handler that cancels the supplied shutdown token.
pub fn spawn_signal_handler(shutdown: CancellationToken) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(error) = wait_for_signal(&shutdown).await {
            warn!(%error, "signal handler failed, forcing shutdown");
            shutdown.cancel();
        }
    })
}

async fn wait_for_signal(shutdown: &CancellationToken) -> Result<()> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sigterm = signal(SignalKind::terminate()).context("failed to register SIGTERM")?;
    let mut sigint = signal(SignalKind::interrupt()).context("failed to register SIGINT")?;

    tokio::select! {
        _ = sigterm.recv() => info!("received SIGTERM, initiating graceful shutdown"),
        _ = sigint.recv() => info!("received SIGINT, initiating graceful shutdown"),
    }

    shutdown.cancel();
    Ok(())
}

#[cfg(test)]
mod tests {
    use tokio_util::sync::CancellationToken;

    #[test]
    fn shutdown_token_propagates_to_child() {
        let token = CancellationToken::new();
        let child = token.child_token();
        token.cancel();
        assert!(child.is_cancelled());
    }
}
