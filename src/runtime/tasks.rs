//! Task helpers for daemon runtime actors.

use tokio::task::JoinHandle;
use tracing::warn;

/// Drain runtime tasks until all complete or the timeout expires.
pub async fn drain_tasks(handles: Vec<JoinHandle<()>>, timeout: std::time::Duration) {
    let drain_all = async {
        for handle in handles {
            if let Err(error) = handle.await {
                warn!(%error, "firewalld task join failed");
            }
        }
    };

    if tokio::time::timeout(timeout, drain_all).await.is_err() {
        warn!(?timeout, "firewalld task drain timed out");
    }
}
