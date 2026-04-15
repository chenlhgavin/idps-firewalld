//! Data-plane polling helpers.

use anyhow::Result;

use crate::dataplane::backend::DataplaneBackend;
use crate::dataplane::events::FactEvent;
use crate::dataplane::stats::{AppTrafficSample, GlobalStats};

/// Poll one dataplane snapshot.
///
/// # Errors
///
/// Returns an error when any backend read fails.
pub async fn poll_once(
    backend: &dyn DataplaneBackend,
) -> Result<(Vec<FactEvent>, GlobalStats, Vec<AppTrafficSample>)> {
    let events = backend.drain_events().await?;
    let global = backend.read_global_stats().await?;
    let apps = backend.read_app_samples().await?;
    Ok((events, global, apps))
}
