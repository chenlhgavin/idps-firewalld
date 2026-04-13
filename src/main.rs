//! IDPS firewalld daemon entry point.

use std::sync::Arc;

use anyhow::{Context, Result};
use idps_firewalld::app::FirewallAppState;
use idps_firewalld::config::FirewallConfig;
use idps_firewalld::dataplane::backend::MockDataplane;
use idps_firewalld::{runtime, signal};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    let state = initialize();
    let _signal_handle = signal::spawn_signal_handler(state.shutdown.clone());
    let dataplane = MockDataplane::default();
    info!("idps-firewalld starting");
    runtime::run_with_backend(&state, &dataplane)
        .await
        .context("firewalld runtime failed")?;
    info!("idps-firewalld stopped");
    Ok(())
}

fn initialize() -> Arc<FirewallAppState> {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(env_filter).init();
    let config = FirewallConfig::load();
    FirewallAppState::new(config)
}
