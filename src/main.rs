//! IDPS firewalld daemon entry point.

use std::sync::Arc;

use anyhow::{Context, Result};
use idps_firewalld::app::FirewallAppState;
use idps_firewalld::config::FirewallConfig;
use idps_firewalld::dataplane::loader::build_backend;
use idps_firewalld::ops::health::HealthSnapshot;
use idps_firewalld::ops::stats::StatisticsSnapshot;
use idps_firewalld::{runtime, signal};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    let command = std::env::args().nth(1);
    let config = FirewallConfig::load();
    if command.as_deref() == Some("health") {
        let snapshot = HealthSnapshot::load_latest(&config.sqlite_path)?;
        println!("{}", snapshot.to_json());
        return Ok(());
    }
    if command.as_deref() == Some("statistics") {
        let snapshot = StatisticsSnapshot::load_latest(&config.sqlite_path)?;
        println!("{}", snapshot.to_json());
        return Ok(());
    }
    let state = initialize(config);
    let _signal_handle = signal::spawn_signal_handler(state.shutdown.clone());
    let dataplane = build_backend(&state.config);
    info!(mode = ?state.config.dataplane_mode, "idps-firewalld starting");
    Box::pin(runtime::run_with_backend(&state, dataplane.as_ref()))
        .await
        .context("firewalld runtime failed")?;
    info!("idps-firewalld stopped");
    Ok(())
}

fn initialize(config: FirewallConfig) -> Arc<FirewallAppState> {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(env_filter).init();
    FirewallAppState::new(config)
}
