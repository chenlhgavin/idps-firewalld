//! Runtime orchestration for the firewall daemon.

pub mod state;
pub mod tasks;

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use idps_client::events::ClientOperation;
use idps_core::rule::depot::CachedRule;
use serde_json::json;
use tracing::{debug, info, warn};

use crate::app::FirewallAppState;
use crate::dataplane::backend::DataplaneBackend;
use crate::dataplane::events::{FactEvent, FactEventKind};
use crate::dataplane::loader::LoaderStatus;
use crate::dataplane::maps::stable_id_hash;
use crate::dataplane::stats::{AppTrafficSample, GlobalStats};
use crate::event::pipeline::{BusinessEvent, build_business_event};
use crate::identity::interface_map::{classify_ifindex, interface_name_for_ifindex};
use crate::identity::model::{AppIdentity, IdentityType};
use crate::identity::procfs::cmdline_for_pid;
use crate::identity::provider::AndroidPackageMap;
use crate::identity::resolve::{identity_from_app_id, resolve_observed_process_identity};
use crate::idps::client::{FirewalldClient, FirewalldRuleSubscription, FirewalldSdkClient};
use crate::idps::events::IntegrationEvent;
use crate::ops::health::HealthSnapshot;
use crate::persistence::db::FirewallDb;
use crate::persistence::outbox::{claim_next, mark_failed, mark_succeeded, reset_in_flight};
use crate::reporter::{
    AppTrafficAppPayload, AppTrafficSummaryPayload, FirewallEventPayload,
    GlobalTrafficSummaryPayload, ReportPayload, decode_payload, enqueue_payload_tx,
    pending_reports,
};
use crate::rule::manager::RuleManager;
use crate::rule::model::NormalizedRuleSet;
use crate::rule::normalize::build_rule_set;
use crate::traffic::aggregate::{AppTrafficSummary, aggregate_app_traffic};

pub use state::RuntimePhase;

const FIREWALL_FUN_ID: i32 = 1;
const TRAFFIC_FUN_ID: i32 = 4;
const RULE_PROT_VER: i32 = 1;
const REQUESTED_RULE_VER: i32 = 0;

/// Run the firewall daemon lifecycle with the provided data-plane backend.
///
/// # Errors
///
/// Returns an error when runtime state transitions are invalid or when
/// recoverable failures cannot be handled.
pub async fn run_with_backend<B>(state: &FirewallAppState, backend: &B) -> Result<()>
where
    B: DataplaneBackend + ?Sized,
{
    if should_use_managed_runtime(&state.config) {
        run_managed_runtime(state, backend).await
    } else if state.config.smoke_mode_requested() {
        run_local_smoke(state, backend).await
    } else {
        bail!(
            "managed runtime config {} is missing and smoke mode was not explicitly requested",
            state.config.runtime_config_path.display()
        )
    }
}

async fn run_managed_runtime<B>(state: &FirewallAppState, backend: &B) -> Result<()>
where
    B: DataplaneBackend + ?Sized,
{
    let mut db = FirewallDb::open(&state.config.sqlite_path)?;
    let _ = reset_in_flight(db.connection())?;

    let mut rule_manager = RuleManager::default();
    let mut rule_cache = RuleCache::default();
    let mut traffic_window = TrafficWindowState::default();
    let restored_identities = restore_app_identity_cache(&db)?;
    if !restored_identities.is_empty() {
        debug!(
            count = restored_identities.len(),
            "restored persisted app identities"
        );
    }
    restore_traffic_window_cursor(&db, &mut traffic_window)?;

    loop {
        if state.shutdown.is_cancelled() {
            break;
        }

        transition(state, RuntimePhase::Bootstrap).await?;
        let session_cancel = state.shutdown.child_token();
        let client = match FirewalldSdkClient::connect(&state.config, session_cancel.clone()).await
        {
            Ok(client) => client,
            Err(error) => {
                warn!(%error, "failed to connect firewalld client");
                session_cancel.cancel();
                reconnect_after_failure(state, backend, &db).await?;
                continue;
            }
        };

        let session_result = run_managed_session(
            state,
            backend,
            &mut db,
            &client,
            &mut rule_manager,
            &mut rule_cache,
            &mut traffic_window,
        )
        .await;
        session_cancel.cancel();

        match session_result {
            Ok(SessionEnd::Shutdown) => break,
            Ok(SessionEnd::Reconnect) => {
                reconnect_after_failure(state, backend, &db).await?;
            }
            Err(error) => {
                if state.shutdown.is_cancelled() {
                    break;
                }
                warn!(%error, "firewalld managed session failed");
                reconnect_after_failure(state, backend, &db).await?;
            }
        }
    }

    let _ = reset_in_flight(db.connection())?;
    let _ = backend.shutdown().await;
    transition(state, RuntimePhase::Shutdown).await
}

#[allow(clippy::too_many_lines)]
async fn run_managed_session<B, C>(
    state: &FirewallAppState,
    backend: &B,
    db: &mut FirewallDb,
    client: &C,
    rule_manager: &mut RuleManager,
    rule_cache: &mut RuleCache,
    traffic_window: &mut TrafficWindowState,
) -> Result<SessionEnd>
where
    B: DataplaneBackend + ?Sized,
    C: FirewalldClient + ?Sized,
{
    let mut event_stream = client.subscribe_events();

    transition(state, RuntimePhase::Registering).await?;
    let registration = client
        .register()
        .await
        .context("failed to send register request")?;

    loop {
        tokio::select! {
            () = state.shutdown.cancelled() => return Ok(SessionEnd::Shutdown),
            event = event_stream.recv() => match event.context("failed to receive registration event")? {
                IntegrationEvent::RegistrationSucceeded(_) => break,
                IntegrationEvent::Disconnected(message) => {
                    warn!(%message, "firewalld disconnected during registration");
                    return Ok(SessionEnd::Reconnect);
                }
                IntegrationEvent::RequestFailed { operation, message } => {
                    bail!("registration phase request failed for {operation:?}: {message}");
                }
                IntegrationEvent::ReportAcknowledged | IntegrationEvent::Heartbeat => {}
            }
        }
    }

    transition(state, RuntimePhase::RuleSyncing).await?;
    let mut firewall_sub = client
        .subscribe_rule(
            registration.acd,
            FIREWALL_FUN_ID,
            RULE_PROT_VER,
            REQUESTED_RULE_VER,
            None,
        )
        .await
        .context("failed to subscribe firewall rule")?;
    let mut traffic_sub = client
        .subscribe_rule(
            registration.acd,
            TRAFFIC_FUN_ID,
            RULE_PROT_VER,
            REQUESTED_RULE_VER,
            None,
        )
        .await
        .context("failed to subscribe traffic rule")?;

    rule_cache.firewall = load_initial_rule(
        client,
        registration.acd,
        FIREWALL_FUN_ID,
        &firewall_sub,
        true,
        state.config.shutdown_timeout,
    )
    .await?;
    if let Some(rule) = load_initial_rule(
        client,
        registration.acd,
        TRAFFIC_FUN_ID,
        &traffic_sub,
        false,
        state.config.shutdown_timeout,
    )
    .await?
    {
        rule_cache.traffic = Some(rule);
    }

    let mut global_tracker = GlobalCounterTracker::default();
    let mut app_tracker = AppCounterTracker::default();
    let mut fact_buffer = FactWindowBuffer::default();
    let mut in_flight_report: Option<InFlightReport> = None;
    let mut last_report_succeeded_at = None;
    let mut last_report_failed_at = None;

    backend.initialize().await?;
    if let Some(applied) =
        apply_rules_from_cache(backend, db, rule_manager, rule_cache, traffic_window, true).await?
    {
        let phase = state.current_phase().await;
        log_health_snapshot(
            phase,
            db,
            &applied,
            backend,
            true,
            true,
            last_report_succeeded_at,
            last_report_failed_at,
            traffic_window,
            &fact_buffer,
        )?;
    }

    transition(state, RuntimePhase::DataPlaneReady).await?;
    transition(state, RuntimePhase::Running).await?;

    let mut poll_tick = tokio::time::interval(state.config.runtime_poll_interval);
    poll_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut report_tick = tokio::time::interval(state.config.runtime_report_interval);
    report_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut cleanup_tick = tokio::time::interval(state.config.retention_cleanup_interval);
    cleanup_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            () = state.shutdown.cancelled() => {
                flush_fact_buffer(db, &mut fact_buffer, now_secs(), true)?;
                if let Some(window) = traffic_window.drain(now_secs()) {
                    persist_closed_traffic_window(db, window)?;
                }
                persist_traffic_window_cursor_state(db, traffic_window)?;
                return Ok(SessionEnd::Shutdown);
            }
            event = event_stream.recv() => {
                match event.context("failed to receive integration event")? {
                    IntegrationEvent::ReportAcknowledged => {
                        if let Some(report) = in_flight_report.take() {
                            mark_report_succeeded(db, &report)?;
                            last_report_succeeded_at = Some(now_secs());
                            if let Some(current) = rule_manager.current() {
                                let applied = applied_rules_from_ruleset(current);
                                let phase = state.current_phase().await;
                                log_health_snapshot(
                                    phase,
                                    db,
                                    &applied,
                                    backend,
                                    true,
                                    true,
                                    last_report_succeeded_at,
                                    last_report_failed_at,
                                    traffic_window,
                                    &fact_buffer,
                                )?;
                            }
                        }
                    }
                    IntegrationEvent::Disconnected(message) => {
                        warn!(%message, "firewalld disconnected");
                        flush_fact_buffer(db, &mut fact_buffer, now_secs(), true)?;
                        return Ok(SessionEnd::Reconnect);
                    }
                    IntegrationEvent::RequestFailed { operation, message } => {
                        if operation == ClientOperation::Report {
                            if let Some(report) = in_flight_report.take() {
                                mark_report_failed(db, &report, &message)?;
                                last_report_failed_at = Some(now_secs());
                                if let Some(current) = rule_manager.current() {
                                    let applied = applied_rules_from_ruleset(current);
                                    let phase = state.current_phase().await;
                                    log_health_snapshot(
                                        phase,
                                        db,
                                        &applied,
                                        backend,
                                        true,
                                        true,
                                        last_report_succeeded_at,
                                        last_report_failed_at,
                                        traffic_window,
                                        &fact_buffer,
                                    )?;
                                }
                            }
                        } else {
                            warn!(?operation, %message, "firewalld request failed");
                        }
                    }
                    IntegrationEvent::RegistrationSucceeded(_) | IntegrationEvent::Heartbeat => {}
                }
            }
            changed = firewall_sub.changed() => {
                changed.context("firewall rule subscription closed")?;
                if let Some(rule) = firewall_sub.current_rule() {
                    rule_cache.firewall = Some(rule);
                    if let Some(applied) = apply_rules_from_cache(
                        backend,
                        db,
                        rule_manager,
                        rule_cache,
                        traffic_window,
                        false,
                    ).await? {
                        let phase = state.current_phase().await;
                        log_health_snapshot(
                            phase,
                            db,
                            &applied,
                            backend,
                            true,
                            true,
                            last_report_succeeded_at,
                            last_report_failed_at,
                            traffic_window,
                            &fact_buffer,
                        )?;
                    }
                }
            }
            changed = traffic_sub.changed() => {
                changed.context("traffic rule subscription closed")?;
                if let Some(rule) = traffic_sub.current_rule() {
                    rule_cache.traffic = Some(rule);
                    if let Some(applied) = apply_rules_from_cache(
                        backend,
                        db,
                        rule_manager,
                        rule_cache,
                        traffic_window,
                        false,
                    ).await? {
                        let phase = state.current_phase().await;
                        log_health_snapshot(
                            phase,
                            db,
                            &applied,
                            backend,
                            true,
                            true,
                            last_report_succeeded_at,
                            last_report_failed_at,
                            traffic_window,
                            &fact_buffer,
                        )?;
                    }
                }
            }
            _ = poll_tick.tick() => {
                let now = now_secs();
                let events = backend.drain_events().await?;
                let current_global = backend.read_global_stats().await?;
                let app_samples = backend.read_app_samples().await?;
                let package_map = load_package_map(&state.config)?;
                let current_ruleset = rule_manager.current().cloned();
                let global_delta = global_tracker.delta(current_global);
                let app_deltas = app_tracker.delta_samples(&app_samples);
                let app_deltas = enrich_app_samples(db, app_deltas, package_map.as_ref())?;
                let app_summaries = aggregate_app_traffic(&app_deltas, classify_ifindex);

                persist_fact_events(
                    db,
                    current_ruleset.as_ref(),
                    package_map.as_ref(),
                    &mut fact_buffer,
                    events,
                )?;
                flush_fact_buffer(db, &mut fact_buffer, now, false)?;

                traffic_window.accumulate(now, global_delta, app_summaries);
                if let Some(window) = traffic_window.maybe_close(now) {
                    persist_closed_traffic_window(db, window)?;
                }
                persist_traffic_window_cursor_state(db, traffic_window)?;
            }
            _ = cleanup_tick.tick() => {
                run_retention_cleanup(db, &state.config)?;
            }
            _ = report_tick.tick(), if in_flight_report.is_none() => {
                if let Some(next) = claim_next(db.connection(), now_i64())? {
                    let payload = match decode_payload(&next) {
                        Ok(payload) => payload,
                        Err(error) => {
                            mark_failed(db.connection(), &next.report_id, &error.to_string())?;
                            continue;
                        }
                    };

                    let event = match payload.to_security_event(registration.acd) {
                        Ok(event) => event,
                        Err(error) => {
                            mark_failed(db.connection(), &next.report_id, &error.to_string())?;
                            update_payload_report_state(db, &payload, "failed")?;
                            continue;
                        }
                    };

                    match client.report(event).await {
                        Ok(()) => {
                            in_flight_report = Some(InFlightReport {
                                report_id: next.report_id,
                                payload,
                            });
                        }
                        Err(error) => {
                            mark_failed(db.connection(), &next.report_id, &error.to_string())?;
                            update_payload_report_state(db, &payload, "failed")?;
                            last_report_failed_at = Some(now_secs());
                        }
                    }
                }
            }
        }
    }
}

async fn reconnect_after_failure<B>(
    state: &FirewallAppState,
    backend: &B,
    db: &FirewallDb,
) -> Result<()>
where
    B: DataplaneBackend + ?Sized,
{
    let _ = reset_in_flight(db.connection())?;
    let _ = backend.shutdown().await;
    if !state.shutdown.is_cancelled() {
        transition(state, RuntimePhase::Reconnect).await?;
        tokio::time::sleep(state.config.reconnect_delay).await;
    }
    Ok(())
}

async fn run_local_smoke<B>(state: &FirewallAppState, backend: &B) -> Result<()>
where
    B: DataplaneBackend + ?Sized,
{
    transition(state, RuntimePhase::Bootstrap).await?;
    transition(state, RuntimePhase::Registering).await?;
    transition(state, RuntimePhase::RuleSyncing).await?;
    backend.initialize().await?;

    let db = if state.config.smoke_firewall_rules.is_some() {
        Some(FirewallDb::open(&state.config.sqlite_path)?)
    } else {
        None
    };

    if let Some(firewall_rules) = state.config.smoke_firewall_rules.as_deref() {
        let ruleset = build_rule_set(
            state.config.smoke_ruleset_version.clone(),
            firewall_rules,
            state.config.smoke_traffic_policy.as_deref(),
        )?;
        backend.apply_ruleset(&ruleset).await?;
        if let Some(db) = db.as_ref() {
            db.insert_raw_rule_snapshot(
                FIREWALL_FUN_ID,
                &ruleset.version,
                &ruleset.checksum,
                "smoke-env",
                "active",
                &json!({
                    "fun": FIREWALL_FUN_ID,
                    "payload": firewall_rules,
                    "source": "smoke-env",
                })
                .to_string(),
            )?;
            if let Some(traffic_policy) = state.config.smoke_traffic_policy.as_deref() {
                db.insert_raw_rule_snapshot(
                    TRAFFIC_FUN_ID,
                    &ruleset.version,
                    &ruleset.checksum,
                    "smoke-env",
                    "active",
                    &json!({
                        "fun": TRAFFIC_FUN_ID,
                        "payload": traffic_policy,
                        "source": "smoke-env",
                    })
                    .to_string(),
                )?;
            } else {
                db.insert_raw_rule_snapshot(
                    TRAFFIC_FUN_ID,
                    "none",
                    "none",
                    "smoke-env",
                    "active",
                    &cleared_rule_metadata(TRAFFIC_FUN_ID),
                )?;
            }
            let applied = applied_rules_from_ruleset(&ruleset);
            log_health_snapshot(
                RuntimePhase::Running,
                db,
                &applied,
                backend,
                true,
                true,
                None,
                None,
                &TrafficWindowState::default(),
                &FactWindowBuffer::default(),
            )?;
        }
    }

    transition(state, RuntimePhase::DataPlaneReady).await?;
    transition(state, RuntimePhase::Running).await?;

    let mut previous_stats = GlobalStats::default();
    while !state.shutdown.is_cancelled() {
        tokio::select! {
            () = state.shutdown.cancelled() => break,
            () = tokio::time::sleep(state.config.smoke_poll_interval) => {
                if let Some(db) = db.as_ref() {
                    sample_smoke_dataplane(backend, db, &mut previous_stats).await?;
                }
            }
        }
    }

    if let Some(db) = db.as_ref() {
        sample_smoke_dataplane(backend, db, &mut previous_stats).await?;
    }
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

async fn sample_smoke_dataplane<B>(
    backend: &B,
    db: &FirewallDb,
    previous_stats: &mut GlobalStats,
) -> Result<()>
where
    B: DataplaneBackend + ?Sized,
{
    let current_stats = backend.read_global_stats().await?;
    let delta = GlobalStats {
        ingress_bytes: current_stats
            .ingress_bytes
            .saturating_sub(previous_stats.ingress_bytes),
        egress_bytes: current_stats
            .egress_bytes
            .saturating_sub(previous_stats.egress_bytes),
        ingress_packets: current_stats
            .ingress_packets
            .saturating_sub(previous_stats.ingress_packets),
        egress_packets: current_stats
            .egress_packets
            .saturating_sub(previous_stats.egress_packets),
    };
    if delta.ingress_packets != 0 || delta.egress_packets != 0 {
        let now = now_i64();
        db.insert_global_window(now.saturating_sub(1), now, &delta)?;
    }
    *previous_stats = current_stats;

    let events = backend.drain_events().await?;
    for event in events {
        db.insert_or_replace_firewall_event(&event, "pending")?;
    }
    Ok(())
}

async fn load_initial_rule<C>(
    client: &C,
    acd: i32,
    fun: i32,
    subscription: &FirewalldRuleSubscription,
    required: bool,
    timeout: Duration,
) -> Result<Option<CachedRule>>
where
    C: FirewalldClient + ?Sized,
{
    if let Some(rule) = subscription.current_rule() {
        return Ok(Some(rule));
    }

    match client
        .load_rule(acd, fun, RULE_PROT_VER, REQUESTED_RULE_VER, None, timeout)
        .await
    {
        Ok(result) => Ok(Some(result.rule)),
        Err(error) if !required => {
            warn!(fun, %error, "optional rule not available during bootstrap");
            Ok(None)
        }
        Err(error) => Err(anyhow!(error.to_string()))
            .with_context(|| format!("required rule {fun} not available during bootstrap")),
    }
}

async fn apply_rules_from_cache<B>(
    backend: &B,
    db: &mut FirewallDb,
    rule_manager: &mut RuleManager,
    rule_cache: &RuleCache,
    traffic_window: &mut TrafficWindowState,
    force_apply: bool,
) -> Result<Option<AppliedRules>>
where
    B: DataplaneBackend + ?Sized,
{
    persist_raw_snapshot_if_needed(db, FIREWALL_FUN_ID, rule_cache.firewall.as_ref())?;
    persist_raw_snapshot_if_needed(db, TRAFFIC_FUN_ID, rule_cache.traffic.as_ref())?;

    let previous_checksum = rule_manager
        .current()
        .map(|ruleset| ruleset.checksum.clone());
    let desired = select_desired_ruleset(db, rule_manager, rule_cache)?;
    let changed = previous_checksum
        .as_ref()
        .is_none_or(|checksum| checksum != &desired.checksum);

    if force_apply || changed {
        backend.apply_ruleset(&desired).await?;
        persist_active_snapshots_if_needed(db, rule_cache)?;
        debug!(version = %desired.version, checksum = %desired.checksum, "applied ruleset");
    }

    if let Some(window) = traffic_window.reconfigure(
        desired
            .traffic_policy
            .as_ref()
            .map(|policy| policy.cycle_secs),
        now_secs(),
    ) {
        persist_closed_traffic_window(db, window)?;
    }
    persist_traffic_window_cursor_state(db, traffic_window)?;

    Ok(Some(applied_rules_from_ruleset(&desired)))
}

fn select_desired_ruleset(
    db: &mut FirewallDb,
    rule_manager: &mut RuleManager,
    rule_cache: &RuleCache,
) -> Result<NormalizedRuleSet> {
    let Some(firewall_rule) = rule_cache.firewall.as_ref() else {
        if let Some(restored) = restore_latest_ruleset(db, rule_manager)? {
            return Ok(restored);
        }
        return rule_manager
            .current()
            .cloned()
            .ok_or_else(|| anyhow!("no firewall rule available"));
    };

    let firewall_payload = rule_payload_text(firewall_rule);
    let traffic_payload = rule_cache.traffic.as_ref().map(rule_payload_text);
    let merged_version = merged_rule_version(rule_cache);

    match rule_manager.load_candidate(
        merged_version,
        &firewall_payload,
        traffic_payload.as_deref(),
    ) {
        Ok(ruleset) => {
            let cloned = ruleset.clone();
            persist_identities_from_ruleset(db, &cloned)?;
            Ok(cloned)
        }
        Err(error) => {
            if let Some(current) = rule_manager.current().cloned() {
                warn!(%error, version = %current.version, "reusing last known-good ruleset");
                Ok(current)
            } else {
                Err(error)
            }
        }
    }
}

fn restore_latest_ruleset(
    db: &mut FirewallDb,
    rule_manager: &mut RuleManager,
) -> Result<Option<NormalizedRuleSet>> {
    let Some(firewall_snapshot) = db.latest_rule_snapshot_with_status(FIREWALL_FUN_ID, "active")?
    else {
        return Ok(None);
    };
    let firewall_payload = snapshot_payload_required(&firewall_snapshot.raw_metadata)?;
    let traffic_snapshot = db.latest_rule_snapshot_with_status(TRAFFIC_FUN_ID, "active")?;
    let traffic_payload = traffic_snapshot
        .as_ref()
        .map(|snapshot| snapshot_payload(&snapshot.raw_metadata))
        .transpose()?
        .flatten();
    let ruleset = rule_manager
        .load_candidate(
            format!(
                "restored={}",
                merged_snapshot_version(&firewall_snapshot, traffic_snapshot.as_ref())
            ),
            &firewall_payload,
            traffic_payload.as_deref(),
        )?
        .clone();
    persist_identities_from_ruleset(db, &ruleset)?;
    Ok(Some(ruleset))
}

fn snapshot_payload(metadata: &str) -> Result<Option<String>> {
    let value: serde_json::Value = serde_json::from_str(metadata)
        .with_context(|| "failed to decode rule snapshot metadata")?;
    match value.get("payload") {
        Some(serde_json::Value::String(payload)) => Ok(Some(payload.to_string())),
        Some(serde_json::Value::Null) | None => Ok(None),
        Some(_) => Err(anyhow!(
            "rule snapshot metadata payload has unsupported type"
        )),
    }
}

fn snapshot_payload_required(metadata: &str) -> Result<String> {
    snapshot_payload(metadata)?.ok_or_else(|| anyhow!("rule snapshot metadata is missing payload"))
}

fn persist_raw_snapshot_if_needed(
    db: &FirewallDb,
    fun_id: i32,
    rule: Option<&CachedRule>,
) -> Result<()> {
    let Some(rule) = rule else {
        return Ok(());
    };

    let version = cached_rule_version(rule);
    persist_snapshot_if_needed(
        fun_id,
        db,
        &version,
        &rule.sha256,
        "received",
        &raw_rule_metadata(rule),
    )?;
    Ok(())
}

fn persist_active_snapshots_if_needed(db: &FirewallDb, rule_cache: &RuleCache) -> Result<()> {
    let Some(firewall_rule) = rule_cache.firewall.as_ref() else {
        return Ok(());
    };
    persist_snapshot_if_needed(
        FIREWALL_FUN_ID,
        db,
        &cached_rule_version(firewall_rule),
        &firewall_rule.sha256,
        "active",
        &raw_rule_metadata(firewall_rule),
    )?;

    if let Some(traffic_rule) = rule_cache.traffic.as_ref() {
        persist_snapshot_if_needed(
            TRAFFIC_FUN_ID,
            db,
            &cached_rule_version(traffic_rule),
            &traffic_rule.sha256,
            "active",
            &raw_rule_metadata(traffic_rule),
        )?;
    } else {
        persist_snapshot_if_needed(
            TRAFFIC_FUN_ID,
            db,
            "none",
            "none",
            "active",
            &cleared_rule_metadata(TRAFFIC_FUN_ID),
        )?;
    }
    Ok(())
}

fn persist_snapshot_if_needed(
    fun_id: i32,
    db: &FirewallDb,
    version: &str,
    checksum: &str,
    status: &str,
    raw_metadata: &str,
) -> Result<()> {
    if let Some(snapshot) = db.latest_rule_snapshot_with_status(fun_id, status)?
        && snapshot.rule_version == version
        && snapshot.checksum == checksum
        && snapshot.raw_metadata == raw_metadata
    {
        return Ok(());
    }

    db.insert_raw_rule_snapshot(
        fun_id,
        version,
        checksum,
        "idps-client",
        status,
        raw_metadata,
    )?;
    Ok(())
}

fn raw_rule_metadata(rule: &CachedRule) -> String {
    json!({
        "acd": rule.acd,
        "fun": rule.fun,
        "protVer": rule.prot_ver,
        "ver": rule.ver,
        "majorVer": rule.major_ver,
        "minorVer": rule.minor_ver,
        "sha256": rule.sha256,
        "bytes": rule.rule.len(),
        "payload": String::from_utf8_lossy(&rule.rule),
    })
    .to_string()
}

fn cleared_rule_metadata(fun_id: i32) -> String {
    json!({
        "fun": fun_id,
        "payload": serde_json::Value::Null,
        "cleared": true,
    })
    .to_string()
}

fn rule_payload_text(rule: &CachedRule) -> String {
    String::from_utf8_lossy(&rule.rule).into_owned()
}

fn cached_rule_version(rule: &CachedRule) -> String {
    format!("{}.{}.{}", rule.major_ver, rule.minor_ver, rule.ver)
}

fn merged_snapshot_version(
    firewall_snapshot: &crate::persistence::db::RuleSnapshotRow,
    traffic_snapshot: Option<&crate::persistence::db::RuleSnapshotRow>,
) -> String {
    let traffic = traffic_snapshot.map_or("none", |snapshot| snapshot.rule_version.as_str());
    format!(
        "firewall={};traffic={traffic}",
        firewall_snapshot.rule_version
    )
}

fn merged_rule_version(rule_cache: &RuleCache) -> String {
    let firewall = rule_cache
        .firewall
        .as_ref()
        .map_or_else(|| "none".to_string(), cached_rule_version);
    let traffic = rule_cache
        .traffic
        .as_ref()
        .map_or_else(|| "none".to_string(), cached_rule_version);
    format!("firewall={firewall};traffic={traffic}")
}

fn applied_rules_from_ruleset(ruleset: &NormalizedRuleSet) -> AppliedRules {
    AppliedRules {
        version: ruleset.version.clone(),
        checksum: ruleset.checksum.clone(),
        traffic_cycle_secs: ruleset
            .traffic_policy
            .as_ref()
            .map(|policy| policy.cycle_secs),
    }
}

fn persist_traffic_window_cursor_state(
    db: &FirewallDb,
    traffic_window: &TrafficWindowState,
) -> Result<()> {
    db.upsert_traffic_window_cursor(
        "default",
        traffic_window.window_start.map(u64_to_i64),
        traffic_window
            .cycle_secs
            .map(|value| i64::try_from(value).unwrap_or(i64::MAX)),
    )?;
    db.upsert_traffic_window_state(&crate::persistence::db::TrafficWindowStateRow {
        cursor_key: "default".to_string(),
        window_start: traffic_window.window_start.map(u64_to_i64),
        cycle_secs: traffic_window
            .cycle_secs
            .map(|value| i64::try_from(value).unwrap_or(i64::MAX)),
        global: traffic_window.global,
        apps: traffic_window.apps.values().cloned().collect(),
        updated_at: now_i64(),
    })
}

fn persist_fact_events(
    db: &FirewallDb,
    ruleset: Option<&NormalizedRuleSet>,
    packages: Option<&AndroidPackageMap>,
    fact_buffer: &mut FactWindowBuffer,
    events: Vec<FactEvent>,
) -> Result<()> {
    for (index, event) in events.into_iter().enumerate() {
        let Some((normalized, identity)) =
            enrich_fact_event(normalize_fact_event(event, index), ruleset, packages)
        else {
            continue;
        };
        if let Some(identity) = identity.as_ref() {
            db.upsert_app_identity(identity)?;
        }
        db.insert_or_replace_firewall_event(&normalized, "pending")?;
        fact_buffer.push(normalized);
    }
    Ok(())
}

fn normalize_fact_event(mut event: FactEvent, index: usize) -> FactEvent {
    if event.event_time_secs == 0 {
        event.event_time_secs = now_secs();
    }
    event.event_id = format!("evt-{}-{index}", now_nanos());
    event
}

fn enrich_fact_event(
    mut event: FactEvent,
    ruleset: Option<&NormalizedRuleSet>,
    packages: Option<&AndroidPackageMap>,
) -> Option<(FactEvent, Option<AppIdentity>)> {
    if should_ignore_fact_event(&event) {
        return None;
    }

    let rule_identity = if event.kind == FactEventKind::PolicyDeny {
        event.rule_id.as_deref().and_then(|rule_id| {
            ruleset.and_then(|ruleset| policy_identity_for_rule(ruleset, rule_id))
        })
    } else {
        None
    };
    let identity = observed_identity_for_event(&event, packages, rule_identity.as_deref());
    if let Some(identity) = identity.as_ref() {
        event.app_id = Some(identity.app_id.clone());
    }
    if event.kind == FactEventKind::PolicyDeny && event.app_id.is_none() {
        return None;
    }
    Some((event, identity))
}

fn policy_identity_for_rule(ruleset: &NormalizedRuleSet, rule_id: &str) -> Option<String> {
    ruleset.firewall_rules.iter().find_map(|rule| match rule {
        crate::rule::model::FirewallRule::App(rule)
            if dataplane_policy_rule_id(&rule.metadata) == rule_id =>
        {
            Some(format!("pkg:{}", rule.package))
        }
        crate::rule::model::FirewallRule::Program(rule)
            if dataplane_policy_rule_id(&rule.metadata) == rule_id =>
        {
            Some(format!("prog:{}", rule.program))
        }
        crate::rule::model::FirewallRule::App(_)
        | crate::rule::model::FirewallRule::Program(_)
        | crate::rule::model::FirewallRule::Tuple(_) => None,
    })
}

fn enrich_app_samples(
    db: &FirewallDb,
    samples: Vec<AppTrafficSample>,
    packages: Option<&AndroidPackageMap>,
) -> Result<Vec<AppTrafficSample>> {
    let mut enriched = Vec::new();
    for mut sample in samples {
        if should_ignore_app_sample(&sample) {
            continue;
        }
        let Some(identity) = observed_identity_for_sample(&sample, packages) else {
            continue;
        };
        db.upsert_app_identity(&identity)?;
        sample.app_id = identity.app_id;
        enriched.push(sample);
    }
    Ok(enriched)
}

fn restore_app_identity_cache(db: &FirewallDb) -> Result<Vec<AppIdentity>> {
    db.all_app_identities()
}

fn restore_traffic_window_cursor(
    db: &FirewallDb,
    traffic_window: &mut TrafficWindowState,
) -> Result<()> {
    if let Some(state) = db.traffic_window_state("default")? {
        traffic_window.window_start = state
            .window_start
            .and_then(|value| u64::try_from(value).ok());
        traffic_window.cycle_secs = state.cycle_secs.and_then(|value| u64::try_from(value).ok());
        traffic_window.global = state.global;
        traffic_window.apps = state
            .apps
            .into_iter()
            .map(|summary| (summary.app_id.clone(), summary))
            .collect();
        return Ok(());
    }

    if let Some(cursor) = db.traffic_window_cursor("default")? {
        traffic_window.window_start = cursor
            .window_start
            .and_then(|value| u64::try_from(value).ok());
        traffic_window.cycle_secs = cursor
            .cycle_secs
            .and_then(|value| u64::try_from(value).ok());
    }
    Ok(())
}

fn identity_for_app_id(app_id: &str, packages: Option<&AndroidPackageMap>) -> AppIdentity {
    identity_from_app_id(app_id, packages)
}

fn observed_identity_for_event(
    event: &FactEvent,
    packages: Option<&AndroidPackageMap>,
    override_app_id: Option<&str>,
) -> Option<AppIdentity> {
    let cmdline = event.process_id().and_then(cmdline_for_pid);
    if let Some(app_id) = override_app_id.or(event.app_id.as_deref()) {
        let mut identity = identity_for_app_id(app_id, packages);
        if identity.identity_type != IdentityType::App
            && identity.app_name.is_none()
            && let Some(cmdline) = cmdline.as_ref()
        {
            identity.app_name = Some(cmdline.clone());
        }
        if identity.identity_type != IdentityType::Unknown {
            return Some(identity);
        }
    }

    let identity = resolve_observed_process_identity(
        packages,
        cmdline.as_deref(),
        event.comm.as_deref(),
        event.uid,
    );
    (identity.identity_type != IdentityType::Unknown).then_some(identity)
}

fn observed_identity_for_sample(
    sample: &AppTrafficSample,
    packages: Option<&AndroidPackageMap>,
) -> Option<AppIdentity> {
    let cmdline = sample.process_id().and_then(cmdline_for_pid);
    if !sample.app_id.is_empty() && sample.app_id != "unknown" {
        let mut identity = identity_for_app_id(&sample.app_id, packages);
        if identity.identity_type != IdentityType::App
            && identity.app_name.is_none()
            && let Some(cmdline) = cmdline.as_ref()
        {
            identity.app_name = Some(cmdline.clone());
        }
        if identity.identity_type != IdentityType::Unknown {
            return Some(identity);
        }
    }

    let identity = resolve_observed_process_identity(
        packages,
        cmdline.as_deref(),
        sample.comm.as_deref(),
        sample.uid,
    );
    (identity.identity_type != IdentityType::Unknown).then_some(identity)
}

fn should_ignore_fact_event(event: &FactEvent) -> bool {
    is_local_only_ip(&event.src_ip, &event.dst_ip)
}

fn should_ignore_app_sample(sample: &AppTrafficSample) -> bool {
    if sample.bytes == 0 && sample.packets == 0 {
        return true;
    }
    is_loopback_interface(sample.ifindex)
}

fn is_local_only_ip(src_ip: &str, dst_ip: &str) -> bool {
    if src_ip == dst_ip {
        return true;
    }

    src_ip
        .parse::<IpAddr>()
        .ok()
        .is_some_and(|addr| addr.is_loopback())
        || dst_ip
            .parse::<IpAddr>()
            .ok()
            .is_some_and(|addr| addr.is_loopback())
}

fn is_loopback_interface(ifindex: u32) -> bool {
    interface_name_for_ifindex(ifindex).is_some_and(|name| name == "lo")
}

fn flush_fact_buffer(
    db: &mut FirewallDb,
    fact_buffer: &mut FactWindowBuffer,
    now: u64,
    force: bool,
) -> Result<()> {
    for event in fact_buffer.flush_ready(now, force) {
        let identity = event
            .business
            .app_id
            .as_deref()
            .map(|app_id| lookup_identity(db, app_id, None))
            .transpose()?;
        let payload = ReportPayload::FirewallEvent(FirewallEventPayload {
            report_id: event.business.event_id.clone(),
            event_id: event.business.event_id.clone(),
            event_ids: event.event_ids,
            event_time_secs: event.business.event_time_secs,
            event_type: event.business.event_type,
            action: action_str(event.business.action).to_string(),
            detail_len: event.business.detail_len,
            detail: event.business.detail,
            app_id: event.business.app_id,
            app_name: identity
                .as_ref()
                .and_then(|identity| identity.app_name.clone()),
            pkgname: identity
                .as_ref()
                .and_then(|identity| identity.package.clone()),
            rule_id: event.business.rule_id,
            src_ip: event.business.src_ip,
            src_port: event.business.src_port,
            dst_ip: event.business.dst_ip,
            dst_port: event.business.dst_port,
            proto: event.business.proto,
        });
        db.transaction(|tx| {
            enqueue_payload_tx(
                tx,
                payload_id(&payload),
                &payload,
                u64_to_i64(event.business.event_time_secs),
            )
        })?;
    }
    Ok(())
}

#[allow(clippy::needless_pass_by_value)]
fn persist_closed_traffic_window(db: &mut FirewallDb, window: ClosedTrafficWindow) -> Result<()> {
    let start_i64 = u64_to_i64(window.window_start);
    let end_i64 = u64_to_i64(window.window_end);

    let global_report = (!is_zero_stats(&window.global)).then(|| {
        ReportPayload::GlobalTrafficSummary(GlobalTrafficSummaryPayload {
            report_id: format!("global-{}-{}", window.window_start, window.window_end),
            window_start: window.window_start,
            window_end: window.window_end,
            ingress_bytes: window.global.ingress_bytes,
            egress_bytes: window.global.egress_bytes,
            ingress_packets: window.global.ingress_packets,
            egress_packets: window.global.egress_packets,
        })
    });

    let mut app_payloads = Vec::with_capacity(window.apps.len());
    for summary in &window.apps {
        let identity = lookup_identity(db, &summary.app_id, None)?;
        let pkgname = identity.package.unwrap_or_default();
        let appname = identity
            .app_name
            .or(identity.program)
            .unwrap_or_else(|| summary.app_id.clone());
        app_payloads.push((summary.clone(), pkgname, appname));
    }

    let app_report = (!app_payloads.is_empty()).then(|| {
        ReportPayload::AppTrafficSummary(AppTrafficSummaryPayload {
            report_id: format!("apps-{}-{}", window.window_start, window.window_end),
            window_start: window.window_start,
            window_end: window.window_end,
            apps: app_payloads
                .iter()
                .map(|(summary, pkgname, appname)| AppTrafficAppPayload {
                    app_id: summary.app_id.clone(),
                    pkgname: pkgname.clone(),
                    appname: appname.clone(),
                    wifi_bytes: summary.wifi_bytes,
                    mobile_bytes: summary.mobile_bytes,
                })
                .collect(),
        })
    });

    db.transaction(|tx| {
        tx.execute(
            "INSERT INTO traffic_window_cursor (cursor_key, window_start, cycle_secs, updated_at) \
             VALUES (?1, ?2, ?3, ?4) \
             ON CONFLICT(cursor_key) DO UPDATE SET \
               window_start = excluded.window_start, \
               cycle_secs = excluded.cycle_secs, \
               updated_at = excluded.updated_at",
            rusqlite::params![
                "default",
                Some(start_i64),
                Some(i64::try_from(window.window_end.saturating_sub(window.window_start)).unwrap_or(i64::MAX)),
                end_i64,
            ],
        )
        .context("failed to upsert traffic window cursor")?;
        if global_report.is_some() {
            tx.execute(
                "INSERT OR REPLACE INTO traffic_global_window \
                 (window_start, window_end, ingress_bytes, egress_bytes, ingress_packets, egress_packets, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![
                    start_i64,
                    end_i64,
                    i64::try_from(window.global.ingress_bytes).unwrap_or(i64::MAX),
                    i64::try_from(window.global.egress_bytes).unwrap_or(i64::MAX),
                    i64::try_from(window.global.ingress_packets).unwrap_or(i64::MAX),
                    i64::try_from(window.global.egress_packets).unwrap_or(i64::MAX),
                    end_i64,
                ],
            )
            .context("failed to insert global traffic window")?;
        }

        for (summary, pkgname, appname) in &app_payloads {
            tx.execute(
                "INSERT OR REPLACE INTO traffic_app_window \
                 (window_start, window_end, app_id, pkgname, appname, wifi_bytes, mobile_bytes, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![
                    start_i64,
                    end_i64,
                    summary.app_id,
                    pkgname,
                    appname,
                    i64::try_from(summary.wifi_bytes).unwrap_or(i64::MAX),
                    i64::try_from(summary.mobile_bytes).unwrap_or(i64::MAX),
                    end_i64,
                ],
            )
            .context("failed to insert app traffic window")?;
        }

        if let Some(report) = global_report.as_ref() {
            enqueue_payload_tx(tx, payload_id(report), report, end_i64)?;
        }
        if let Some(report) = app_report.as_ref() {
            enqueue_payload_tx(tx, payload_id(report), report, end_i64)?;
        }
        Ok(())
    })
}

fn lookup_identity(
    db: &FirewallDb,
    app_id: &str,
    packages: Option<&AndroidPackageMap>,
) -> Result<AppIdentity> {
    if let Some(identity) = db.app_identity(app_id)? {
        return Ok(identity);
    }

    Ok(identity_for_app_id(app_id, packages))
}

fn mark_report_succeeded(db: &FirewallDb, report: &InFlightReport) -> Result<()> {
    mark_succeeded(db.connection(), &report.report_id)?;
    update_payload_report_state(db, &report.payload, "succeeded")
}

fn mark_report_failed(db: &FirewallDb, report: &InFlightReport, message: &str) -> Result<()> {
    mark_failed(db.connection(), &report.report_id, message)?;
    update_payload_report_state(db, &report.payload, "failed")
}

fn update_payload_report_state(
    db: &FirewallDb,
    payload: &ReportPayload,
    state: &str,
) -> Result<()> {
    if let ReportPayload::FirewallEvent(payload) = payload {
        for event_id in &payload.event_ids {
            db.update_firewall_event_report_state(event_id, state)?;
        }
    }
    Ok(())
}

fn payload_id(payload: &ReportPayload) -> &str {
    match payload {
        ReportPayload::FirewallEvent(payload) => payload.report_id.as_str(),
        ReportPayload::AppTrafficSummary(payload) => payload.report_id.as_str(),
        ReportPayload::GlobalTrafficSummary(payload) => payload.report_id.as_str(),
    }
}

fn action_str(action: crate::dataplane::events::FactAction) -> &'static str {
    match action {
        crate::dataplane::events::FactAction::Allow => "allow",
        crate::dataplane::events::FactAction::Alert => "alert",
        crate::dataplane::events::FactAction::Block => "block",
    }
}

fn load_package_map(config: &crate::config::FirewallConfig) -> Result<Option<AndroidPackageMap>> {
    AndroidPackageMap::load_if_present(&config.android_packages_list_path)
}

fn dataplane_policy_rule_id(metadata: &crate::rule::model::RuleMetadata) -> String {
    let stable_id = metadata.policy_id.as_deref().unwrap_or(&metadata.rule_id);
    format!("policy-{:016x}", stable_id_hash(stable_id))
}

fn should_use_managed_runtime(config: &crate::config::FirewallConfig) -> bool {
    config.runtime_config_path.exists()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos())
}

fn now_i64() -> i64 {
    u64_to_i64(now_secs())
}

fn run_retention_cleanup(db: &FirewallDb, config: &crate::config::FirewallConfig) -> Result<()> {
    let now = now_i64();
    let firewall_before = now.saturating_sub(u64_to_i64(config.firewall_event_retention.as_secs()));
    let traffic_before = now.saturating_sub(u64_to_i64(config.traffic_window_retention.as_secs()));
    let outbox_before = now.saturating_sub(u64_to_i64(config.succeeded_outbox_retention.as_secs()));
    let deleted = db.cleanup_retention(firewall_before, traffic_before, outbox_before)?;
    debug!(?deleted, "completed firewalld retention cleanup");
    Ok(())
}

fn u64_to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn is_zero_stats(stats: &GlobalStats) -> bool {
    stats.ingress_bytes == 0
        && stats.egress_bytes == 0
        && stats.ingress_packets == 0
        && stats.egress_packets == 0
}

#[allow(clippy::too_many_arguments)]
fn log_health_snapshot<B>(
    phase: RuntimePhase,
    db: &FirewallDb,
    applied: &AppliedRules,
    backend: &B,
    connected: bool,
    registered: bool,
    last_report_succeeded_at: Option<u64>,
    last_report_failed_at: Option<u64>,
    traffic_window: &TrafficWindowState,
    fact_buffer: &FactWindowBuffer,
) -> Result<()>
where
    B: DataplaneBackend + ?Sized,
{
    let dataplane = backend.health();
    let snapshot = HealthSnapshot {
        phase,
        connected,
        registered,
        rule_version: Some(applied.version.clone()),
        traffic_cycle_secs: applied.traffic_cycle_secs,
        pending_reports: pending_reports(db.connection())?,
        last_report_succeeded_at,
        last_report_failed_at,
        current_window_started_at: traffic_window.window_start,
        buffered_fact_windows: fact_buffer.buckets.len(),
        dataplane_status: match dataplane.status {
            LoaderStatus::Detached => "detached".to_string(),
            LoaderStatus::Ready => "ready".to_string(),
        },
        dataplane_checksum: dataplane.active_checksum,
        dataplane_lost_events: dataplane.lost_events,
    };
    db.upsert_health_snapshot(&snapshot)?;
    debug!(?snapshot, checksum = %applied.checksum, "firewalld health snapshot");
    Ok(())
}

fn persist_identities_from_ruleset(db: &FirewallDb, ruleset: &NormalizedRuleSet) -> Result<()> {
    for rule in &ruleset.firewall_rules {
        match rule {
            crate::rule::model::FirewallRule::App(rule) => {
                let mut identity = AppIdentity {
                    app_id: format!("pkg:{}", rule.package),
                    identity_type: IdentityType::App,
                    package: Some(rule.package.clone()),
                    app_name: (!rule.app_name.is_empty()).then(|| rule.app_name.clone()),
                    program: None,
                    uid: None,
                };
                if identity.app_name.is_none() {
                    identity.app_name = Some(rule.package.clone());
                }
                db.upsert_app_identity(&identity)?;
            }
            crate::rule::model::FirewallRule::Program(rule) => {
                db.upsert_app_identity(&AppIdentity {
                    app_id: format!("prog:{}", rule.program),
                    identity_type: IdentityType::Program,
                    package: None,
                    app_name: None,
                    program: Some(rule.program.clone()),
                    uid: None,
                })?;
            }
            crate::rule::model::FirewallRule::Tuple(_) => {}
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AppliedRules {
    version: String,
    checksum: String,
    traffic_cycle_secs: Option<u64>,
}

#[derive(Debug, Default)]
struct RuleCache {
    firewall: Option<CachedRule>,
    traffic: Option<CachedRule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InFlightReport {
    report_id: String,
    payload: ReportPayload,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionEnd {
    Reconnect,
    Shutdown,
}

#[derive(Debug, Default)]
struct GlobalCounterTracker {
    previous: GlobalStats,
}

impl GlobalCounterTracker {
    fn delta(&mut self, current: GlobalStats) -> GlobalStats {
        let delta = GlobalStats {
            ingress_bytes: current
                .ingress_bytes
                .saturating_sub(self.previous.ingress_bytes),
            egress_bytes: current
                .egress_bytes
                .saturating_sub(self.previous.egress_bytes),
            ingress_packets: current
                .ingress_packets
                .saturating_sub(self.previous.ingress_packets),
            egress_packets: current
                .egress_packets
                .saturating_sub(self.previous.egress_packets),
        };
        self.previous = current;
        delta
    }
}

#[derive(Debug, Default)]
struct AppCounterTracker {
    previous: BTreeMap<ObservedAppKey, AppSampleCounter>,
}

impl AppCounterTracker {
    fn delta_samples(&mut self, current: &[AppTrafficSample]) -> Vec<AppTrafficSample> {
        let mut current_map = BTreeMap::new();
        let mut deltas = Vec::new();

        for sample in current {
            let key = ObservedAppKey::from_sample(sample);
            let previous = self.previous.get(&key).copied().unwrap_or_default();
            let delta_bytes = if sample.bytes >= previous.bytes {
                sample.bytes - previous.bytes
            } else {
                sample.bytes
            };
            let delta_packets = if sample.packets >= previous.packets {
                sample.packets - previous.packets
            } else {
                sample.packets
            };
            current_map.insert(
                key.clone(),
                AppSampleCounter {
                    bytes: sample.bytes,
                    packets: sample.packets,
                },
            );

            if delta_bytes != 0 || delta_packets != 0 {
                deltas.push(AppTrafficSample {
                    app_id: sample.app_id.clone(),
                    pid: sample.pid,
                    tgid: sample.tgid,
                    uid: sample.uid,
                    comm: sample.comm.clone(),
                    ifindex: sample.ifindex,
                    bytes: delta_bytes,
                    packets: delta_packets,
                });
            }
        }

        self.previous = current_map;
        deltas
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct AppSampleCounter {
    bytes: u64,
    packets: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ObservedAppKey {
    app_id: String,
    pid: u32,
    tgid: u32,
    uid: u32,
    comm: String,
    ifindex: u32,
}

impl ObservedAppKey {
    fn from_sample(sample: &AppTrafficSample) -> Self {
        Self {
            app_id: sample.app_id.clone(),
            pid: sample.pid.unwrap_or(0),
            tgid: sample.tgid.unwrap_or(0),
            uid: sample.uid.unwrap_or(0),
            comm: sample.comm.clone().unwrap_or_default(),
            ifindex: sample.ifindex,
        }
    }
}

#[derive(Debug, Default)]
struct TrafficWindowState {
    cycle_secs: Option<u64>,
    window_start: Option<u64>,
    global: GlobalStats,
    apps: BTreeMap<String, AppTrafficSummary>,
}

impl TrafficWindowState {
    fn reconfigure(&mut self, cycle_secs: Option<u64>, now: u64) -> Option<ClosedTrafficWindow> {
        if self.cycle_secs == cycle_secs {
            if self.window_start.is_none() && cycle_secs.is_some() {
                self.window_start = Some(now);
            }
            return None;
        }

        let flushed = self.take_window(now);
        self.cycle_secs = cycle_secs;
        self.window_start = cycle_secs.map(|_| now);
        flushed
    }

    fn accumulate(&mut self, now: u64, global: GlobalStats, apps: Vec<AppTrafficSummary>) {
        if self.cycle_secs.is_none() {
            return;
        }
        if self.window_start.is_none() {
            self.window_start = Some(now);
        }

        self.global.ingress_bytes = self
            .global
            .ingress_bytes
            .saturating_add(global.ingress_bytes);
        self.global.egress_bytes = self.global.egress_bytes.saturating_add(global.egress_bytes);
        self.global.ingress_packets = self
            .global
            .ingress_packets
            .saturating_add(global.ingress_packets);
        self.global.egress_packets = self
            .global
            .egress_packets
            .saturating_add(global.egress_packets);

        for summary in apps {
            let entry =
                self.apps
                    .entry(summary.app_id.clone())
                    .or_insert_with(|| AppTrafficSummary {
                        app_id: summary.app_id.clone(),
                        wifi_bytes: 0,
                        mobile_bytes: 0,
                    });
            entry.wifi_bytes = entry.wifi_bytes.saturating_add(summary.wifi_bytes);
            entry.mobile_bytes = entry.mobile_bytes.saturating_add(summary.mobile_bytes);
        }
    }

    fn maybe_close(&mut self, now: u64) -> Option<ClosedTrafficWindow> {
        let cycle = self.cycle_secs?;
        let Some(start) = self.window_start else {
            self.window_start = Some(now);
            return None;
        };
        if now.saturating_sub(start) < cycle {
            return None;
        }
        self.take_window(now)
    }

    fn drain(&mut self, now: u64) -> Option<ClosedTrafficWindow> {
        self.take_window(now)
    }

    fn take_window(&mut self, end: u64) -> Option<ClosedTrafficWindow> {
        let start = self.window_start?;
        if is_zero_stats(&self.global) && self.apps.is_empty() {
            self.global = GlobalStats::default();
            self.window_start = self.cycle_secs.map(|_| end);
            return None;
        }

        let apps = self.apps.values().cloned().collect();
        let global = self.global;
        self.global = GlobalStats::default();
        self.apps.clear();
        self.window_start = self.cycle_secs.map(|_| end);

        Some(ClosedTrafficWindow {
            window_start: start,
            window_end: end,
            global,
            apps,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ClosedTrafficWindow {
    window_start: u64,
    window_end: u64,
    global: GlobalStats,
    apps: Vec<AppTrafficSummary>,
}

#[derive(Debug, Default)]
struct FactWindowBuffer {
    buckets: BTreeMap<FactWindowKey, Vec<FactEvent>>,
}

impl FactWindowBuffer {
    fn push(&mut self, event: FactEvent) {
        let key = FactWindowKey::from_event(&event);
        self.buckets.entry(key).or_default().push(event);
    }

    fn flush_ready(&mut self, now: u64, force: bool) -> Vec<BufferedBusinessEvent> {
        let mut ready_keys = Vec::new();
        for key in self.buckets.keys() {
            if force || key.second < now {
                ready_keys.push(key.clone());
            }
        }

        ready_keys
            .into_iter()
            .filter_map(|key| self.buckets.remove(&key))
            .filter_map(|events| {
                let business = build_business_event(&events)?;
                let event_ids = events.iter().map(|event| event.event_id.clone()).collect();
                Some(BufferedBusinessEvent {
                    business,
                    event_ids,
                })
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FactWindowKey {
    second: u64,
    kind: u8,
    src_ip: String,
    dst_ip: String,
    proto: String,
    app_id: Option<String>,
    rule_id: Option<String>,
    ifindex: u32,
}

impl FactWindowKey {
    fn from_event(event: &FactEvent) -> Self {
        Self {
            second: event.event_time_secs,
            kind: event_kind_code(event.kind),
            src_ip: event.src_ip.clone(),
            dst_ip: event.dst_ip.clone(),
            proto: event.proto.clone(),
            app_id: event.app_id.clone(),
            rule_id: event.rule_id.clone(),
            ifindex: event.ifindex,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BufferedBusinessEvent {
    business: BusinessEvent,
    event_ids: Vec<String>,
}

fn event_kind_code(kind: FactEventKind) -> u8 {
    match kind {
        FactEventKind::IngressRuleMatch => 0,
        FactEventKind::EgressRuleMatch => 1,
        FactEventKind::PolicyDeny => 2,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::config::FirewallConfig;
    use crate::dataplane::backend::MockDataplane;
    use crate::idps::client::MockFirewalldClient;
    use crate::idps::events::IntegrationEvent;

    #[tokio::test]
    async fn run_with_backend_reaches_shutdown_after_cancel() {
        let mut config = FirewallConfig::default();
        config.runtime_config_path =
            std::path::PathBuf::from("/tmp/idps-firewalld-missing-test-config.yaml");
        config.smoke_firewall_rules =
            Some("name=allow,dip=10.0.0.1,dport=53,chain=output,action=allow".to_string());
        let state = FirewallAppState::new(config);
        let backend = MockDataplane::default();
        let cancel_state = Arc::clone(&state);
        let cancel_task = tokio::spawn(async move {
            cancel_state.wait_for_phase(RuntimePhase::Running).await;
            cancel_state.shutdown.cancel();
        });
        run_with_backend(&state, &backend)
            .await
            .expect("runtime completed");
        cancel_task.await.expect("cancel task joined");
        assert_eq!(state.current_phase().await, RuntimePhase::Shutdown);
    }

    #[tokio::test]
    async fn run_with_backend_fails_fast_without_runtime_config_or_smoke_mode() {
        let mut config = FirewallConfig::default();
        config.runtime_config_path =
            std::path::PathBuf::from("/tmp/idps-firewalld-missing-test-config.yaml");
        let state = FirewallAppState::new(config);
        let backend = MockDataplane::default();

        let error = run_with_backend(&state, &backend)
            .await
            .expect_err("missing runtime config rejected");
        assert!(
            error
                .to_string()
                .contains("smoke mode was not explicitly requested")
        );
    }

    fn make_cached_rule(fun: i32, payload: &str) -> CachedRule {
        make_cached_rule_with_version(fun, payload, 1, 0, 1, "deadbeef")
    }

    fn make_cached_rule_with_version(
        fun: i32,
        payload: &str,
        major: i32,
        minor: i32,
        version: i32,
        sha256: &str,
    ) -> CachedRule {
        CachedRule::builder()
            .acd(1234)
            .fun(fun)
            .prot_ver(1)
            .ver(version)
            .major_ver(major)
            .minor_ver(minor)
            .rule(payload.as_bytes().to_vec())
            .sha256(sha256.to_string())
            .sign(String::new())
            .build()
    }

    #[tokio::test]
    async fn managed_session_reports_reconnect_on_disconnect() {
        let state = FirewallAppState::new(FirewallConfig::default());
        let backend = MockDataplane::default();
        let mut db = FirewallDb::open_in_memory().expect("db opened");
        let client = MockFirewalldClient::default();
        transition(&state, RuntimePhase::Bootstrap)
            .await
            .expect("bootstrap phase");
        client.set_firewall_rule(make_cached_rule(
            FIREWALL_FUN_ID,
            "name=allow,dip=10.0.0.1,dport=53,chain=output,action=allow",
        ));
        client.set_traffic_rule(make_cached_rule(TRAFFIC_FUN_ID, "{\"cycle\":10}"));
        client.send_event(IntegrationEvent::RegistrationSucceeded(1234));
        client.send_event(IntegrationEvent::Disconnected("bye".to_string()));

        let result = run_managed_session(
            &state,
            &backend,
            &mut db,
            &client,
            &mut RuleManager::default(),
            &mut RuleCache::default(),
            &mut TrafficWindowState::default(),
        )
        .await
        .expect("session result");
        assert_eq!(result, SessionEnd::Reconnect);
    }

    #[tokio::test]
    async fn managed_session_marks_outbox_failed_when_report_send_fails() {
        let mut config = FirewallConfig::default();
        config.runtime_report_interval = Duration::from_millis(5);
        let state = FirewallAppState::new(config);
        let backend = MockDataplane::default();
        let mut db = FirewallDb::open_in_memory().expect("db opened");
        let client = MockFirewalldClient::default();
        *client.report_result.lock().expect("report mutex") = Err(
            idps_client::error::ClientError::InvalidRuntimeConfig("report fail".to_string()),
        );
        transition(&state, RuntimePhase::Bootstrap)
            .await
            .expect("bootstrap phase");
        client.set_firewall_rule(make_cached_rule(
            FIREWALL_FUN_ID,
            "name=allow,dip=10.0.0.1,dport=53,chain=output,action=allow",
        ));
        client.set_traffic_rule(make_cached_rule(TRAFFIC_FUN_ID, "{\"cycle\":10}"));
        client.send_event(IntegrationEvent::RegistrationSucceeded(1234));

        let payload = ReportPayload::FirewallEvent(FirewallEventPayload {
            report_id: "evt-1".to_string(),
            event_id: "evt-1".to_string(),
            event_ids: vec!["evt-1".to_string()],
            event_time_secs: 1,
            event_type: crate::event::classify::BusinessEventType::NetworkBlock,
            action: "block".to_string(),
            detail: "blocked".to_string(),
            detail_len: "blocked".len(),
            app_id: Some("prog:curl".to_string()),
            app_name: Some("curl".to_string()),
            pkgname: None,
            rule_id: Some("rule-1".to_string()),
            src_ip: "10.0.0.1".to_string(),
            src_port: 1,
            dst_ip: "10.0.0.2".to_string(),
            dst_port: 2,
            proto: "tcp".to_string(),
        });
        db.transaction(|tx| {
            enqueue_payload_tx(tx, "evt-1", &payload, 1)?;
            Ok(())
        })
        .expect("payload enqueued");

        let cancel_state = state.clone();
        let cancel_task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            cancel_state.shutdown.cancel();
        });
        let _ = run_managed_session(
            &state,
            &backend,
            &mut db,
            &client,
            &mut RuleManager::default(),
            &mut RuleCache::default(),
            &mut TrafficWindowState::default(),
        )
        .await;
        cancel_task.await.expect("cancel task joined");
        let failed = crate::persistence::outbox::count_by_state(
            db.connection(),
            crate::persistence::outbox::OutboxState::Failed,
        )
        .expect("failed count");
        assert_eq!(failed, 1);
    }

    #[tokio::test]
    async fn managed_session_marks_outbox_succeeded_on_report_ack() {
        let mut config = FirewallConfig::default();
        config.runtime_report_interval = Duration::from_millis(5);
        let state = FirewallAppState::new(config);
        let backend = MockDataplane::default();
        let mut db = FirewallDb::open_in_memory().expect("db opened");
        let client = MockFirewalldClient::default();
        transition(&state, RuntimePhase::Bootstrap)
            .await
            .expect("bootstrap phase");
        client.set_firewall_rule(make_cached_rule(
            FIREWALL_FUN_ID,
            "name=allow,dip=10.0.0.1,dport=53,chain=output,action=allow",
        ));
        client.set_traffic_rule(make_cached_rule(TRAFFIC_FUN_ID, "{\"cycle\":10}"));
        client.send_event(IntegrationEvent::RegistrationSucceeded(1234));

        let payload = ReportPayload::FirewallEvent(FirewallEventPayload {
            report_id: "evt-ack".to_string(),
            event_id: "evt-ack".to_string(),
            event_ids: vec!["evt-ack".to_string()],
            event_time_secs: 1,
            event_type: crate::event::classify::BusinessEventType::NetworkBlock,
            action: "block".to_string(),
            detail: "blocked".to_string(),
            detail_len: "blocked".len(),
            app_id: Some("prog:curl".to_string()),
            app_name: Some("curl".to_string()),
            pkgname: None,
            rule_id: Some("rule-1".to_string()),
            src_ip: "10.0.0.1".to_string(),
            src_port: 1,
            dst_ip: "10.0.0.2".to_string(),
            dst_port: 2,
            proto: "tcp".to_string(),
        });
        db.insert_or_replace_firewall_event(
            &FactEvent {
                event_id: "evt-ack".to_string(),
                event_time_secs: 1,
                kind: FactEventKind::EgressRuleMatch,
                action: crate::dataplane::events::FactAction::Block,
                src_ip: "10.0.0.1".to_string(),
                src_port: 1,
                dst_ip: "10.0.0.2".to_string(),
                dst_port: 2,
                proto: "tcp".to_string(),
                ifindex: 1,
                pid: None,
                tgid: None,
                uid: None,
                comm: None,
                app_id: Some("prog:curl".to_string()),
                rule_id: Some("rule-1".to_string()),
            },
            "pending",
        )
        .expect("event inserted");
        db.transaction(|tx| {
            enqueue_payload_tx(tx, "evt-ack", &payload, 1)?;
            Ok(())
        })
        .expect("payload enqueued");

        let event_client = client.event_tx.clone();
        let cancel_state = state.clone();
        let cancel_task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let _ = event_client.send(IntegrationEvent::ReportAcknowledged);
            tokio::time::sleep(Duration::from_millis(10)).await;
            cancel_state.shutdown.cancel();
        });
        let _ = run_managed_session(
            &state,
            &backend,
            &mut db,
            &client,
            &mut RuleManager::default(),
            &mut RuleCache::default(),
            &mut TrafficWindowState::default(),
        )
        .await;
        cancel_task.await.expect("cancel task joined");
        let succeeded = crate::persistence::outbox::count_by_state(
            db.connection(),
            crate::persistence::outbox::OutboxState::Succeeded,
        )
        .expect("succeeded count");
        assert_eq!(succeeded, 1);
    }

    #[tokio::test]
    async fn managed_session_reapplies_rules_after_rule_update() {
        let state = FirewallAppState::new(FirewallConfig::default());
        let backend = MockDataplane::default();
        let mut db = FirewallDb::open_in_memory().expect("db opened");
        let client = MockFirewalldClient::default();
        transition(&state, RuntimePhase::Bootstrap)
            .await
            .expect("bootstrap phase");
        client.set_firewall_rule(make_cached_rule(
            FIREWALL_FUN_ID,
            "name=allow,dip=10.0.0.1,dport=53,chain=output,action=allow",
        ));
        client.set_traffic_rule(make_cached_rule(TRAFFIC_FUN_ID, "{\"cycle\":10}"));
        client.send_event(IntegrationEvent::RegistrationSucceeded(1234));

        let update_client = client.firewall_rule_sender();
        let cancel_state = state.clone();
        let update_task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let _ = update_client.send(Some(make_cached_rule(
                FIREWALL_FUN_ID,
                "name=block,dip=10.0.0.2,dport=443,chain=output,action=block",
            )));
            tokio::time::sleep(Duration::from_millis(10)).await;
            cancel_state.shutdown.cancel();
        });
        let _ = run_managed_session(
            &state,
            &backend,
            &mut db,
            &client,
            &mut RuleManager::default(),
            &mut RuleCache::default(),
            &mut TrafficWindowState::default(),
        )
        .await;
        update_task.await.expect("update task joined");
        assert!(backend.is_initialized());
    }

    #[tokio::test]
    async fn managed_session_returns_error_when_dataplane_apply_fails() {
        let state = FirewallAppState::new(FirewallConfig::default());
        let backend = MockDataplane::default();
        backend.set_fail_apply(true);
        let mut db = FirewallDb::open_in_memory().expect("db opened");
        let client = MockFirewalldClient::default();
        transition(&state, RuntimePhase::Bootstrap)
            .await
            .expect("bootstrap phase");
        client.set_firewall_rule(make_cached_rule(
            FIREWALL_FUN_ID,
            "name=allow,dip=10.0.0.1,dport=53,chain=output,action=allow",
        ));
        client.set_traffic_rule(make_cached_rule(TRAFFIC_FUN_ID, "{\"cycle\":10}"));
        client.send_event(IntegrationEvent::RegistrationSucceeded(1234));

        let error = run_managed_session(
            &state,
            &backend,
            &mut db,
            &client,
            &mut RuleManager::default(),
            &mut RuleCache::default(),
            &mut TrafficWindowState::default(),
        )
        .await
        .expect_err("apply failure surfaced");
        assert!(error.to_string().contains("mock dataplane apply failure"));
    }

    #[tokio::test]
    async fn managed_session_returns_error_when_register_fails() {
        let state = FirewallAppState::new(FirewallConfig::default());
        let backend = MockDataplane::default();
        let mut db = FirewallDb::open_in_memory().expect("db opened");
        let mut client = MockFirewalldClient::default();
        client.registration = None;
        client.registration_error = Some("register fail".to_string());
        transition(&state, RuntimePhase::Bootstrap)
            .await
            .expect("bootstrap phase");

        let error = run_managed_session(
            &state,
            &backend,
            &mut db,
            &client,
            &mut RuleManager::default(),
            &mut RuleCache::default(),
            &mut TrafficWindowState::default(),
        )
        .await
        .expect_err("register failure surfaced");
        assert!(
            error
                .to_string()
                .contains("failed to send register request")
        );
    }

    #[tokio::test]
    async fn managed_session_soak_harness_survives_multiple_rule_updates_and_ack() {
        let mut config = FirewallConfig::default();
        config.runtime_report_interval = Duration::from_millis(5);
        let state = FirewallAppState::new(config);
        let backend = MockDataplane::default();
        let mut db = FirewallDb::open_in_memory().expect("db opened");
        let client = MockFirewalldClient::default();
        transition(&state, RuntimePhase::Bootstrap)
            .await
            .expect("bootstrap phase");
        client.set_firewall_rule(make_cached_rule(
            FIREWALL_FUN_ID,
            "name=allow,dip=10.0.0.1,dport=53,chain=output,action=allow",
        ));
        client.set_traffic_rule(make_cached_rule(TRAFFIC_FUN_ID, "{\"cycle\":10}"));
        client.send_event(IntegrationEvent::RegistrationSucceeded(1234));

        let payload = ReportPayload::FirewallEvent(FirewallEventPayload {
            report_id: "evt-soak".to_string(),
            event_id: "evt-soak".to_string(),
            event_ids: vec!["evt-soak".to_string()],
            event_time_secs: 1,
            event_type: crate::event::classify::BusinessEventType::NetworkBlock,
            action: "block".to_string(),
            detail: "blocked".to_string(),
            detail_len: "blocked".len(),
            app_id: Some("prog:curl".to_string()),
            app_name: Some("curl".to_string()),
            pkgname: None,
            rule_id: Some("rule-1".to_string()),
            src_ip: "10.0.0.1".to_string(),
            src_port: 1,
            dst_ip: "10.0.0.2".to_string(),
            dst_port: 2,
            proto: "tcp".to_string(),
        });
        db.insert_or_replace_firewall_event(
            &FactEvent {
                event_id: "evt-soak".to_string(),
                event_time_secs: 1,
                kind: FactEventKind::EgressRuleMatch,
                action: crate::dataplane::events::FactAction::Block,
                src_ip: "10.0.0.1".to_string(),
                src_port: 1,
                dst_ip: "10.0.0.2".to_string(),
                dst_port: 2,
                proto: "tcp".to_string(),
                ifindex: 1,
                pid: None,
                tgid: None,
                uid: None,
                comm: None,
                app_id: Some("prog:curl".to_string()),
                rule_id: Some("rule-1".to_string()),
            },
            "pending",
        )
        .expect("event inserted");
        db.transaction(|tx| {
            enqueue_payload_tx(tx, "evt-soak", &payload, 1)?;
            Ok(())
        })
        .expect("payload enqueued");

        let update_client = client.firewall_rule_sender();
        let event_client = client.event_tx.clone();
        let cancel_state = state.clone();
        let driver = tokio::spawn(async move {
            for idx in 0..3 {
                tokio::time::sleep(Duration::from_millis(10)).await;
                let _ = update_client.send(Some(make_cached_rule(
                    FIREWALL_FUN_ID,
                    &format!("name=rule-{idx},dip=10.0.0.{idx},dport=53,chain=output,action=allow"),
                )));
            }
            let _ = event_client.send(IntegrationEvent::ReportAcknowledged);
            tokio::time::sleep(Duration::from_millis(10)).await;
            cancel_state.shutdown.cancel();
        });
        let _ = run_managed_session(
            &state,
            &backend,
            &mut db,
            &client,
            &mut RuleManager::default(),
            &mut RuleCache::default(),
            &mut TrafficWindowState::default(),
        )
        .await;
        driver.await.expect("driver joined");
        let succeeded = crate::persistence::outbox::count_by_state(
            db.connection(),
            crate::persistence::outbox::OutboxState::Succeeded,
        )
        .expect("succeeded count");
        assert_eq!(succeeded, 1);
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

    #[test]
    fn log_health_snapshot_includes_dataplane_health() {
        let db = FirewallDb::open_in_memory().expect("db opened");
        let backend = MockDataplane::default();
        let applied = AppliedRules {
            version: "v1".to_string(),
            checksum: "abc".to_string(),
            traffic_cycle_secs: Some(10),
        };
        log_health_snapshot(
            RuntimePhase::Running,
            &db,
            &applied,
            &backend,
            true,
            true,
            None,
            None,
            &TrafficWindowState::default(),
            &FactWindowBuffer::default(),
        )
        .expect("health logged");
    }

    #[tokio::test]
    async fn invalid_candidate_does_not_replace_active_snapshot() {
        let backend = MockDataplane::default();
        backend.initialize().await.expect("backend initialized");
        let mut db = FirewallDb::open_in_memory().expect("db opened");
        let mut rule_manager = RuleManager::default();
        let mut traffic_window = TrafficWindowState::default();

        let valid_firewall = make_cached_rule_with_version(
            FIREWALL_FUN_ID,
            "prog=test-client,allow=true",
            1,
            0,
            1,
            "sha-valid",
        );
        let valid_traffic =
            make_cached_rule_with_version(TRAFFIC_FUN_ID, "{\"cycle\":10}", 1, 0, 1, "sha-traffic");
        let valid_cache = RuleCache {
            firewall: Some(valid_firewall),
            traffic: Some(valid_traffic),
        };
        apply_rules_from_cache(
            &backend,
            &mut db,
            &mut rule_manager,
            &valid_cache,
            &mut traffic_window,
            true,
        )
        .await
        .expect("valid rules applied");

        let invalid_cache = RuleCache {
            firewall: Some(make_cached_rule_with_version(
                FIREWALL_FUN_ID,
                "prog=test-client,allow=maybe",
                2,
                0,
                1,
                "sha-invalid",
            )),
            traffic: valid_cache.traffic.clone(),
        };
        let applied = apply_rules_from_cache(
            &backend,
            &mut db,
            &mut rule_manager,
            &invalid_cache,
            &mut traffic_window,
            false,
        )
        .await
        .expect("invalid candidate falls back")
        .expect("applied rules");

        assert_eq!(applied.version, "firewall=1.0.1;traffic=1.0.1");
        assert_eq!(
            db.latest_rule_snapshot_with_status(FIREWALL_FUN_ID, "active")
                .expect("active snapshot")
                .expect("active row")
                .rule_version,
            "1.0.1"
        );
        assert_eq!(
            db.latest_rule_snapshot_with_status(FIREWALL_FUN_ID, "received")
                .expect("received snapshot")
                .expect("received row")
                .rule_version,
            "2.0.1"
        );
    }

    #[test]
    fn restores_app_identity_cache_from_db() {
        let db = FirewallDb::open_in_memory().expect("db opened");
        db.upsert_app_identity(&AppIdentity {
            app_id: "prog:curl".to_string(),
            identity_type: IdentityType::Program,
            package: None,
            app_name: None,
            program: Some("curl".to_string()),
            uid: Some(1000),
        })
        .expect("identity inserted");
        let identities = restore_app_identity_cache(&db).expect("cache restored");
        assert_eq!(identities.len(), 1);
        assert_eq!(identities[0].app_id, "prog:curl");
    }

    #[test]
    fn restores_inflight_traffic_window_state_from_db() {
        let db = FirewallDb::open_in_memory().expect("db opened");
        db.upsert_traffic_window_state(&crate::persistence::db::TrafficWindowStateRow {
            cursor_key: "default".to_string(),
            window_start: Some(10),
            cycle_secs: Some(30),
            global: GlobalStats {
                ingress_bytes: 1,
                egress_bytes: 2,
                ingress_packets: 3,
                egress_packets: 4,
            },
            apps: vec![AppTrafficSummary {
                app_id: "pkg:com.demo.browser".to_string(),
                wifi_bytes: 10,
                mobile_bytes: 20,
            }],
            updated_at: 100,
        })
        .expect("window state inserted");

        let mut traffic_window = TrafficWindowState::default();
        restore_traffic_window_cursor(&db, &mut traffic_window).expect("state restored");

        assert_eq!(traffic_window.window_start, Some(10));
        assert_eq!(traffic_window.cycle_secs, Some(30));
        assert_eq!(traffic_window.global.egress_bytes, 2);
        assert_eq!(traffic_window.apps.len(), 1);
    }

    #[test]
    fn fact_buffer_groups_same_second_events() {
        let mut buffer = FactWindowBuffer::default();
        let event = FactEvent {
            event_id: "evt-1".to_string(),
            event_time_secs: 1,
            kind: FactEventKind::IngressRuleMatch,
            action: crate::dataplane::events::FactAction::Block,
            src_ip: "10.0.0.1".to_string(),
            src_port: 100,
            dst_ip: "10.0.0.2".to_string(),
            dst_port: 200,
            proto: "tcp".to_string(),
            ifindex: 1,
            pid: None,
            tgid: None,
            uid: None,
            comm: None,
            app_id: None,
            rule_id: Some("r1".to_string()),
        };
        buffer.push(event.clone());
        buffer.push(FactEvent {
            event_id: "evt-2".to_string(),
            ..event
        });
        let flushed = buffer.flush_ready(2, false);
        assert_eq!(flushed.len(), 1);
        assert_eq!(flushed[0].event_ids.len(), 2);
    }
}
