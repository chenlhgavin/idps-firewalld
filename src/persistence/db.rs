//! `SQLite` database access for firewall daemon state.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use crate::dataplane::events::FactEvent;
use crate::dataplane::stats::GlobalStats;
use crate::identity::model::{AppIdentity, IdentityType};
use crate::ops::health::HealthSnapshot;
use crate::persistence::schema::{INIT_SCHEMA, SCHEMA_VERSION};
use crate::rule::model::NormalizedRuleSet;
use crate::runtime::RuntimePhase;
use crate::traffic::aggregate::AppTrafficSummary;

/// Local firewall daemon database.
#[derive(Debug)]
pub struct FirewallDb {
    conn: Connection,
}

/// One latest persisted rule snapshot row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleSnapshotRow {
    /// Function id.
    pub fun_id: i32,
    /// Rule version.
    pub rule_version: String,
    /// Rule checksum.
    pub checksum: String,
    /// Load timestamp.
    pub loaded_at: i64,
    /// Snapshot source.
    pub source: String,
    /// Snapshot status.
    pub status: String,
    /// Raw metadata JSON.
    pub raw_metadata: String,
}

/// Retention cleanup result counts.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RetentionCleanupResult {
    /// Deleted firewall event rows.
    pub deleted_firewall_events: usize,
    /// Deleted global traffic window rows.
    pub deleted_global_windows: usize,
    /// Deleted app traffic window rows.
    pub deleted_app_windows: usize,
    /// Deleted succeeded outbox rows.
    pub deleted_outbox_rows: usize,
}

/// Persisted traffic window cursor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrafficWindowCursorRow {
    /// Cursor key.
    pub cursor_key: String,
    /// Window start time.
    pub window_start: Option<i64>,
    /// Active cycle.
    pub cycle_secs: Option<i64>,
    /// Update time.
    pub updated_at: i64,
}

/// Persisted in-flight traffic window state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrafficWindowStateRow {
    /// Cursor key.
    pub cursor_key: String,
    /// Window start time.
    pub window_start: Option<i64>,
    /// Active cycle.
    pub cycle_secs: Option<i64>,
    /// Accumulated global counters.
    pub global: GlobalStats,
    /// Accumulated per-app summaries.
    pub apps: Vec<AppTrafficSummary>,
    /// Update time.
    pub updated_at: i64,
}

impl FirewallDb {
    /// Open or create the database and apply migrations.
    ///
    /// # Errors
    ///
    /// Returns an error when the database cannot be opened or migrated.
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)
            .with_context(|| format!("failed to open firewalld database at {}", path.display()))?;
        let db = Self { conn };
        db.migrate()?;
        Ok(db)
    }

    /// Open an in-memory database for tests.
    ///
    /// # Errors
    ///
    /// Returns an error when schema migration fails.
    pub fn open_in_memory() -> Result<Self> {
        let db = Self {
            conn: Connection::open_in_memory().context("failed to open in-memory database")?,
        };
        db.migrate()?;
        Ok(db)
    }

    /// Return a reference to the raw connection for low-level module use.
    #[must_use]
    pub const fn connection(&self) -> &Connection {
        &self.conn
    }

    /// Execute a closure inside one `SQLite` transaction.
    ///
    /// # Errors
    ///
    /// Returns an error when starting, executing, or committing the transaction fails.
    pub fn transaction<T>(&mut self, f: impl FnOnce(&Transaction<'_>) -> Result<T>) -> Result<T> {
        let transaction = self
            .conn
            .transaction()
            .context("failed to start firewalld transaction")?;
        let result = f(&transaction)?;
        transaction
            .commit()
            .context("failed to commit firewalld transaction")?;
        Ok(result)
    }

    fn migrate(&self) -> Result<()> {
        self.conn
            .execute_batch(INIT_SCHEMA)
            .context("failed to apply firewalld schema")?;
        self.conn
            .pragma_update(None, "user_version", SCHEMA_VERSION)
            .context("failed to set schema version")?;
        Ok(())
    }

    /// Persist a normalized rule snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error when the insert fails.
    pub fn insert_rule_snapshot(
        &self,
        fun_id: i32,
        ruleset: &NormalizedRuleSet,
        source: &str,
        status: &str,
        raw_metadata: &str,
    ) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO rule_snapshot \
                 (fun_id, rule_version, checksum, loaded_at, source, status, raw_metadata) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    fun_id,
                    ruleset.version,
                    ruleset.checksum,
                    now_secs(),
                    source,
                    status,
                    raw_metadata,
                ],
            )
            .context("failed to insert rule snapshot")?;
        Ok(())
    }

    /// Return the latest rule snapshot version for a function id.
    ///
    /// # Errors
    ///
    /// Returns an error when the query fails.
    pub fn latest_rule_version(&self, fun_id: i32) -> Result<Option<String>> {
        Ok(self
            .latest_rule_snapshot(fun_id)?
            .map(|snapshot| snapshot.rule_version))
    }

    /// Return the latest rule snapshot row for a function id.
    ///
    /// # Errors
    ///
    /// Returns an error when the query fails.
    pub fn latest_rule_snapshot(&self, fun_id: i32) -> Result<Option<RuleSnapshotRow>> {
        self.conn
            .query_row(
                "SELECT fun_id, rule_version, checksum, loaded_at, source, status, raw_metadata \
                 FROM rule_snapshot WHERE fun_id = ?1 ORDER BY loaded_at DESC, id DESC LIMIT 1",
                params![fun_id],
                decode_rule_snapshot_row,
            )
            .optional()
            .context("failed to load latest rule snapshot")
    }

    /// Return the latest rule snapshot row for a function id constrained to one
    /// snapshot status.
    ///
    /// # Errors
    ///
    /// Returns an error when the query fails.
    pub fn latest_rule_snapshot_with_status(
        &self,
        fun_id: i32,
        status: &str,
    ) -> Result<Option<RuleSnapshotRow>> {
        self.conn
            .query_row(
                "SELECT fun_id, rule_version, checksum, loaded_at, source, status, raw_metadata \
                 FROM rule_snapshot \
                 WHERE fun_id = ?1 AND status = ?2 \
                 ORDER BY loaded_at DESC, id DESC LIMIT 1",
                params![fun_id, status],
                decode_rule_snapshot_row,
            )
            .optional()
            .with_context(|| {
                format!("failed to load latest {status} rule snapshot for function {fun_id}")
            })
    }

    /// Return the latest rule snapshot version for a function id constrained to
    /// one snapshot status.
    ///
    /// # Errors
    ///
    /// Returns an error when the query fails.
    pub fn latest_rule_version_with_status(
        &self,
        fun_id: i32,
        status: &str,
    ) -> Result<Option<String>> {
        Ok(self
            .latest_rule_snapshot_with_status(fun_id, status)?
            .map(|snapshot| snapshot.rule_version))
    }

    /// Persist or update a drained firewall fact event.
    ///
    /// # Errors
    ///
    /// Returns an error when the upsert fails.
    pub fn insert_or_replace_firewall_event(
        &self,
        event: &FactEvent,
        report_state: &str,
    ) -> Result<()> {
        let event_time = if event.event_time_secs == 0 {
            now_secs()
        } else {
            i64::try_from(event.event_time_secs).unwrap_or(i64::MAX)
        };
        self.conn
            .execute(
                "INSERT OR REPLACE INTO firewall_event \
                 (event_id, event_time, event_type, action, app_id, ifindex, src_ip, src_port, dst_ip, dst_port, proto, rule_id, detail, report_state) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                params![
                    event.event_id,
                    event_time,
                    format!("{:?}", event.kind),
                    format!("{:?}", event.action).to_lowercase(),
                    event.app_id,
                    event.ifindex,
                    event.src_ip,
                    i64::from(event.src_port),
                    event.dst_ip,
                    i64::from(event.dst_port),
                    event.proto,
                    event.rule_id,
                    format!("{}:{} -> {}:{}", event.src_ip, event.src_port, event.dst_ip, event.dst_port),
                    report_state,
                ],
            )
            .context("failed to upsert firewall event")?;
        Ok(())
    }

    /// Persist one global traffic window.
    ///
    /// # Errors
    ///
    /// Returns an error when the insert fails.
    pub fn insert_global_window(
        &self,
        window_start: i64,
        window_end: i64,
        stats: &GlobalStats,
    ) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO traffic_global_window \
                 (window_start, window_end, ingress_bytes, egress_bytes, ingress_packets, egress_packets, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    window_start,
                    window_end,
                    i64::try_from(stats.ingress_bytes).unwrap_or(i64::MAX),
                    i64::try_from(stats.egress_bytes).unwrap_or(i64::MAX),
                    i64::try_from(stats.ingress_packets).unwrap_or(i64::MAX),
                    i64::try_from(stats.egress_packets).unwrap_or(i64::MAX),
                    now_secs(),
                ],
            )
            .context("failed to insert global traffic window")?;
        Ok(())
    }

    /// Persist one application traffic window row.
    ///
    /// # Errors
    ///
    /// Returns an error when the insert fails.
    pub fn insert_app_window(
        &self,
        window_start: i64,
        window_end: i64,
        summary: &AppTrafficSummary,
        pkgname: &str,
        appname: &str,
    ) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO traffic_app_window \
                 (window_start, window_end, app_id, pkgname, appname, wifi_bytes, mobile_bytes, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    window_start,
                    window_end,
                    summary.app_id,
                    pkgname,
                    appname,
                    i64::try_from(summary.wifi_bytes).unwrap_or(i64::MAX),
                    i64::try_from(summary.mobile_bytes).unwrap_or(i64::MAX),
                    now_secs(),
                ],
            )
            .context("failed to insert app traffic window")?;
        Ok(())
    }

    /// Persist or update an application identity row.
    ///
    /// # Errors
    ///
    /// Returns an error when the upsert fails.
    pub fn upsert_app_identity(&self, identity: &AppIdentity) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO app_identity \
                 (app_id, identity_type, pkg, app_name, prog, uid, updated_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) \
                 ON CONFLICT(app_id) DO UPDATE SET \
                   identity_type = excluded.identity_type, \
                   pkg = excluded.pkg, \
                   app_name = excluded.app_name, \
                   prog = excluded.prog, \
                   uid = excluded.uid, \
                   updated_at = excluded.updated_at",
                params![
                    identity.app_id,
                    identity.identity_type.as_str(),
                    identity.package,
                    identity.app_name,
                    identity.program,
                    identity.uid.map(i64::from),
                    now_secs(),
                ],
            )
            .context("failed to upsert app identity")?;
        Ok(())
    }

    /// Load one application identity by app id.
    ///
    /// # Errors
    ///
    /// Returns an error when the query fails.
    pub fn app_identity(&self, app_id: &str) -> Result<Option<AppIdentity>> {
        self.conn
            .query_row(
                "SELECT app_id, identity_type, pkg, app_name, prog, uid \
                 FROM app_identity WHERE app_id = ?1",
                params![app_id],
                decode_app_identity_row,
            )
            .optional()
            .context("failed to load app identity")
    }

    /// Load all persisted application identities.
    ///
    /// # Errors
    ///
    /// Returns an error when the query fails.
    pub fn all_app_identities(&self) -> Result<Vec<AppIdentity>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT app_id, identity_type, pkg, app_name, prog, uid \
                 FROM app_identity ORDER BY updated_at DESC, app_id ASC",
            )
            .context("failed to prepare app identity query")?;
        let rows = stmt
            .query_map([], decode_app_identity_row)
            .context("failed to query app identities")?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("failed to decode app identities")
    }

    /// Persist a raw rule snapshot without requiring a merged ruleset.
    ///
    /// # Errors
    ///
    /// Returns an error when the insert fails.
    pub fn insert_raw_rule_snapshot(
        &self,
        fun_id: i32,
        rule_version: &str,
        checksum: &str,
        source: &str,
        status: &str,
        raw_metadata: &str,
    ) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO rule_snapshot \
                 (fun_id, rule_version, checksum, loaded_at, source, status, raw_metadata) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    fun_id,
                    rule_version,
                    checksum,
                    now_secs(),
                    source,
                    status,
                    raw_metadata,
                ],
            )
            .context("failed to insert raw rule snapshot")?;
        Ok(())
    }

    /// Update the report state for one persisted firewall event.
    ///
    /// # Errors
    ///
    /// Returns an error when the update fails.
    pub fn update_firewall_event_report_state(
        &self,
        event_id: &str,
        report_state: &str,
    ) -> Result<()> {
        self.conn
            .execute(
                "UPDATE firewall_event SET report_state = ?1 WHERE event_id = ?2",
                params![report_state, event_id],
            )
            .with_context(|| {
                format!("failed to update report_state for firewall event {event_id}")
            })?;
        Ok(())
    }

    /// Count persisted firewall events.
    ///
    /// # Errors
    ///
    /// Returns an error when the query fails.
    pub fn count_firewall_events(&self) -> Result<i64> {
        self.conn
            .query_row("SELECT COUNT(*) FROM firewall_event", [], |row| row.get(0))
            .context("failed to count firewall events")
    }

    /// Persist the current traffic window cursor.
    ///
    /// # Errors
    ///
    /// Returns an error when the upsert fails.
    pub fn upsert_traffic_window_cursor(
        &self,
        cursor_key: &str,
        window_start: Option<i64>,
        cycle_secs: Option<i64>,
    ) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO traffic_window_cursor (cursor_key, window_start, cycle_secs, updated_at) \
                 VALUES (?1, ?2, ?3, ?4) \
                 ON CONFLICT(cursor_key) DO UPDATE SET \
                   window_start = excluded.window_start, \
                   cycle_secs = excluded.cycle_secs, \
                   updated_at = excluded.updated_at",
                params![cursor_key, window_start, cycle_secs, now_secs()],
            )
            .context("failed to upsert traffic window cursor")?;
        Ok(())
    }

    /// Load one traffic window cursor by key.
    ///
    /// # Errors
    ///
    /// Returns an error when the query fails.
    pub fn traffic_window_cursor(
        &self,
        cursor_key: &str,
    ) -> Result<Option<TrafficWindowCursorRow>> {
        self.conn
            .query_row(
                "SELECT cursor_key, window_start, cycle_secs, updated_at \
                 FROM traffic_window_cursor WHERE cursor_key = ?1",
                params![cursor_key],
                |row| {
                    Ok(TrafficWindowCursorRow {
                        cursor_key: row.get(0)?,
                        window_start: row.get(1)?,
                        cycle_secs: row.get(2)?,
                        updated_at: row.get(3)?,
                    })
                },
            )
            .optional()
            .context("failed to load traffic window cursor")
    }

    /// Persist the full in-flight traffic window state.
    ///
    /// # Errors
    ///
    /// Returns an error when the upsert fails.
    pub fn upsert_traffic_window_state(&self, state: &TrafficWindowStateRow) -> Result<()> {
        let app_summaries = serde_json::to_string(&state.apps)
            .context("failed to encode traffic window app summaries")?;
        self.conn
            .execute(
                "INSERT INTO traffic_window_state \
                 (cursor_key, window_start, cycle_secs, global_ingress_bytes, global_egress_bytes, \
                  global_ingress_packets, global_egress_packets, app_summaries_json, updated_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9) \
                 ON CONFLICT(cursor_key) DO UPDATE SET \
                   window_start = excluded.window_start, \
                   cycle_secs = excluded.cycle_secs, \
                   global_ingress_bytes = excluded.global_ingress_bytes, \
                   global_egress_bytes = excluded.global_egress_bytes, \
                   global_ingress_packets = excluded.global_ingress_packets, \
                   global_egress_packets = excluded.global_egress_packets, \
                   app_summaries_json = excluded.app_summaries_json, \
                   updated_at = excluded.updated_at",
                params![
                    &state.cursor_key,
                    state.window_start,
                    state.cycle_secs,
                    i64::try_from(state.global.ingress_bytes).unwrap_or(i64::MAX),
                    i64::try_from(state.global.egress_bytes).unwrap_or(i64::MAX),
                    i64::try_from(state.global.ingress_packets).unwrap_or(i64::MAX),
                    i64::try_from(state.global.egress_packets).unwrap_or(i64::MAX),
                    app_summaries,
                    state.updated_at,
                ],
            )
            .context("failed to upsert traffic window state")?;
        Ok(())
    }

    /// Load the full in-flight traffic window state by key.
    ///
    /// # Errors
    ///
    /// Returns an error when the query fails.
    pub fn traffic_window_state(&self, cursor_key: &str) -> Result<Option<TrafficWindowStateRow>> {
        self.conn
            .query_row(
                "SELECT cursor_key, window_start, cycle_secs, global_ingress_bytes, global_egress_bytes, \
                 global_ingress_packets, global_egress_packets, app_summaries_json, updated_at \
                 FROM traffic_window_state WHERE cursor_key = ?1",
                params![cursor_key],
                |row| {
                    let apps_json: String = row.get(7)?;
                    let apps = serde_json::from_str::<Vec<AppTrafficSummary>>(&apps_json)
                        .unwrap_or_default();
                    Ok(TrafficWindowStateRow {
                        cursor_key: row.get(0)?,
                        window_start: row.get(1)?,
                        cycle_secs: row.get(2)?,
                        global: GlobalStats {
                            ingress_bytes: row
                                .get::<_, i64>(3)
                                .ok()
                                .and_then(|value| u64::try_from(value).ok())
                                .unwrap_or_default(),
                            egress_bytes: row
                                .get::<_, i64>(4)
                                .ok()
                                .and_then(|value| u64::try_from(value).ok())
                                .unwrap_or_default(),
                            ingress_packets: row
                                .get::<_, i64>(5)
                                .ok()
                                .and_then(|value| u64::try_from(value).ok())
                                .unwrap_or_default(),
                            egress_packets: row
                                .get::<_, i64>(6)
                                .ok()
                                .and_then(|value| u64::try_from(value).ok())
                                .unwrap_or_default(),
                        },
                        apps,
                        updated_at: row.get(8)?,
                    })
                },
            )
            .optional()
            .context("failed to load traffic window state")
    }

    /// Persist the latest daemon health snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error when the upsert fails.
    pub fn upsert_health_snapshot(&self, snapshot: &HealthSnapshot) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO health_snapshot \
                 (snapshot_key, phase, connected, registered, rule_version, traffic_cycle_secs, pending_reports, \
                  last_report_succeeded_at, last_report_failed_at, current_window_started_at, buffered_fact_windows, \
                  dataplane_status, dataplane_checksum, dataplane_lost_events, updated_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15) \
                 ON CONFLICT(snapshot_key) DO UPDATE SET \
                   phase = excluded.phase, \
                   connected = excluded.connected, \
                   registered = excluded.registered, \
                   rule_version = excluded.rule_version, \
                   traffic_cycle_secs = excluded.traffic_cycle_secs, \
                   pending_reports = excluded.pending_reports, \
                   last_report_succeeded_at = excluded.last_report_succeeded_at, \
                   last_report_failed_at = excluded.last_report_failed_at, \
                   current_window_started_at = excluded.current_window_started_at, \
                   buffered_fact_windows = excluded.buffered_fact_windows, \
                   dataplane_status = excluded.dataplane_status, \
                   dataplane_checksum = excluded.dataplane_checksum, \
                   dataplane_lost_events = excluded.dataplane_lost_events, \
                   updated_at = excluded.updated_at",
                params![
                    "default",
                    snapshot.phase.as_str(),
                    if snapshot.connected { 1_i64 } else { 0_i64 },
                    if snapshot.registered { 1_i64 } else { 0_i64 },
                    snapshot.rule_version.as_deref(),
                    snapshot.traffic_cycle_secs.map(|value| i64::try_from(value).unwrap_or(i64::MAX)),
                    snapshot.pending_reports,
                    snapshot
                        .last_report_succeeded_at
                        .map(|value| i64::try_from(value).unwrap_or(i64::MAX)),
                    snapshot
                        .last_report_failed_at
                        .map(|value| i64::try_from(value).unwrap_or(i64::MAX)),
                    snapshot
                        .current_window_started_at
                        .map(|value| i64::try_from(value).unwrap_or(i64::MAX)),
                    i64::try_from(snapshot.buffered_fact_windows).unwrap_or(i64::MAX),
                    snapshot.dataplane_status.as_str(),
                    snapshot.dataplane_checksum.as_deref(),
                    i64::try_from(snapshot.dataplane_lost_events).unwrap_or(i64::MAX),
                    now_secs(),
                ],
            )
            .context("failed to upsert health snapshot")?;
        Ok(())
    }

    /// Load the latest daemon health snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error when the query fails or the persisted phase cannot be
    /// decoded.
    pub fn latest_health_snapshot(&self) -> Result<Option<HealthSnapshot>> {
        self.conn
            .query_row(
                "SELECT phase, connected, registered, rule_version, traffic_cycle_secs, pending_reports, \
                 last_report_succeeded_at, last_report_failed_at, current_window_started_at, buffered_fact_windows, \
                 dataplane_status, dataplane_checksum, dataplane_lost_events \
                 FROM health_snapshot WHERE snapshot_key = ?1",
                params!["default"],
                |row| {
                    let phase: String = row.get(0)?;
                    let phase = RuntimePhase::from_str(&phase).ok_or_else(|| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Text,
                            format!("unknown runtime phase {phase}").into(),
                        )
                    })?;
                    Ok(HealthSnapshot {
                        phase,
                        connected: row.get::<_, i64>(1)? != 0,
                        registered: row.get::<_, i64>(2)? != 0,
                        rule_version: row.get(3)?,
                        traffic_cycle_secs: row
                            .get::<_, Option<i64>>(4)?
                            .and_then(|value| u64::try_from(value).ok()),
                        pending_reports: row.get(5)?,
                        last_report_succeeded_at: row
                            .get::<_, Option<i64>>(6)?
                            .and_then(|value| u64::try_from(value).ok()),
                        last_report_failed_at: row
                            .get::<_, Option<i64>>(7)?
                            .and_then(|value| u64::try_from(value).ok()),
                        current_window_started_at: row
                            .get::<_, Option<i64>>(8)?
                            .and_then(|value| u64::try_from(value).ok()),
                        buffered_fact_windows: row
                            .get::<_, i64>(9)
                            .ok()
                            .and_then(|value| usize::try_from(value).ok())
                            .unwrap_or_default(),
                        dataplane_status: row.get(10)?,
                        dataplane_checksum: row.get(11)?,
                        dataplane_lost_events: row
                            .get::<_, i64>(12)
                            .ok()
                            .and_then(|value| usize::try_from(value).ok())
                            .unwrap_or_default(),
                    })
                },
            )
            .optional()
            .context("failed to load latest health snapshot")
    }

    /// Delete old persisted rows based on retention cutoffs.
    ///
    /// # Errors
    ///
    /// Returns an error when any delete statement fails.
    pub fn cleanup_retention(
        &self,
        firewall_event_before: i64,
        traffic_window_before: i64,
        succeeded_outbox_before: i64,
    ) -> Result<RetentionCleanupResult> {
        let deleted_firewall_events = self
            .conn
            .execute(
                "DELETE FROM firewall_event WHERE event_time < ?1 AND report_state = 'succeeded'",
                params![firewall_event_before],
            )
            .context("failed to delete retained firewall events")?;
        let deleted_global_windows = self
            .conn
            .execute(
                "DELETE FROM traffic_global_window WHERE window_end < ?1",
                params![traffic_window_before],
            )
            .context("failed to delete retained global windows")?;
        let deleted_app_windows = self
            .conn
            .execute(
                "DELETE FROM traffic_app_window WHERE window_end < ?1",
                params![traffic_window_before],
            )
            .context("failed to delete retained app windows")?;
        let deleted_outbox_rows = self
            .conn
            .execute(
                "DELETE FROM report_outbox WHERE created_at < ?1 AND state = 'succeeded'",
                params![succeeded_outbox_before],
            )
            .context("failed to delete retained outbox rows")?;
        Ok(RetentionCleanupResult {
            deleted_firewall_events,
            deleted_global_windows,
            deleted_app_windows,
            deleted_outbox_rows,
        })
    }

    /// Sum persisted global packet counters.
    ///
    /// # Errors
    ///
    /// Returns an error when the query fails.
    pub fn sum_global_traffic(&self) -> Result<GlobalStats> {
        self.conn
            .query_row(
                "SELECT COALESCE(SUM(ingress_bytes), 0), COALESCE(SUM(egress_bytes), 0), \
                        COALESCE(SUM(ingress_packets), 0), COALESCE(SUM(egress_packets), 0) \
                 FROM traffic_global_window",
                [],
                |row| {
                    Ok(GlobalStats {
                        ingress_bytes: row.get::<_, i64>(0).map_or(0, |value| value.max(0) as u64),
                        egress_bytes: row.get::<_, i64>(1).map_or(0, |value| value.max(0) as u64),
                        ingress_packets: row
                            .get::<_, i64>(2)
                            .map_or(0, |value| value.max(0) as u64),
                        egress_packets: row.get::<_, i64>(3).map_or(0, |value| value.max(0) as u64),
                    })
                },
            )
            .context("failed to sum global traffic")
    }

    /// Sum persisted global packet counters.
    ///
    /// # Errors
    ///
    /// Returns an error when the query fails.
    pub fn sum_global_packets(&self) -> Result<(i64, i64)> {
        self.conn
            .query_row(
                "SELECT COALESCE(SUM(ingress_packets), 0), COALESCE(SUM(egress_packets), 0) FROM traffic_global_window",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .context("failed to sum global packets")
    }
}

fn decode_app_identity_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AppIdentity> {
    let uid = row.get::<_, Option<i64>>(5)?;
    Ok(AppIdentity {
        app_id: row.get(0)?,
        identity_type: IdentityType::from_storage_str(&row.get::<_, String>(1)?),
        package: row.get(2)?,
        app_name: row.get(3)?,
        program: row.get(4)?,
        uid: uid.and_then(|value| u32::try_from(value).ok()),
    })
}

fn decode_rule_snapshot_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RuleSnapshotRow> {
    Ok(RuleSnapshotRow {
        fun_id: row.get(0)?,
        rule_version: row.get(1)?,
        checksum: row.get(2)?,
        loaded_at: row.get(3)?,
        source: row.get(4)?,
        status: row.get(5)?,
        raw_metadata: row.get(6)?,
    })
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
        })
}

#[cfg(test)]
mod tests {
    use super::{FirewallDb, TrafficWindowStateRow};
    use crate::dataplane::events::{FactAction, FactEvent, FactEventKind};
    use crate::dataplane::stats::GlobalStats;
    use crate::ops::health::HealthSnapshot;
    use crate::rule::normalize::build_rule_set;
    use crate::runtime::RuntimePhase;

    #[test]
    fn migration_creates_expected_tables() {
        let db = FirewallDb::open_in_memory().expect("db opened");
        let count: i64 = db
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN \
                 ('rule_snapshot','app_identity','traffic_global_window','traffic_app_window','firewall_event','report_outbox','traffic_window_cursor','traffic_window_state','health_snapshot')",
                [],
                |row| row.get(0),
            )
            .expect("count tables");
        assert_eq!(count, 9);
    }

    #[test]
    fn stores_and_restores_latest_rule_version() {
        let db = FirewallDb::open_in_memory().expect("db opened");
        let ruleset = build_rule_set("v1", "prog=test-client,allow=true", Some("{\"cycle\": 10}"))
            .expect("ruleset");
        db.insert_rule_snapshot(1, &ruleset, "test", "active", "{}")
            .expect("snapshot inserted");
        assert_eq!(
            db.latest_rule_version(1).expect("latest"),
            Some("v1".to_string())
        );
    }

    #[test]
    fn loads_latest_rule_snapshot_row() {
        let db = FirewallDb::open_in_memory().expect("db opened");
        let ruleset = build_rule_set("v1", "prog=test-client,allow=true", Some("{\"cycle\": 10}"))
            .expect("ruleset");
        db.insert_rule_snapshot(4, &ruleset, "test", "active", "{\"payload\":\"x\"}")
            .expect("snapshot inserted");
        let snapshot = db
            .latest_rule_snapshot(4)
            .expect("snapshot loaded")
            .expect("snapshot row");
        assert_eq!(snapshot.fun_id, 4);
        assert_eq!(snapshot.rule_version, "v1");
        assert_eq!(snapshot.source, "test");
    }

    #[test]
    fn loads_all_app_identities() {
        let db = FirewallDb::open_in_memory().expect("db opened");
        db.upsert_app_identity(&crate::identity::model::AppIdentity {
            app_id: "pkg:com.demo.browser".to_string(),
            identity_type: crate::identity::model::IdentityType::App,
            package: Some("com.demo.browser".to_string()),
            app_name: Some("Browser".to_string()),
            program: None,
            uid: Some(1000),
        })
        .expect("identity inserted");
        let identities = db.all_app_identities().expect("identities loaded");
        assert_eq!(identities.len(), 1);
        assert_eq!(identities[0].app_id, "pkg:com.demo.browser");
    }

    #[test]
    fn persists_firewall_events() {
        let db = FirewallDb::open_in_memory().expect("db opened");
        let event = FactEvent {
            event_id: "evt-1".to_string(),
            event_time_secs: 0,
            kind: FactEventKind::EgressRuleMatch,
            action: FactAction::Block,
            src_ip: "192.0.2.2".to_string(),
            src_port: 12345,
            dst_ip: "192.0.2.1".to_string(),
            dst_port: 80,
            proto: "tcp".to_string(),
            ifindex: 1,
            pid: None,
            tgid: None,
            uid: None,
            comm: None,
            app_id: None,
            rule_id: Some("smoke:0".to_string()),
        };
        db.insert_or_replace_firewall_event(&event, "pending")
            .expect("event inserted");
        assert_eq!(db.count_firewall_events().expect("count"), 1);
    }

    #[test]
    fn persists_global_windows() {
        let db = FirewallDb::open_in_memory().expect("db opened");
        db.insert_global_window(
            1,
            2,
            &GlobalStats {
                ingress_bytes: 10,
                egress_bytes: 20,
                ingress_packets: 3,
                egress_packets: 4,
            },
        )
        .expect("window inserted");
        assert_eq!(db.sum_global_packets().expect("sum"), (3, 4));
    }

    #[test]
    fn cleans_up_retained_rows() {
        let db = FirewallDb::open_in_memory().expect("db opened");
        db.insert_or_replace_firewall_event(
            &FactEvent {
                event_id: "evt-1".to_string(),
                event_time_secs: 1,
                kind: FactEventKind::EgressRuleMatch,
                action: FactAction::Block,
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
                app_id: None,
                rule_id: Some("r1".to_string()),
            },
            "succeeded",
        )
        .expect("event inserted");
        db.insert_global_window(1, 2, &GlobalStats::default())
            .expect("global inserted");
        crate::persistence::outbox::enqueue_report(
            db.connection(),
            "r1",
            "firewall_event",
            "{}",
            1,
        )
        .expect("outbox inserted");
        crate::persistence::outbox::mark_succeeded(db.connection(), "r1")
            .expect("outbox succeeded");
        let deleted = db.cleanup_retention(10, 10, 10).expect("cleanup");
        assert_eq!(deleted.deleted_firewall_events, 1);
        assert_eq!(deleted.deleted_global_windows, 1);
        assert_eq!(deleted.deleted_outbox_rows, 1);
    }

    #[test]
    fn stores_and_loads_traffic_window_cursor() {
        let db = FirewallDb::open_in_memory().expect("db opened");
        db.upsert_traffic_window_cursor("default", Some(10), Some(30))
            .expect("cursor stored");
        let cursor = db
            .traffic_window_cursor("default")
            .expect("cursor loaded")
            .expect("cursor row");
        assert_eq!(cursor.window_start, Some(10));
        assert_eq!(cursor.cycle_secs, Some(30));
    }

    #[test]
    fn stores_and_loads_traffic_window_state() {
        let db = FirewallDb::open_in_memory().expect("db opened");
        let state = TrafficWindowStateRow {
            cursor_key: "default".to_string(),
            window_start: Some(10),
            cycle_secs: Some(30),
            global: GlobalStats {
                ingress_bytes: 1,
                egress_bytes: 2,
                ingress_packets: 3,
                egress_packets: 4,
            },
            apps: vec![crate::traffic::aggregate::AppTrafficSummary {
                app_id: "pkg:com.demo.browser".to_string(),
                wifi_bytes: 10,
                mobile_bytes: 20,
            }],
            updated_at: 100,
        };
        db.upsert_traffic_window_state(&state)
            .expect("state persisted");
        let restored = db
            .traffic_window_state("default")
            .expect("state loaded")
            .expect("state row");
        assert_eq!(restored.window_start, Some(10));
        assert_eq!(restored.cycle_secs, Some(30));
        assert_eq!(restored.global.egress_bytes, 2);
        assert_eq!(restored.apps.len(), 1);
        assert_eq!(restored.apps[0].wifi_bytes, 10);
    }

    #[test]
    fn loads_rule_snapshot_by_status() {
        let db = FirewallDb::open_in_memory().expect("db opened");
        db.insert_raw_rule_snapshot(1, "v1", "aaa", "test", "received", "{\"payload\":\"x\"}")
            .expect("received inserted");
        db.insert_raw_rule_snapshot(1, "v0", "bbb", "test", "active", "{\"payload\":\"y\"}")
            .expect("active inserted");
        let snapshot = db
            .latest_rule_snapshot_with_status(1, "active")
            .expect("snapshot loaded")
            .expect("active snapshot");
        assert_eq!(snapshot.rule_version, "v0");
        assert_eq!(
            db.latest_rule_version_with_status(1, "received")
                .expect("version loaded"),
            Some("v1".to_string())
        );
    }

    #[test]
    fn stores_and_loads_health_snapshot() {
        let db = FirewallDb::open_in_memory().expect("db opened");
        db.upsert_health_snapshot(&HealthSnapshot {
            phase: RuntimePhase::Running,
            connected: true,
            registered: true,
            rule_version: Some("v1".to_string()),
            traffic_cycle_secs: Some(10),
            pending_reports: 2,
            last_report_succeeded_at: Some(3),
            last_report_failed_at: Some(4),
            current_window_started_at: Some(5),
            buffered_fact_windows: 6,
            dataplane_status: "ready".to_string(),
            dataplane_checksum: Some("abc".to_string()),
            dataplane_lost_events: 7,
        })
        .expect("snapshot stored");
        let snapshot = db
            .latest_health_snapshot()
            .expect("snapshot loaded")
            .expect("snapshot row");
        assert_eq!(snapshot.phase, RuntimePhase::Running);
        assert_eq!(snapshot.pending_reports, 2);
        assert_eq!(snapshot.dataplane_checksum.as_deref(), Some("abc"));
    }
}
