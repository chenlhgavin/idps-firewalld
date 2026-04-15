//! Durable report outbox helpers.

use anyhow::{Context, Result, anyhow};
use rusqlite::{Connection, OptionalExtension, params};

/// Report outbox state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboxState {
    /// Pending upload.
    Pending,
    /// Upload is currently in progress.
    InFlight,
    /// Upload completed.
    Succeeded,
    /// Upload failed and can be retried.
    Failed,
}

impl OutboxState {
    /// Return the stable storage string for this state.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::InFlight => "in_flight",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
        }
    }

    /// Parse a persisted outbox state string.
    ///
    /// # Errors
    ///
    /// Returns an error when the value is not recognized.
    pub fn from_storage_str(value: &str) -> Result<Self> {
        match value {
            "pending" => Ok(Self::Pending),
            "in_flight" => Ok(Self::InFlight),
            "succeeded" => Ok(Self::Succeeded),
            "failed" => Ok(Self::Failed),
            _ => Err(anyhow!("unsupported outbox state: {value}")),
        }
    }
}

/// One persisted report-outbox row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxEntry {
    /// Unique report id.
    pub report_id: String,
    /// Logical report type.
    pub report_type: String,
    /// Serialized payload.
    pub payload: String,
    /// Creation timestamp.
    pub created_at: i64,
    /// Current state.
    pub state: OutboxState,
    /// Retry counter.
    pub retry_count: i64,
    /// Last attempt timestamp.
    pub last_attempt_at: Option<i64>,
    /// Last failure detail.
    pub last_error: Option<String>,
}

/// Insert a pending report into the outbox.
///
/// # Errors
///
/// Returns an error when the insert fails.
pub fn enqueue_report(
    conn: &Connection,
    report_id: &str,
    report_type: &str,
    payload: &str,
    created_at: i64,
) -> Result<()> {
    conn.execute(
        "INSERT INTO report_outbox \
         (report_id, report_type, payload, created_at, state, retry_count) \
         VALUES (?1, ?2, ?3, ?4, ?5, 0)",
        params![
            report_id,
            report_type,
            payload,
            created_at,
            OutboxState::Pending.as_str()
        ],
    )
    .context("failed to enqueue report")?;
    Ok(())
}

/// Insert a pending report into the outbox inside an existing transaction.
///
/// # Errors
///
/// Returns an error when the insert fails.
pub fn enqueue_report_tx(
    tx: &rusqlite::Transaction<'_>,
    report_id: &str,
    report_type: &str,
    payload: &str,
    created_at: i64,
) -> Result<()> {
    tx.execute(
        "INSERT INTO report_outbox \
         (report_id, report_type, payload, created_at, state, retry_count) \
         VALUES (?1, ?2, ?3, ?4, ?5, 0)",
        params![
            report_id,
            report_type,
            payload,
            created_at,
            OutboxState::Pending.as_str()
        ],
    )
    .context("failed to enqueue report")?;
    Ok(())
}

/// Count reports currently in a given state.
///
/// # Errors
///
/// Returns an error when the query fails.
pub fn count_by_state(conn: &Connection, state: OutboxState) -> Result<i64> {
    conn.query_row(
        "SELECT COUNT(*) FROM report_outbox WHERE state = ?1",
        params![state.as_str()],
        |row| row.get(0),
    )
    .context("failed to count outbox state")
}

/// Reset stale in-flight reports back to pending.
///
/// # Errors
///
/// Returns an error when the update fails.
pub fn reset_in_flight(conn: &Connection) -> Result<usize> {
    conn.execute(
        "UPDATE report_outbox \
         SET state = ?1, last_error = COALESCE(last_error, 'requeued after restart') \
         WHERE state = ?2",
        params![
            OutboxState::Pending.as_str(),
            OutboxState::InFlight.as_str()
        ],
    )
    .context("failed to reset in-flight outbox rows")
}

/// Claim the next retryable outbox row in FIFO order.
///
/// # Errors
///
/// Returns an error when the select or update fails.
pub fn claim_next(conn: &Connection, attempt_at: i64) -> Result<Option<OutboxEntry>> {
    let entry = conn
        .query_row(
            "SELECT report_id, report_type, payload, created_at, state, retry_count, last_attempt_at, last_error \
             FROM report_outbox \
             WHERE state IN (?1, ?2) \
             ORDER BY created_at ASC, report_id ASC \
             LIMIT 1",
            params![OutboxState::Pending.as_str(), OutboxState::Failed.as_str()],
            |row| {
                let state: String = row.get(4)?;
                Ok(OutboxEntry {
                    report_id: row.get(0)?,
                    report_type: row.get(1)?,
                    payload: row.get(2)?,
                    created_at: row.get(3)?,
                    state: OutboxState::from_storage_str(&state).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            4,
                            rusqlite::types::Type::Text,
                            Box::new(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                error.to_string(),
                            )),
                        )
                    })?,
                    retry_count: row.get(5)?,
                    last_attempt_at: row.get(6)?,
                    last_error: row.get(7)?,
                })
            },
        )
        .optional()
        .context("failed to read next outbox row")?;

    let Some(mut entry) = entry else {
        return Ok(None);
    };

    conn.execute(
        "UPDATE report_outbox \
         SET state = ?1, retry_count = retry_count + 1, last_attempt_at = ?2, last_error = NULL \
         WHERE report_id = ?3",
        params![
            OutboxState::InFlight.as_str(),
            attempt_at,
            entry.report_id.as_str()
        ],
    )
    .with_context(|| format!("failed to claim outbox report {}", entry.report_id))?;

    entry.state = OutboxState::InFlight;
    entry.retry_count += 1;
    entry.last_attempt_at = Some(attempt_at);
    entry.last_error = None;
    Ok(Some(entry))
}

/// Mark a report as successfully uploaded.
///
/// # Errors
///
/// Returns an error when the update fails.
pub fn mark_succeeded(conn: &Connection, report_id: &str) -> Result<()> {
    conn.execute(
        "UPDATE report_outbox SET state = ?1, last_error = NULL WHERE report_id = ?2",
        params![OutboxState::Succeeded.as_str(), report_id],
    )
    .with_context(|| format!("failed to mark report {report_id} as succeeded"))?;
    Ok(())
}

/// Mark a claimed report as failed and retryable.
///
/// # Errors
///
/// Returns an error when the update fails.
pub fn mark_failed(conn: &Connection, report_id: &str, error: &str) -> Result<()> {
    conn.execute(
        "UPDATE report_outbox SET state = ?1, last_error = ?2 WHERE report_id = ?3",
        params![OutboxState::Failed.as_str(), error, report_id],
    )
    .with_context(|| format!("failed to mark report {report_id} as failed"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::persistence::db::FirewallDb;

    use super::{
        OutboxState, claim_next, count_by_state, enqueue_report, mark_failed, mark_succeeded,
        reset_in_flight,
    };

    #[test]
    fn enqueues_pending_report() {
        let db = FirewallDb::open_in_memory().expect("db opened");
        enqueue_report(db.connection(), "r1", "firewall_event", "{}", 1).expect("enqueue");
        assert_eq!(
            count_by_state(db.connection(), OutboxState::Pending).expect("count"),
            1
        );
    }

    #[test]
    fn claim_and_complete_report() {
        let db = FirewallDb::open_in_memory().expect("db opened");
        enqueue_report(db.connection(), "r1", "firewall_event", "{}", 1).expect("enqueue");
        let claimed = claim_next(db.connection(), 10)
            .expect("claim")
            .expect("row exists");
        assert_eq!(claimed.state, OutboxState::InFlight);
        assert_eq!(claimed.retry_count, 1);
        mark_succeeded(db.connection(), "r1").expect("mark success");
        assert_eq!(
            count_by_state(db.connection(), OutboxState::Succeeded).expect("count"),
            1
        );
    }

    #[test]
    fn failed_rows_are_retryable() {
        let db = FirewallDb::open_in_memory().expect("db opened");
        enqueue_report(db.connection(), "r1", "firewall_event", "{}", 1).expect("enqueue");
        let _ = claim_next(db.connection(), 10).expect("claim");
        mark_failed(db.connection(), "r1", "boom").expect("mark failed");
        assert_eq!(
            count_by_state(db.connection(), OutboxState::Failed).expect("count"),
            1
        );
        let claimed = claim_next(db.connection(), 20)
            .expect("claim")
            .expect("row exists");
        assert_eq!(claimed.retry_count, 2);
    }

    #[test]
    fn resets_in_flight_rows_after_restart() {
        let db = FirewallDb::open_in_memory().expect("db opened");
        enqueue_report(db.connection(), "r1", "firewall_event", "{}", 1).expect("enqueue");
        let _ = claim_next(db.connection(), 10).expect("claim");
        assert_eq!(reset_in_flight(db.connection()).expect("reset"), 1);
        assert_eq!(
            count_by_state(db.connection(), OutboxState::Pending).expect("count"),
            1
        );
    }
}
