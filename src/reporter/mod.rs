//! Local report outbox and retry helpers.

use anyhow::{Context, Result, bail};
use idps_client::report::SecurityEvent;
use idps_protocol::serialize::report_detail::ReportDetail;
use idps_protocol::types::component::{AttackType, ResultAction};
use idps_protocol::types::report::{
    FirewallDetail, IntrusionDetail, TrafficAppDetail, TrafficDetail,
};
use rusqlite::{Connection, Transaction};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::event::classify::BusinessEventType;
use crate::persistence::outbox::{
    OutboxEntry, OutboxState, count_by_state, enqueue_report, enqueue_report_tx,
};

const REPORT_TYPE_FIREWALL_EVENT: &str = "firewall_event";
const REPORT_TYPE_APP_TRAFFIC: &str = "traffic_app_summary";
const REPORT_TYPE_GLOBAL_TRAFFIC: &str = "traffic_global_summary";

/// One serialized outbound report payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReportPayload {
    /// Firewall or intrusion event.
    FirewallEvent(FirewallEventPayload),
    /// Application traffic window summary.
    AppTrafficSummary(AppTrafficSummaryPayload),
    /// Global traffic window summary.
    GlobalTrafficSummary(GlobalTrafficSummaryPayload),
}

impl ReportPayload {
    /// Return the logical report type stored in the outbox.
    #[must_use]
    pub const fn report_type(&self) -> &'static str {
        match self {
            Self::FirewallEvent(_) => REPORT_TYPE_FIREWALL_EVENT,
            Self::AppTrafficSummary(_) => REPORT_TYPE_APP_TRAFFIC,
            Self::GlobalTrafficSummary(_) => REPORT_TYPE_GLOBAL_TRAFFIC,
        }
    }

    /// Build a transport-ready `SecurityEvent`.
    ///
    /// # Errors
    ///
    /// Returns an error when the payload is internally inconsistent.
    pub fn to_security_event(&self, acd: i32) -> Result<SecurityEvent> {
        match self {
            Self::FirewallEvent(payload) => payload.to_security_event(acd),
            Self::AppTrafficSummary(payload) => payload.to_security_event(acd),
            Self::GlobalTrafficSummary(payload) => Ok(payload.to_security_event(acd)),
        }
    }
}

/// Firewall business-event payload persisted in the outbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallEventPayload {
    /// Report id shared with the outbox row.
    pub report_id: String,
    /// Primary firewall-event id for audit linkage.
    pub event_id: String,
    /// All source firewall-event ids covered by this business event.
    pub event_ids: Vec<String>,
    /// Event time in seconds since epoch.
    pub event_time_secs: u64,
    /// Business event classification.
    pub event_type: BusinessEventType,
    /// Effective action string.
    pub action: String,
    /// Detail string.
    pub detail: String,
    /// Detail length.
    pub detail_len: usize,
    /// Optional app id.
    pub app_id: Option<String>,
    /// Optional app display name.
    pub app_name: Option<String>,
    /// Optional package name.
    pub pkgname: Option<String>,
    /// Optional rule id.
    pub rule_id: Option<String>,
    /// Source IP.
    pub src_ip: String,
    /// Source port.
    pub src_port: u16,
    /// Destination IP.
    pub dst_ip: String,
    /// Destination port.
    pub dst_port: u16,
    /// L4 protocol.
    pub proto: String,
}

impl FirewallEventPayload {
    fn to_security_event(&self, acd: i32) -> Result<SecurityEvent> {
        let (attack_type, detail) = match self.event_type {
            BusinessEventType::NetworkBlock | BusinessEventType::AppPolicyDeny => (
                AttackType::NetConn.as_i32(),
                FirewallOrIntrusionDetail::Firewall(firewall_detail(
                    &self.src_ip,
                    self.src_port,
                    &self.dst_ip,
                    self.dst_port,
                    &self.proto,
                    &self.detail,
                )?),
            ),
            BusinessEventType::PortScan => (
                match self.proto.as_str() {
                    "udp" => AttackType::IntrusionUdpPortScan.as_i32(),
                    _ => AttackType::IntrusionTcpPortScan.as_i32(),
                },
                FirewallOrIntrusionDetail::Intrusion(intrusion_detail(
                    &self.src_ip,
                    self.src_port,
                    &self.dst_ip,
                    self.dst_port,
                    &self.detail,
                )?),
            ),
            BusinessEventType::ConnectionStateAnomaly => (
                match self.proto.as_str() {
                    "udp" => AttackType::IntrusionUdpAbnPacket.as_i32(),
                    _ => AttackType::IntrusionTcpAbnPacket.as_i32(),
                },
                FirewallOrIntrusionDetail::Intrusion(intrusion_detail(
                    &self.src_ip,
                    self.src_port,
                    &self.dst_ip,
                    self.dst_port,
                    &self.detail,
                )?),
            ),
        };

        let event = SecurityEvent::new(acd, attack_type, result_action(&self.action))
            .with_description(self.detail.clone())
            .with_ip(self.src_ip.clone())
            .with_time_ms(self.event_time_secs.saturating_mul(1000));

        Ok(match detail {
            FirewallOrIntrusionDetail::Firewall(detail) => {
                event.with_typed_detail(ReportDetail::Firewall(detail))
            }
            FirewallOrIntrusionDetail::Intrusion(detail) => {
                event.with_typed_detail(ReportDetail::Intrusion(detail))
            }
        })
    }
}

/// Application traffic-window payload persisted in the outbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppTrafficSummaryPayload {
    /// Report id shared with the outbox row.
    pub report_id: String,
    /// Window start.
    pub window_start: u64,
    /// Window end.
    pub window_end: u64,
    /// Aggregated applications.
    pub apps: Vec<AppTrafficAppPayload>,
}

impl AppTrafficSummaryPayload {
    fn to_security_event(&self, acd: i32) -> Result<SecurityEvent> {
        let detail = traffic_detail(self.window_start, self.window_end, &self.apps)?;

        Ok(SecurityEvent::new(
            acd,
            AttackType::FlowMonitor.as_i32(),
            ResultAction::Pass as u8,
        )
        .with_description("application traffic summary")
        .with_time_ms(self.window_end.saturating_mul(1000))
        .with_typed_detail(ReportDetail::Traffic(detail)))
    }
}

/// One application entry in a traffic summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppTrafficAppPayload {
    /// Internal app id.
    pub app_id: String,
    /// Package name.
    pub pkgname: String,
    /// Display app name.
    pub appname: String,
    /// Wi-Fi bytes.
    pub wifi_bytes: u64,
    /// Mobile bytes.
    pub mobile_bytes: u64,
}

/// Global traffic-window payload persisted in the outbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GlobalTrafficSummaryPayload {
    /// Report id shared with the outbox row.
    pub report_id: String,
    /// Window start.
    pub window_start: u64,
    /// Window end.
    pub window_end: u64,
    /// Ingress bytes.
    pub ingress_bytes: u64,
    /// Egress bytes.
    pub egress_bytes: u64,
    /// Ingress packets.
    pub ingress_packets: u64,
    /// Egress packets.
    pub egress_packets: u64,
}

impl GlobalTrafficSummaryPayload {
    fn to_security_event(&self, acd: i32) -> SecurityEvent {
        let payload = json!({
            "windowStart": self.window_start,
            "windowEnd": self.window_end,
            "ingressBytes": self.ingress_bytes,
            "egressBytes": self.egress_bytes,
            "ingressPackets": self.ingress_packets,
            "egressPackets": self.egress_packets,
            "scope": "device",
        });

        SecurityEvent::new(
            acd,
            AttackType::FlowMonitor.as_i32(),
            ResultAction::Pass as u8,
        )
        .with_description("global traffic summary")
        .with_time_ms(self.window_end.saturating_mul(1000))
        .with_json_detail(payload.to_string())
    }
}

#[derive(Debug, Clone, PartialEq)]
enum FirewallOrIntrusionDetail {
    Firewall(FirewallDetail),
    Intrusion(IntrusionDetail),
}

/// Count pending items that still need upload.
///
/// # Errors
///
/// Returns an error when the outbox query fails.
pub fn pending_reports(conn: &Connection) -> Result<i64> {
    count_by_state(conn, OutboxState::Pending)
}

/// Enqueue a typed report payload.
///
/// # Errors
///
/// Returns an error when serialization or persistence fails.
pub fn enqueue_payload(
    conn: &Connection,
    report_id: &str,
    payload: &ReportPayload,
    created_at: i64,
) -> Result<()> {
    let serialized =
        serde_json::to_string(payload).context("failed to serialize report payload")?;
    enqueue_report(
        conn,
        report_id,
        payload.report_type(),
        &serialized,
        created_at,
    )
}

/// Enqueue a typed report payload inside an existing transaction.
///
/// # Errors
///
/// Returns an error when serialization or persistence fails.
pub fn enqueue_payload_tx(
    tx: &Transaction<'_>,
    report_id: &str,
    payload: &ReportPayload,
    created_at: i64,
) -> Result<()> {
    let serialized =
        serde_json::to_string(payload).context("failed to serialize report payload")?;
    enqueue_report_tx(
        tx,
        report_id,
        payload.report_type(),
        &serialized,
        created_at,
    )
}

/// Decode one claimed outbox row into a typed payload.
///
/// # Errors
///
/// Returns an error when the outbox row is malformed.
pub fn decode_payload(entry: &OutboxEntry) -> Result<ReportPayload> {
    let payload: ReportPayload =
        serde_json::from_str(&entry.payload).context("failed to decode outbox payload")?;
    if payload.report_type() != entry.report_type {
        bail!(
            "outbox report type mismatch: stored={} decoded={}",
            entry.report_type,
            payload.report_type()
        );
    }
    Ok(payload)
}

fn protocol_number(proto: &str) -> i32 {
    match proto {
        "icmp" => 1,
        "tcp" => 6,
        "udp" => 17,
        _ => 0,
    }
}

fn result_action(action: &str) -> u8 {
    match action {
        "allow" => ResultAction::Pass as u8,
        "alert" => ResultAction::Warn as u8,
        _ => ResultAction::Block as u8,
    }
}

fn firewall_detail(
    src_ip: &str,
    src_port: u16,
    dst_ip: &str,
    dst_port: u16,
    proto: &str,
    detail: &str,
) -> Result<FirewallDetail> {
    serde_json::from_value(json!({
        "srcip": src_ip,
        "srcpo": src_port.to_string(),
        "desip": dst_ip,
        "despo": dst_port.to_string(),
        "type": protocol_number(proto),
        "det": detail,
    }))
    .context("failed to build firewall detail")
}

fn intrusion_detail(
    src_ip: &str,
    src_port: u16,
    dst_ip: &str,
    dst_port: u16,
    detail: &str,
) -> Result<IntrusionDetail> {
    serde_json::from_value(json!({
        "idpsmd": 0,
        "srcip": src_ip,
        "srcpo": src_port.to_string(),
        "desip": dst_ip,
        "despo": dst_port.to_string(),
        "det": detail,
    }))
    .context("failed to build intrusion detail")
}

fn traffic_detail(
    window_start: u64,
    window_end: u64,
    apps: &[AppTrafficAppPayload],
) -> Result<TrafficDetail> {
    let apps: Vec<TrafficAppDetail> = apps
        .iter()
        .map(|app| {
            serde_json::from_value(json!({
                "pkgname": app.pkgname,
                "appname": app.appname,
                "wifi": app.wifi_bytes,
                "mobile": app.mobile_bytes,
            }))
            .context("failed to build traffic app detail")
        })
        .collect::<Result<_>>()?;

    serde_json::from_value(json!({
        "stime": window_start.saturating_mul(1000),
        "etime": window_end.saturating_mul(1000),
        "apps": apps,
    }))
    .context("failed to build traffic detail")
}

#[cfg(test)]
mod tests {
    use crate::persistence::db::FirewallDb;
    use crate::persistence::outbox::claim_next;
    use idps_protocol::types::component::AttackType;

    use super::{
        AppTrafficAppPayload, AppTrafficSummaryPayload, FirewallEventPayload,
        GlobalTrafficSummaryPayload, ReportPayload, decode_payload, enqueue_payload,
        pending_reports,
    };
    use crate::event::classify::BusinessEventType;

    #[test]
    fn counts_pending_reports() {
        let db = FirewallDb::open_in_memory().expect("db opened");
        let payload = ReportPayload::GlobalTrafficSummary(GlobalTrafficSummaryPayload {
            report_id: "r1".to_string(),
            window_start: 1,
            window_end: 2,
            ingress_bytes: 10,
            egress_bytes: 20,
            ingress_packets: 1,
            egress_packets: 2,
        });
        enqueue_payload(db.connection(), "r1", &payload, 1).expect("enqueue");
        assert_eq!(pending_reports(db.connection()).expect("count"), 1);
    }

    #[test]
    fn decodes_claimed_payload() {
        let db = FirewallDb::open_in_memory().expect("db opened");
        let payload = ReportPayload::FirewallEvent(FirewallEventPayload {
            report_id: "evt-1".to_string(),
            event_id: "evt-1".to_string(),
            event_ids: vec!["evt-1".to_string()],
            event_time_secs: 10,
            event_type: BusinessEventType::NetworkBlock,
            action: "block".to_string(),
            detail: "blocked outbound connect".to_string(),
            detail_len: "blocked outbound connect".len(),
            app_id: Some("pkg:demo".to_string()),
            app_name: Some("Demo Browser".to_string()),
            pkgname: Some("com.demo".to_string()),
            rule_id: Some("rule-1".to_string()),
            src_ip: "10.0.0.1".to_string(),
            src_port: 1000,
            dst_ip: "8.8.8.8".to_string(),
            dst_port: 53,
            proto: "udp".to_string(),
        });
        enqueue_payload(db.connection(), "evt-1", &payload, 10).expect("enqueue");
        let entry = claim_next(db.connection(), 11)
            .expect("claim")
            .expect("entry");
        let decoded = decode_payload(&entry).expect("decode");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn app_traffic_payload_builds_security_event() {
        let payload = ReportPayload::AppTrafficSummary(AppTrafficSummaryPayload {
            report_id: "traffic-1".to_string(),
            window_start: 1,
            window_end: 2,
            apps: vec![AppTrafficAppPayload {
                app_id: "pkg:demo".to_string(),
                pkgname: "com.demo".to_string(),
                appname: "Demo".to_string(),
                wifi_bytes: 100,
                mobile_bytes: 50,
            }],
        });
        let event = payload.to_security_event(1).expect("event");
        assert_eq!(event.atttp, AttackType::FlowMonitor.as_i32());
    }

    #[test]
    fn decode_payload_rejects_mismatched_report_type() {
        let db = FirewallDb::open_in_memory().expect("db opened");
        enqueue_payload(
            db.connection(),
            "evt-1",
            &ReportPayload::FirewallEvent(FirewallEventPayload {
                report_id: "evt-1".to_string(),
                event_id: "evt-1".to_string(),
                event_ids: vec!["evt-1".to_string()],
                event_time_secs: 10,
                event_type: BusinessEventType::NetworkBlock,
                action: "block".to_string(),
                detail: "blocked outbound connect".to_string(),
                detail_len: "blocked outbound connect".len(),
                app_id: Some("pkg:demo".to_string()),
                app_name: Some("Demo Browser".to_string()),
                pkgname: Some("com.demo".to_string()),
                rule_id: Some("rule-1".to_string()),
                src_ip: "10.0.0.1".to_string(),
                src_port: 1000,
                dst_ip: "8.8.8.8".to_string(),
                dst_port: 53,
                proto: "udp".to_string(),
            }),
            10,
        )
        .expect("enqueue");
        db.connection()
            .execute(
                "UPDATE report_outbox SET report_type = 'traffic_app_summary' WHERE report_id = 'evt-1'",
                [],
            )
            .expect("update type");
        let entry = claim_next(db.connection(), 11)
            .expect("claim")
            .expect("entry");
        let error = decode_payload(&entry).expect_err("type mismatch rejected");
        assert!(error.to_string().contains("outbox report type mismatch"));
    }
}
