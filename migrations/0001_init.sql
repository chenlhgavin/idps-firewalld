CREATE TABLE IF NOT EXISTS rule_snapshot (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fun_id INTEGER NOT NULL,
    rule_version TEXT NOT NULL,
    checksum TEXT NOT NULL,
    loaded_at INTEGER NOT NULL,
    source TEXT NOT NULL,
    status TEXT NOT NULL,
    raw_metadata TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS app_identity (
    app_id TEXT PRIMARY KEY,
    identity_type TEXT NOT NULL,
    pkg TEXT,
    app_name TEXT,
    prog TEXT,
    uid INTEGER,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS traffic_global_window (
    window_start INTEGER NOT NULL,
    window_end INTEGER NOT NULL,
    ingress_bytes INTEGER NOT NULL,
    egress_bytes INTEGER NOT NULL,
    ingress_packets INTEGER NOT NULL,
    egress_packets INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (window_start, window_end)
);

CREATE TABLE IF NOT EXISTS traffic_app_window (
    window_start INTEGER NOT NULL,
    window_end INTEGER NOT NULL,
    app_id TEXT NOT NULL,
    pkgname TEXT NOT NULL,
    appname TEXT NOT NULL,
    wifi_bytes INTEGER NOT NULL,
    mobile_bytes INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (window_start, window_end, app_id)
);

CREATE TABLE IF NOT EXISTS firewall_event (
    event_id TEXT PRIMARY KEY,
    event_time INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    action TEXT NOT NULL,
    app_id TEXT,
    ifindex INTEGER,
    src_ip TEXT NOT NULL,
    src_port INTEGER NOT NULL,
    dst_ip TEXT NOT NULL,
    dst_port INTEGER NOT NULL,
    proto TEXT NOT NULL,
    rule_id TEXT,
    detail TEXT NOT NULL,
    report_state TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS report_outbox (
    report_id TEXT PRIMARY KEY,
    report_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    state TEXT NOT NULL,
    retry_count INTEGER NOT NULL DEFAULT 0,
    last_attempt_at INTEGER,
    last_error TEXT
);

CREATE TABLE IF NOT EXISTS traffic_window_cursor (
    cursor_key TEXT PRIMARY KEY,
    window_start INTEGER,
    cycle_secs INTEGER,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS traffic_window_state (
    cursor_key TEXT PRIMARY KEY,
    window_start INTEGER,
    cycle_secs INTEGER,
    global_ingress_bytes INTEGER NOT NULL DEFAULT 0,
    global_egress_bytes INTEGER NOT NULL DEFAULT 0,
    global_ingress_packets INTEGER NOT NULL DEFAULT 0,
    global_egress_packets INTEGER NOT NULL DEFAULT 0,
    app_summaries_json TEXT NOT NULL DEFAULT '[]',
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS health_snapshot (
    snapshot_key TEXT PRIMARY KEY,
    phase TEXT NOT NULL,
    connected INTEGER NOT NULL,
    registered INTEGER NOT NULL,
    rule_version TEXT,
    traffic_cycle_secs INTEGER,
    pending_reports INTEGER NOT NULL,
    last_report_succeeded_at INTEGER,
    last_report_failed_at INTEGER,
    current_window_started_at INTEGER,
    buffered_fact_windows INTEGER NOT NULL,
    dataplane_status TEXT NOT NULL,
    dataplane_checksum TEXT,
    dataplane_lost_events INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
