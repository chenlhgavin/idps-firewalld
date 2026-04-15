#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OBJ_PATH="${IDPS_FIREWALLD_EBPF_OBJECT:-$ROOT_DIR/target/bpfel-unknown-none/release/idps-firewalld-ebpf}"
ALT_OBJ_PATH="$ROOT_DIR/ebpf/target/bpfel-unknown-none/release/idps-firewalld-ebpf"
VETH_HOST="${IDPS_FIREWALLD_SMOKE_HOST_IFACE:-idpsfw0}"
VETH_NS="${IDPS_FIREWALLD_SMOKE_NS_IFACE:-idpsfw1}"
NETNS="${IDPS_FIREWALLD_SMOKE_NS:-idpsfw-smoke}"
DB_PATH="${IDPS_FIREWALLD_SMOKE_DB:-/tmp/idps-firewalld-smoke.sqlite3}"
LOG_PATH="${IDPS_FIREWALLD_SMOKE_LOG:-/tmp/idps-firewalld-smoke.log}"
RUNTIME_CONFIG="${IDPS_FIREWALLD_CONFIG:-/etc/idd/idps.yaml}"
FIREWALLD_BIN="${IDPS_FIREWALLD_BIN:-$ROOT_DIR/target/debug/idps-firewalld}"

cleanup() {
  set +e
  if [[ -n "${FIREWALLD_PID:-}" ]]; then
    kill "$FIREWALLD_PID" >/dev/null 2>&1 || true
    wait "$FIREWALLD_PID" >/dev/null 2>&1 || true
  fi
  ip netns del "$NETNS" >/dev/null 2>&1 || true
  ip link del "$VETH_HOST" >/dev/null 2>&1 || true
}
trap cleanup EXIT

if [[ "${EUID}" -ne 0 ]]; then
  echo "error: smoke-ebpf requires root"
  exit 1
fi

if [[ ! -f "$OBJ_PATH" && -f "$ALT_OBJ_PATH" ]]; then
  OBJ_PATH="$ALT_OBJ_PATH"
fi

if [[ ! -f "$OBJ_PATH" ]]; then
  echo "error: missing eBPF object at $OBJ_PATH"
  echo "hint: make build-ebpf"
  exit 1
fi

if [[ ! -x "$FIREWALLD_BIN" ]]; then
  echo "error: missing firewalld binary at $FIREWALLD_BIN"
  echo "hint: make build project=firewalld"
  exit 1
fi

for cmd in ip tc timeout ping; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "error: $cmd is required for smoke-ebpf"
    exit 1
  fi
done

if [[ ! -f "$RUNTIME_CONFIG" ]]; then
  echo "error: runtime config not found at $RUNTIME_CONFIG"
  exit 1
fi

rm -f "$DB_PATH" "$LOG_PATH"
ip netns add "$NETNS"
ip link add "$VETH_HOST" type veth peer name "$VETH_NS"
ip link set "$VETH_NS" netns "$NETNS"
ip addr add 192.0.2.1/24 dev "$VETH_HOST"
ip link set "$VETH_HOST" up
ip netns exec "$NETNS" ip addr add 192.0.2.2/24 dev "$VETH_NS"
ip netns exec "$NETNS" ip link set lo up
ip netns exec "$NETNS" ip link set "$VETH_NS" up

export IDPS_FIREWALLD_DATAPLANE=ebpf
export IDPS_FIREWALLD_EBPF_OBJECT="$OBJ_PATH"
export IDPS_FIREWALLD_ATTACH_IFACES="$VETH_HOST"
export IDPS_FIREWALLD_DB="$DB_PATH"
export IDPS_FIREWALLD_CONFIG="$RUNTIME_CONFIG"
export IDPS_FIREWALLD_SMOKE_RULESET_VERSION="${IDPS_FIREWALLD_SMOKE_RULESET_VERSION:-smoke-v1}"
export IDPS_FIREWALLD_SMOKE_FIREWALL_RULES="${IDPS_FIREWALLD_SMOKE_FIREWALL_RULES:-name=smoke-block,dip=192.0.2.1,chain=output,action=block}"
export IDPS_FIREWALLD_SMOKE_TRAFFIC_POLICY="${IDPS_FIREWALLD_SMOKE_TRAFFIC_POLICY:-{\"cycle\":10}}"
export IDPS_FIREWALLD_SMOKE_POLL_INTERVAL_MS="${IDPS_FIREWALLD_SMOKE_POLL_INTERVAL_MS:-250}"
RUST_LOG="${RUST_LOG:-info}" "$FIREWALLD_BIN" >"$LOG_PATH" 2>&1 &
FIREWALLD_PID=$!

sleep 1
if ! kill -0 "$FIREWALLD_PID" >/dev/null 2>&1; then
  echo "error: firewalld exited early"
  cat "$LOG_PATH"
  exit 1
fi

if ip netns exec "$NETNS" ping -c 3 -W 1 192.0.2.1 >/dev/null 2>&1; then
  echo "error: ping unexpectedly succeeded; smoke block rule did not take effect"
  cat "$LOG_PATH"
  exit 1
fi
sleep 2
kill "$FIREWALLD_PID" >/dev/null 2>&1 || true
wait "$FIREWALLD_PID" >/dev/null 2>&1 || true
FIREWALLD_PID=""

python3 - <<'PY'
import sqlite3
import sys

db = sqlite3.connect("/tmp/idps-firewalld-smoke.sqlite3")
rule = db.execute("SELECT rule_version FROM rule_snapshot ORDER BY id DESC LIMIT 1").fetchone()
if not rule or rule[0] != "smoke-v1":
    print("error: smoke rule snapshot missing or unexpected", rule)
    sys.exit(1)
event_count = db.execute("SELECT COUNT(*) FROM firewall_event").fetchone()[0]
if event_count < 1:
    print("error: expected at least one firewall_event, got", event_count)
    sys.exit(1)
block_count = db.execute("SELECT COUNT(*) FROM firewall_event WHERE action = 'block'").fetchone()[0]
if block_count < 1:
    print("error: expected at least one blocked firewall_event, got", block_count)
    sys.exit(1)
packet_sums = db.execute("SELECT COALESCE(SUM(ingress_packets),0), COALESCE(SUM(egress_packets),0) FROM traffic_global_window").fetchone()
if packet_sums[0] + packet_sums[1] <= 0:
    print("error: expected non-zero traffic_global_window packet counts, got", packet_sums)
    sys.exit(1)
print("smoke database assertions ok")
PY

echo "smoke-ebpf completed setup/run/cleanup/assert sequence"
echo "host iface: $VETH_HOST"
echo "netns iface: $VETH_NS"
echo "db: $DB_PATH"
echo "log: $LOG_PATH"
