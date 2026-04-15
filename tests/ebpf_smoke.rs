//! Compile-time smoke coverage for eBPF loader wiring.

use std::path::Path;

use idps_firewalld::config::{DataplaneMode, FirewallConfig};
use idps_firewalld::dataplane::loader::build_backend;

#[test]
fn ebpf_mode_backend_can_be_constructed() {
    let mut config = FirewallConfig::default();
    config.dataplane_mode = DataplaneMode::Ebpf;
    config.attach_ifaces = vec!["eth0".to_string()];
    config.ebpf_object_path = "dummy.o".into();
    let _backend = build_backend(&config);
}

#[test]
fn smoke_script_exists() {
    assert!(Path::new("scripts/ebpf-smoke.sh").exists());
}

#[test]
fn smoke_script_mentions_veth_setup() {
    let script = std::fs::read_to_string("scripts/ebpf-smoke.sh").expect("read smoke script");
    assert!(script.contains("ip link add"));
    assert!(script.contains("ip netns add"));
    assert!(script.contains("IDPS_FIREWALLD_DATAPLANE=ebpf"));
    assert!(script.contains("firewall_event"));
    assert!(script.contains("traffic_global_window"));
}
