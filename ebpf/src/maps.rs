use aya_ebpf::macros::map;
use aya_ebpf::maps::{Array, HashMap, PerCpuArray, PerCpuHashMap, PerfEventArray};
use bytemuck::{Pod, Zeroable};

pub const NS_PER_SEC: u64 = 1_000_000_000;

pub const TASK_COMM_LEN: usize = 16;
pub const MAX_RULE_ENTRIES: u32 = 1024;
pub const MAX_POLICY_ENTRIES: u32 = 1024;
pub const ACTIVE_CONFIG_SLOTS: u32 = 2;
pub const FLOW_OWNERSHIP_ENTRIES: u32 = 4096;
pub const MAX_INTERFACE_CLASS_ENTRIES: u32 = 64;

pub const POLICY_KIND_APP: u8 = 1;
pub const POLICY_KIND_PROGRAM: u8 = 2;
pub const NETWORK_SCOPE_ALL: u8 = 0;
pub const NETWORK_SCOPE_WIFI: u8 = 1;
pub const NETWORK_SCOPE_MOBILE: u8 = 2;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pod, Zeroable)]
pub struct RuleV4 {
    pub rule_id_hash: u64,
    pub src_addr: u32,
    pub src_mask: u32,
    pub dst_addr: u32,
    pub dst_mask: u32,
    pub src_port_start: u16,
    pub src_port_end: u16,
    pub dst_port_start: u16,
    pub dst_port_end: u16,
    pub proto: u8,
    pub action: u8,
    pub direction: u8,
    pub enabled: u8,
    pub reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pod, Zeroable)]
pub struct AppPolicyEntry {
    pub policy_id_hash: u64,
    pub scope_ifindex: u32,
    pub match_uid: u32,
    pub identity: [u8; TASK_COMM_LEN],
    pub action: u8,
    pub kind: u8,
    pub network_scope: u8,
    pub reserved: [u8; 5],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pod, Zeroable)]
pub struct TrafficPolicyEntry {
    pub policy_id_hash: u64,
    pub cycle_secs: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pod, Zeroable)]
pub struct RuleConfig {
    pub checksum_low: u64,
    pub active_slot: u32,
    pub rule_count: u32,
    pub policy_count: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pod, Zeroable)]
pub struct WireFactEvent {
    pub event_time_secs: u64,
    pub rule_id_hash: u64,
    pub bytes: u64,
    pub ifindex: u32,
    pub app_uid: u32,
    pub app_pid: u32,
    pub app_tgid: u32,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub rule_index: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub event_kind: u8,
    pub action: u8,
    pub proto: u8,
    pub reserved: [u8; 5],
    pub app_comm: [u8; TASK_COMM_LEN],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pod, Zeroable)]
pub struct GlobalCounter {
    pub ingress_bytes: u64,
    pub egress_bytes: u64,
    pub ingress_packets: u64,
    pub egress_packets: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pod, Zeroable)]
pub struct AppTrafficKey {
    pub uid: u32,
    pub pid: u32,
    pub tgid: u32,
    pub ifindex: u32,
    pub comm: [u8; TASK_COMM_LEN],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pod, Zeroable)]
pub struct AppTrafficValue {
    pub bytes: u64,
    pub packets: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pod, Zeroable)]
pub struct FlowOwnershipKey {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub reserved: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pod, Zeroable)]
pub struct FlowOwnershipValue {
    pub uid: u32,
    pub pid: u32,
    pub tgid: u32,
    pub comm: [u8; TASK_COMM_LEN],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pod, Zeroable)]
pub struct InterfaceClassValue {
    pub network_scope: u8,
    pub reserved: [u8; 3],
}

#[map]
pub static RULES_V4: Array<RuleV4> =
    Array::with_max_entries(MAX_RULE_ENTRIES * ACTIVE_CONFIG_SLOTS, 0);

#[map]
pub static APP_POLICIES: Array<AppPolicyEntry> =
    Array::with_max_entries(MAX_POLICY_ENTRIES * ACTIVE_CONFIG_SLOTS, 0);

#[map]
pub static TRAFFIC_POLICY: Array<TrafficPolicyEntry> =
    Array::with_max_entries(ACTIVE_CONFIG_SLOTS, 0);

#[map]
pub static RULE_CONFIG: Array<RuleConfig> = Array::with_max_entries(1, 0);

#[map]
pub static INTERFACE_CLASSES: HashMap<u32, InterfaceClassValue> =
    HashMap::with_max_entries(MAX_INTERFACE_CLASS_ENTRIES, 0);

#[map]
pub static EVENTS: PerfEventArray<WireFactEvent> = PerfEventArray::new(0);

#[map]
pub static GLOBAL_STATS: PerCpuArray<GlobalCounter> = PerCpuArray::with_max_entries(1, 0);

#[map]
pub static APP_STATS: PerCpuHashMap<AppTrafficKey, AppTrafficValue> =
    PerCpuHashMap::with_max_entries(2048, 0);

#[map]
pub static FLOW_OWNERSHIP: PerCpuHashMap<FlowOwnershipKey, FlowOwnershipValue> =
    PerCpuHashMap::with_max_entries(FLOW_OWNERSHIP_ENTRIES, 0);
