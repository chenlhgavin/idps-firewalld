use aya_ebpf::bindings::{TC_ACT_OK, TC_ACT_SHOT};
use aya_ebpf::helpers::bpf_ktime_get_ns;
use aya_ebpf::macros::classifier;
use aya_ebpf::programs::TcContext;

use crate::identity::{TaskIdentity, current_identity};
use crate::maps::{
    APP_POLICIES, EVENTS, FLOW_OWNERSHIP, FlowOwnershipKey, FlowOwnershipValue, GLOBAL_STATS,
    INTERFACE_CLASSES, InterfaceClassValue, MAX_POLICY_ENTRIES, MAX_RULE_ENTRIES, NS_PER_SEC,
    NETWORK_SCOPE_ALL, RULE_CONFIG, RULES_V4, WireFactEvent,
};
use crate::packet::{PacketMetaV4, parse_ipv4_packet};
use crate::rules::{policy_matches, rule_matches};
use crate::stats::{bump_app_egress, bump_egress};

const POLICY_ACTION_DENY: u8 = 2;
const RULE_ACTION_ALLOW: u8 = 0;
const RULE_ACTION_ALERT: u8 = 1;
const RULE_ACTION_BLOCK: u8 = 2;
const RULE_ACTION_INGRESS_OBSERVE: u8 = 3;
const RULE_ACTION_BLOCK_SILENT: u8 = 4;

#[classifier]
pub fn firewalld_egress(ctx: TcContext) -> i32 {
    let Some(packet) = parse_ipv4_packet(&ctx) else {
        return TC_ACT_OK;
    };

    if let Some(counter) = GLOBAL_STATS.get_ptr_mut(0) {
        // SAFETY: index 0 exists because the array is defined with one entry.
        unsafe { bump_egress(&mut *counter, &ctx, u64::from(packet.len)); }
    }

    let current = current_identity();
    let identity = resolve_flow_identity(&packet, current);
    remember_flow_identity(&packet, identity);
    let network_scope = interface_network_scope(packet.ifindex);
    let config = RULE_CONFIG.get(0).copied().unwrap_or_default();
    let policy_base = config.active_slot.saturating_mul(MAX_POLICY_ENTRIES);
    let rule_base = config.active_slot.saturating_mul(MAX_RULE_ENTRIES);
    let policy_count = config.policy_count;
    let rule_count = config.rule_count;

    let mut policy_index = 0;
    while policy_index < policy_count {
        if let Some(policy) = APP_POLICIES.get(policy_base.saturating_add(policy_index))
            && policy_matches(
                policy,
                identity.uid,
                &identity.comm,
                packet.ifindex,
                network_scope,
            )
        {
            if policy.action == POLICY_ACTION_DENY {
                let event = WireFactEvent {
                    event_time_secs: unsafe { bpf_ktime_get_ns() } / NS_PER_SEC,
                    rule_id_hash: policy.policy_id_hash,
                    ifindex: packet.ifindex,
                    app_uid: identity.uid,
                    app_pid: identity.pid,
                    app_tgid: identity.tgid,
                    src_ip: packet.src_ip,
                    dst_ip: packet.dst_ip,
                    rule_index: policy_index,
                    bytes: u64::from(packet.len),
                    src_port: packet.src_port,
                    dst_port: packet.dst_port,
                    event_kind: 2,
                    action: 2,
                    proto: packet.proto,
                    reserved: [0; 5],
                    app_comm: identity.comm,
                };
                let _ = EVENTS.output(&ctx, &event, 0);
                return TC_ACT_SHOT;
            }
            break;
        }
        policy_index += 1;
    }

    let mut index = 0;
    while index < rule_count {
        if let Some(rule) = RULES_V4.get(rule_base.saturating_add(index))
            && rule.direction == 1
            && rule_matches(rule, &packet)
        {
            if should_emit_event(rule.action, false) {
                let event = WireFactEvent {
                    event_time_secs: unsafe { bpf_ktime_get_ns() } / NS_PER_SEC,
                    rule_id_hash: rule.rule_id_hash,
                    ifindex: packet.ifindex,
                    app_uid: identity.uid,
                    app_pid: identity.pid,
                    app_tgid: identity.tgid,
                    src_ip: packet.src_ip,
                    dst_ip: packet.dst_ip,
                    rule_index: index,
                    bytes: u64::from(packet.len),
                    src_port: packet.src_port,
                    dst_port: packet.dst_port,
                    event_kind: 1,
                    action: event_action(rule.action),
                    proto: packet.proto,
                    reserved: [0; 5],
                    app_comm: identity.comm,
                };
                let _ = EVENTS.output(&ctx, &event, 0);
            }
            if !should_block(rule.action) {
                bump_app_egress(&identity, packet.ifindex, u64::from(packet.len));
            }
            return if should_block(rule.action) {
                TC_ACT_SHOT
            } else {
                TC_ACT_OK
            };
        }
        index += 1;
    }

    bump_app_egress(&identity, packet.ifindex, u64::from(packet.len));
    TC_ACT_OK
}

fn flow_key(packet: &PacketMetaV4) -> FlowOwnershipKey {
    FlowOwnershipKey {
        src_ip: packet.src_ip,
        dst_ip: packet.dst_ip,
        src_port: packet.src_port,
        dst_port: packet.dst_port,
        proto: packet.proto,
        reserved: [0; 3],
    }
}

fn resolve_flow_identity(packet: &PacketMetaV4, current: TaskIdentity) -> TaskIdentity {
    let key = flow_key(packet);
    if let Some(ownership) = FLOW_OWNERSHIP.get(&key) {
        return TaskIdentity {
            uid: ownership.uid,
            pid: ownership.pid,
            tgid: ownership.tgid,
            comm: ownership.comm,
        };
    }
    current
}

fn remember_flow_identity(packet: &PacketMetaV4, identity: TaskIdentity) {
    let key = flow_key(packet);
    let value = FlowOwnershipValue {
        uid: identity.uid,
        pid: identity.pid,
        tgid: identity.tgid,
        comm: identity.comm,
    };
    let _ = FLOW_OWNERSHIP.insert(&key, &value, 0);
}

fn interface_network_scope(ifindex: u32) -> u8 {
    if ifindex == 0 {
        return NETWORK_SCOPE_ALL;
    }
    INTERFACE_CLASSES
        .get(&ifindex)
        .map_or(NETWORK_SCOPE_ALL, |value: &InterfaceClassValue| value.network_scope)
}

fn should_emit_event(action: u8, ingress: bool) -> bool {
    match action {
        RULE_ACTION_ALLOW => false,
        RULE_ACTION_ALERT => true,
        RULE_ACTION_BLOCK => true,
        RULE_ACTION_INGRESS_OBSERVE => ingress,
        RULE_ACTION_BLOCK_SILENT => false,
        _ => false,
    }
}

fn should_block(action: u8) -> bool {
    matches!(action, RULE_ACTION_BLOCK | RULE_ACTION_BLOCK_SILENT)
}

fn event_action(action: u8) -> u8 {
    match action {
        RULE_ACTION_INGRESS_OBSERVE => RULE_ACTION_BLOCK,
        other => other,
    }
}
