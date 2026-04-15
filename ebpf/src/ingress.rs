use aya_ebpf::bindings::{TC_ACT_OK, TC_ACT_SHOT};
use aya_ebpf::helpers::bpf_ktime_get_ns;
use aya_ebpf::macros::classifier;
use aya_ebpf::programs::TcContext;

use crate::maps::{
    EVENTS, GLOBAL_STATS, MAX_RULE_ENTRIES, NS_PER_SEC, RULE_CONFIG, RULES_V4, WireFactEvent,
};
use crate::packet::parse_ipv4_packet;
use crate::rules::rule_matches;
use crate::stats::bump_ingress;

const RULE_ACTION_ALLOW: u8 = 0;
const RULE_ACTION_ALERT: u8 = 1;
const RULE_ACTION_BLOCK: u8 = 2;
const RULE_ACTION_INGRESS_OBSERVE: u8 = 3;
const RULE_ACTION_BLOCK_SILENT: u8 = 4;

#[classifier]
pub fn firewalld_ingress(ctx: TcContext) -> i32 {
    let Some(packet) = parse_ipv4_packet(&ctx) else {
        return TC_ACT_OK;
    };

    if let Some(counter) = GLOBAL_STATS.get_ptr_mut(0) {
        // SAFETY: index 0 exists because the array is defined with one entry.
        unsafe { bump_ingress(&mut *counter, &ctx, u64::from(packet.len)); }
    }

    let Some(config) = RULE_CONFIG.get(0) else {
        return TC_ACT_OK;
    };
    let base_index = config.active_slot.saturating_mul(MAX_RULE_ENTRIES);
    let rule_count = config.rule_count;

    let mut index = 0;
    while index < rule_count {
        if let Some(rule) = RULES_V4.get(base_index.saturating_add(index)) {
            if rule.direction == 0 && rule_matches(rule, &packet) {
                if should_emit_event(rule.action) {
                    let event = WireFactEvent {
                        event_time_secs: unsafe { bpf_ktime_get_ns() } / NS_PER_SEC,
                        rule_id_hash: rule.rule_id_hash,
                        ifindex: packet.ifindex,
                        app_uid: 0,
                        app_pid: 0,
                        app_tgid: 0,
                        src_ip: packet.src_ip,
                        dst_ip: packet.dst_ip,
                        rule_index: index,
                        bytes: u64::from(packet.len),
                        src_port: packet.src_port,
                        dst_port: packet.dst_port,
                        event_kind: 0,
                        action: event_action(rule.action),
                        proto: packet.proto,
                        reserved: [0; 5],
                        app_comm: [0; crate::maps::TASK_COMM_LEN],
                    };
                    let _ = EVENTS.output(&ctx, &event, 0);
                }
                return if should_block(rule.action) {
                    TC_ACT_SHOT
                } else {
                    TC_ACT_OK
                };
            }
        }
        index += 1;
    }

    TC_ACT_OK
}

fn should_emit_event(action: u8) -> bool {
    matches!(
        action,
        RULE_ACTION_ALERT | RULE_ACTION_BLOCK | RULE_ACTION_INGRESS_OBSERVE
    )
}

fn should_block(action: u8) -> bool {
    matches!(action, RULE_ACTION_BLOCK | RULE_ACTION_BLOCK_SILENT)
}

fn event_action(action: u8) -> u8 {
    match action {
        RULE_ACTION_INGRESS_OBSERVE => RULE_ACTION_BLOCK,
        RULE_ACTION_ALLOW => RULE_ACTION_ALLOW,
        RULE_ACTION_ALERT => RULE_ACTION_ALERT,
        RULE_ACTION_BLOCK | RULE_ACTION_BLOCK_SILENT => RULE_ACTION_BLOCK,
        _ => RULE_ACTION_BLOCK,
    }
}
