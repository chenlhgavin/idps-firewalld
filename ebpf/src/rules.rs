use crate::maps::{
    AppPolicyEntry, NETWORK_SCOPE_ALL, NETWORK_SCOPE_MOBILE, NETWORK_SCOPE_WIFI, POLICY_KIND_APP,
    POLICY_KIND_PROGRAM, RuleV4, TASK_COMM_LEN,
};
use crate::packet::PacketMetaV4;

pub fn rule_matches(rule: &RuleV4, packet: &PacketMetaV4) -> bool {
    if rule.enabled == 0 {
        return false;
    }
    if rule.proto != 0 && rule.proto != packet.proto {
        return false;
    }
    if rule.src_mask != 0 && (packet.src_ip & rule.src_mask) != (rule.src_addr & rule.src_mask) {
        return false;
    }
    if rule.dst_mask != 0 && (packet.dst_ip & rule.dst_mask) != (rule.dst_addr & rule.dst_mask) {
        return false;
    }
    let src_ok = if rule.src_port_start == 0 && rule.src_port_end == 0 {
        true
    } else {
        packet.src_port >= rule.src_port_start && packet.src_port <= rule.src_port_end
    };
    let dst_ok = if rule.dst_port_start == 0 && rule.dst_port_end == 0 {
        true
    } else {
        packet.dst_port >= rule.dst_port_start && packet.dst_port <= rule.dst_port_end
    };
    src_ok && dst_ok
}

pub fn policy_matches(
    policy: &AppPolicyEntry,
    uid: u32,
    comm: &[u8; TASK_COMM_LEN],
    ifindex: u32,
    network_scope: u8,
) -> bool {
    match policy.kind {
        POLICY_KIND_APP => policy.match_uid != 0 && policy.match_uid == uid,
        POLICY_KIND_PROGRAM => policy.identity == *comm,
        _ => false,
    }
        && (policy.scope_ifindex == 0 || policy.scope_ifindex == ifindex)
        && match policy.network_scope {
            NETWORK_SCOPE_ALL => true,
            NETWORK_SCOPE_WIFI => network_scope == NETWORK_SCOPE_WIFI,
            NETWORK_SCOPE_MOBILE => network_scope == NETWORK_SCOPE_MOBILE,
            _ => false,
        }
}
