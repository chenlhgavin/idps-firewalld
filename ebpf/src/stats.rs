use aya_ebpf::programs::TcContext;

use crate::identity::TaskIdentity;
use crate::maps::{APP_STATS, AppTrafficKey, AppTrafficValue, GlobalCounter};

pub fn bump_ingress(counter: &mut GlobalCounter, _ctx: &TcContext, bytes: u64) {
    counter.ingress_bytes = counter.ingress_bytes.saturating_add(bytes);
    counter.ingress_packets = counter.ingress_packets.saturating_add(1);
}

pub fn bump_egress(counter: &mut GlobalCounter, _ctx: &TcContext, bytes: u64) {
    counter.egress_bytes = counter.egress_bytes.saturating_add(bytes);
    counter.egress_packets = counter.egress_packets.saturating_add(1);
}

pub fn bump_app_egress(identity: &TaskIdentity, ifindex: u32, bytes: u64) {
    let key = AppTrafficKey {
        uid: identity.uid,
        pid: identity.pid,
        tgid: identity.tgid,
        ifindex,
        comm: identity.comm,
    };
    if let Some(counter) = APP_STATS.get_ptr_mut(&key) {
        // SAFETY: `get_ptr_mut` returns a valid pointer to the current CPU's slot.
        unsafe {
            (*counter).bytes = (*counter).bytes.saturating_add(bytes);
            (*counter).packets = (*counter).packets.saturating_add(1);
        }
        return;
    }

    let value = AppTrafficValue { bytes, packets: 1 };
    let _ = APP_STATS.insert(&key, &value, 0);
}
