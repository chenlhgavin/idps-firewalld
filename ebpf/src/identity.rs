use aya_ebpf::helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid};

use crate::maps::TASK_COMM_LEN;

#[derive(Clone, Copy, Debug, Default)]
pub struct TaskIdentity {
    pub uid: u32,
    pub pid: u32,
    pub tgid: u32,
    pub comm: [u8; TASK_COMM_LEN],
}

pub fn current_identity() -> TaskIdentity {
    let uid_gid = unsafe { bpf_get_current_uid_gid() };
    let uid = (uid_gid & u64::from(u32::MAX)) as u32;
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let pid = (pid_tgid & u64::from(u32::MAX)) as u32;
    let tgid = (pid_tgid >> 32) as u32;
    let mut comm = [0; TASK_COMM_LEN];
    let _ = unsafe { bpf_get_current_comm(comm.as_mut_ptr().cast(), TASK_COMM_LEN as u32) };
    TaskIdentity {
        uid,
        pid,
        tgid,
        comm,
    }
}
