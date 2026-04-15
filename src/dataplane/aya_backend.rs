//! Aya-based tc dataplane backend.

#[cfg(feature = "ebpf")]
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[cfg(feature = "ebpf")]
use anyhow::Context;
use anyhow::{Result, bail};
#[cfg(feature = "ebpf")]
use aya::Ebpf;
#[cfg(feature = "ebpf")]
use aya::maps::perf::PerfEventArrayBuffer;
#[cfg(feature = "ebpf")]
use aya::maps::{Array, HashMap, Map, MapData, PerCpuArray, PerCpuHashMap, PerfEventArray};
#[cfg(feature = "ebpf")]
use aya::programs::{
    SchedClassifier,
    tc::{self, TcAttachType},
};
#[cfg(feature = "ebpf")]
use aya::util::online_cpus;
#[cfg(feature = "ebpf")]
use tokio_util::bytes::BytesMut;

use crate::dataplane::backend::{DataplaneBackend, DataplaneFuture};
use crate::dataplane::compile::compile_ruleset;
use crate::dataplane::events::FactEvent;
use crate::dataplane::loader::{DataplaneHealth, LoaderStatus};
#[cfg(feature = "ebpf")]
use crate::dataplane::maps::{
    ACTIVE_CONFIG_SLOTS, AppPolicyEntry, AppTrafficKey, AppTrafficValue, FlowOwnershipKey,
    FlowOwnershipValue, InterfaceClassValue, MAX_POLICY_ENTRIES, MAX_RULE_ENTRIES, RuleConfig,
    RuleV4, TASK_COMM_LEN, TrafficPolicyEntry, decode_app_id, decode_task_comm,
};
#[cfg(feature = "ebpf")]
use crate::dataplane::stats::snapshot_global_stats;
use crate::dataplane::stats::{AppTrafficSample, GlobalStats};
#[cfg(feature = "ebpf")]
use crate::identity::interface_map::{NetworkClass, classify_interface};
use crate::identity::provider::AndroidPackageMap;
use crate::rule::model::NormalizedRuleSet;

#[cfg(feature = "ebpf")]
const INGRESS_PROGRAM_NAME: &str = "firewalld_ingress";
#[cfg(feature = "ebpf")]
const EGRESS_PROGRAM_NAME: &str = "firewalld_egress";

/// Aya tc backend that owns a loadable eBPF object and the userspace map
/// programming path.
pub struct AyaTcDataplane {
    object_path: PathBuf,
    attach_ifaces: Vec<String>,
    android_packages_list_path: PathBuf,
    initialized: AtomicBool,
    active_checksum: Mutex<Option<String>>,
    lost_events: AtomicUsize,
    #[cfg(feature = "ebpf")]
    ebpf: Mutex<Option<Ebpf>>,
    #[cfg(feature = "ebpf")]
    event_buffers: Mutex<Vec<CpuPerfBuffer>>,
}

impl std::fmt::Debug for AyaTcDataplane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AyaTcDataplane")
            .field("object_path", &self.object_path)
            .field("attach_ifaces", &self.attach_ifaces)
            .field(
                "android_packages_list_path",
                &self.android_packages_list_path,
            )
            .field("initialized", &self.initialized.load(Ordering::SeqCst))
            .field(
                "active_checksum",
                &self.active_checksum.lock().expect("checksum mutex"),
            )
            .field("lost_events", &self.lost_events.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "ebpf")]
struct CpuPerfBuffer {
    cpu_id: u32,
    buffer: PerfEventArrayBuffer<MapData>,
}

impl AyaTcDataplane {
    /// Build a new Aya tc backend.
    #[must_use]
    pub fn new(
        object_path: PathBuf,
        attach_ifaces: Vec<String>,
        android_packages_list_path: PathBuf,
    ) -> Arc<Self> {
        Arc::new(Self {
            object_path,
            attach_ifaces,
            android_packages_list_path,
            initialized: AtomicBool::new(false),
            active_checksum: Mutex::new(None),
            lost_events: AtomicUsize::new(0),
            #[cfg(feature = "ebpf")]
            ebpf: Mutex::new(None),
            #[cfg(feature = "ebpf")]
            event_buffers: Mutex::new(Vec::new()),
        })
    }

    fn validate_config(&self) -> Result<()> {
        if self.attach_ifaces.is_empty() {
            bail!("IDPS_FIREWALLD_ATTACH_IFACES must not be empty for ebpf mode");
        }
        if self.object_path.as_os_str().is_empty() {
            bail!("IDPS_FIREWALLD_EBPF_OBJECT must not be empty for ebpf mode");
        }
        Ok(())
    }

    fn load_package_map(&self) -> Result<Option<AndroidPackageMap>> {
        AndroidPackageMap::load_if_present(&self.android_packages_list_path)
    }

    #[cfg(feature = "ebpf")]
    fn load_object(&self) -> Result<Ebpf> {
        Ebpf::load_file(&self.object_path)
            .with_context(|| format!("failed to load eBPF object {}", self.object_path.display()))
    }

    #[cfg(feature = "ebpf")]
    fn attach_programs(&self, ebpf: &mut Ebpf) -> Result<()> {
        {
            let ingress: &mut SchedClassifier = ebpf
                .program_mut(INGRESS_PROGRAM_NAME)
                .with_context(|| format!("{INGRESS_PROGRAM_NAME} program missing"))?
                .try_into()
                .with_context(|| format!("{INGRESS_PROGRAM_NAME} type mismatch"))?;
            ingress
                .load()
                .with_context(|| format!("failed to load {INGRESS_PROGRAM_NAME}"))?;
        }
        {
            let egress: &mut SchedClassifier = ebpf
                .program_mut(EGRESS_PROGRAM_NAME)
                .with_context(|| format!("{EGRESS_PROGRAM_NAME} program missing"))?
                .try_into()
                .with_context(|| format!("{EGRESS_PROGRAM_NAME} type mismatch"))?;
            egress
                .load()
                .with_context(|| format!("failed to load {EGRESS_PROGRAM_NAME}"))?;
        }

        for iface in &self.attach_ifaces {
            tc::qdisc_add_clsact(iface)
                .or_else(|error| {
                    if error.kind() == std::io::ErrorKind::AlreadyExists {
                        Ok(())
                    } else {
                        Err(error)
                    }
                })
                .with_context(|| format!("failed to add clsact qdisc on {iface}"))?;
            self.detach_programs_on_interface(iface)?;
            {
                let ingress: &mut SchedClassifier = ebpf
                    .program_mut(INGRESS_PROGRAM_NAME)
                    .with_context(|| format!("{INGRESS_PROGRAM_NAME} program missing"))?
                    .try_into()
                    .with_context(|| format!("{INGRESS_PROGRAM_NAME} type mismatch"))?;
                ingress
                    .attach(iface, TcAttachType::Ingress)
                    .with_context(|| format!("failed to attach ingress classifier on {iface}"))?;
            }
            {
                let egress: &mut SchedClassifier = ebpf
                    .program_mut(EGRESS_PROGRAM_NAME)
                    .with_context(|| format!("{EGRESS_PROGRAM_NAME} program missing"))?
                    .try_into()
                    .with_context(|| format!("{EGRESS_PROGRAM_NAME} type mismatch"))?;
                egress
                    .attach(iface, TcAttachType::Egress)
                    .with_context(|| format!("failed to attach egress classifier on {iface}"))?;
            }
        }
        Ok(())
    }

    #[cfg(feature = "ebpf")]
    fn detach_programs_on_interface(&self, iface: &str) -> Result<()> {
        for (attach_type, name) in [
            (TcAttachType::Ingress, INGRESS_PROGRAM_NAME),
            (TcAttachType::Egress, EGRESS_PROGRAM_NAME),
        ] {
            match tc::qdisc_detach_program(iface, attach_type, name) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("failed to detach {name} from {iface} ({attach_type:?})")
                    });
                }
            }
        }
        Ok(())
    }

    #[cfg(feature = "ebpf")]
    fn detach_programs(&self) -> Result<()> {
        for iface in &self.attach_ifaces {
            self.detach_programs_on_interface(iface)?;
        }
        Ok(())
    }

    #[cfg(feature = "ebpf")]
    fn program_rules(&self, ebpf: &mut Ebpf, ruleset: &NormalizedRuleSet) -> Result<()> {
        let package_map = self.load_package_map()?;
        let mut compiled = compile_ruleset(ruleset, package_map.as_ref())?;
        let previous_config = {
            let rule_config: Array<_, RuleConfig> = ebpf
                .map_mut("RULE_CONFIG")
                .context("RULE_CONFIG map missing")?
                .try_into()
                .context("RULE_CONFIG map type mismatch")?;
            rule_config.get(&0, 0).unwrap_or_default()
        };
        let target_slot = Self::next_slot(previous_config);
        compiled.config.active_slot = target_slot;

        let mut rules_v4: Array<_, RuleV4> = ebpf
            .map_mut("RULES_V4")
            .context("RULES_V4 map missing")?
            .try_into()
            .context("RULES_V4 map type mismatch")?;
        let rules_start = Self::slot_start(target_slot, MAX_RULE_ENTRIES);
        for (index, rule) in compiled.rules_v4.iter().enumerate() {
            rules_v4
                .set(
                    rules_start.saturating_add(index.try_into().unwrap_or(u32::MAX)),
                    *rule,
                    0,
                )
                .with_context(|| format!("failed to write RULES_V4[{index}]"))?;
        }
        Self::clear_unused_rules(&mut rules_v4, rules_start, compiled.rules_v4.len())?;

        let mut app_policies: Array<_, AppPolicyEntry> = ebpf
            .map_mut("APP_POLICIES")
            .context("APP_POLICIES map missing")?
            .try_into()
            .context("APP_POLICIES map type mismatch")?;
        let policies_start = Self::slot_start(target_slot, MAX_POLICY_ENTRIES);
        for (index, policy) in compiled.app_policies.iter().enumerate() {
            app_policies
                .set(
                    policies_start.saturating_add(index.try_into().unwrap_or(u32::MAX)),
                    *policy,
                    0,
                )
                .with_context(|| format!("failed to write APP_POLICIES[{index}]"))?;
        }
        Self::clear_unused_policies(
            &mut app_policies,
            policies_start,
            compiled.app_policies.len(),
        )?;

        let mut traffic_policy_map: Array<_, TrafficPolicyEntry> = ebpf
            .map_mut("TRAFFIC_POLICY")
            .context("TRAFFIC_POLICY map missing")?
            .try_into()
            .context("TRAFFIC_POLICY map type mismatch")?;
        traffic_policy_map
            .set(target_slot, compiled.traffic_policy.unwrap_or_default(), 0)
            .context("failed to write TRAFFIC_POLICY")?;
        self.program_interface_classes(ebpf)?;

        let _: PerCpuHashMap<_, FlowOwnershipKey, FlowOwnershipValue> = ebpf
            .map_mut("FLOW_OWNERSHIP")
            .context("FLOW_OWNERSHIP map missing")?
            .try_into()
            .context("FLOW_OWNERSHIP map type mismatch")?;

        let mut rule_config: Array<_, RuleConfig> = ebpf
            .map_mut("RULE_CONFIG")
            .context("RULE_CONFIG map missing")?
            .try_into()
            .context("RULE_CONFIG map type mismatch")?;
        rule_config
            .set(0, compiled.config, 0)
            .context("failed to write RULE_CONFIG")?;

        *self.active_checksum.lock().expect("checksum mutex") = Some(compiled.summary.checksum);
        Ok(())
    }

    #[cfg(feature = "ebpf")]
    fn clear_unused_rules<T>(
        rules_v4: &mut Array<T, RuleV4>,
        slot_start: u32,
        active_count: usize,
    ) -> Result<()>
    where
        T: std::borrow::Borrow<MapData> + std::borrow::BorrowMut<MapData>,
    {
        for index in active_count..MAX_RULE_ENTRIES {
            rules_v4
                .set(
                    slot_start.saturating_add(index.try_into().unwrap_or(u32::MAX)),
                    RuleV4::default(),
                    0,
                )
                .with_context(|| format!("failed to clear RULES_V4[{index}]"))?;
        }
        Ok(())
    }

    #[cfg(feature = "ebpf")]
    fn clear_unused_policies<T>(
        app_policies: &mut Array<T, AppPolicyEntry>,
        slot_start: u32,
        active_count: usize,
    ) -> Result<()>
    where
        T: std::borrow::Borrow<MapData> + std::borrow::BorrowMut<MapData>,
    {
        let disabled = Self::disabled_policy_entry();
        for index in active_count..MAX_POLICY_ENTRIES {
            app_policies
                .set(
                    slot_start.saturating_add(index.try_into().unwrap_or(u32::MAX)),
                    disabled,
                    0,
                )
                .with_context(|| format!("failed to clear APP_POLICIES[{index}]"))?;
        }
        Ok(())
    }

    #[cfg(feature = "ebpf")]
    fn disabled_policy_entry() -> AppPolicyEntry {
        AppPolicyEntry {
            policy_id_hash: 0,
            scope_ifindex: 0,
            match_uid: 0,
            identity: [u8::MAX; TASK_COMM_LEN],
            action: 0,
            kind: 0,
            network_scope: 0,
            reserved: [0; 5],
        }
    }

    #[cfg(feature = "ebpf")]
    fn next_slot(previous_config: RuleConfig) -> u32 {
        let configured_slots = u32::try_from(ACTIVE_CONFIG_SLOTS).unwrap_or(1).max(1);
        if previous_config.rule_count == 0
            && previous_config.policy_count == 0
            && previous_config.checksum_low == 0
        {
            0
        } else {
            (previous_config.active_slot + 1) % configured_slots
        }
    }

    #[cfg(feature = "ebpf")]
    fn slot_start(slot: u32, slot_size: usize) -> u32 {
        slot.saturating_mul(u32::try_from(slot_size).unwrap_or(u32::MAX))
    }

    #[cfg(feature = "ebpf")]
    fn program_interface_classes(&self, ebpf: &mut Ebpf) -> Result<()> {
        let mut interface_classes: HashMap<_, u32, InterfaceClassValue> = ebpf
            .map_mut("INTERFACE_CLASSES")
            .context("INTERFACE_CLASSES map missing")?
            .try_into()
            .context("INTERFACE_CLASSES map type mismatch")?;

        for iface in &self.attach_ifaces {
            let Some(ifindex) = Self::ifindex_for_interface(iface) else {
                continue;
            };
            interface_classes
                .insert(
                    ifindex,
                    InterfaceClassValue {
                        network_scope: Self::network_scope_for_interface(iface),
                        reserved: [0; 3],
                    },
                    0,
                )
                .with_context(|| format!("failed to write INTERFACE_CLASSES[{iface}]"))?;
        }
        Ok(())
    }

    #[cfg(feature = "ebpf")]
    fn ifindex_for_interface(iface: &str) -> Option<u32> {
        let path = PathBuf::from("/sys/class/net").join(iface).join("ifindex");
        let value = fs::read_to_string(path).ok()?;
        value.trim().parse::<u32>().ok()
    }

    #[cfg(feature = "ebpf")]
    fn network_scope_for_interface(iface: &str) -> u8 {
        match classify_interface(iface) {
            NetworkClass::Wifi => crate::dataplane::maps::NETWORK_SCOPE_WIFI,
            NetworkClass::Mobile => crate::dataplane::maps::NETWORK_SCOPE_MOBILE,
            NetworkClass::Other => crate::dataplane::maps::NETWORK_SCOPE_ALL,
        }
    }

    #[cfg(feature = "ebpf")]
    fn read_global_from_maps(ebpf: &Ebpf) -> Result<GlobalStats> {
        let array: PerCpuArray<_, GlobalStats> = ebpf
            .map("GLOBAL_STATS")
            .context("GLOBAL_STATS map missing")?
            .try_into()
            .context("GLOBAL_STATS map type mismatch")?;
        let values = array.get(&0, 0).context("failed to read GLOBAL_STATS")?;
        let stats: Vec<GlobalStats> = values.iter().copied().collect();
        Ok(snapshot_global_stats(&stats))
    }

    #[cfg(feature = "ebpf")]
    fn open_event_buffers(map: Map) -> Result<Vec<CpuPerfBuffer>> {
        let mut perf_array: PerfEventArray<_> =
            map.try_into().context("EVENTS map type mismatch")?;
        let mut buffers = Vec::new();
        for cpu_id in online_cpus().map_err(|(_, error)| error)? {
            let buffer = perf_array
                .open(cpu_id, None)
                .with_context(|| format!("failed to open perf event buffer for cpu {cpu_id}"))?;
            buffers.push(CpuPerfBuffer { cpu_id, buffer });
        }
        Ok(buffers)
    }
}

impl DataplaneBackend for AyaTcDataplane {
    fn initialize(&self) -> DataplaneFuture<'_> {
        Box::pin(async move {
            self.validate_config()?;
            #[cfg(feature = "ebpf")]
            {
                let mut ebpf = self.load_object()?;
                self.attach_programs(&mut ebpf)?;
                let event_buffers = match ebpf.take_map("EVENTS") {
                    Some(map) => Self::open_event_buffers(map)?,
                    None => Vec::new(),
                };
                *self.event_buffers.lock().expect("event buffers mutex") = event_buffers;
                *self.ebpf.lock().expect("ebpf mutex") = Some(ebpf);
            }
            self.initialized.store(true, Ordering::SeqCst);
            Ok(())
        })
    }

    fn shutdown(&self) -> DataplaneFuture<'_> {
        Box::pin(async move {
            #[cfg(feature = "ebpf")]
            self.detach_programs()?;
            self.initialized.store(false, Ordering::SeqCst);
            *self.active_checksum.lock().expect("checksum mutex") = None;
            self.lost_events.store(0, Ordering::SeqCst);
            #[cfg(feature = "ebpf")]
            {
                self.event_buffers
                    .lock()
                    .expect("event buffers mutex")
                    .clear();
                *self.ebpf.lock().expect("ebpf mutex") = None;
            }
            Ok(())
        })
    }

    fn apply_ruleset(&self, ruleset: &NormalizedRuleSet) -> DataplaneFuture<'_> {
        if !self.initialized.load(Ordering::SeqCst) {
            return Box::pin(async {
                bail!("dataplane must be initialized before applying a ruleset");
            });
        }
        let package_map = match self.load_package_map() {
            Ok(package_map) => package_map,
            Err(error) => return Box::pin(async move { Err(error) }),
        };
        let compiled = match compile_ruleset(ruleset, package_map.as_ref()) {
            Ok(compiled) => compiled,
            Err(error) => return Box::pin(async move { Err(error) }),
        };
        let tuple_rule_count = ruleset
            .firewall_rules
            .iter()
            .filter(|rule| matches!(rule, crate::rule::model::FirewallRule::Tuple(_)))
            .count();
        #[cfg(feature = "ebpf")]
        {
            let mut guard = self.ebpf.lock().expect("ebpf mutex");
            let Some(ebpf) = guard.as_mut() else {
                return Box::pin(async {
                    bail!("eBPF object not loaded");
                });
            };
            if let Err(error) = self.program_rules(ebpf, ruleset) {
                return Box::pin(async move { Err(error) });
            }
        }
        #[cfg(not(feature = "ebpf"))]
        let checksum = compiled.summary.checksum.clone();
        Box::pin(async move {
            if compiled.rules_v4.is_empty() && tuple_rule_count != 0 {
                bail!("ruleset does not contain any dataplane-programmable tuple rules");
            }
            #[cfg(not(feature = "ebpf"))]
            {
                *self.active_checksum.lock().expect("checksum mutex") = Some(checksum);
            }
            Ok(())
        })
    }

    fn read_global_stats(&self) -> DataplaneFuture<'_, GlobalStats> {
        Box::pin(async move {
            #[cfg(feature = "ebpf")]
            {
                let guard = self.ebpf.lock().expect("ebpf mutex");
                let ebpf = guard.as_ref().context("eBPF object not loaded")?;
                Self::read_global_from_maps(ebpf)
            }
            #[cfg(not(feature = "ebpf"))]
            {
                Ok(GlobalStats::default())
            }
        })
    }

    fn read_app_samples(&self) -> DataplaneFuture<'_, Vec<AppTrafficSample>> {
        Box::pin(async move {
            #[cfg(feature = "ebpf")]
            {
                let guard = self.ebpf.lock().expect("ebpf mutex");
                let ebpf = guard.as_ref().context("eBPF object not loaded")?;
                let package_map = self.load_package_map()?;
                let stats: PerCpuHashMap<_, AppTrafficKey, AppTrafficValue> = ebpf
                    .map("APP_STATS")
                    .context("APP_STATS map missing")?
                    .try_into()
                    .context("APP_STATS map type mismatch")?;
                let samples = stats
                    .iter()
                    .map(|entry| {
                        let (key, values) = entry.context("failed to read APP_STATS entry")?;
                        let (bytes, packets) =
                            values
                                .iter()
                                .fold((0_u64, 0_u64), |(bytes, packets), value| {
                                    (
                                        bytes.saturating_add(value.bytes),
                                        packets.saturating_add(value.packets),
                                    )
                                });
                        Ok::<_, anyhow::Error>(AppTrafficSample {
                            app_id: decode_app_id(key.uid, &key.comm, package_map.as_ref())
                                .unwrap_or_else(|| format!("uid:{}", key.uid)),
                            pid: (key.pid != 0).then_some(key.pid),
                            tgid: (key.tgid != 0).then_some(key.tgid),
                            uid: (key.uid != 0).then_some(key.uid),
                            comm: {
                                let comm = decode_task_comm(&key.comm);
                                (!comm.is_empty()).then_some(comm)
                            },
                            ifindex: key.ifindex,
                            bytes,
                            packets,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                Ok(samples)
            }
            #[cfg(not(feature = "ebpf"))]
            {
                Ok(Vec::new())
            }
        })
    }

    fn drain_events(&self) -> DataplaneFuture<'_, Vec<FactEvent>> {
        Box::pin(async move {
            #[cfg(feature = "ebpf")]
            {
                let mut guard = self.event_buffers.lock().expect("event buffers mutex");
                let event_size = std::mem::size_of::<crate::dataplane::maps::WireFactEvent>();
                let checksum = self
                    .active_checksum
                    .lock()
                    .expect("checksum mutex")
                    .clone()
                    .unwrap_or_default();
                let package_map = self.load_package_map()?;
                let mut decoded = Vec::new();

                for cpu_buffer in guard.iter_mut() {
                    if !cpu_buffer.buffer.readable() {
                        continue;
                    }
                    let mut buffers = vec![BytesMut::with_capacity(event_size); 32];
                    let events =
                        cpu_buffer
                            .buffer
                            .read_events(&mut buffers)
                            .with_context(|| {
                                format!("failed to read perf events for cpu {}", cpu_buffer.cpu_id)
                            })?;
                    self.lost_events.fetch_add(events.lost, Ordering::SeqCst);
                    decoded.extend(buffers.iter().take(events.read).filter_map(|bytes| {
                        if bytes.len() < event_size {
                            return None;
                        }
                        let event = bytemuck::pod_read_unaligned::<
                            crate::dataplane::maps::WireFactEvent,
                        >(&bytes[..event_size]);
                        Some(crate::dataplane::events::decode_wire_event(
                            &checksum,
                            event,
                            package_map.as_ref(),
                        ))
                    }));
                }
                Ok(decoded)
            }
            #[cfg(not(feature = "ebpf"))]
            {
                Ok(Vec::new())
            }
        })
    }

    fn health(&self) -> DataplaneHealth {
        DataplaneHealth {
            status: if self.initialized.load(Ordering::SeqCst) {
                LoaderStatus::Ready
            } else {
                LoaderStatus::Detached
            },
            active_checksum: self.active_checksum.lock().expect("checksum mutex").clone(),
            queued_events: 0,
            lost_events: self.lost_events.load(Ordering::SeqCst),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::dataplane::backend::DataplaneBackend;
    use crate::rule::normalize::build_rule_set;

    use super::AyaTcDataplane;

    #[tokio::test]
    async fn ebpf_backend_requires_attach_ifaces() {
        let backend = AyaTcDataplane::new("dummy.o".into(), Vec::new(), "packages.list".into());
        let error = backend
            .initialize()
            .await
            .expect_err("missing ifaces rejected");
        assert!(error.to_string().contains("ATTACH_IFACES"));
    }

    #[tokio::test]
    async fn ebpf_backend_reports_ready_after_init() {
        let backend = AyaTcDataplane::new(
            "dummy.o".into(),
            vec!["eth0".to_string()],
            "packages.list".into(),
        );
        #[cfg(feature = "ebpf")]
        {
            let error = backend
                .initialize()
                .await
                .expect_err("missing object rejected");
            assert!(error.to_string().contains("failed to load eBPF object"));
        }
        #[cfg(not(feature = "ebpf"))]
        {
            backend.initialize().await.expect("initialized");
            assert_eq!(
                backend.health().status,
                crate::dataplane::loader::LoaderStatus::Ready
            );
            assert_eq!(backend.health().lost_events, 0);
        }
    }

    #[tokio::test]
    async fn ebpf_backend_rejects_apply_before_init() {
        let backend = AyaTcDataplane::new(
            "dummy.o".into(),
            vec!["eth0".to_string()],
            "packages.list".into(),
        );
        let ruleset = build_rule_set(
            "v1",
            "name=allow,dip=10.0.0.1,dport=53,chain=output,action=allow",
            None,
        )
        .expect("ruleset");
        let error = backend
            .apply_ruleset(&ruleset)
            .await
            .expect_err("apply rejected");
        assert!(error.to_string().contains("initialized"));
    }
}
