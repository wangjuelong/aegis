use aegis_model::{
    ContainerContext, EventPayload, NetworkContext, NormalizedEvent, Priority, Severity,
    SidecarControlMessage,
};
use anyhow::{bail, Result};
use std::collections::BTreeMap;
use std::path::PathBuf;
#[cfg(unix)]
use std::{
    fs::remove_file,
    io::{Read, Write},
    os::unix::net::{UnixListener, UnixStream},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KubernetesMetadata {
    pub namespace: String,
    pub pod_name: String,
    pub node_name: Option<String>,
    pub service_account: Option<String>,
    pub labels: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContainerAsset {
    pub container_id: String,
    pub image: Option<String>,
    pub pod_name: Option<String>,
    pub namespace: Option<String>,
    pub node_name: Option<String>,
    pub pid_namespace: Option<String>,
    pub network_namespace: Option<String>,
    pub service_account: Option<String>,
    pub labels: BTreeMap<String, String>,
}

pub struct ContainerMetadataMapper;

impl ContainerMetadataMapper {
    pub fn map_event(
        event: &NormalizedEvent,
        metadata: Option<&KubernetesMetadata>,
    ) -> Option<ContainerAsset> {
        let container = event
            .container
            .clone()
            .or_else(|| container_from_process(&event.process.container_id, metadata))?;
        let pid_namespace = event
            .process
            .namespace_ids
            .iter()
            .find(|value| value.starts_with("pid:"))
            .cloned();
        let network_namespace = event
            .process
            .namespace_ids
            .iter()
            .find(|value| value.starts_with("net:"))
            .cloned();

        Some(ContainerAsset {
            container_id: container.container_id,
            image: container.image,
            pod_name: container
                .pod_name
                .or_else(|| metadata.map(|value| value.pod_name.clone())),
            namespace: container
                .namespace
                .or_else(|| metadata.map(|value| value.namespace.clone())),
            node_name: container
                .node_name
                .or_else(|| metadata.and_then(|value| value.node_name.clone())),
            pid_namespace,
            network_namespace,
            service_account: metadata.and_then(|value| value.service_account.clone()),
            labels: metadata
                .map(|value| value.labels.clone())
                .unwrap_or_default(),
        })
    }
}

fn container_from_process(
    container_id: &Option<String>,
    metadata: Option<&KubernetesMetadata>,
) -> Option<ContainerContext> {
    let container_id = container_id.clone()?;
    Some(ContainerContext {
        container_id,
        image: None,
        pod_name: metadata.map(|value| value.pod_name.clone()),
        namespace: metadata.map(|value| value.namespace.clone()),
        node_name: metadata.and_then(|value| value.node_name.clone()),
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DaemonSetHostAgentConfig {
    pub namespace: String,
    pub service_account: String,
    pub host_pid: bool,
    pub host_network: bool,
    pub privileged: bool,
    pub read_only_root_filesystem: bool,
    pub run_as_non_root: bool,
    pub added_capabilities: Vec<String>,
    pub dropped_capabilities: Vec<String>,
    pub mount_points: Vec<PathBuf>,
}

impl DaemonSetHostAgentConfig {
    pub fn required_capabilities() -> &'static [&'static str] {
        &[
            "BPF",
            "PERFMON",
            "SYS_ADMIN",
            "SYS_PTRACE",
            "NET_ADMIN",
            "SYS_RESOURCE",
        ]
    }

    pub fn required_mount_points() -> &'static [&'static str] {
        &["/sys/fs/bpf", "/proc", "/var/lib/aegis", "/var/run/aegis"]
    }

    pub fn validate(&self) -> Result<()> {
        if self.namespace.is_empty() || self.service_account.is_empty() {
            bail!("daemonset config requires namespace and service account");
        }
        if !self.host_pid {
            bail!("host agent daemonset must run with host pid enabled");
        }
        if self.host_network {
            bail!("host agent daemonset must keep host network disabled");
        }
        if self.privileged {
            bail!("host agent daemonset must not run privileged");
        }
        if !self.read_only_root_filesystem {
            bail!("host agent daemonset must keep root filesystem read-only");
        }
        if self.run_as_non_root {
            bail!("host agent daemonset must run as root to load eBPF programs");
        }
        if !self
            .dropped_capabilities
            .iter()
            .any(|capability| capability == "ALL")
        {
            bail!("host agent daemonset must drop all Linux capabilities before re-adding required ones");
        }
        for required_capability in Self::required_capabilities() {
            if !self
                .added_capabilities
                .iter()
                .any(|capability| capability == required_capability)
            {
                bail!(
                    "host agent daemonset is missing required capability {}",
                    required_capability
                );
            }
        }
        if self.mount_points.is_empty() {
            bail!("host agent daemonset requires host mount points");
        }
        for required_mount in Self::required_mount_points() {
            if !self
                .mount_points
                .iter()
                .any(|mount| mount == &PathBuf::from(required_mount))
            {
                bail!(
                    "host agent daemonset is missing required mount point {}",
                    required_mount
                );
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SidecarLiteContract {
    pub control_socket_path: PathBuf,
    pub shared_cache_path: PathBuf,
    pub host_pid: bool,
    pub privileged: bool,
    pub max_memory_mb: u32,
    pub dropped_capabilities: Vec<String>,
}

impl SidecarLiteContract {
    pub fn validate(&self) -> Result<()> {
        if self.host_pid || self.privileged {
            bail!("sidecar lite must not run with host pid or privileged access");
        }
        if !self.control_socket_path.is_absolute() || !self.shared_cache_path.is_absolute() {
            bail!("sidecar lite paths must be absolute");
        }
        if self.max_memory_mb == 0 || self.max_memory_mb > 256 {
            bail!("sidecar lite memory limit must stay within 1-256 MB");
        }
        if !self
            .dropped_capabilities
            .iter()
            .any(|capability| capability == "ALL")
        {
            bail!("sidecar lite must drop all Linux capabilities");
        }
        Ok(())
    }
}

#[cfg(unix)]
pub struct SidecarLocalControlPlane {
    socket_path: PathBuf,
    listener: UnixListener,
}

#[cfg(unix)]
impl SidecarLocalControlPlane {
    pub fn bind(contract: &SidecarLiteContract) -> Result<Self> {
        contract.validate()?;
        if contract.control_socket_path.exists() {
            let _ = remove_file(&contract.control_socket_path);
        }
        let listener = UnixListener::bind(&contract.control_socket_path)?;
        Ok(Self {
            socket_path: contract.control_socket_path.clone(),
            listener,
        })
    }

    pub fn recv_once(&self) -> Result<SidecarControlMessage> {
        let (mut stream, _) = self.listener.accept()?;
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes)?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub fn send_message(
        socket_path: impl AsRef<std::path::Path>,
        message: &SidecarControlMessage,
    ) -> Result<()> {
        let mut stream = UnixStream::connect(socket_path)?;
        stream.write_all(&serde_json::to_vec(message)?)?;
        Ok(())
    }

    pub fn socket_path(&self) -> &PathBuf {
        &self.socket_path
    }
}

#[cfg(unix)]
impl Drop for SidecarLocalControlPlane {
    fn drop(&mut self) {
        let _ = remove_file(&self.socket_path);
    }
}

#[cfg(not(unix))]
pub struct SidecarLocalControlPlane;

#[cfg(not(unix))]
impl SidecarLocalControlPlane {
    pub fn bind(_contract: &SidecarLiteContract) -> Result<Self> {
        bail!("sidecar local control plane currently requires unix sockets")
    }

    pub fn recv_once(&self) -> Result<SidecarControlMessage> {
        bail!("sidecar local control plane currently requires unix sockets")
    }

    pub fn send_message(
        _socket_path: impl AsRef<std::path::Path>,
        _message: &SidecarControlMessage,
    ) -> Result<()> {
        bail!("sidecar local control plane currently requires unix sockets")
    }

    pub fn socket_path(&self) -> &PathBuf {
        unreachable!("non-unix control plane does not expose a socket path")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContainerDetectionKind {
    EscapeAttempt,
    LateralMovement,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContainerDetectionFinding {
    pub kind: ContainerDetectionKind,
    pub severity: Severity,
    pub priority: Priority,
    pub summary: String,
}

pub struct ContainerDetectionEngine;

impl ContainerDetectionEngine {
    pub fn evaluate(&self, event: &NormalizedEvent) -> Vec<ContainerDetectionFinding> {
        let mut findings = Vec::new();
        let Some(container_id) = event.process.container_id.clone().or_else(|| {
            event
                .container
                .as_ref()
                .map(|container| container.container_id.clone())
        }) else {
            return findings;
        };

        if event.process.cmdline.contains("nsenter")
            || event.process.cmdline.contains("/proc/1/root")
            || event.process.cmdline.contains("mount /host")
        {
            findings.push(ContainerDetectionFinding {
                kind: ContainerDetectionKind::EscapeAttempt,
                severity: Severity::Critical,
                priority: Priority::Critical,
                summary: format!("container {container_id} shows host escape primitives"),
            });
        }

        if let EventPayload::Network(NetworkContext {
            dst_ip,
            dst_port,
            protocol,
            ..
        }) = &event.payload
        {
            let cluster_admin_port =
                matches!(dst_port, Some(2375 | 2376 | 2380 | 6443 | 10250 | 10255));
            let cluster_internal_ip = dst_ip
                .as_deref()
                .is_some_and(|ip| ip.starts_with("10.") || ip.starts_with("192.168."));
            if cluster_admin_port && cluster_internal_ip {
                findings.push(ContainerDetectionFinding {
                    kind: ContainerDetectionKind::LateralMovement,
                    severity: Severity::High,
                    priority: Priority::High,
                    summary: format!(
                        "container {container_id} contacted {:?} {:?} over {:?}",
                        dst_ip, dst_port, protocol
                    ),
                });
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ContainerDetectionEngine, ContainerDetectionKind, ContainerMetadataMapper,
        DaemonSetHostAgentConfig, KubernetesMetadata, SidecarLiteContract,
        SidecarLocalControlPlane,
    };
    use aegis_model::{
        EventPayload, EventType, NetworkContext, NormalizedEvent, Priority, ProcessContext,
        Severity, SidecarControlMessage,
    };
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    #[cfg(unix)]
    use std::thread;

    #[test]
    fn container_metadata_mapper_merges_kubernetes_and_namespace_data() {
        let mut event = NormalizedEvent::new(
            100,
            EventType::ProcessCreate,
            Priority::High,
            Severity::High,
            ProcessContext {
                container_id: Some("container-1".to_string()),
                namespace_ids: vec!["pid:4026532836".to_string(), "net:4026532840".to_string()],
                ..ProcessContext::default()
            },
            EventPayload::None,
        );
        event.container = None;

        let asset = ContainerMetadataMapper::map_event(
            &event,
            Some(&KubernetesMetadata {
                namespace: "prod".to_string(),
                pod_name: "orders-api-123".to_string(),
                node_name: Some("node-a".to_string()),
                service_account: Some("orders".to_string()),
                labels: BTreeMap::from([("app".to_string(), "orders".to_string())]),
            }),
        )
        .expect("container asset");

        assert_eq!(asset.container_id, "container-1");
        assert_eq!(asset.namespace.as_deref(), Some("prod"));
        assert_eq!(asset.pid_namespace.as_deref(), Some("pid:4026532836"));
        assert_eq!(asset.labels.get("app").map(String::as_str), Some("orders"));
    }

    #[test]
    fn sidecar_and_daemonset_contracts_validate_expected_constraints() {
        let daemonset = DaemonSetHostAgentConfig {
            namespace: "aegis-system".to_string(),
            service_account: "aegis-host-agent".to_string(),
            host_pid: true,
            host_network: false,
            privileged: false,
            read_only_root_filesystem: true,
            run_as_non_root: false,
            added_capabilities: DaemonSetHostAgentConfig::required_capabilities()
                .iter()
                .map(|value| value.to_string())
                .collect(),
            dropped_capabilities: vec!["ALL".to_string()],
            mount_points: vec![
                PathBuf::from("/sys/fs/bpf"),
                PathBuf::from("/proc"),
                PathBuf::from("/var/lib/aegis"),
                PathBuf::from("/var/run/aegis"),
                PathBuf::from("/var/lib/kubelet"),
                PathBuf::from("/var/run/containerd/containerd.sock"),
            ],
        };
        let sidecar = SidecarLiteContract {
            control_socket_path: PathBuf::from("/var/run/aegis/sidecar.sock"),
            shared_cache_path: PathBuf::from("/var/lib/aegis-sidecar/cache"),
            host_pid: false,
            privileged: false,
            max_memory_mb: 128,
            dropped_capabilities: vec!["ALL".to_string()],
        };

        daemonset.validate().expect("valid daemonset");
        sidecar.validate().expect("valid sidecar");
    }

    #[test]
    fn container_detection_engine_flags_escape_and_lateral_signals() {
        let mut escape_event = NormalizedEvent::new(
            200,
            EventType::ProcessCreate,
            Priority::High,
            Severity::High,
            ProcessContext {
                container_id: Some("container-2".to_string()),
                cmdline: "nsenter -t 1 -m sh".to_string(),
                ..ProcessContext::default()
            },
            EventPayload::None,
        );
        escape_event.container = None;

        let lateral_event = NormalizedEvent::new(
            201,
            EventType::NetConnect,
            Priority::High,
            Severity::High,
            ProcessContext {
                container_id: Some("container-2".to_string()),
                ..ProcessContext::default()
            },
            EventPayload::Network(NetworkContext {
                dst_ip: Some("10.0.0.10".to_string()),
                dst_port: Some(6443),
                protocol: Some("tcp".to_string()),
                ..NetworkContext::default()
            }),
        );

        let engine = ContainerDetectionEngine;
        let escape = engine.evaluate(&escape_event);
        let lateral = engine.evaluate(&lateral_event);

        assert_eq!(escape[0].kind, ContainerDetectionKind::EscapeAttempt);
        assert_eq!(lateral[0].kind, ContainerDetectionKind::LateralMovement);
    }

    #[cfg(unix)]
    #[test]
    fn sidecar_local_control_plane_forwards_unix_socket_messages() {
        let contract = SidecarLiteContract {
            control_socket_path: PathBuf::from(format!(
                "/tmp/aegis-{}.sock",
                uuid::Uuid::now_v7().simple()
            )),
            shared_cache_path: PathBuf::from("/var/lib/aegis-sidecar/cache"),
            host_pid: false,
            privileged: false,
            max_memory_mb: 128,
            dropped_capabilities: vec!["ALL".to_string()],
        };
        let plane = SidecarLocalControlPlane::bind(&contract).expect("bind control plane");
        let socket_path = plane.socket_path().clone();
        let receiver = thread::spawn(move || plane.recv_once().expect("receive sidecar message"));
        let message = SidecarControlMessage {
            tenant_id: "tenant-a".to_string(),
            agent_id: "agent-a".to_string(),
            operation: "flush-telemetry".to_string(),
            metadata: BTreeMap::from([("scope".to_string(), "runtime".to_string())]),
            sent_at_ms: 1_713_000_300_000,
        };

        SidecarLocalControlPlane::send_message(&socket_path, &message)
            .expect("send sidecar message");
        let received = receiver.join().expect("join receiver thread");

        assert_eq!(received, message);
    }
}
