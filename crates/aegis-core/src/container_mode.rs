use aegis_model::{
    ContainerContext, EventPayload, NetworkContext, NormalizedEvent, Priority, Severity,
};
use anyhow::{bail, Result};
use std::collections::BTreeMap;
use std::path::PathBuf;

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
    pub mount_points: Vec<PathBuf>,
}

impl DaemonSetHostAgentConfig {
    pub fn validate(&self) -> Result<()> {
        if self.namespace.is_empty() || self.service_account.is_empty() {
            bail!("daemonset config requires namespace and service account");
        }
        if !self.host_pid || !self.host_network || !self.privileged {
            bail!("host agent daemonset must run with host pid/network and privileged access");
        }
        if self.mount_points.is_empty() {
            bail!("host agent daemonset requires host mount points");
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
    };
    use aegis_model::{
        EventPayload, EventType, NetworkContext, NormalizedEvent, Priority, ProcessContext,
        Severity,
    };
    use std::collections::BTreeMap;
    use std::path::PathBuf;

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
            host_network: true,
            privileged: true,
            mount_points: vec![PathBuf::from("/var/lib/kubelet")],
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
}
