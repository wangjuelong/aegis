use crate::comms::TransportDriver;
use crate::config::{
    CommunicationConfig, DomainFrontingCommunicationConfig, HttpPollingCommunicationConfig,
};
use aegis_model::{
    BatchAck, BatchAckStatus, ClientAckStatus, CommunicationChannelKind, DownlinkMessage,
    EventType, FlowControlHint, HeartbeatRequest, Priority, Severity, SignedServerCommand,
    TelemetryEvent, TelemetryIntegrity, UplinkMessage,
};
use anyhow::{anyhow, Context, Result};
use futures_util::{SinkExt, StreamExt};
use lz4_flex::compress_prepend_size;
use prost::Message as ProstMessage;
use reqwest::blocking::Client as BlockingClient;
use serde::Serialize;
use std::any::Any;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::runtime::Handle;
use tokio::sync::mpsc;
use tokio::time;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use tonic::transport::Endpoint;
use tonic::Request;
use uuid::Uuid;

pub(crate) mod transport_rpc {
    tonic::include_proto!("aegis.agent.v1");
}

use transport_rpc::agent_service_client::AgentServiceClient;

const GRPC_CONNECT_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Clone)]
pub struct TransportAgentContext {
    pub tenant_id: String,
    pub agent_id: String,
}

#[derive(Clone, Debug, PartialEq)]
enum ClientTransportFrame {
    Uplink(UplinkMessage),
    Heartbeat(HeartbeatRequest),
}

#[derive(Clone, Debug, PartialEq)]
enum ServerTransportFrame {
    Downlink(DownlinkMessage),
    Heartbeat,
}

#[derive(Default)]
struct StreamingLinkState {
    outbound_tx: Option<mpsc::UnboundedSender<ClientTransportFrame>>,
    connected: bool,
}

pub fn build_transport_drivers(
    config: &CommunicationConfig,
    agent: &TransportAgentContext,
) -> Result<Vec<Box<dyn TransportDriver>>> {
    let handle = Handle::current();
    let mut drivers: Vec<Box<dyn TransportDriver>> = Vec::new();

    if config.grpc.enabled {
        drivers.push(Box::new(GrpcTransportDriver::new(
            config.grpc.endpoint.clone(),
            agent.clone(),
            handle.clone(),
        )));
    }
    if config.websocket.enabled {
        drivers.push(Box::new(WebSocketTransportDriver::new(
            config.websocket.endpoint.clone(),
            handle.clone(),
        )));
    }
    if config.long_polling.enabled {
        drivers.push(Box::new(HttpTransportDriver::new(
            CommunicationChannelKind::LongPolling,
            config.long_polling.clone(),
            HttpRequestDecoration::default(),
        )?));
    }
    if config.domain_fronting.enabled {
        drivers.push(Box::new(HttpTransportDriver::new(
            CommunicationChannelKind::DomainFronting,
            domain_fronting_as_http(&config.domain_fronting),
            HttpRequestDecoration {
                front_domain: Some(config.domain_fronting.front_domain.clone()),
                host_header: Some(config.domain_fronting.host_header.clone()),
            },
        )?));
    }

    Ok(drivers)
}

fn domain_fronting_as_http(
    config: &DomainFrontingCommunicationConfig,
) -> HttpPollingCommunicationConfig {
    HttpPollingCommunicationConfig {
        enabled: config.enabled,
        uplink_url: config.uplink_url.clone(),
        heartbeat_url: config.heartbeat_url.clone(),
        downlink_url: config.downlink_url.clone(),
        probe_url: config.probe_url.clone(),
        timeout_ms: config.timeout_ms,
    }
}

fn encode_priority(priority: Priority) -> i32 {
    match priority {
        Priority::Low => transport_rpc::Priority::Low as i32,
        Priority::Normal => transport_rpc::Priority::Normal as i32,
        Priority::High => transport_rpc::Priority::High as i32,
        Priority::Critical => transport_rpc::Priority::Critical as i32,
    }
}

fn serialize_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(value)?)
}

fn serialize_optional_json_bytes<T: Serialize>(value: &Option<T>) -> Result<Vec<u8>> {
    match value {
        Some(value) => serialize_json_bytes(value),
        None => Ok(Vec::new()),
    }
}

#[cfg(test)]
fn deserialize_json_bytes<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    Ok(serde_json::from_slice(bytes)?)
}

#[cfg(test)]
fn deserialize_optional_json_bytes<T: DeserializeOwned>(bytes: &[u8]) -> Result<Option<T>> {
    if bytes.is_empty() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_slice(bytes)?))
}

fn encode_event_type(event_type: EventType) -> i32 {
    match event_type {
        EventType::ProcessCreate => transport_rpc::EventType::ProcessCreate as i32,
        EventType::ProcessExit => transport_rpc::EventType::ProcessExit as i32,
        EventType::FileWrite => transport_rpc::EventType::FileWrite as i32,
        EventType::NetConnect => transport_rpc::EventType::NetConnect as i32,
        EventType::Alert => transport_rpc::EventType::Alert as i32,
        EventType::RegistryWrite => transport_rpc::EventType::RegistryWrite as i32,
        EventType::Auth => transport_rpc::EventType::Auth as i32,
        EventType::Script => transport_rpc::EventType::Script as i32,
        EventType::Memory => transport_rpc::EventType::Memory as i32,
        EventType::Container => transport_rpc::EventType::Container as i32,
        EventType::NamedPipe => transport_rpc::EventType::NamedPipe as i32,
        EventType::ModuleLoad => transport_rpc::EventType::ModuleLoad as i32,
        EventType::DeviceControl => transport_rpc::EventType::DeviceControl as i32,
        EventType::Unknown => transport_rpc::EventType::Unknown as i32,
    }
}

#[cfg(test)]
fn decode_event_type(event_type: i32) -> EventType {
    match transport_rpc::EventType::try_from(event_type)
        .unwrap_or(transport_rpc::EventType::Unknown)
    {
        transport_rpc::EventType::ProcessCreate => EventType::ProcessCreate,
        transport_rpc::EventType::ProcessExit => EventType::ProcessExit,
        transport_rpc::EventType::FileWrite => EventType::FileWrite,
        transport_rpc::EventType::NetConnect => EventType::NetConnect,
        transport_rpc::EventType::Alert => EventType::Alert,
        transport_rpc::EventType::RegistryWrite => EventType::RegistryWrite,
        transport_rpc::EventType::Auth => EventType::Auth,
        transport_rpc::EventType::Script => EventType::Script,
        transport_rpc::EventType::Memory => EventType::Memory,
        transport_rpc::EventType::Container => EventType::Container,
        transport_rpc::EventType::NamedPipe => EventType::NamedPipe,
        transport_rpc::EventType::ModuleLoad => EventType::ModuleLoad,
        transport_rpc::EventType::DeviceControl => EventType::DeviceControl,
        transport_rpc::EventType::Unknown | transport_rpc::EventType::Unspecified => {
            EventType::Unknown
        }
    }
}

fn encode_severity(severity: Severity) -> i32 {
    match severity {
        Severity::Info => transport_rpc::Severity::Info as i32,
        Severity::Low => transport_rpc::Severity::Low as i32,
        Severity::Medium => transport_rpc::Severity::Medium as i32,
        Severity::High => transport_rpc::Severity::High as i32,
        Severity::Critical => transport_rpc::Severity::Critical as i32,
    }
}

#[cfg(test)]
fn decode_severity(severity: i32) -> Severity {
    match transport_rpc::Severity::try_from(severity)
        .unwrap_or(transport_rpc::Severity::Unspecified)
    {
        transport_rpc::Severity::Info => Severity::Info,
        transport_rpc::Severity::Low => Severity::Low,
        transport_rpc::Severity::Medium => Severity::Medium,
        transport_rpc::Severity::High => Severity::High,
        transport_rpc::Severity::Critical => Severity::Critical,
        transport_rpc::Severity::Unspecified => Severity::Info,
    }
}

fn encode_integrity(integrity: TelemetryIntegrity) -> i32 {
    match integrity {
        TelemetryIntegrity::Full => transport_rpc::TelemetryIntegrity::Full as i32,
        TelemetryIntegrity::Partial => transport_rpc::TelemetryIntegrity::Partial as i32,
    }
}

#[cfg(test)]
fn decode_integrity(integrity: i32) -> TelemetryIntegrity {
    match transport_rpc::TelemetryIntegrity::try_from(integrity)
        .unwrap_or(transport_rpc::TelemetryIntegrity::Full)
    {
        transport_rpc::TelemetryIntegrity::Partial => TelemetryIntegrity::Partial,
        transport_rpc::TelemetryIntegrity::Full => TelemetryIntegrity::Full,
    }
}

fn encode_telemetry_event_for_grpc(
    event: &TelemetryEvent,
) -> Result<transport_rpc::TelemetryEvent> {
    Ok(transport_rpc::TelemetryEvent {
        event_id: event.event_id.to_string(),
        lineage_id: event.lineage_id.to_string(),
        timestamp_ns: event.timestamp_ns,
        tenant_id: event.tenant_id.clone(),
        agent_id: event.agent_id.clone(),
        integrity: encode_integrity(event.integrity),
        event_type: encode_event_type(event.event_type),
        priority: encode_priority(event.priority),
        severity: encode_severity(event.severity),
        host_json: serialize_json_bytes(&event.host)?,
        process_json: serialize_json_bytes(&event.process)?,
        payload_json: serialize_json_bytes(&event.payload)?,
        container_json: serialize_optional_json_bytes(&event.container)?,
        storyline_json: serialize_optional_json_bytes(&event.storyline)?,
        enrichment_json: serialize_json_bytes(&event.enrichment)?,
        syscall_origin_json: serialize_optional_json_bytes(&event.syscall_origin)?,
        lineage_json: serialize_json_bytes(&event.lineage)?,
    })
}

#[cfg(test)]
fn decode_telemetry_event_from_grpc(
    event: transport_rpc::TelemetryEvent,
) -> Result<TelemetryEvent> {
    Ok(TelemetryEvent {
        event_id: Uuid::parse_str(&event.event_id)
            .with_context(|| format!("invalid telemetry event id {}", event.event_id))?,
        lineage_id: Uuid::parse_str(&event.lineage_id)
            .with_context(|| format!("invalid lineage id {}", event.lineage_id))?,
        timestamp_ns: event.timestamp_ns,
        tenant_id: event.tenant_id,
        agent_id: event.agent_id,
        integrity: decode_integrity(event.integrity),
        event_type: decode_event_type(event.event_type),
        priority: match transport_rpc::Priority::try_from(event.priority)
            .unwrap_or(transport_rpc::Priority::Normal)
        {
            transport_rpc::Priority::Low => Priority::Low,
            transport_rpc::Priority::Normal | transport_rpc::Priority::Unspecified => {
                Priority::Normal
            }
            transport_rpc::Priority::High => Priority::High,
            transport_rpc::Priority::Critical => Priority::Critical,
        },
        severity: decode_severity(event.severity),
        host: deserialize_json_bytes(&event.host_json)?,
        process: deserialize_json_bytes(&event.process_json)?,
        payload: deserialize_json_bytes(&event.payload_json)?,
        container: deserialize_optional_json_bytes(&event.container_json)?,
        storyline: deserialize_optional_json_bytes(&event.storyline_json)?,
        enrichment: deserialize_json_bytes(&event.enrichment_json)?,
        syscall_origin: deserialize_optional_json_bytes(&event.syscall_origin_json)?,
        lineage: deserialize_json_bytes(&event.lineage_json)?,
    })
}

fn encode_telemetry_batch(events: &[TelemetryEvent]) -> Result<Vec<u8>> {
    let batch = transport_rpc::TelemetryBatch {
        events: events
            .iter()
            .map(encode_telemetry_event_for_grpc)
            .collect::<Result<Vec<_>>>()?,
    };
    let mut bytes = Vec::new();
    batch.encode(&mut bytes)?;
    Ok(compress_prepend_size(&bytes))
}

#[cfg(test)]
fn decode_telemetry_batch(compressed_events: &[u8]) -> Result<Vec<TelemetryEvent>> {
    let payload = lz4_flex::decompress_size_prepended(compressed_events)?;
    let batch = transport_rpc::TelemetryBatch::decode(payload.as_slice())?;
    batch
        .events
        .into_iter()
        .map(decode_telemetry_event_from_grpc)
        .collect()
}

fn encode_uplink_for_grpc(message: &UplinkMessage) -> Result<transport_rpc::UplinkMessage> {
    let kind = match message {
        UplinkMessage::EventBatch(batch) => {
            let compressed_events = encode_telemetry_batch(&batch.events)?;
            let batched_at = batch
                .events
                .iter()
                .map(|event| (event.timestamp_ns / 1_000_000) as i64)
                .max()
                .unwrap_or_default();
            transport_rpc::uplink_message::Kind::EventBatch(transport_rpc::EventBatch {
                batch_id: batch.batch_id.to_string(),
                sequence_id: batch.sequence_hint,
                event_count: batch.events.len() as u32,
                compressed_events,
                priority: encode_priority(
                    batch
                        .events
                        .iter()
                        .map(|event| event.priority)
                        .max()
                        .unwrap_or(Priority::Normal),
                ),
                batched_at,
                tenant_id: batch.tenant_id.clone(),
                agent_id: batch.agent_id.clone(),
            })
        }
        UplinkMessage::ClientAck(ack) => {
            transport_rpc::uplink_message::Kind::ClientAck(transport_rpc::ClientAck {
                command_id: ack.command_id.to_string(),
                status: match ack.status {
                    ClientAckStatus::Received => transport_rpc::client_ack::Status::Received as i32,
                    ClientAckStatus::Executed => transport_rpc::client_ack::Status::Executed as i32,
                    ClientAckStatus::Rejected => transport_rpc::client_ack::Status::Rejected as i32,
                    ClientAckStatus::Failed => transport_rpc::client_ack::Status::Failed as i32,
                },
                error_detail: ack.detail.clone().unwrap_or_default(),
                acked_at: ack.acked_at,
            })
        }
        UplinkMessage::FlowControlHint(hint) => {
            transport_rpc::uplink_message::Kind::FlowControlHint(transport_rpc::FlowControlHint {
                pause_low_priority: hint.pause_low_priority,
                max_batch_events: hint.max_batch_events as u32,
                suggested_rate_eps: hint.suggested_rate_eps.unwrap_or_default(),
                cooldown_ms: hint.cooldown_ms.unwrap_or_default(),
                reason: hint.reason.clone().unwrap_or_default(),
            })
        }
    };
    Ok(transport_rpc::UplinkMessage { kind: Some(kind) })
}

fn decode_downlink_from_grpc(message: transport_rpc::DownlinkMessage) -> Result<DownlinkMessage> {
    let kind = message
        .kind
        .ok_or_else(|| anyhow!("grpc downlink frame missing payload"))?;
    Ok(match kind {
        transport_rpc::downlink_message::Kind::BatchAck(ack) => {
            DownlinkMessage::BatchAck(BatchAck {
                batch_id: Uuid::parse_str(&ack.batch_id)
                    .with_context(|| format!("invalid batch ack id {}", ack.batch_id))?,
                sequence_id: ack.sequence_id,
                status: match transport_rpc::batch_ack::Status::try_from(ack.status)
                    .unwrap_or(transport_rpc::batch_ack::Status::Accepted)
                {
                    transport_rpc::batch_ack::Status::Accepted => BatchAckStatus::Accepted,
                    transport_rpc::batch_ack::Status::RejectedRateLimit => {
                        BatchAckStatus::RejectedRateLimit
                    }
                    transport_rpc::batch_ack::Status::RejectedBackpressure => {
                        BatchAckStatus::RejectedBackpressure
                    }
                    transport_rpc::batch_ack::Status::RejectedMalformed => {
                        BatchAckStatus::RejectedMalformed
                    }
                    transport_rpc::batch_ack::Status::RejectedAuth => BatchAckStatus::RejectedAuth,
                    transport_rpc::batch_ack::Status::RejectedQuotaExceeded => {
                        BatchAckStatus::RejectedQuotaExceeded
                    }
                },
                retry_after_ms: ack.retry_after_ms,
                reason: (!ack.reason.is_empty()).then_some(ack.reason),
                acked_at: ack.acked_at,
                accepted_events: ack.accepted_events,
                rejected_events: ack.rejected_events,
            })
        }
        transport_rpc::downlink_message::Kind::ServerCommand(command) => {
            DownlinkMessage::ServerCommand(SignedServerCommand {
                payload: command.payload,
                signature: command.signature,
                signing_key_id: command.signing_key_id,
            })
        }
        transport_rpc::downlink_message::Kind::FlowHint(hint) => {
            DownlinkMessage::FlowControlHint(FlowControlHint {
                pause_low_priority: hint.pause_low_priority,
                max_batch_events: hint.max_batch_events as usize,
                suggested_rate_eps: (hint.suggested_rate_eps > 0)
                    .then_some(hint.suggested_rate_eps),
                cooldown_ms: (hint.cooldown_ms > 0).then_some(hint.cooldown_ms),
                reason: (!hint.reason.is_empty()).then_some(hint.reason),
            })
        }
    })
}

fn encode_heartbeat_for_grpc(
    heartbeat: &HeartbeatRequest,
) -> Result<transport_rpc::HeartbeatRequest> {
    Ok(transport_rpc::HeartbeatRequest {
        tenant_id: heartbeat.tenant_id.clone(),
        agent_id: heartbeat.agent_id.clone(),
        health_json: serde_json::to_vec(&heartbeat.health)?,
        communication_json: serde_json::to_vec(&heartbeat.communication)?,
        wal_utilization_ratio: heartbeat.wal_utilization_ratio,
        restart_epoch: heartbeat.restart_epoch,
    })
}

fn grpc_probe_request(agent: &TransportAgentContext) -> transport_rpc::HeartbeatRequest {
    transport_rpc::HeartbeatRequest {
        tenant_id: agent.tenant_id.clone(),
        agent_id: agent.agent_id.clone(),
        health_json: Vec::new(),
        communication_json: Vec::new(),
        wal_utilization_ratio: 0.0,
        restart_epoch: 0,
    }
}

fn encode_client_transport_bundle(frame: &ClientTransportFrame) -> Result<Vec<u8>> {
    let kind = match frame {
        ClientTransportFrame::Uplink(message) => {
            transport_rpc::client_transport_envelope::Kind::UplinkMessage(encode_uplink_for_grpc(
                message,
            )?)
        }
        ClientTransportFrame::Heartbeat(heartbeat) => {
            transport_rpc::client_transport_envelope::Kind::Heartbeat(encode_heartbeat_for_grpc(
                heartbeat,
            )?)
        }
    };
    let bundle = transport_rpc::ClientTransportBundle {
        messages: vec![transport_rpc::ClientTransportEnvelope { kind: Some(kind) }],
    };
    let mut bytes = Vec::new();
    bundle.encode(&mut bytes)?;
    Ok(bytes)
}

fn decode_server_transport_bundle(bytes: &[u8]) -> Result<Vec<ServerTransportFrame>> {
    let bundle = transport_rpc::ServerTransportBundle::decode(bytes)?;
    bundle
        .messages
        .into_iter()
        .map(|message| {
            let kind = message
                .kind
                .ok_or_else(|| anyhow!("transport server envelope missing payload"))?;
            Ok(match kind {
                transport_rpc::server_transport_envelope::Kind::DownlinkMessage(message) => {
                    ServerTransportFrame::Downlink(decode_downlink_from_grpc(message)?)
                }
                transport_rpc::server_transport_envelope::Kind::HeartbeatResponse(_) => {
                    ServerTransportFrame::Heartbeat
                }
            })
        })
        .collect()
}

pub struct GrpcTransportDriver {
    endpoint: String,
    agent: TransportAgentContext,
    handle: Handle,
    link: Arc<Mutex<StreamingLinkState>>,
    inbound: Arc<Mutex<VecDeque<DownlinkMessage>>>,
}

impl GrpcTransportDriver {
    pub fn new(endpoint: String, agent: TransportAgentContext, handle: Handle) -> Self {
        let driver = Self {
            endpoint,
            agent,
            handle,
            link: Arc::new(Mutex::new(StreamingLinkState::default())),
            inbound: Arc::new(Mutex::new(VecDeque::new())),
        };
        driver.ensure_connected();
        driver
    }

    fn is_connected(&self) -> bool {
        self.link.lock().expect("grpc link poisoned").connected
    }

    fn ensure_connected(&self) {
        let needs_spawn = {
            let link = self.link.lock().expect("grpc link poisoned");
            link.outbound_tx
                .as_ref()
                .map(|sender| sender.is_closed())
                .unwrap_or(true)
        };
        if !needs_spawn {
            return;
        }

        let (outbound_tx, outbound_rx) = mpsc::unbounded_channel();
        {
            let mut link = self.link.lock().expect("grpc link poisoned");
            link.outbound_tx = Some(outbound_tx);
            link.connected = false;
        }

        let endpoint = self.endpoint.clone();
        let link = Arc::clone(&self.link);
        let inbound = Arc::clone(&self.inbound);
        self.handle.spawn(async move {
            if let Err(error) =
                run_grpc_exchange(endpoint, outbound_rx, Arc::clone(&link), inbound).await
            {
                tracing::debug!(%error, "grpc transport task exited");
            }
            link.lock().expect("grpc link poisoned").connected = false;
        });
    }

    fn heartbeat_probe(&self) -> bool {
        let endpoint = self.endpoint.clone();
        let request = grpc_probe_request(&self.agent);
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .ok()?;
            runtime.block_on(async move {
                let channel = Endpoint::from_shared(endpoint.clone())
                    .ok()?
                    .connect_timeout(GRPC_CONNECT_TIMEOUT)
                    .timeout(GRPC_CONNECT_TIMEOUT)
                    .connect()
                    .await
                    .ok()?;
                let mut client = AgentServiceClient::new(channel);
                time::timeout(
                    GRPC_CONNECT_TIMEOUT,
                    client.heartbeat(Request::new(request)),
                )
                .await
                .ok()?
                .ok()?;
                Some(())
            })
        })
        .join()
        .ok()
        .flatten()
        .is_some()
    }

    fn send_frame(&self, frame: ClientTransportFrame) -> Result<()> {
        self.ensure_connected();
        if !self.is_connected() && !self.heartbeat_probe() {
            return Err(anyhow!("grpc transport is not reachable"));
        }
        let sender = {
            self.link
                .lock()
                .expect("grpc link poisoned")
                .outbound_tx
                .clone()
        }
        .ok_or_else(|| anyhow!("grpc transport sender missing"))?;
        sender
            .send(frame)
            .map_err(|_| anyhow!("grpc transport is disconnected"))
    }

    fn send_heartbeat_rpc(&self, heartbeat: &HeartbeatRequest) -> Result<()> {
        let request = encode_heartbeat_for_grpc(heartbeat)?;
        let endpoint = self.endpoint.clone();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("build grpc heartbeat runtime")?;
            runtime.block_on(async move {
                let channel = Endpoint::from_shared(endpoint.clone())
                    .context("invalid grpc endpoint")?
                    .connect_timeout(GRPC_CONNECT_TIMEOUT)
                    .timeout(GRPC_CONNECT_TIMEOUT)
                    .connect()
                    .await
                    .with_context(|| format!("failed to connect grpc endpoint {endpoint}"))?;
                let mut client = AgentServiceClient::new(channel);
                time::timeout(
                    GRPC_CONNECT_TIMEOUT,
                    client.heartbeat(Request::new(request)),
                )
                .await
                .context("grpc heartbeat request timed out")??;
                Ok::<(), anyhow::Error>(())
            })
        })
        .join()
        .map_err(|_| anyhow!("grpc heartbeat thread panicked"))?
    }
}

impl TransportDriver for GrpcTransportDriver {
    fn channel(&self) -> CommunicationChannelKind {
        CommunicationChannelKind::Grpc
    }

    fn send_uplink(&self, message: &UplinkMessage) -> Result<()> {
        self.send_frame(ClientTransportFrame::Uplink(message.clone()))
    }

    fn send_heartbeat(&self, heartbeat: &HeartbeatRequest) -> Result<()> {
        self.send_heartbeat_rpc(heartbeat)
    }

    fn recv_downlink(&self) -> Result<Option<DownlinkMessage>> {
        Ok(self
            .inbound
            .lock()
            .expect("grpc inbound queue poisoned")
            .pop_front())
    }

    fn probe(&self) -> bool {
        self.ensure_connected();
        if self.is_connected() {
            return true;
        }
        self.heartbeat_probe()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

async fn run_grpc_exchange(
    endpoint: String,
    outbound_rx: mpsc::UnboundedReceiver<ClientTransportFrame>,
    link: Arc<Mutex<StreamingLinkState>>,
    inbound: Arc<Mutex<VecDeque<DownlinkMessage>>>,
) -> Result<()> {
    let channel = Endpoint::from_shared(endpoint.clone())
        .context("invalid grpc endpoint")?
        .connect_timeout(GRPC_CONNECT_TIMEOUT)
        .timeout(GRPC_CONNECT_TIMEOUT)
        .connect()
        .await
        .with_context(|| format!("failed to connect grpc endpoint {endpoint}"))?;
    let mut client = AgentServiceClient::new(channel);
    let outbound_stream =
        UnboundedReceiverStream::new(outbound_rx).filter_map(|frame| async move {
            match frame {
                ClientTransportFrame::Uplink(message) => match encode_uplink_for_grpc(&message) {
                    Ok(message) => Some(message),
                    Err(error) => {
                        tracing::debug!(%error, "failed to encode grpc uplink");
                        None
                    }
                },
                ClientTransportFrame::Heartbeat(_) => None,
            }
        });
    let response = time::timeout(
        GRPC_CONNECT_TIMEOUT,
        client.event_stream(Request::new(outbound_stream)),
    )
    .await
    .context("grpc event stream setup timed out")??;
    link.lock().expect("grpc link poisoned").connected = true;
    let mut stream = response.into_inner();

    while let Some(message) = stream.next().await {
        let message = message?;
        inbound
            .lock()
            .expect("grpc inbound queue poisoned")
            .push_back(decode_downlink_from_grpc(message)?);
    }

    Ok(())
}

pub struct WebSocketTransportDriver {
    endpoint: String,
    handle: Handle,
    link: Arc<Mutex<StreamingLinkState>>,
    inbound: Arc<Mutex<VecDeque<DownlinkMessage>>>,
}

impl WebSocketTransportDriver {
    pub fn new(endpoint: String, handle: Handle) -> Self {
        let driver = Self {
            endpoint,
            handle,
            link: Arc::new(Mutex::new(StreamingLinkState::default())),
            inbound: Arc::new(Mutex::new(VecDeque::new())),
        };
        driver.ensure_connected();
        driver
    }

    fn is_connected(&self) -> bool {
        self.link.lock().expect("websocket link poisoned").connected
    }

    fn ensure_connected(&self) {
        let needs_spawn = {
            let link = self.link.lock().expect("websocket link poisoned");
            link.outbound_tx
                .as_ref()
                .map(|sender| sender.is_closed())
                .unwrap_or(true)
        };
        if !needs_spawn {
            return;
        }

        let (outbound_tx, outbound_rx) = mpsc::unbounded_channel();
        {
            let mut link = self.link.lock().expect("websocket link poisoned");
            link.outbound_tx = Some(outbound_tx);
            link.connected = false;
        }

        let endpoint = self.endpoint.clone();
        let link = Arc::clone(&self.link);
        let inbound = Arc::clone(&self.inbound);
        self.handle.spawn(async move {
            if let Err(error) =
                run_websocket_exchange(endpoint, outbound_rx, Arc::clone(&link), inbound).await
            {
                tracing::debug!(%error, "websocket transport task exited");
            }
            link.lock().expect("websocket link poisoned").connected = false;
        });
    }

    fn send_frame(&self, frame: ClientTransportFrame) -> Result<()> {
        self.ensure_connected();
        if !self.is_connected() {
            return Err(anyhow!("websocket transport is not ready"));
        }
        let sender = {
            self.link
                .lock()
                .expect("websocket link poisoned")
                .outbound_tx
                .clone()
        }
        .ok_or_else(|| anyhow!("websocket transport sender missing"))?;
        sender
            .send(frame)
            .map_err(|_| anyhow!("websocket transport is disconnected"))
    }
}

impl TransportDriver for WebSocketTransportDriver {
    fn channel(&self) -> CommunicationChannelKind {
        CommunicationChannelKind::WebSocket
    }

    fn send_uplink(&self, message: &UplinkMessage) -> Result<()> {
        self.send_frame(ClientTransportFrame::Uplink(message.clone()))
    }

    fn send_heartbeat(&self, heartbeat: &HeartbeatRequest) -> Result<()> {
        self.send_frame(ClientTransportFrame::Heartbeat(heartbeat.clone()))
    }

    fn recv_downlink(&self) -> Result<Option<DownlinkMessage>> {
        Ok(self
            .inbound
            .lock()
            .expect("websocket inbound queue poisoned")
            .pop_front())
    }

    fn probe(&self) -> bool {
        self.ensure_connected();
        self.is_connected()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

async fn run_websocket_exchange(
    endpoint: String,
    mut outbound_rx: mpsc::UnboundedReceiver<ClientTransportFrame>,
    link: Arc<Mutex<StreamingLinkState>>,
    inbound: Arc<Mutex<VecDeque<DownlinkMessage>>>,
) -> Result<()> {
    let (stream, _) = connect_async(endpoint.clone())
        .await
        .with_context(|| format!("failed to connect websocket endpoint {endpoint}"))?;
    link.lock().expect("websocket link poisoned").connected = true;
    let (mut sink, mut source) = stream.split();

    loop {
        tokio::select! {
            maybe_frame = outbound_rx.recv() => {
                let Some(frame) = maybe_frame else {
                    break;
                };
                let payload = encode_client_transport_bundle(&frame)?;
                sink.send(Message::Binary(payload)).await?;
            }
            maybe_message = source.next() => {
                let Some(message) = maybe_message else {
                    break;
                };
                match message? {
                    Message::Binary(bytes) => {
                        for frame in decode_server_transport_bundle(&bytes)? {
                            if let ServerTransportFrame::Downlink(message) = frame {
                                inbound.lock().expect("websocket inbound queue poisoned").push_back(message);
                            }
                        }
                    }
                    Message::Ping(payload) => sink.send(Message::Pong(payload)).await?,
                    Message::Close(_) => break,
                    _ => {}
                }
            }
        }
    }

    Ok(())
}

#[derive(Clone, Default)]
struct HttpRequestDecoration {
    front_domain: Option<String>,
    host_header: Option<String>,
}

pub struct HttpTransportDriver {
    channel: CommunicationChannelKind,
    endpoints: HttpPollingCommunicationConfig,
    decoration: HttpRequestDecoration,
    inbound: Arc<Mutex<VecDeque<DownlinkMessage>>>,
}

impl HttpTransportDriver {
    fn new(
        channel: CommunicationChannelKind,
        endpoints: HttpPollingCommunicationConfig,
        decoration: HttpRequestDecoration,
    ) -> Result<Self> {
        Ok(Self {
            channel,
            endpoints,
            decoration,
            inbound: Arc::new(Mutex::new(VecDeque::new())),
        })
    }

    fn post_frame(&self, url: &str, frame: &ClientTransportFrame) -> Result<()> {
        let decoration = self.decoration.clone();
        let url = url.to_string();
        let payload = encode_client_transport_bundle(frame)?;
        let timeout_ms = self.endpoints.timeout_ms;
        let inbound = Arc::clone(&self.inbound);
        std::thread::spawn(move || {
            let client = BlockingClient::builder()
                .timeout(Duration::from_millis(timeout_ms.max(1)))
                .build()?;
            let mut request = client.post(url).body(payload);
            if let Some(host_header) = &decoration.host_header {
                request = request.header("Host", host_header);
            }
            if let Some(front_domain) = &decoration.front_domain {
                request = request.header("X-Aegis-Front-Domain", front_domain);
            }
            request = request.header(reqwest::header::CONTENT_TYPE, "application/x-protobuf");
            let response = request.send()?;
            if response.status() == reqwest::StatusCode::NO_CONTENT {
                return Ok::<(), anyhow::Error>(());
            }
            let response = response.error_for_status()?;
            let bytes = response.bytes()?;
            if bytes.is_empty() {
                return Ok::<(), anyhow::Error>(());
            }
            for frame in decode_server_transport_bundle(bytes.as_ref())? {
                if let ServerTransportFrame::Downlink(message) = frame {
                    inbound
                        .lock()
                        .expect("http inbound queue poisoned")
                        .push_back(message);
                }
            }
            Ok::<(), anyhow::Error>(())
        })
        .join()
        .map_err(|_| anyhow!("http transport thread panicked"))?
    }
}

impl TransportDriver for HttpTransportDriver {
    fn channel(&self) -> CommunicationChannelKind {
        self.channel
    }

    fn send_uplink(&self, message: &UplinkMessage) -> Result<()> {
        self.post_frame(
            &self.endpoints.uplink_url,
            &ClientTransportFrame::Uplink(message.clone()),
        )
    }

    fn send_heartbeat(&self, heartbeat: &HeartbeatRequest) -> Result<()> {
        self.post_frame(
            &self.endpoints.heartbeat_url,
            &ClientTransportFrame::Heartbeat(heartbeat.clone()),
        )
    }

    fn recv_downlink(&self) -> Result<Option<DownlinkMessage>> {
        if let Some(message) = self
            .inbound
            .lock()
            .expect("http inbound queue poisoned")
            .pop_front()
        {
            return Ok(Some(message));
        }
        let decoration = self.decoration.clone();
        let downlink_url = self.endpoints.downlink_url.clone();
        let timeout_ms = self.endpoints.timeout_ms;
        std::thread::spawn(move || {
            let client = BlockingClient::builder()
                .timeout(Duration::from_millis(timeout_ms.max(1)))
                .build()?;
            let mut request = client.get(&downlink_url);
            if let Some(host_header) = &decoration.host_header {
                request = request.header("Host", host_header);
            }
            if let Some(front_domain) = &decoration.front_domain {
                request = request.header("X-Aegis-Front-Domain", front_domain);
            }
            let response = request.send()?;
            if response.status() == reqwest::StatusCode::NO_CONTENT {
                return Ok(None);
            }
            let response = response.error_for_status()?;
            let bytes = response.bytes()?;
            let frames = decode_server_transport_bundle(bytes.as_ref())?;
            let message = frames.into_iter().find_map(|frame| match frame {
                ServerTransportFrame::Downlink(message) => Some(message),
                ServerTransportFrame::Heartbeat => None,
            });
            Ok::<Option<DownlinkMessage>, anyhow::Error>(message)
        })
        .join()
        .map_err(|_| anyhow!("http transport thread panicked"))?
    }

    fn probe(&self) -> bool {
        let decoration = self.decoration.clone();
        let probe_url = self.endpoints.probe_url.clone();
        let timeout_ms = self.endpoints.timeout_ms;
        std::thread::spawn(move || {
            let Ok(client) = BlockingClient::builder()
                .timeout(Duration::from_millis(timeout_ms.max(1)))
                .build()
            else {
                return false;
            };
            let mut request = client.get(&probe_url);
            if let Some(host_header) = &decoration.host_header {
                request = request.header("Host", host_header);
            }
            if let Some(front_domain) = &decoration.front_domain {
                request = request.header("X-Aegis-Front-Domain", front_domain);
            }
            request
                .send()
                .and_then(|response| response.error_for_status())
                .is_ok()
        })
        .join()
        .unwrap_or(false)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
fn decode_uplink_from_grpc(message: transport_rpc::UplinkMessage) -> Result<UplinkMessage> {
    let kind = message
        .kind
        .ok_or_else(|| anyhow!("grpc uplink frame missing payload"))?;
    Ok(match kind {
        transport_rpc::uplink_message::Kind::EventBatch(batch) => {
            let events = decode_telemetry_batch(&batch.compressed_events)?;
            UplinkMessage::EventBatch(aegis_model::EventBatch {
                batch_id: Uuid::parse_str(&batch.batch_id)
                    .with_context(|| format!("invalid event batch id {}", batch.batch_id))?,
                tenant_id: batch.tenant_id,
                agent_id: batch.agent_id,
                sequence_hint: batch.sequence_id,
                events,
            })
        }
        transport_rpc::uplink_message::Kind::ClientAck(ack) => {
            let status = match transport_rpc::client_ack::Status::try_from(ack.status)
                .unwrap_or(transport_rpc::client_ack::Status::Failed)
            {
                transport_rpc::client_ack::Status::Received => ClientAckStatus::Received,
                transport_rpc::client_ack::Status::Executed => ClientAckStatus::Executed,
                transport_rpc::client_ack::Status::Rejected => ClientAckStatus::Rejected,
                transport_rpc::client_ack::Status::Failed => ClientAckStatus::Failed,
            };
            UplinkMessage::ClientAck(aegis_model::ClientAck {
                command_id: Uuid::parse_str(&ack.command_id)
                    .with_context(|| format!("invalid command id {}", ack.command_id))?,
                status,
                detail: (!ack.error_detail.is_empty()).then_some(ack.error_detail),
                acked_at: ack.acked_at,
            })
        }
        transport_rpc::uplink_message::Kind::FlowControlHint(hint) => {
            UplinkMessage::FlowControlHint(FlowControlHint {
                pause_low_priority: hint.pause_low_priority,
                max_batch_events: hint.max_batch_events as usize,
                suggested_rate_eps: (hint.suggested_rate_eps > 0)
                    .then_some(hint.suggested_rate_eps),
                cooldown_ms: (hint.cooldown_ms > 0).then_some(hint.cooldown_ms),
                reason: (!hint.reason.is_empty()).then_some(hint.reason),
            })
        }
    })
}

#[cfg(test)]
fn encode_downlink_for_grpc(message: &DownlinkMessage) -> transport_rpc::DownlinkMessage {
    let kind = match message {
        DownlinkMessage::BatchAck(ack) => {
            transport_rpc::downlink_message::Kind::BatchAck(transport_rpc::BatchAck {
                batch_id: ack.batch_id.to_string(),
                sequence_id: ack.sequence_id,
                status: match ack.status {
                    BatchAckStatus::Accepted => transport_rpc::batch_ack::Status::Accepted as i32,
                    BatchAckStatus::RejectedRateLimit => {
                        transport_rpc::batch_ack::Status::RejectedRateLimit as i32
                    }
                    BatchAckStatus::RejectedBackpressure => {
                        transport_rpc::batch_ack::Status::RejectedBackpressure as i32
                    }
                    BatchAckStatus::RejectedMalformed => {
                        transport_rpc::batch_ack::Status::RejectedMalformed as i32
                    }
                    BatchAckStatus::RejectedAuth => {
                        transport_rpc::batch_ack::Status::RejectedAuth as i32
                    }
                    BatchAckStatus::RejectedQuotaExceeded => {
                        transport_rpc::batch_ack::Status::RejectedQuotaExceeded as i32
                    }
                },
                retry_after_ms: ack.retry_after_ms,
                reason: ack.reason.clone().unwrap_or_default(),
                acked_at: ack.acked_at,
                accepted_events: ack.accepted_events,
                rejected_events: ack.rejected_events,
            })
        }
        DownlinkMessage::ServerCommand(command) => {
            transport_rpc::downlink_message::Kind::ServerCommand(
                transport_rpc::SignedServerCommand {
                    payload: command.payload.clone(),
                    signature: command.signature.clone(),
                    signing_key_id: command.signing_key_id.clone(),
                },
            )
        }
        DownlinkMessage::FlowControlHint(hint) => {
            transport_rpc::downlink_message::Kind::FlowHint(transport_rpc::FlowControlHint {
                pause_low_priority: hint.pause_low_priority,
                max_batch_events: hint.max_batch_events as u32,
                suggested_rate_eps: hint.suggested_rate_eps.unwrap_or_default(),
                cooldown_ms: hint.cooldown_ms.unwrap_or_default(),
                reason: hint.reason.clone().unwrap_or_default(),
            })
        }
    };
    transport_rpc::DownlinkMessage { kind: Some(kind) }
}

#[cfg(test)]
mod tests {
    use super::{
        decode_uplink_from_grpc, encode_downlink_for_grpc, transport_rpc, HttpRequestDecoration,
        HttpTransportDriver, TransportAgentContext, WebSocketTransportDriver,
    };
    use crate::comms::{CommunicationRuntime, TelemetryBatchBuilder, TransportDriver};
    use crate::config::{
        CommunicationConfig, DomainFrontingCommunicationConfig, GrpcCommunicationConfig,
        HttpPollingCommunicationConfig, WebSocketCommunicationConfig,
    };
    use aegis_model::{
        BatchAck, BatchAckStatus, CommunicationChannelKind, DownlinkMessage, EventPayload,
        EventType, HeartbeatRequest, NormalizedEvent, Priority, ProcessContext, Severity,
        TelemetryEvent, UplinkMessage,
    };
    use axum::body::Bytes;
    use axum::extract::State;
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::IntoResponse;
    use axum::routing::{get, post};
    use axum::Router;
    use futures_util::{SinkExt, Stream, StreamExt};
    use prost::Message as _;
    use std::collections::VecDeque;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::runtime::Handle;
    use tokio::sync::Mutex as AsyncMutex;
    use tokio_stream::wrappers::ReceiverStream;
    use tokio_tungstenite::accept_async;
    use tokio_tungstenite::tungstenite::Message;
    use tonic::{Request, Response, Status};
    use transport_rpc::agent_service_server::{AgentService, AgentServiceServer};
    use transport_rpc::{DownlinkMessage as ProtoDownlinkMessage, HeartbeatResponse};

    #[derive(Clone, Default)]
    struct TestTransportState {
        uplinks: Arc<AsyncMutex<Vec<UplinkMessage>>>,
        heartbeats: Arc<AsyncMutex<Vec<HeartbeatRequest>>>,
        downlinks: Arc<AsyncMutex<VecDeque<DownlinkMessage>>>,
    }

    #[derive(Clone, Default)]
    struct GrpcTransportService {
        state: TestTransportState,
    }

    type GrpcStream = Pin<Box<dyn Stream<Item = Result<ProtoDownlinkMessage, Status>> + Send>>;
    type UpdateStream =
        Pin<Box<dyn Stream<Item = Result<transport_rpc::UpdateChunk, Status>> + Send>>;

    #[tonic::async_trait]
    impl AgentService for GrpcTransportService {
        type EventStreamStream = GrpcStream;

        async fn event_stream(
            &self,
            request: Request<tonic::Streaming<transport_rpc::UplinkMessage>>,
        ) -> Result<Response<Self::EventStreamStream>, Status> {
            let state = self.state.clone();
            let mut inbound = request.into_inner();
            tokio::spawn(async move {
                while let Some(message) = inbound.next().await {
                    let message = message.expect("grpc frame");
                    let message = decode_uplink_from_grpc(message).expect("decode uplink");
                    state.uplinks.lock().await.push(message);
                }
            });

            let (tx, rx) = tokio::sync::mpsc::channel(8);
            let state = self.state.clone();
            tokio::spawn(async move {
                if let Some(message) = state.downlinks.lock().await.pop_front() {
                    let _ = tx.send(Ok(encode_downlink_for_grpc(&message))).await;
                }
            });

            Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
        }

        async fn heartbeat(
            &self,
            request: Request<transport_rpc::HeartbeatRequest>,
        ) -> Result<Response<HeartbeatResponse>, Status> {
            let state = self.state.clone();
            let heartbeat = request.into_inner();
            state.heartbeats.lock().await.push(HeartbeatRequest {
                tenant_id: heartbeat.tenant_id,
                agent_id: heartbeat.agent_id,
                health: serde_json::from_slice(&heartbeat.health_json).unwrap_or_else(|_| {
                    aegis_model::AgentHealth {
                        agent_version: String::new(),
                        policy_version: String::new(),
                        ruleset_version: String::new(),
                        model_version: String::new(),
                        cpu_percent_p95: 0.0,
                        memory_rss_mb: 0,
                        queue_depths: Default::default(),
                        dropped_events_total: 0,
                        lineage_counters: Default::default(),
                        runtime_signals: aegis_model::RuntimeHealthSignals {
                            communication_channel: CommunicationChannelKind::Grpc,
                            adaptive_whitelist_size: 0,
                            etw_tamper_detected: false,
                            amsi_tamper_detected: false,
                            bpf_integrity_pass: false,
                        },
                    }
                }),
                communication: serde_json::from_slice(&heartbeat.communication_json)
                    .unwrap_or_default(),
                wal_utilization_ratio: heartbeat.wal_utilization_ratio,
                restart_epoch: heartbeat.restart_epoch,
            });
            Ok(Response::new(HeartbeatResponse {
                server_time_ms: 1,
                pending_update_ids: Vec::new(),
                config_changed: false,
            }))
        }

        async fn upload_artifact(
            &self,
            _request: Request<tonic::Streaming<transport_rpc::ArtifactChunk>>,
        ) -> Result<Response<transport_rpc::UploadResult>, Status> {
            Ok(Response::new(transport_rpc::UploadResult {
                upload_id: "upload-test".to_string(),
                accepted_chunks: 1,
                accepted_bytes: 16,
                digest_hex: "digest".to_string(),
            }))
        }

        type PullUpdateStream = UpdateStream;

        async fn pull_update(
            &self,
            _request: Request<transport_rpc::UpdateRequest>,
        ) -> Result<Response<Self::PullUpdateStream>, Status> {
            let (_tx, rx) = tokio::sync::mpsc::channel(1);
            Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn grpc_transport_driver_sends_and_receives_frames() {
        let state = TestTransportState::default();
        state
            .downlinks
            .lock()
            .await
            .push_back(DownlinkMessage::BatchAck(BatchAck {
                batch_id: uuid::Uuid::now_v7(),
                sequence_id: 1,
                status: BatchAckStatus::Accepted,
                retry_after_ms: 0,
                reason: None,
                acked_at: 1,
                accepted_events: 1,
                rejected_events: 0,
            }));

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind grpc");
        let address = listener.local_addr().expect("grpc addr");
        let service = GrpcTransportService {
            state: state.clone(),
        };
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(AgentServiceServer::new(service))
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
                .expect("serve grpc");
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        let driver = super::GrpcTransportDriver::new(
            format!("http://{}", address),
            TransportAgentContext {
                tenant_id: "tenant-a".to_string(),
                agent_id: "agent-a".to_string(),
            },
            Handle::current(),
        );

        let uplink = sample_uplink();
        wait_until_ready(Duration::from_secs(2), || driver.probe()).await;
        driver.send_uplink(&uplink).expect("send uplink");
        tokio::time::sleep(Duration::from_millis(50)).await;
        let downlink = driver
            .recv_downlink()
            .expect("poll downlink")
            .expect("downlink exists");

        assert_eq!(state.uplinks.lock().await.len(), 1);
        assert!(matches!(downlink, DownlinkMessage::BatchAck(_)));

        server.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn websocket_transport_driver_sends_and_receives_frames() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind ws");
        let address = listener.local_addr().expect("ws addr");
        let uplinks = Arc::new(AsyncMutex::new(Vec::new()));
        let uplinks_task = Arc::clone(&uplinks);
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept ws");
            handle_ws_connection(stream, uplinks_task).await;
        });

        let driver =
            WebSocketTransportDriver::new(format!("ws://{}/ws", address), Handle::current());
        wait_until_ready(Duration::from_secs(1), || driver.probe()).await;
        driver
            .send_uplink(&sample_uplink())
            .expect("send ws uplink");
        tokio::time::sleep(Duration::from_millis(50)).await;
        let downlink = driver
            .recv_downlink()
            .expect("poll ws downlink")
            .expect("ws downlink exists");

        assert_eq!(uplinks.lock().await.len(), 1);
        assert!(matches!(downlink, DownlinkMessage::BatchAck(_)));

        server.abort();
    }

    #[test]
    fn http_transport_driver_respects_domain_fronting_headers() {
        let runtime = tokio::runtime::Runtime::new().expect("http runtime");
        let state = Arc::new(AsyncMutex::new(VecDeque::from([
            DownlinkMessage::BatchAck(BatchAck {
                batch_id: uuid::Uuid::now_v7(),
                sequence_id: 1,
                status: BatchAckStatus::Accepted,
                retry_after_ms: 0,
                reason: None,
                acked_at: 1,
                accepted_events: 1,
                rejected_events: 0,
            }),
        ])));
        let host_headers = Arc::new(AsyncMutex::new(Vec::new()));
        let host_headers_state = Arc::clone(&host_headers);
        let app_state = HttpTestState {
            downlinks: Arc::clone(&state),
            host_headers: host_headers_state,
        };
        let listener = runtime
            .block_on(async { TcpListener::bind("127.0.0.1:0").await })
            .expect("bind http");
        let address = listener.local_addr().expect("http addr");
        let app = Router::new()
            .route("/uplink", post(http_record_frame))
            .route("/heartbeat", post(http_record_frame))
            .route("/downlink", get(http_next_downlink))
            .route("/probe", get(http_probe))
            .with_state(app_state);
        let server = runtime.spawn(async move {
            axum::serve(listener, app).await.expect("serve http");
        });

        let endpoints = HttpPollingCommunicationConfig {
            enabled: true,
            uplink_url: format!("http://{}/uplink", address),
            heartbeat_url: format!("http://{}/heartbeat", address),
            downlink_url: format!("http://{}/downlink", address),
            probe_url: format!("http://{}/probe", address),
            timeout_ms: 2_000,
        };
        let driver = HttpTransportDriver::new(
            CommunicationChannelKind::DomainFronting,
            endpoints,
            HttpRequestDecoration {
                front_domain: Some("cdn.example.com".to_string()),
                host_header: Some("control-plane.aegis.local".to_string()),
            },
        )
        .expect("build http driver");

        driver.send_uplink(&sample_uplink()).expect("http uplink");
        let downlink = driver
            .recv_downlink()
            .expect("http recv")
            .expect("http downlink exists");

        assert!(driver.probe());
        assert!(matches!(downlink, DownlinkMessage::BatchAck(_)));
        let captured_headers = runtime.block_on(async { host_headers.lock().await.clone() });
        assert!(captured_headers
            .iter()
            .any(|header| header == "control-plane.aegis.local"));

        server.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn communication_runtime_builds_from_config_without_loopback() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind grpc");
        let address = listener.local_addr().expect("grpc addr");
        let service = GrpcTransportService::default();
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(AgentServiceServer::new(service))
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
                .expect("serve grpc");
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        let config = CommunicationConfig {
            failure_threshold: 2,
            development_allow_loopback: false,
            grpc: GrpcCommunicationConfig {
                enabled: true,
                endpoint: format!("http://{}", address),
            },
            websocket: WebSocketCommunicationConfig {
                enabled: false,
                endpoint: "ws://127.0.0.1:7444/ws".to_string(),
            },
            long_polling: HttpPollingCommunicationConfig {
                enabled: false,
                ..HttpPollingCommunicationConfig::default()
            },
            domain_fronting: DomainFrontingCommunicationConfig {
                enabled: false,
                ..DomainFrontingCommunicationConfig::default()
            },
        };
        let mut runtime = CommunicationRuntime::from_config(
            &config,
            &TransportAgentContext {
                tenant_id: "tenant-a".to_string(),
                agent_id: "agent-a".to_string(),
            },
        )
        .expect("build runtime");
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut channel = None;
        for _ in 0..20 {
            match runtime.send_uplink(&sample_uplink(), 1) {
                Ok(active_channel) => {
                    channel = Some(active_channel);
                    break;
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
        let channel = channel.expect("send via config runtime");
        assert_eq!(channel, CommunicationChannelKind::Grpc);
        assert!(runtime
            .loopback_handle(CommunicationChannelKind::Grpc)
            .is_none());

        server.abort();
    }

    async fn handle_ws_connection(stream: TcpStream, uplinks: Arc<AsyncMutex<Vec<UplinkMessage>>>) {
        let websocket = accept_async(stream).await.expect("accept websocket");
        let (mut sink, mut source) = websocket.split();
        if let Some(message) = source.next().await {
            let message = message.expect("read websocket");
            let bytes = message.into_data();
            let bundle = transport_rpc::ClientTransportBundle::decode(bytes.as_ref())
                .expect("decode ws bundle");
            for envelope in bundle.messages {
                let kind = envelope.kind.expect("client envelope kind");
                if let transport_rpc::client_transport_envelope::Kind::UplinkMessage(message) = kind
                {
                    let message = decode_uplink_from_grpc(message).expect("decode ws uplink");
                    uplinks.lock().await.push(message);
                }
            }
        }
        let downlink = DownlinkMessage::BatchAck(BatchAck {
            batch_id: uuid::Uuid::now_v7(),
            sequence_id: 1,
            status: BatchAckStatus::Accepted,
            retry_after_ms: 0,
            reason: None,
            acked_at: 1,
            accepted_events: 1,
            rejected_events: 0,
        });
        let bundle = transport_rpc::ServerTransportBundle {
            messages: vec![transport_rpc::ServerTransportEnvelope {
                kind: Some(
                    transport_rpc::server_transport_envelope::Kind::DownlinkMessage(
                        encode_downlink_for_grpc(&downlink),
                    ),
                ),
            }],
        };
        let mut bytes = Vec::new();
        bundle.encode(&mut bytes).expect("encode ws downlink");
        sink.send(Message::Binary(bytes))
            .await
            .expect("write websocket");
    }

    async fn wait_until_ready<F>(timeout: Duration, mut ready: F)
    where
        F: FnMut() -> bool,
    {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if ready() {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "transport did not become ready within {:?}",
                timeout
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    #[derive(Clone)]
    struct HttpTestState {
        downlinks: Arc<AsyncMutex<VecDeque<DownlinkMessage>>>,
        host_headers: Arc<AsyncMutex<Vec<String>>>,
    }

    async fn http_record_frame(
        State(state): State<HttpTestState>,
        headers: HeaderMap,
        body: Bytes,
    ) -> impl IntoResponse {
        if let Some(host) = headers.get("host") {
            state
                .host_headers
                .lock()
                .await
                .push(host.to_str().unwrap_or_default().to_string());
        }
        let bundle = transport_rpc::ClientTransportBundle::decode(body.as_ref())
            .expect("decode http client bundle");
        assert!(!bundle.messages.is_empty(), "bundle should not be empty");
        let downlink = DownlinkMessage::BatchAck(BatchAck {
            batch_id: uuid::Uuid::now_v7(),
            sequence_id: 7,
            status: BatchAckStatus::Accepted,
            retry_after_ms: 0,
            reason: None,
            acked_at: 7,
            accepted_events: 1,
            rejected_events: 0,
        });
        let response = transport_rpc::ServerTransportBundle {
            messages: vec![transport_rpc::ServerTransportEnvelope {
                kind: Some(
                    transport_rpc::server_transport_envelope::Kind::DownlinkMessage(
                        encode_downlink_for_grpc(&downlink),
                    ),
                ),
            }],
        };
        let mut bytes = Vec::new();
        response.encode(&mut bytes).expect("encode http response");
        (StatusCode::OK, bytes).into_response()
    }

    async fn http_next_downlink(
        State(state): State<HttpTestState>,
        headers: HeaderMap,
    ) -> impl IntoResponse {
        if let Some(host) = headers.get("host") {
            state
                .host_headers
                .lock()
                .await
                .push(host.to_str().unwrap_or_default().to_string());
        }
        let maybe = state.downlinks.lock().await.pop_front();
        match maybe {
            Some(message) => {
                let response = transport_rpc::ServerTransportBundle {
                    messages: vec![transport_rpc::ServerTransportEnvelope {
                        kind: Some(
                            transport_rpc::server_transport_envelope::Kind::DownlinkMessage(
                                encode_downlink_for_grpc(&message),
                            ),
                        ),
                    }],
                };
                let mut bytes = Vec::new();
                response.encode(&mut bytes).expect("encode downlink bundle");
                (StatusCode::OK, bytes).into_response()
            }
            None => StatusCode::NO_CONTENT.into_response(),
        }
    }

    async fn http_probe(
        State(state): State<HttpTestState>,
        headers: HeaderMap,
    ) -> impl IntoResponse {
        if let Some(host) = headers.get("host") {
            state
                .host_headers
                .lock()
                .await
                .push(host.to_str().unwrap_or_default().to_string());
        }
        let _ = state;
        StatusCode::OK
    }

    fn sample_uplink() -> UplinkMessage {
        let event = TelemetryEvent::from_normalized(
            &NormalizedEvent::new(
                1,
                EventType::ProcessCreate,
                Priority::Normal,
                Severity::Low,
                ProcessContext::default(),
                EventPayload::None,
            ),
            "tenant-a".to_string(),
            "agent-a".to_string(),
        );
        TelemetryBatchBuilder::new(4)
            .build("tenant-a", "agent-a", 1, vec![event])
            .expect("build sample uplink")
    }
}
#[cfg(test)]
use serde::de::DeserializeOwned;
