use crate::error::CoreError;
use crate::ring_buffer::{FourLaneBuffer, LanePriority};
use crate::spill::SpillStore;
use aegis_model::{
    ContainerContext, EventEnrichment, EventPayload, EventType, HostContext, LineageCheckpoint,
    NormalizedEvent, Priority, ProcessContext, Severity, StorylineContext, SyscallOrigin,
};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RawSensorEvent {
    pub lane: LanePriority,
    pub timestamp_ns: u64,
    pub event_type: EventType,
    pub priority: Priority,
    pub severity: Severity,
    pub process: ProcessContext,
    pub payload: EventPayload,
    pub host: Option<HostContext>,
    pub container: Option<ContainerContext>,
    pub storyline: Option<StorylineContext>,
    pub enrichment: Option<EventEnrichment>,
    pub syscall_origin: Option<SyscallOrigin>,
}

pub struct SensorDispatch {
    spill_store: SpillStore,
}

impl SensorDispatch {
    pub fn new(spill_root: impl AsRef<Path>) -> Result<Self, CoreError> {
        Ok(Self {
            spill_store: SpillStore::new(spill_root.as_ref())?,
        })
    }

    pub fn enqueue(
        &self,
        buffer: &mut FourLaneBuffer<RawSensorEvent>,
        raw: RawSensorEvent,
    ) -> Result<bool, CoreError> {
        if let Some(spilled) = buffer.push(raw.lane, raw) {
            self.spill_store.append(spilled.lane, &spilled)?;
            return Ok(true);
        }
        Ok(false)
    }

    pub fn drain_next(
        &self,
        buffer: &mut FourLaneBuffer<RawSensorEvent>,
    ) -> Result<Option<NormalizedEvent>, CoreError> {
        let Some((_lane, raw)) = buffer.drain_next() else {
            return Ok(None);
        };
        Ok(Some(self.decode(raw)))
    }

    pub fn recover_spill(
        &self,
        buffer: &mut FourLaneBuffer<RawSensorEvent>,
        lane: LanePriority,
    ) -> Result<usize, CoreError> {
        let records = self.spill_store.drain::<RawSensorEvent>(lane)?;
        let mut recovered = 0usize;
        for record in records {
            if buffer.push(record.lane, record).is_some() {
                break;
            }
            recovered += 1;
        }
        Ok(recovered)
    }

    pub fn spill_store(&self) -> &SpillStore {
        &self.spill_store
    }

    fn decode(&self, raw: RawSensorEvent) -> NormalizedEvent {
        let mut event = NormalizedEvent::new(
            raw.timestamp_ns,
            raw.event_type,
            raw.priority,
            raw.severity,
            raw.process,
            raw.payload,
        );
        if let Some(host) = raw.host {
            event.host = host;
        }
        event.container = raw.container;
        event.storyline = raw.storyline;
        event.enrichment = raw.enrichment.unwrap_or_default();
        event.syscall_origin = raw.syscall_origin;
        event
            .lineage
            .push(LineageCheckpoint::RingBufferConsumed, 1, raw.timestamp_ns);
        event
    }
}

#[cfg(test)]
mod tests {
    use super::{RawSensorEvent, SensorDispatch};
    use crate::ring_buffer::{FourLaneBuffer, LaneCapacities, LanePriority};
    use aegis_model::{EventPayload, EventType, Priority, ProcessContext, Severity};
    use std::path::PathBuf;
    use uuid::Uuid;

    fn temp_spill_root() -> PathBuf {
        std::env::temp_dir().join(format!("aegis-spill-{}", Uuid::now_v7()))
    }

    fn raw_event(lane: LanePriority, priority: Priority, ts: u64) -> RawSensorEvent {
        RawSensorEvent {
            lane,
            timestamp_ns: ts,
            event_type: EventType::ProcessCreate,
            priority,
            severity: Severity::Info,
            process: ProcessContext::default(),
            payload: EventPayload::None,
            host: None,
            container: None,
            storyline: None,
            enrichment: None,
            syscall_origin: None,
        }
    }

    #[test]
    fn dispatch_drains_higher_priority_event_first() {
        let spill_root = temp_spill_root();
        let dispatch = SensorDispatch::new(&spill_root).expect("create dispatch");
        let mut buffer = FourLaneBuffer::new(LaneCapacities {
            critical: 2,
            high: 2,
            normal: 2,
            low: 2,
        });

        dispatch
            .enqueue(
                &mut buffer,
                raw_event(LanePriority::Low, Priority::Low, 100),
            )
            .expect("enqueue low");
        dispatch
            .enqueue(
                &mut buffer,
                raw_event(LanePriority::Critical, Priority::Critical, 101),
            )
            .expect("enqueue critical");

        let first = dispatch
            .drain_next(&mut buffer)
            .expect("drain")
            .expect("first event");
        assert_eq!(first.priority, Priority::Critical);

        std::fs::remove_dir_all(spill_root).ok();
    }

    #[test]
    fn overflow_is_spilled_and_can_be_recovered() {
        let spill_root = temp_spill_root();
        let dispatch = SensorDispatch::new(&spill_root).expect("create dispatch");
        let mut buffer = FourLaneBuffer::new(LaneCapacities {
            critical: 1,
            high: 1,
            normal: 1,
            low: 1,
        });

        let first_spilled = dispatch
            .enqueue(
                &mut buffer,
                raw_event(LanePriority::Normal, Priority::Normal, 200),
            )
            .expect("enqueue first");
        let second_spilled = dispatch
            .enqueue(
                &mut buffer,
                raw_event(LanePriority::Normal, Priority::Normal, 201),
            )
            .expect("enqueue second");

        assert!(!first_spilled);
        assert!(second_spilled);
        assert_eq!(
            dispatch
                .spill_store()
                .pending_records(LanePriority::Normal)
                .expect("pending spill"),
            1
        );

        let drained = dispatch
            .drain_next(&mut buffer)
            .expect("drain queued")
            .expect("queued event");
        assert_eq!(drained.timestamp_ns, 200);

        let recovered = dispatch
            .recover_spill(&mut buffer, LanePriority::Normal)
            .expect("recover spill");
        assert_eq!(recovered, 1);

        let recovered_event = dispatch
            .drain_next(&mut buffer)
            .expect("drain recovered")
            .expect("recovered event");
        assert_eq!(recovered_event.timestamp_ns, 201);

        std::fs::remove_dir_all(spill_root).ok();
    }
}
