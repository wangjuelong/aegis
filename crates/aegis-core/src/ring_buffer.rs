use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

#[derive(
    Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
pub enum LanePriority {
    Critical,
    High,
    #[default]
    Normal,
    Low,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LaneCapacities {
    pub critical: usize,
    pub high: usize,
    pub normal: usize,
    pub low: usize,
}

impl Default for LaneCapacities {
    fn default() -> Self {
        Self {
            critical: 1_024,
            high: 8_192,
            normal: 32_768,
            low: 16_384,
        }
    }
}

pub struct FourLaneBuffer<T> {
    critical: VecDeque<T>,
    high: VecDeque<T>,
    normal: VecDeque<T>,
    low: VecDeque<T>,
    capacities: LaneCapacities,
}

impl<T> FourLaneBuffer<T> {
    pub fn new(capacities: LaneCapacities) -> Self {
        Self {
            critical: VecDeque::with_capacity(capacities.critical),
            high: VecDeque::with_capacity(capacities.high),
            normal: VecDeque::with_capacity(capacities.normal),
            low: VecDeque::with_capacity(capacities.low),
            capacities,
        }
    }

    pub fn push(&mut self, lane: LanePriority, item: T) -> Option<T> {
        let capacity = self.capacity(lane);
        let queue = self.queue_mut(lane);
        if queue.len() >= capacity {
            return Some(item);
        }
        queue.push_back(item);
        None
    }

    pub fn drain_next(&mut self) -> Option<(LanePriority, T)> {
        if let Some(item) = self.critical.pop_front() {
            return Some((LanePriority::Critical, item));
        }
        if let Some(item) = self.high.pop_front() {
            return Some((LanePriority::High, item));
        }
        if let Some(item) = self.normal.pop_front() {
            return Some((LanePriority::Normal, item));
        }
        self.low.pop_front().map(|item| (LanePriority::Low, item))
    }

    pub fn pending(&self, lane: LanePriority) -> usize {
        self.queue(lane).len()
    }

    pub fn total_pending(&self) -> usize {
        self.critical.len() + self.high.len() + self.normal.len() + self.low.len()
    }

    pub fn capacity(&self, lane: LanePriority) -> usize {
        match lane {
            LanePriority::Critical => self.capacities.critical,
            LanePriority::High => self.capacities.high,
            LanePriority::Normal => self.capacities.normal,
            LanePriority::Low => self.capacities.low,
        }
    }

    fn queue(&self, lane: LanePriority) -> &VecDeque<T> {
        match lane {
            LanePriority::Critical => &self.critical,
            LanePriority::High => &self.high,
            LanePriority::Normal => &self.normal,
            LanePriority::Low => &self.low,
        }
    }

    fn queue_mut(&mut self, lane: LanePriority) -> &mut VecDeque<T> {
        match lane {
            LanePriority::Critical => &mut self.critical,
            LanePriority::High => &mut self.high,
            LanePriority::Normal => &mut self.normal,
            LanePriority::Low => &mut self.low,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{FourLaneBuffer, LaneCapacities, LanePriority};

    #[test]
    fn drains_higher_priority_before_lower_priority() {
        let mut buffer = FourLaneBuffer::new(LaneCapacities {
            critical: 1,
            high: 1,
            normal: 1,
            low: 1,
        });

        buffer.push(LanePriority::Low, "low");
        buffer.push(LanePriority::Critical, "critical");

        assert_eq!(
            buffer.drain_next(),
            Some((LanePriority::Critical, "critical"))
        );
        assert_eq!(buffer.drain_next(), Some((LanePriority::Low, "low")));
    }
}
