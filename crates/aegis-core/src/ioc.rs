use std::collections::{BTreeMap, HashSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IndicatorRisk {
    Low,
    Medium,
    High,
    Critical,
}

impl IndicatorRisk {
    fn descending() -> [Self; 4] {
        [Self::Critical, Self::High, Self::Medium, Self::Low]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IndicatorKind {
    Sha256,
    Domain,
    Ip,
    Path,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Indicator {
    pub kind: IndicatorKind,
    pub value: String,
}

impl Indicator {
    pub fn new(kind: IndicatorKind, value: impl Into<String>) -> Self {
        Self {
            kind,
            value: value.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IocHit {
    pub indicator: Indicator,
    pub risk: IndicatorRisk,
}

#[derive(Clone, Debug)]
struct BloomFilter {
    words: Vec<u64>,
    bit_len: usize,
}

impl BloomFilter {
    fn new(bit_len: usize) -> Self {
        let aligned_bits = bit_len.max(64).next_multiple_of(64);
        Self {
            words: vec![0; aligned_bits / 64],
            bit_len: aligned_bits,
        }
    }

    fn insert(&mut self, indicator: &Indicator) {
        for position in self.positions(indicator) {
            let word = position / 64;
            let bit = position % 64;
            self.words[word] |= 1u64 << bit;
        }
    }

    fn may_match(&self, indicator: &Indicator) -> bool {
        self.positions(indicator).into_iter().all(|position| {
            let word = position / 64;
            let bit = position % 64;
            (self.words[word] & (1u64 << bit)) != 0
        })
    }

    fn positions(&self, indicator: &Indicator) -> [usize; 2] {
        let fingerprint = format!("{:?}|{}", indicator.kind, indicator.value);
        let primary = blake3::hash(fingerprint.as_bytes());
        let secondary = blake3::hash(format!("{fingerprint}|secondary").as_bytes());
        [primary, secondary].map(|hash| {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&hash.as_bytes()[..8]);
            (u64::from_le_bytes(bytes) as usize) % self.bit_len
        })
    }
}

#[derive(Clone, Debug)]
struct IndicatorTier {
    bloom: BloomFilter,
    cuckoo_exact: HashSet<Indicator>,
}

impl IndicatorTier {
    fn new(bit_len: usize) -> Self {
        Self {
            bloom: BloomFilter::new(bit_len),
            cuckoo_exact: HashSet::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct TieredIndicatorIndex {
    tiers: BTreeMap<IndicatorRisk, IndicatorTier>,
}

impl Default for TieredIndicatorIndex {
    fn default() -> Self {
        Self {
            tiers: BTreeMap::from([
                (IndicatorRisk::Low, IndicatorTier::new(256)),
                (IndicatorRisk::Medium, IndicatorTier::new(256)),
                (IndicatorRisk::High, IndicatorTier::new(256)),
                (IndicatorRisk::Critical, IndicatorTier::new(256)),
            ]),
        }
    }
}

impl TieredIndicatorIndex {
    pub fn insert(&mut self, risk: IndicatorRisk, indicator: Indicator) {
        if let Some(tier) = self.tiers.get_mut(&risk) {
            tier.bloom.insert(&indicator);
            tier.cuckoo_exact.insert(indicator);
        }
    }

    pub fn match_candidates(&self, candidates: &[Indicator]) -> Vec<IocHit> {
        let mut hits = Vec::new();

        for risk in IndicatorRisk::descending() {
            let Some(tier) = self.tiers.get(&risk) else {
                continue;
            };

            for candidate in candidates {
                if tier.bloom.may_match(candidate) && tier.cuckoo_exact.contains(candidate) {
                    hits.push(IocHit {
                        indicator: candidate.clone(),
                        risk,
                    });
                }
            }
        }

        hits
    }
}

#[cfg(test)]
mod tests {
    use super::{Indicator, IndicatorKind, IndicatorRisk, TieredIndicatorIndex};

    #[test]
    fn tiered_index_returns_hits_in_risk_order() {
        let mut index = TieredIndicatorIndex::default();
        index.insert(
            IndicatorRisk::High,
            Indicator::new(IndicatorKind::Domain, "bad.example"),
        );
        index.insert(
            IndicatorRisk::Low,
            Indicator::new(IndicatorKind::Ip, "10.0.0.7"),
        );

        let hits = index.match_candidates(&[
            Indicator::new(IndicatorKind::Ip, "10.0.0.7"),
            Indicator::new(IndicatorKind::Domain, "bad.example"),
        ]);

        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].risk, IndicatorRisk::High);
        assert_eq!(hits[1].risk, IndicatorRisk::Low);
    }

    #[test]
    fn tiered_index_requires_exact_confirmation_after_bloom_match() {
        let mut index = TieredIndicatorIndex::default();
        index.insert(
            IndicatorRisk::Critical,
            Indicator::new(IndicatorKind::Sha256, "deadbeef"),
        );

        let hits = index.match_candidates(&[Indicator::new(IndicatorKind::Sha256, "beadfeed")]);

        assert!(hits.is_empty());
    }
}
