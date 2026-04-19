use aegis_model::Priority;
use std::collections::{HashMap, HashSet, VecDeque};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum YaraScanTarget {
    FilePath(String),
    Content(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct YaraJob {
    pub job_id: Uuid,
    pub target: YaraScanTarget,
    pub submitted_at_ns: u64,
    pub priority: Priority,
    pub cache_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct YaraMatch {
    pub rule_name: String,
    pub tags: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct YaraResult {
    pub cache_key: String,
    pub matches: Vec<YaraMatch>,
    pub scanned_at_ns: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnqueueDisposition {
    Queued(Uuid),
    Cached,
    DuplicatePending,
}

#[derive(Clone, Debug, Default)]
pub struct YaraScheduler {
    queue: VecDeque<YaraJob>,
    cache: HashMap<String, YaraResult>,
    pending_keys: HashSet<String>,
}

impl YaraScheduler {
    pub fn enqueue(
        &mut self,
        target: YaraScanTarget,
        submitted_at_ns: u64,
        priority: Priority,
    ) -> EnqueueDisposition {
        let cache_key = cache_key(&target);
        if self.cache.contains_key(&cache_key) {
            return EnqueueDisposition::Cached;
        }
        if !self.pending_keys.insert(cache_key.clone()) {
            return EnqueueDisposition::DuplicatePending;
        }

        let job = YaraJob {
            job_id: Uuid::now_v7(),
            target,
            submitted_at_ns,
            priority,
            cache_key: cache_key.clone(),
        };
        let job_id = job.job_id;
        self.queue.push_back(job);
        EnqueueDisposition::Queued(job_id)
    }

    pub fn pop_next(&mut self) -> Option<YaraJob> {
        self.queue.pop_front()
    }

    pub fn complete(&mut self, job: &YaraJob, result: YaraResult) {
        self.pending_keys.remove(&job.cache_key);
        self.cache.insert(job.cache_key.clone(), result);
    }

    pub fn cached(&self, target: &YaraScanTarget) -> Option<&YaraResult> {
        self.cache.get(&cache_key(target))
    }
}

pub fn cache_key(target: &YaraScanTarget) -> String {
    let seed = match target {
        YaraScanTarget::FilePath(path) => format!("path|{path}"),
        YaraScanTarget::Content(content) => format!("content|{content}"),
    };
    blake3::hash(seed.as_bytes()).to_hex().to_string()
}

#[cfg(test)]
mod tests {
    use super::{EnqueueDisposition, YaraMatch, YaraResult, YaraScanTarget, YaraScheduler};
    use aegis_model::Priority;

    #[test]
    fn yara_scheduler_caches_completed_targets() {
        let mut scheduler = YaraScheduler::default();
        let disposition = scheduler.enqueue(
            YaraScanTarget::Content("IEX(New-Object Net.WebClient)".to_string()),
            10,
            Priority::High,
        );

        let EnqueueDisposition::Queued(_) = disposition else {
            panic!("job should be queued");
        };
        let job = scheduler.pop_next().expect("queued job");
        scheduler.complete(
            &job,
            YaraResult {
                cache_key: job.cache_key.clone(),
                matches: vec![YaraMatch {
                    rule_name: "SuspiciousPowerShell".to_string(),
                    tags: vec!["script".to_string()],
                }],
                scanned_at_ns: 11,
            },
        );

        let second = scheduler.enqueue(
            YaraScanTarget::Content("IEX(New-Object Net.WebClient)".to_string()),
            12,
            Priority::High,
        );

        assert_eq!(second, EnqueueDisposition::Cached);
        assert_eq!(
            scheduler
                .cached(&YaraScanTarget::Content(
                    "IEX(New-Object Net.WebClient)".to_string()
                ))
                .expect("cached result")
                .matches
                .len(),
            1
        );
    }

    #[test]
    fn yara_scheduler_deduplicates_pending_targets() {
        let mut scheduler = YaraScheduler::default();
        let first = scheduler.enqueue(
            YaraScanTarget::FilePath("/tmp/payload.bin".to_string()),
            20,
            Priority::Normal,
        );
        let second = scheduler.enqueue(
            YaraScanTarget::FilePath("/tmp/payload.bin".to_string()),
            21,
            Priority::Normal,
        );

        assert!(matches!(first, EnqueueDisposition::Queued(_)));
        assert_eq!(second, EnqueueDisposition::DuplicatePending);
    }
}
