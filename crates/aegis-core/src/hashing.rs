use crate::error::CoreError;
use sha2::Digest;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileHashes {
    pub sha256: String,
    pub blake3: Option<String>,
    pub bytes_processed: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CachedHash {
    path: PathBuf,
    hashes: FileHashes,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HashingPolicy {
    pub blake3_prefilter_threshold_bytes: u64,
    pub cache_capacity: usize,
}

impl Default for HashingPolicy {
    fn default() -> Self {
        Self {
            blake3_prefilter_threshold_bytes: 16 * 1024 * 1024,
            cache_capacity: 10_000,
        }
    }
}

#[derive(Default)]
pub struct HashCache {
    entries: HashMap<PathBuf, CachedHash>,
}

impl HashCache {
    pub fn compute_file(
        &mut self,
        path: &Path,
        policy: &HashingPolicy,
    ) -> Result<FileHashes, CoreError> {
        if let Some(entry) = self.entries.get(path) {
            return Ok(entry.hashes.clone());
        }

        let mut file = File::open(path)?;
        let mut sha256 = sha2::Sha256::new();
        let mut blake3_hasher = blake3::Hasher::new();
        let mut buffer = [0u8; 8192];
        let mut bytes_processed = 0u64;

        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            let chunk = &buffer[..read];
            sha2::Digest::update(&mut sha256, chunk);
            bytes_processed += read as u64;
            if bytes_processed <= policy.blake3_prefilter_threshold_bytes {
                blake3_hasher.update(chunk);
            }
        }

        let hashes = FileHashes {
            sha256: hex::encode(sha256.finalize()),
            blake3: if bytes_processed <= policy.blake3_prefilter_threshold_bytes {
                Some(blake3_hasher.finalize().to_hex().to_string())
            } else {
                None
            },
            bytes_processed,
        };
        self.insert_cache(path.to_path_buf(), hashes.clone(), policy.cache_capacity);
        Ok(hashes)
    }

    fn insert_cache(&mut self, path: PathBuf, hashes: FileHashes, cache_capacity: usize) {
        if self.entries.len() >= cache_capacity {
            if let Some(first_key) = self.entries.keys().next().cloned() {
                self.entries.remove(&first_key);
            }
        }

        self.entries
            .insert(path.clone(), CachedHash { path, hashes });
    }
}

#[cfg(test)]
mod tests {
    use super::{HashCache, HashingPolicy};
    use std::io::Write;
    use uuid::Uuid;

    #[test]
    fn computes_and_caches_file_hashes() {
        let path = std::env::temp_dir().join(format!("aegis-hash-{}.bin", Uuid::now_v7()));
        let mut file = std::fs::File::create(&path).expect("create temp file");
        file.write_all(b"hello-aegis").expect("write temp file");

        let mut cache = HashCache::default();
        let first = cache
            .compute_file(&path, &HashingPolicy::default())
            .expect("compute hash");
        let second = cache
            .compute_file(&path, &HashingPolicy::default())
            .expect("reuse hash");

        assert_eq!(first.sha256, second.sha256);
        assert!(first.blake3.is_some());

        std::fs::remove_file(path).ok();
    }
}
