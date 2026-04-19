use crate::error::CoreError;
use crate::ring_buffer::LanePriority;
use serde::{de::DeserializeOwned, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

pub struct SpillStore {
    root: PathBuf,
}

impl SpillStore {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, CoreError> {
        let root = root.into();
        std::fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    pub fn append<T: Serialize>(
        &self,
        lane: LanePriority,
        record: &T,
    ) -> Result<PathBuf, CoreError> {
        let path = self.file_path(lane);
        let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
        serde_json::to_writer(&mut file, record)?;
        writeln!(file)?;
        Ok(path)
    }

    pub fn drain<T: DeserializeOwned>(&self, lane: LanePriority) -> Result<Vec<T>, CoreError> {
        let path = self.file_path(lane);
        if !path.exists() {
            return Ok(Vec::new());
        }

        let file = File::open(&path)?;
        let reader = BufReader::new(file);
        let mut records = Vec::new();
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            records.push(serde_json::from_str::<T>(&line)?);
        }

        std::fs::remove_file(&path)?;
        Ok(records)
    }

    pub fn pending_records(&self, lane: LanePriority) -> Result<usize, CoreError> {
        let path = self.file_path(lane);
        if !path.exists() {
            return Ok(0);
        }

        let file = File::open(path)?;
        let reader = BufReader::new(file);
        Ok(reader.lines().count())
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn file_path(&self, lane: LanePriority) -> PathBuf {
        self.root.join(format!("{}.jsonl", lane.as_str()))
    }
}

impl LanePriority {
    pub fn as_str(self) -> &'static str {
        match self {
            LanePriority::Critical => "critical",
            LanePriority::High => "high",
            LanePriority::Normal => "normal",
            LanePriority::Low => "low",
        }
    }
}
