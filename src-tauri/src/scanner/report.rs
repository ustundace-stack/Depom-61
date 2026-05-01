use crate::scanner::rules::{MatchedRule, Severity};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanVerdict {
    Clean,
    Suspicious,
    Quarantined,
    Skipped,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanEntry {
    pub path: PathBuf,
    pub sha256: String,
    pub size_bytes: u64,
    pub verdict: ScanVerdict,
    pub severity: Option<Severity>,
    pub matched_rules: Vec<MatchedRule>,
    pub entropy: f64,
    pub magic_hit: Option<String>,
    pub quarantine_path: Option<PathBuf>,
    pub dry_run: bool,
    pub cot_trace: Vec<String>,
    pub scanned_at: DateTime<Utc>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub scan_id: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub dry_run: bool,
    pub target_path: PathBuf,
    pub total_files: usize,
    pub clean: usize,
    pub suspicious: usize,
    pub quarantined: usize,
    pub skipped: usize,
    pub errors: usize,
    pub entries: Vec<ScanEntry>,
}

impl ScanReport {
    pub fn new(scan_id: String, target: PathBuf, dry_run: bool) -> Self {
        Self {
            scan_id,
            started_at: Utc::now(),
            finished_at: None,
            dry_run,
            target_path: target,
            total_files: 0,
            clean: 0,
            suspicious: 0,
            quarantined: 0,
            skipped: 0,
            errors: 0,
            entries: Vec::new(),
        }
    }

    pub fn push(&mut self, entry: ScanEntry) {
        match entry.verdict {
            ScanVerdict::Clean => self.clean += 1,
            ScanVerdict::Suspicious => self.suspicious += 1,
            ScanVerdict::Quarantined => self.quarantined += 1,
            ScanVerdict::Skipped => self.skipped += 1,
            ScanVerdict::Error => self.errors += 1,
        }
        self.total_files += 1;
        self.entries.push(entry);
    }

    pub fn finalize(&mut self) {
        self.finished_at = Some(Utc::now());
    }
}
