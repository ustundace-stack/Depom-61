pub mod engine;
pub mod rules;
pub mod report;

pub use engine::ScanEngine;
pub use report::{ScanReport, ScanEntry, ScanVerdict};
pub use rules::RuleSet;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub dry_run: bool,
    pub quarantine_dir: PathBuf,
    pub max_file_size_mb: u64,
    pub whitelist: Vec<String>,
    pub blacklist: Vec<String>,
    pub recursive: bool,
    pub scan_hidden: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            dry_run: true,
            quarantine_dir: PathBuf::from("/tmp/quarantine"),
            max_file_size_mb: 512,
            whitelist: vec![
                "*.log".into(),
                "*.txt".into(),
                "*.md".into(),
                "*.json".into(),
                "*.toml".into(),
                "*.yaml".into(),
                "*.yml".into(),
            ],
            blacklist: vec![
                "*.exe".into(),
                "*.bat".into(),
                "*.cmd".into(),
                "*.vbs".into(),
                "*.ps1".into(),
                "*.sh".into(),
                "*.dll".into(),
                "*.so".into(),
                "*.bin".into(),
                "*.enc".into(),
                "*.locked".into(),
                "*.crypto".into(),
                "*.ransom".into(),
            ],
            recursive: true,
            scan_hidden: false,
        }
    }
}
