use crate::scanner::{
    report::{ScanEntry, ScanReport, ScanVerdict},
    rules::{RuleSet, Severity, HIGH_ENTROPY_THRESHOLD},
    ScanConfig,
};
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
};
use thiserror::Error;
use uuid::Uuid;
use walkdir::WalkDir;

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("I/O error at {path}: {source}")]
    Io { path: PathBuf, source: io::Error },

    #[error("Quarantine failed for {path}: {reason}")]
    Quarantine { path: PathBuf, reason: String },

    #[error("Permission denied: {0}")]
    PermissionDenied(PathBuf),
}

pub struct ScanEngine {
    config: ScanConfig,
    rules: RuleSet,
}

impl ScanEngine {
    pub fn new(config: ScanConfig) -> Self {
        Self {
            config,
            rules: RuleSet::default_set(),
        }
    }

    /// Entry point: walk `target`, classify and optionally quarantine each file.
    pub fn run(&self, target: &Path) -> ScanReport {
        let scan_id = Uuid::new_v4().to_string();
        let mut report = ScanReport::new(scan_id, target.to_path_buf(), self.config.dry_run);

        let walker = WalkDir::new(target)
            .max_depth(if self.config.recursive { usize::MAX } else { 1 })
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| {
                if !self.config.scan_hidden {
                    !e.file_name()
                        .to_str()
                        .map(|s| s.starts_with('.'))
                        .unwrap_or(false)
                } else {
                    true
                }
            });

        for result in walker {
            match result {
                Err(e) => {
                    let entry = self.error_entry(
                        PathBuf::from(e.path().unwrap_or(Path::new("<unknown>"))),
                        e.to_string(),
                    );
                    report.push(entry);
                }
                Ok(dir_entry) => {
                    if dir_entry.file_type().is_dir() {
                        continue;
                    }
                    let entry = self.scan_file(dir_entry.path());
                    report.push(entry);
                }
            }
        }

        report.finalize();
        report
    }

    /// Full CoT pipeline for a single file.
    fn scan_file(&self, path: &Path) -> ScanEntry {
        let mut cot: Vec<String> = Vec::new();
        cot.push(format!("[CoT:1] Target: {}", path.display()));

        // --- Step 1: Metadata ---
        let meta = match fs::metadata(path) {
            Err(e) => {
                return self.error_entry(path.to_path_buf(), e.to_string());
            }
            Ok(m) => m,
        };
        let size_bytes = meta.len();
        let max_bytes = self.config.max_file_size_mb * 1024 * 1024;
        cot.push(format!("[CoT:2] Size={} bytes, limit={}", size_bytes, max_bytes));

        if size_bytes > max_bytes {
            cot.push("[CoT:3] SKIP: exceeds size limit".into());
            return self.skipped_entry(path.to_path_buf(), size_bytes, cot);
        }

        // --- Step 2: Extension filter ---
        let ext_str = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|s| format!(".{}", s.to_lowercase()))
            .unwrap_or_default();

        cot.push(format!("[CoT:3] Extension={}", ext_str));

        if self.matches_glob(&ext_str, &self.config.whitelist) {
            cot.push("[CoT:4] WHITELIST hit → skip deep scan".into());
            let sha = self.hash_file(path).unwrap_or_default();
            return ScanEntry {
                path: path.to_path_buf(),
                sha256: sha,
                size_bytes,
                verdict: ScanVerdict::Clean,
                severity: None,
                matched_rules: vec![],
                entropy: 0.0,
                magic_hit: None,
                quarantine_path: None,
                dry_run: self.config.dry_run,
                cot_trace: cot,
                scanned_at: Utc::now(),
                error: None,
            };
        }

        if self.matches_glob(&ext_str, &self.config.blacklist) {
            cot.push("[CoT:4] BLACKLIST hit → escalate to quarantine pipeline".into());
        }

        // --- Step 3: Read bytes ---
        let bytes = match self.read_bytes(path) {
            Err(e) => return self.error_entry(path.to_path_buf(), e.to_string()),
            Ok(b) => b,
        };

        // --- Step 4: SHA-256 ---
        let sha256 = hex::encode(Sha256::digest(&bytes));
        cot.push(format!("[CoT:5] SHA256={}", &sha256[..16]));

        // --- Step 5: Magic signature ---
        let header = &bytes[..bytes.len().min(16)];
        let magic_hit = RuleSet::check_magic(header).map(|(desc, _)| desc.to_string());
        if let Some(ref m) = magic_hit {
            cot.push(format!("[CoT:6] Magic={}", m));
        }

        // --- Step 6: Entropy ---
        let entropy = RuleSet::shannon_entropy(&bytes);
        cot.push(format!("[CoT:7] Entropy={:.4}", entropy));
        let high_entropy = entropy > HIGH_ENTROPY_THRESHOLD;

        // --- Step 7: Text pattern rules ---
        let text_content = String::from_utf8_lossy(&bytes);
        let matched_rules = self.rules.scan_text(&text_content);
        cot.push(format!("[CoT:8] Rules matched={}", matched_rules.len()));

        // --- Step 8: Verdict logic (CoT reasoning) ---
        let blacklisted = self.matches_glob(&ext_str, &self.config.blacklist);
        let max_sev = matched_rules.iter().map(|r| r.severity).max();

        cot.push(format!(
            "[CoT:9] blacklisted={} high_entropy={} magic_hit={} rule_sev={:?}",
            blacklisted,
            high_entropy,
            magic_hit.is_some(),
            max_sev
        ));

        let is_threat = blacklisted
            || magic_hit.is_some()
            || high_entropy
            || matches!(max_sev, Some(Severity::High) | Some(Severity::Critical));

        if !is_threat {
            cot.push("[CoT:10] VERDICT: Clean".into());
            return ScanEntry {
                path: path.to_path_buf(),
                sha256,
                size_bytes,
                verdict: ScanVerdict::Clean,
                severity: None,
                matched_rules,
                entropy,
                magic_hit,
                quarantine_path: None,
                dry_run: self.config.dry_run,
                cot_trace: cot,
                scanned_at: Utc::now(),
                error: None,
            };
        }

        cot.push("[CoT:10] VERDICT: Threat detected → quarantine".into());

        // --- Step 9: Quarantine ---
        let (verdict, quarantine_path, qerr) = if self.config.dry_run {
            let simulated = self
                .config
                .quarantine_dir
                .join(path.file_name().unwrap_or_default())
                .with_extension("infected");
            cot.push(format!(
                "[CoT:11] DRY-RUN: would move → {}",
                simulated.display()
            ));
            (ScanVerdict::Suspicious, Some(simulated), None)
        } else {
            match self.quarantine(path) {
                Ok(qpath) => {
                    cot.push(format!("[CoT:11] Quarantined → {}", qpath.display()));
                    (ScanVerdict::Quarantined, Some(qpath), None)
                }
                Err(e) => {
                    let msg = e.to_string();
                    cot.push(format!("[CoT:11] Quarantine FAILED: {}", msg));
                    (ScanVerdict::Error, None, Some(msg))
                }
            }
        };

        ScanEntry {
            path: path.to_path_buf(),
            sha256,
            size_bytes,
            verdict,
            severity: max_sev.or(if blacklisted || magic_hit.is_some() {
                Some(Severity::High)
            } else if high_entropy {
                Some(Severity::Medium)
            } else {
                None
            }),
            matched_rules,
            entropy,
            magic_hit,
            quarantine_path,
            dry_run: self.config.dry_run,
            cot_trace: cot,
            scanned_at: Utc::now(),
            error: qerr,
        }
    }

    /// Rename file to `<quarantine_dir>/<filename>.infected`.
    fn quarantine(&self, path: &Path) -> Result<PathBuf, ScanError> {
        fs::create_dir_all(&self.config.quarantine_dir).map_err(|e| ScanError::Io {
            path: self.config.quarantine_dir.clone(),
            source: e,
        })?;

        let filename = path
            .file_name()
            .ok_or_else(|| ScanError::Quarantine {
                path: path.to_path_buf(),
                reason: "no filename".into(),
            })?;

        let dest = self
            .config
            .quarantine_dir
            .join(filename)
            .with_extension("infected");

        // Guard: refuse to quarantine anything already inside quarantine_dir
        if path.starts_with(&self.config.quarantine_dir) {
            return Err(ScanError::Quarantine {
                path: path.to_path_buf(),
                reason: "already in quarantine directory".into(),
            });
        }

        fs::rename(path, &dest).map_err(|e| ScanError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;

        Ok(dest)
    }

    fn read_bytes(&self, path: &Path) -> Result<Vec<u8>, ScanError> {
        let mut f = fs::File::open(path).map_err(|e| {
            if e.kind() == io::ErrorKind::PermissionDenied {
                ScanError::PermissionDenied(path.to_path_buf())
            } else {
                ScanError::Io {
                    path: path.to_path_buf(),
                    source: e,
                }
            }
        })?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).map_err(|e| ScanError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        Ok(buf)
    }

    fn hash_file(&self, path: &Path) -> Result<String, ScanError> {
        let bytes = self.read_bytes(path)?;
        Ok(hex::encode(Sha256::digest(&bytes)))
    }

    /// Simple glob matching: supports `*.ext` and literal strings.
    fn matches_glob(&self, value: &str, patterns: &[String]) -> bool {
        patterns.iter().any(|pat| {
            if let Some(suffix) = pat.strip_prefix('*') {
                value.ends_with(suffix)
            } else {
                value == pat.as_str()
            }
        })
    }

    fn skipped_entry(&self, path: PathBuf, size: u64, cot: Vec<String>) -> ScanEntry {
        ScanEntry {
            path,
            sha256: String::new(),
            size_bytes: size,
            verdict: ScanVerdict::Skipped,
            severity: None,
            matched_rules: vec![],
            entropy: 0.0,
            magic_hit: None,
            quarantine_path: None,
            dry_run: self.config.dry_run,
            cot_trace: cot,
            scanned_at: Utc::now(),
            error: None,
        }
    }

    fn error_entry(&self, path: PathBuf, error: String) -> ScanEntry {
        ScanEntry {
            path,
            sha256: String::new(),
            size_bytes: 0,
            verdict: ScanVerdict::Error,
            severity: None,
            matched_rules: vec![],
            entropy: 0.0,
            magic_hit: None,
            quarantine_path: None,
            dry_run: self.config.dry_run,
            cot_trace: vec![format!("[CoT:ERR] {}", error)],
            scanned_at: Utc::now(),
            error: Some(error),
        }
    }
}
