use regex::Regex;
use serde::{Deserialize, Serialize};

/// Byte-level magic signatures for binary threat detection.
/// Each entry: (description, offset, pattern)
pub static MAGIC_SIGNATURES: &[(&str, usize, &[u8])] = &[
    ("MZ PE executable",    0, &[0x4D, 0x5A]),
    ("ELF binary",          0, &[0x7F, 0x45, 0x4C, 0x46]),
    ("Mach-O 64-bit",       0, &[0xCF, 0xFA, 0xED, 0xFE]),
    ("Mach-O 32-bit",       0, &[0xCE, 0xFA, 0xED, 0xFE]),
    ("PowerShell encoded",  0, &[0x4A, 0x41, 0x42, 0x58]),
    ("ZIP archive",         0, &[0x50, 0x4B, 0x03, 0x04]),
];

/// Entropy threshold above which file content is considered obfuscated/encrypted.
pub const HIGH_ENTROPY_THRESHOLD: f64 = 7.2;

/// Suspicious string patterns found in text-readable files.
pub static SUSPICIOUS_PATTERNS: &[&str] = &[
    r"(?i)cmd\.exe\s*/c",
    r"(?i)powershell\s+-enc",
    r"(?i)powershell\s+-w\s+hidden",
    r"(?i)WScript\.Shell",
    r"(?i)CreateObject\(",
    r"(?i)Shell\(.*cmd",
    r"(?i)base64_decode\s*\(",
    r"(?i)eval\s*\(",
    r"(?i)exec\s*\(",
    r"(?i)system\s*\(",
    r"(?i)wget\s+http",
    r"(?i)curl\s+.*\|\s*bash",
    r"(?i)chmod\s+777",
    r"(?i)/dev/tcp/",
    r"(?i)rm\s+-rf\s+/",
    r"(?i)dd\s+if=",
    r"(?i)\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchedRule {
    pub rule_id: String,
    pub description: String,
    pub severity: Severity,
    pub evidence: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

pub struct RuleSet {
    patterns: Vec<(String, Regex, Severity)>,
}

impl RuleSet {
    pub fn default_set() -> Self {
        let patterns = SUSPICIOUS_PATTERNS
            .iter()
            .enumerate()
            .filter_map(|(i, pat)| {
                Regex::new(pat).ok().map(|re| {
                    let severity = match i {
                        0..=3 => Severity::High,
                        4..=9 => Severity::Critical,
                        _ => Severity::Medium,
                    };
                    (format!("RULE_{:03}", i), re, severity)
                })
            })
            .collect();
        Self { patterns }
    }

    /// Scan text content; returns all matched rules.
    pub fn scan_text(&self, content: &str) -> Vec<MatchedRule> {
        self.patterns
            .iter()
            .filter_map(|(id, re, sev)| {
                re.find(content).map(|m| MatchedRule {
                    rule_id: id.clone(),
                    description: format!("Pattern match: {}", re.as_str()),
                    severity: *sev,
                    evidence: m.as_str().chars().take(80).collect(),
                })
            })
            .collect()
    }

    /// Compute Shannon entropy of a byte slice.
    pub fn shannon_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let mut freq = [0u64; 256];
        for &b in data {
            freq[b as usize] += 1;
        }
        let len = data.len() as f64;
        freq.iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = c as f64 / len;
                -p * p.log2()
            })
            .sum()
    }

    /// Check byte-level magic signatures against file header bytes.
    pub fn check_magic(header: &[u8]) -> Option<(&'static str, usize)> {
        MAGIC_SIGNATURES.iter().find_map(|(desc, offset, sig)| {
            let start = *offset;
            let end = start + sig.len();
            if header.len() >= end && &header[start..end] == *sig {
                Some((*desc, start))
            } else {
                None
            }
        })
    }
}
