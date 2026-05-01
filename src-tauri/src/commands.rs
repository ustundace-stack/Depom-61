use crate::scanner::{ScanConfig, ScanEngine, ScanReport};
use std::path::PathBuf;
use tauri::command;

#[command]
pub async fn run_scan(
    target: String,
    dry_run: bool,
    quarantine_dir: String,
    whitelist: Vec<String>,
    blacklist: Vec<String>,
    recursive: bool,
    max_file_size_mb: u64,
) -> Result<ScanReport, String> {
    let config = ScanConfig {
        dry_run,
        quarantine_dir: PathBuf::from(&quarantine_dir),
        whitelist: if whitelist.is_empty() {
            ScanConfig::default().whitelist
        } else {
            whitelist
        },
        blacklist: if blacklist.is_empty() {
            ScanConfig::default().blacklist
        } else {
            blacklist
        },
        recursive,
        max_file_size_mb,
        scan_hidden: false,
    };

    let target_path = PathBuf::from(&target);
    if !target_path.exists() {
        return Err(format!("Target path does not exist: {}", target));
    }

    // Spawn blocking I/O off the async executor.
    tokio::task::spawn_blocking(move || {
        let engine = ScanEngine::new(config);
        engine.run(&target_path)
    })
    .await
    .map_err(|e| format!("Scan task panicked: {}", e))
}

#[command]
pub fn default_config() -> ScanConfig {
    ScanConfig::default()
}
