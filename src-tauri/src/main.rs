#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod scanner;

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            commands::run_scan,
            commands::default_config,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
