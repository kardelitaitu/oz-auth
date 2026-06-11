#![allow(private_interfaces)]

pub mod commands;
pub mod config;
pub mod crypto;
pub mod diagnostics;
pub mod models;
pub mod paths;
pub mod storage;
pub mod tray;
pub mod utils;

use std::sync::Mutex;
use tauri::window::Color;
use tauri::Manager;

/// Cached encryption key — kept in memory while unlocked.
/// Cleared on `lock()`.
pub(crate) struct AppState {
    encryption_key: Mutex<Option<[u8; 32]>>,
}

impl AppState {
    fn get_key(&self) -> Result<Option<[u8; 32]>, String> {
        self.encryption_key
            .lock()
            .map(|g| *g)
            .map_err(|e| format!("lock error: {e}"))
    }

    fn set_key(&self, key: [u8; 32]) -> Result<(), String> {
        let mut guard = self
            .encryption_key
            .lock()
            .map_err(|e| format!("lock error: {e}"))?;
        *guard = Some(key);
        Ok(())
    }

    fn clear_key(&self) -> Result<(), String> {
        let mut guard = self
            .encryption_key
            .lock()
            .map_err(|e| format!("lock error: {e}"))?;
        *guard = None;
        Ok(())
    }
}

// ── Simple commands ──────────────────────────────────────────

#[tauri::command]
fn get_app_name() -> String {
    crate::paths::exe_stem()
}

#[tauri::command]
fn load_config() -> Result<crate::config::Config, String> {
    Ok(crate::storage::try_load()?.config)
}

#[tauri::command]
fn update_tray_icon(pct: f64, app: tauri::AppHandle) {
    tray::update_icon(&app, pct);
}

#[tauri::command]
fn save_config(cfg: crate::config::Config) -> Result<(), String> {
    let mut data = crate::storage::try_load()?;
    let mut merged = cfg;

    // Preserve password metadata from storage — security-critical
    merged.password_protected = data.config.password_protected;
    merged.password_salt = data.config.password_salt.clone();

    data.config = merged;
    data.log = crate::diagnostics::flush_to_log_str();
    crate::storage::save(&data)
}

// ── App entry ────────────────────────────────────────────────

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    crate::diagnostics::init();
    let _ = crate::paths::verify();

    // Restore diagnostics from existing .auth file
    if crate::storage::exists() {
        let data = crate::storage::load();
        crate::diagnostics::restore_from_log_str(&data.log);
    }

    tauri::Builder::default()
        .manage(AppState {
            encryption_key: Mutex::new(None),
        })
        .manage(tray::TrayState::<tauri::Wry>::new())
        .setup(|app| {
            let data = crate::storage::load();
            let cfg = data.config;
            let exe_name = crate::paths::exe_stem();

            if let Some(window) = app.get_webview_window("main") {
                if crate::storage::exists() {
                    let _ = window.set_position(tauri::PhysicalPosition::new(cfg.left, cfg.top));
                    let _ = window.set_size(tauri::PhysicalSize::new(cfg.width, cfg.height));
                } else {
                    let _ = window.set_size(tauri::PhysicalSize::new(cfg.width, cfg.height));
                    let _ = window.center();
                }
                let _ = window.set_always_on_top(cfg.always_on_top);
                #[cfg(windows)]
                let _ = window.set_background_color(Some(Color(30, 30, 30, 255)));
                let _ = window.show();
                let _ = window.set_focus();
                let _ = window.set_title(&exe_name);
            }

            // Build system tray
            let _ = tray::build(app.handle(), &exe_name);

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_app_name,
            load_config,
            save_config,
            update_tray_icon,
            commands::totp::generate_code,
            commands::totp::generate_all_codes,
            commands::accounts::add_account,
            commands::accounts::add_account_from_uri,
            commands::accounts::remove_account,
            commands::accounts::update_account,
            commands::accounts::list_accounts,
            commands::auth::set_lock,
            commands::auth::unlock,
            commands::auth::lock,
            commands::auth::is_locked,
            commands::auth::change_pin,
            commands::auth::export_backup,
            commands::auth::import_backup,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
