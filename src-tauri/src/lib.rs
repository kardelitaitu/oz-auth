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
use zeroize::Zeroizing;

/// Cached encryption key — kept in memory while unlocked.
///
/// Wrapped in `Zeroizing` so the key bytes are overwritten on drop,
/// preventing recovery from a memory dump after `lock()`.
/// On Windows, `VirtualLock` prevents the key from being paged to disk.
pub(crate) struct AppState {
    encryption_key: Mutex<Option<Zeroizing<[u8; 32]>>>,
}

impl AppState {
    /// Return a clone of the key wrapper. The clone is also wrapped in `Zeroizing`
    /// and will auto-zeroize when dropped. Callers must NOT hold the raw key longer
    /// than needed.
    fn get_key(&self) -> Result<Option<Zeroizing<[u8; 32]>>, String> {
        self.encryption_key
            .lock()
            .map(|g| g.clone())
            .map_err(|e| format!("lock error: {e}"))
    }

    /// Check whether a key is currently held, without cloning it.
    fn has_key(&self) -> bool {
        self.encryption_key
            .lock()
            .map(|g| g.is_some())
            .unwrap_or(false)
    }

    fn set_key(&self, key: [u8; 32]) -> Result<(), String> {
        let mut guard = self
            .encryption_key
            .lock()
            .map_err(|e| format!("lock error: {e}"))?;
        let wrapper = Zeroizing::new(key);
        // Prevent paging to disk on Windows
        #[cfg(windows)]
        unsafe {
            let ptr = wrapper.as_ptr() as *const std::ffi::c_void;
            let _ = windows_virtual_lock(ptr, 32);
        }
        *guard = Some(wrapper);
        Ok(())
    }

    /// Clear the encryption key. `Zeroizing` ensures the bytes are overwritten on drop.
    /// On Windows, `VirtualUnlock` allows the OS to page the memory again.
    fn clear_key(&self) -> Result<(), String> {
        let mut guard = self
            .encryption_key
            .lock()
            .map_err(|e| format!("lock error: {e}"))?;
        if let Some(wrapper) = guard.take() {
            // Unlock from physical memory so OS can reclaim
            #[cfg(windows)]
            unsafe {
                let ptr = wrapper.as_ptr() as *const std::ffi::c_void;
                let _ = windows_virtual_unlock(ptr, 32);
            }
            // Zeroizing wrapper overwrites bytes on drop — defense-in-depth
            drop(wrapper);
        }
        Ok(())
    }
}

/// Windows API: prevent memory from being paged to swap.
#[cfg(windows)]
unsafe fn windows_virtual_lock(ptr: *const std::ffi::c_void, size: usize) -> bool {
    extern "system" {
        fn VirtualLock(lpAddress: *const std::ffi::c_void, dwSize: usize) -> i32;
    }
    VirtualLock(ptr, size) != 0
}

/// Windows API: allow memory to be paged again.
#[cfg(windows)]
unsafe fn windows_virtual_unlock(ptr: *const std::ffi::c_void, size: usize) -> bool {
    extern "system" {
        fn VirtualUnlock(lpAddress: *const std::ffi::c_void, dwSize: usize) -> i32;
    }
    VirtualUnlock(ptr, size) != 0
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
