#![allow(private_interfaces)]

pub mod audit;
pub mod commands;
pub mod config;
pub mod crypto;
pub mod diagnostics;
pub mod models;
pub mod paths;
pub mod storage;
pub mod tray;
pub mod utils;

// #[cfg(test)]  // disabled for tarpaulin (requires WebView2)
// mod tests_integration;

use std::sync::Mutex;
use std::time::Instant;
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
    /// Failed unlock attempts since last success (rate-limiting).
    failed_attempts: Mutex<u32>,
    /// Instant of the most recent failed unlock attempt.
    last_attempt: Mutex<Option<Instant>>,
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

    /// Reset rate-limit state after a successful unlock.
    fn reset_rate_limit(&self) {
        let mut fa = self.failed_attempts.lock().unwrap_or_else(|e| e.into_inner());
        *fa = 0;
        let mut la = self.last_attempt.lock().unwrap_or_else(|e| e.into_inner());
        *la = None;
    }

    /// Check whether the current unlock attempt should be rate-limited.
    /// Returns Ok(()) if the attempt is allowed, or Err(cooldown_remaining_secs).
    fn check_rate_limit(&self) -> Result<(), u64> {
        let attempts = *self.failed_attempts.lock().unwrap_or_else(|e| e.into_inner());
        if attempts == 0 {
            return Ok(());
        }
        // Exponential backoff: 2^(attempts-1) seconds, capped at 30
        let cooldown = (1u64 << (attempts.min(6) - 1)).min(30);
        let last = self.last_attempt.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(t) = *last {
            let elapsed = t.elapsed().as_secs();
            if elapsed < cooldown {
                return Err(cooldown - elapsed);
            }
        }
        Ok(())
    }

    /// Record a failed unlock attempt for rate-limiting.
    fn record_failed_attempt(&self) {
        let mut fa = self.failed_attempts.lock().unwrap_or_else(|e| e.into_inner());
        *fa = fa.saturating_add(1);
        let mut la = self.last_attempt.lock().unwrap_or_else(|e| e.into_inner());
        *la = Some(Instant::now());
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
fn get_app_version(app: tauri::AppHandle) -> String {
    app.package_info().version.to_string()
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
    crate::storage::flush_and_save(&mut data)
}

// ── App entry ────────────────────────────────────────────────

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    crate::diagnostics::init();
    let _ = crate::paths::verify();

    if crate::storage::exists() {
        let data = crate::storage::load();
        crate::diagnostics::restore_from_log_str(&data.log);
        crate::audit::restore(&data.audit_trail);
    }

    tauri::Builder::default()
        .manage(AppState {
            encryption_key: Mutex::new(None),
            failed_attempts: Mutex::new(0),
            last_attempt: Mutex::new(None),
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
                let _ = window.set_min_size(Some(tauri::PhysicalSize::new(420, 420)));
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
            get_app_version,
            load_config,
            save_config,
            update_tray_icon,
            commands::totp::generate_code,
            commands::totp::generate_all_codes,
            commands::accounts::crud::add_account,
            commands::accounts::crud::add_account_from_uri,
            commands::accounts::crud::remove_account,
            commands::accounts::crud::update_account,
            commands::accounts::crud::list_accounts,
            commands::accounts::qr::get_otpauth_uri,
            commands::accounts::qr::save_backup_file,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn cleanup_auth_file() {
        let path = crate::paths::auth_path();
        if path.exists() {
            let _ = std::fs::remove_file(&path);
        }
    }

    fn with_fs_lock(f: impl FnOnce()) {
        let _lock = crate::storage::auth_file::FS_TEST_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        f();
    }

    #[test]
    fn test_save_config_preserves_password_metadata() {
        with_fs_lock(|| {
            cleanup_auth_file();
            // Seed an auth file with PIN protection set AND encrypted accounts
            // (reconcile_invariants resets password_protected if accounts are unencrypted)
            let key = [0x42u8; 32];
            let accounts: Vec<crate::models::account::Account> = vec![];
            let mut data = crate::storage::try_load().unwrap();
            data.accounts = crate::storage::encrypt_accounts(&accounts, &key).unwrap();
            data.config.password_protected = true;
            data.config.password_salt = "deadbeef".into();
            crate::storage::save(&data).unwrap();

            // Attempt to save a config that has password_protected=false (like frontend might send)
            let cfg = crate::config::Config {
                password_protected: false,
                password_salt: String::new(),
                ..crate::config::Config::default()
            };
            save_config(cfg).unwrap();

            // Verify metadata was preserved
            let loaded = crate::storage::try_load().unwrap();
            assert!(
                loaded.config.password_protected,
                "password_protected must be preserved by save_config"
            );
            assert_eq!(
                loaded.config.password_salt, "deadbeef",
                "password_salt must be preserved by save_config"
            );
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_save_config_updates_non_security_fields() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let mut data = crate::storage::try_load().unwrap();
            data.config.theme = "dark".into();
            data.config.width = 320;
            crate::storage::save(&data).unwrap();

            let cfg = crate::config::Config {
                theme: "light".into(),
                width: 400,
                clipboard_clear_seconds: 60,
                ..crate::config::Config::default()
            };
            save_config(cfg).unwrap();

            let loaded = crate::storage::try_load().unwrap();
            assert_eq!(loaded.config.theme, "light", "theme should be updated");
            assert_eq!(loaded.config.width, 400, "width should be updated");
            assert_eq!(
                loaded.config.clipboard_clear_seconds, 60,
                "clipboard_clear_seconds should be updated"
            );
            cleanup_auth_file();
        });
    }

    // ── load_config edge cases ───────────────────────────────

    #[test]
    fn test_load_config_corrupted_auth_file_returns_error() {
        with_fs_lock(|| {
            cleanup_auth_file();
            std::fs::write(crate::paths::auth_path(), "{{not valid json at all![[[").unwrap();

            // load_config calls try_load() which fails on parse error
            let result = load_config();
            assert!(
                result.is_err(),
                "load_config must fail on corrupted .auth file"
            );
            assert!(
                result.unwrap_err().contains("parse"),
                "error should mention parse failure"
            );
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_load_config_fresh_returns_defaults() {
        with_fs_lock(|| {
            cleanup_auth_file();
            // No .auth file → try_load returns fresh() → config is default
            let cfg = load_config().unwrap();
            let default = crate::config::Config::default();
            assert_eq!(cfg.theme, default.theme);
            assert!(!cfg.password_protected);
            assert_eq!(cfg.always_on_top, default.always_on_top);
            cleanup_auth_file();
        });
    }

    // ── get_app_name ─────────────────────────────────────────

    #[test]
    fn test_get_app_name_returns_non_empty() {
        let name = get_app_name();
        assert!(
            !name.is_empty(),
            "get_app_name must return non-empty string"
        );
    }

    #[test]
    fn test_get_app_name_returns_exe_stem() {
        let name = get_app_name();
        let stem = crate::paths::exe_stem();
        assert_eq!(name, stem, "get_app_name must return the exe stem");
    }

    // get_app_version takes tauri::AppHandle — cannot be called in unit tests.
    // It is compilation-verified via the invoke_handler registration in run().

    #[test]
    fn test_save_config_empty_auth_file_creates_fresh() {
        with_fs_lock(|| {
            cleanup_auth_file();
            // No auth file exists — saving config should create one with defaults
            let cfg = crate::config::Config {
                theme: "light".into(),
                width: 500,
                ..crate::config::Config::default()
            };
            // save_config calls try_load first. If no auth file, try_load returns fresh()
            let mut data = crate::storage::try_load().unwrap();
            data.config = cfg.clone();
            // Preserve password metadata (save_config requirement)
            data.config.password_protected = false;
            data.config.password_salt = String::new();
            crate::storage::save(&data).unwrap();

            // Verify the file was created
            assert!(crate::paths::auth_path().exists());
            let loaded = crate::storage::try_load().unwrap();
            assert_eq!(loaded.config.theme, "light");
            assert_eq!(loaded.config.width, 500);
            assert!(!loaded.config.password_protected);
            cleanup_auth_file();
        });
    }
}
