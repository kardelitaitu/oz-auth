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

#[cfg(test)]
pub(crate) mod test_utils;

// #[cfg(test)]  // disabled for tarpaulin (requires WebView2)
// mod tests_integration;

use std::sync::Mutex;
use std::time::Instant;
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
    /// Cached AuthData — avoids re-reading + re-parsing .auth file on every IPC call.
    /// Stores (data, file_modification_time) for staleness detection.
    cached_data: Mutex<Option<(crate::storage::AuthData, Option<std::time::SystemTime>)>>,
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
        let mut fa = self
            .failed_attempts
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *fa = 0;
        let mut la = self.last_attempt.lock().unwrap_or_else(|e| e.into_inner());
        *la = None;
    }

    /// Check whether the current unlock attempt should be rate-limited.
    /// Returns Ok(()) if the attempt is allowed, or Err(cooldown_remaining_secs).
    fn check_rate_limit(&self) -> Result<(), u64> {
        let attempts = *self
            .failed_attempts
            .lock()
            .unwrap_or_else(|e| e.into_inner());
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
        let mut fa = self
            .failed_attempts
            .lock()
            .unwrap_or_else(|e| e.into_inner());
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

    /// Load AuthData from cache if valid, otherwise read from disk.
    /// Cache is invalidated on every save (via `invalidate_cache`).
    pub(crate) fn load_data(&self) -> Result<crate::storage::AuthData, String> {
        let cache = self
            .cached_data
            .lock()
            .map_err(|e| format!("lock error: {e}"))?;
        if let Some((ref data, cached_at)) = *cache {
            // Check if file has been modified externally (import_backup, etc.)
            if let Ok(modified) =
                std::fs::metadata(crate::paths::auth_path()).and_then(|m| m.modified())
            {
                if let Some(ct) = cached_at {
                    if modified > ct {
                        drop(cache);
                        return self.reload_from_disk();
                    }
                }
            }
            return Ok(data.clone());
        }
        drop(cache);
        self.reload_from_disk()
    }

    /// Read from disk, populate cache, return data.
    fn reload_from_disk(&self) -> Result<crate::storage::AuthData, String> {
        let data = crate::storage::try_load()?;
        let mtime = std::fs::metadata(crate::paths::auth_path())
            .ok()
            .and_then(|m| m.modified().ok());
        let mut cache = self
            .cached_data
            .lock()
            .map_err(|e| format!("lock error: {e}"))?;
        *cache = Some((data.clone(), mtime));
        Ok(data)
    }

    /// Invalidate the cache — must be called after every save to disk.
    pub(crate) fn invalidate_cache(&self) {
        if let Ok(mut cache) = self.cached_data.lock() {
            *cache = None;
        }
    }

    #[cfg(test)]
    pub(crate) fn new_test() -> Self {
        Self {
            encryption_key: Mutex::new(None),
            failed_attempts: Mutex::new(0),
            last_attempt: Mutex::new(None),
            cached_data: Mutex::new(None),
        }
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

fn load_config_impl(state: &AppState) -> Result<crate::config::Config, String> {
    Ok(state.load_data()?.config)
}

#[tauri::command]
fn load_config(state: tauri::State<'_, AppState>) -> Result<crate::config::Config, String> {
    load_config_impl(&state)
}

#[tauri::command]
fn update_tray_icon(pct: f64, app: tauri::AppHandle) {
    tray::update_icon(&app, pct);
}

#[tauri::command]
fn get_audit_log() -> Vec<crate::audit::AuditEntry> {
    crate::audit::snapshot()
}

fn save_config_impl(cfg: crate::config::Config, state: &AppState) -> Result<(), String> {
    let mut data = state.load_data()?;
    let mut merged = cfg;

    // Preserve password metadata from storage — security-critical
    merged.password_protected = data.config.password_protected;
    merged.password_salt = data.config.password_salt.clone();

    data.config = merged;
    crate::storage::flush_and_save(&mut data)?;
    state.invalidate_cache();
    crate::diagnostics::event("config", "settings updated");
    Ok(())
}

#[tauri::command]
fn save_config(
    cfg: crate::config::Config,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    save_config_impl(cfg, &state)
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

    // Push startup AFTER restore so the event survives in the audit trail
    // (diagnostics::init() only sets up the panic hook — the event is pushed here)
    crate::diagnostics::event("startup", "Application started");

    tauri::Builder::default()
        .manage(AppState {
            encryption_key: Mutex::new(None),
            failed_attempts: Mutex::new(0),
            last_attempt: Mutex::new(None),
            cached_data: Mutex::new(None),
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
                let _ = window.set_background_color(Some(tauri::window::Color(30, 30, 30, 255)));
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
            get_audit_log,
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
    use crate::test_utils::{cleanup_auth_file, test_app_state, with_fs_lock};

    #[test]
    fn test_save_config_preserves_password_metadata() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
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
            save_config_impl(cfg, &state).unwrap();

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
            let state = test_app_state();
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
            save_config_impl(cfg, &state).unwrap();

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
            let state = test_app_state();
            std::fs::write(crate::paths::auth_path(), "{{not valid json at all![[[").unwrap();

            // load_config calls try_load() which fails on parse error
            let result = load_config_impl(&state);
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
            let state = test_app_state();
            // No .auth file → try_load returns fresh() → config is default
            let cfg = load_config_impl(&state).unwrap();
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

    // ── Cache tests ───────────────────────────────────────────

    #[test]
    fn test_load_data_returns_same_data_on_second_call() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            // Seed an auth file
            let mut data = crate::storage::try_load().unwrap();
            data.config.theme = "dark".into();
            crate::storage::save(&data).unwrap();

            // First load — reads from disk
            let loaded1 = state.load_data().unwrap();
            assert_eq!(loaded1.config.theme, "dark");

            // Second load — should return cached data
            let loaded2 = state.load_data().unwrap();
            assert_eq!(loaded2.config.theme, "dark");
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_invalidate_cache_forces_reload() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            // Seed an auth file
            let mut data = crate::storage::try_load().unwrap();
            data.config.theme = "dark".into();
            crate::storage::save(&data).unwrap();

            // Load (populates cache)
            let loaded = state.load_data().unwrap();
            assert_eq!(loaded.config.theme, "dark");

            // Modify the file directly (simulates external change)
            let mut data2 = crate::storage::try_load().unwrap();
            data2.config.theme = "light".into();
            crate::storage::save(&data2).unwrap();

            // Without invalidation, cache returns stale data
            let _cached = state.load_data().unwrap();
            // (might return stale "dark" if mtime hasn't changed yet)

            // After invalidation, must return fresh data
            state.invalidate_cache();
            let fresh = state.load_data().unwrap();
            assert_eq!(fresh.config.theme, "light", "must reload after invalidate");
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_load_data_populates_cache() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            // No auth file yet — fresh() should be returned
            let loaded = state.load_data().unwrap();
            assert!(!loaded.config.password_protected);

            // Verify cache is populated
            let cache = state.cached_data.lock().unwrap();
            assert!(cache.is_some(), "cache should be populated after load_data");
            drop(cache);
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_cache_detects_external_file_modification() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            // Seed an auth file
            let mut data = crate::storage::try_load().unwrap();
            data.config.theme = "dark".into();
            crate::storage::save(&data).unwrap();

            // Load (populates cache with mtime)
            let loaded = state.load_data().unwrap();
            assert_eq!(loaded.config.theme, "dark");

            // Small delay to ensure mtime changes on Windows (1s resolution)
            std::thread::sleep(std::time::Duration::from_millis(1100));

            // Modify the file directly (different mtime)
            let mut data2 = crate::storage::try_load().unwrap();
            data2.config.theme = "light".into();
            crate::storage::save(&data2).unwrap();

            // load_data should detect the mtime change and reload
            let fresh = state.load_data().unwrap();
            assert_eq!(
                fresh.config.theme, "light",
                "must detect external modification"
            );
            cleanup_auth_file();
        });
    }
}
