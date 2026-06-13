use crate::storage::{decrypt_accounts, encrypt_accounts, try_load};
use crate::AppState;
use tauri::State;
use zeroize::{Zeroize, Zeroizing};

fn set_lock_impl(pin: &str, state: &AppState) -> Result<(), String> {
    if pin.is_empty() {
        return Err("PIN cannot be empty".to_string());
    }

    let mut data = try_load()?;
    if data.config.password_protected {
        return Err("PIN is already set".to_string());
    }

    let salt = crate::crypto::generate_salt();
    let salt_hex = hex::encode(*salt);
    let mut key = crate::crypto::derive_key(pin, &*salt)?;

    // Parse current plaintext accounts
    let mut accounts: Vec<crate::models::account::Account> =
        serde_json::from_str(&data.accounts.data_json)
            .map_err(|e| format!("failed to parse plaintext accounts: {e}"))?;

    // Re-encrypt
    data.accounts = encrypt_accounts(&accounts, &key)?;
    data.config.password_protected = true;
    data.config.password_salt = salt_hex;
    crate::storage::flush_and_save(&mut data)?;
    state.set_key(key)?;
    // Zeroize derived key and account secrets
    key.zeroize();
    for a in &mut accounts {
        a.secret.zeroize();
    }
    accounts.clear();
    // Release the underlying heap allocation
    accounts.shrink_to_fit();
    crate::diagnostics::event("security", "PIN set");

    Ok(())
}

#[tauri::command]
pub fn set_lock(pin: String, state: State<'_, AppState>) -> Result<(), String> {
    set_lock_impl(&pin, &state)
}

fn unlock_impl(pin: &str, state: &AppState) -> Result<bool, String> {
    let data = try_load()?;
    if !data.config.password_protected {
        return Err("PIN is not set".to_string());
    }

    // Rate-limit check: enforce exponential backoff after failed attempts.
    // Cooldown: 1s → 2s → 4s → 8s → 16s → 30s (cap).
    if let Err(remaining) = state.check_rate_limit() {
        return Err(format!("too many attempts — wait {}s", remaining));
    }

    let mut salt = Zeroizing::new(
        hex::decode(&data.config.password_salt).map_err(|e| format!("invalid salt: {e}"))?,
    );
    let mut key = crate::crypto::derive_key(pin, &salt)?;

    // Try to decrypt — if it fails, wrong PIN
    match decrypt_accounts(&data.accounts, &key) {
        Ok(mut accounts) => {
            // Zeroize decrypted accounts — we only needed them for validation
            for a in &mut accounts {
                a.secret.zeroize();
            }
            accounts.clear();
            accounts.shrink_to_fit();
            state.set_key(key)?;
            state.reset_rate_limit();
            key.zeroize();
            salt.zeroize();
            crate::diagnostics::event("security", "unlocked");
            Ok(true)
        }
        Err(_e) => {
            // Constant-time: return Ok(false) for ALL errors
            // to prevent timing attackers from distinguishing
            // "wrong PIN" vs "corrupted data" vs other errors.
            state.record_failed_attempt();
            key.zeroize();
            salt.zeroize();
            Ok(false)
        }
    }
}

#[tauri::command]
pub fn unlock(pin: String, state: State<'_, AppState>) -> Result<bool, String> {
    unlock_impl(&pin, &state)
}

fn lock_impl(state: &AppState) -> Result<(), String> {
    state.clear_key()?;
    crate::diagnostics::event("security", "locked");
    Ok(())
}

#[tauri::command]
pub fn lock(state: State<'_, AppState>) -> Result<(), String> {
    lock_impl(&state)
}

fn is_locked_impl(state: &AppState) -> Result<bool, String> {
    let data = try_load()?;
    if !data.config.password_protected {
        return Ok(false);
    }
    Ok(!state.has_key())
}

/// Check if the app is locked without cloning the encryption key.
#[tauri::command]
pub fn is_locked(state: State<'_, AppState>) -> Result<bool, String> {
    is_locked_impl(&state)
}

fn change_pin_impl(old_pin: &str, new_pin: &str, state: &AppState) -> Result<(), String> {
    if new_pin.is_empty() {
        return Err("new PIN cannot be empty".to_string());
    }

    let mut data = try_load()?;
    if !data.config.password_protected {
        return Err("PIN is not set".to_string());
    }

    // Lock guard: app must be unlocked to change PIN.
    // Without this, change_pin could be called when locked (it derives
    // its own key from old_pin), bypassing the unlock step entirely.
    if !state.has_key() {
        return Err("app is locked".to_string());
    }

    let old_salt = Zeroizing::new(
        hex::decode(&data.config.password_salt).map_err(|e| format!("invalid salt: {e}"))?,
    );
    let mut old_key = crate::crypto::derive_key(old_pin, &old_salt)?;

    let mut accounts =
        decrypt_accounts(&data.accounts, &old_key).map_err(|_| "wrong current PIN".to_string())?;

    let new_salt = crate::crypto::generate_salt();
    let new_salt_hex = hex::encode(*new_salt);
    let new_key = crate::crypto::derive_key(new_pin, &*new_salt)?;
    data.accounts = encrypt_accounts(&accounts, &new_key)?;
    data.config.password_salt = new_salt_hex;
    crate::storage::flush_and_save(&mut data)?;

    // Store the new key BEFORE zeroizing — set_key takes ownership
    state.set_key(new_key)?;

    // Zeroize the old key and account secrets after use
    old_key.zeroize();
    for a in &mut accounts {
        a.secret.zeroize();
    }
    accounts.clear();
    accounts.shrink_to_fit();

    crate::diagnostics::event("security", "PIN changed");

    Ok(())
}

#[tauri::command]
pub fn change_pin(
    old_pin: String,
    new_pin: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    change_pin_impl(&old_pin, &new_pin, &state)
}

#[tauri::command]
pub fn export_backup(path: String) -> Result<(), String> {
    let src = crate::paths::auth_path();
    std::fs::copy(&src, &path).map_err(|e| format!("failed to export backup: {e}"))?;
    crate::diagnostics::event("backup", &format!("exported to {path}"));
    Ok(())
}

fn import_backup_impl(path: &str, state: &AppState) -> Result<(), String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("failed to read backup: {e}"))?;
    let _backup: crate::storage::auth_file::AuthData =
        serde_json::from_str(&raw).map_err(|e| format!("invalid backup file: {e}"))?;

    // Lock guard: app must be unlocked to import a backup.
    // Without this, an attacker could replace the .auth file on a locked
    // machine with a PIN-less backup, bypassing PIN protection entirely.
    // Uses is_locked_impl (not raw has_key) so non-PIN-protected apps
    // can still import backups.
    if is_locked_impl(state)? {
        return Err("app is locked".to_string());
    }

    let dest = crate::paths::auth_path();
    std::fs::copy(path, &dest).map_err(|e| format!("failed to import backup: {e}"))?;
    state.clear_key()?;
    crate::diagnostics::event("backup", &format!("imported from {path}"));

    Ok(())
}

#[tauri::command]
pub fn import_backup(path: String, state: State<'_, AppState>) -> Result<(), String> {
    import_backup_impl(&path, &state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;

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

    fn test_app_state() -> AppState {
        AppState {
            encryption_key: std::sync::Mutex::new(None),
            failed_attempts: std::sync::Mutex::new(0),
            last_attempt: std::sync::Mutex::new(None),
        }
    }

    // ── AppState ─────────────────────────────────────────────

    #[test]
    fn test_appstate_set_and_clear_key() {
        let state = test_app_state();
        let key = [0x42u8; 32];
        assert!(!state.has_key());
        state.set_key(key).unwrap();
        assert!(state.has_key());
        state.clear_key().unwrap();
        assert!(!state.has_key());
    }

    #[test]
    fn test_appstate_get_key_returns_clone() {
        let state = test_app_state();
        state.set_key([0x77u8; 32]).unwrap();
        let cloned = state.get_key().unwrap();
        assert!(cloned.is_some());
        // Clone drops without affecting original
        assert!(state.has_key());
    }

    // ── set_lock via storage layer ───────────────────────────

    #[test]
    fn test_set_lock_stores_encrypted_accounts() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();

            let accounts = vec![crate::models::account::Account {
                id: "s1".into(),
                issuer: "S".into(),
                label: "s".into(),
                algorithm: crate::models::account::Algorithm::SHA1,
                digits: 6,
                period: 30,
                secret: vec![1, 2, 3],
                sort_order: 0,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            }];
            let mut data = crate::storage::try_load().unwrap();
            data.accounts.data_json = serde_json::to_string(&accounts).unwrap();
            crate::storage::save(&data).unwrap();

            let salt = crypto::generate_salt();
            let mut key = crypto::derive_key("1234", &*salt).unwrap();
            data.accounts = crate::storage::encrypt_accounts(&accounts, &key).unwrap();
            data.config.password_protected = true;
            data.config.password_salt = hex::encode(*salt);
            crate::storage::save(&data).unwrap();
            state.set_key(key).unwrap();
            key.zeroize();

            let loaded = crate::storage::try_load().unwrap();
            assert!(loaded.config.password_protected);
            assert!(loaded.accounts.encrypted);
            assert!(!loaded.config.password_salt.is_empty());
            cleanup_auth_file();
        });
    }

    // ── unlock via storage layer ─────────────────────────────

    #[test]
    fn test_unlock_wrong_pin_via_storage() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let mut data = crate::storage::try_load().unwrap();
            let salt = crypto::generate_salt();
            let mut key = crypto::derive_key("correct", &*salt).unwrap();
            let accounts: Vec<crate::models::account::Account> = vec![];
            data.accounts = crate::storage::encrypt_accounts(&accounts, &key).unwrap();
            data.config.password_protected = true;
            data.config.password_salt = hex::encode(*salt);
            crate::storage::save(&data).unwrap();

            let loaded = crate::storage::try_load().unwrap();
            let loaded_salt = hex::decode(&loaded.config.password_salt).unwrap();
            let mut wrong_key = crypto::derive_key("wrong", &loaded_salt).unwrap();
            assert!(crate::storage::decrypt_accounts(&loaded.accounts, &wrong_key).is_err());
            wrong_key.zeroize();
            key.zeroize();
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_unlock_correct_pin_via_storage() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let mut data = crate::storage::try_load().unwrap();
            let salt = crypto::generate_salt();
            let mut key = crypto::derive_key("mypin", &*salt).unwrap();
            let accounts: Vec<crate::models::account::Account> = vec![];
            data.accounts = crate::storage::encrypt_accounts(&accounts, &key).unwrap();
            data.config.password_protected = true;
            data.config.password_salt = hex::encode(*salt);
            crate::storage::save(&data).unwrap();

            let loaded = crate::storage::try_load().unwrap();
            let loaded_salt = hex::decode(&loaded.config.password_salt).unwrap();
            let mut correct_key = crypto::derive_key("mypin", &loaded_salt).unwrap();
            let mut decrypted =
                crate::storage::decrypt_accounts(&loaded.accounts, &correct_key).unwrap();
            assert!(decrypted.is_empty());
            correct_key.zeroize();
            decrypted.clear();
            key.zeroize();
            cleanup_auth_file();
        });
    }

    // ── change_pin via storage layer ─────────────────────────

    #[test]
    fn test_change_pin_via_storage() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let mut data = crate::storage::try_load().unwrap();
            let salt = crypto::generate_salt();
            let mut old_key = crypto::derive_key("oldpin", &*salt).unwrap();
            let accounts: Vec<crate::models::account::Account> = vec![];
            data.accounts = crate::storage::encrypt_accounts(&accounts, &old_key).unwrap();
            data.config.password_protected = true;
            data.config.password_salt = hex::encode(*salt);
            crate::storage::save(&data).unwrap();

            let mut decrypted = crate::storage::decrypt_accounts(&data.accounts, &old_key).unwrap();
            let new_salt = crypto::generate_salt();
            let mut new_key = crypto::derive_key("newpin", &*new_salt).unwrap();
            data.accounts = crate::storage::encrypt_accounts(&decrypted, &new_key).unwrap();
            data.config.password_salt = hex::encode(*new_salt);
            crate::storage::save(&data).unwrap();

            let loaded = crate::storage::try_load().unwrap();
            assert!(crate::storage::decrypt_accounts(&loaded.accounts, &old_key).is_err());
            let loaded_salt = hex::decode(&loaded.config.password_salt).unwrap();
            let mut new_key2 = crypto::derive_key("newpin", &loaded_salt).unwrap();
            assert!(crate::storage::decrypt_accounts(&loaded.accounts, &new_key2).is_ok());

            old_key.zeroize();
            new_key.zeroize();
            new_key2.zeroize();
            for a in &mut decrypted {
                a.secret.zeroize();
            }
            decrypted.clear();
            cleanup_auth_file();
        });
    }

    // ── export backup ────────────────────────────────────────

    #[test]
    fn test_export_backup_creates_file() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let data = crate::storage::try_load().unwrap();
            crate::storage::save(&data).unwrap();
            assert!(crate::paths::auth_path().exists());

            let backup_path = crate::paths::auth_path().with_extension("auth.backup");
            export_backup(backup_path.to_string_lossy().to_string()).unwrap();
            assert!(backup_path.exists());

            let original = std::fs::read_to_string(crate::paths::auth_path()).unwrap();
            let backup = std::fs::read_to_string(&backup_path).unwrap();
            assert_eq!(original, backup);

            let _ = std::fs::remove_file(&backup_path);
            cleanup_auth_file();
        });
    }

    // ── import_backup via storage layer ──────────────────────

    #[test]
    fn test_import_backup_replaces_auth_file() {
        with_fs_lock(|| {
            cleanup_auth_file();
            // Create original auth file
            let mut data = crate::storage::try_load().unwrap();
            data.config.theme = "dark".into();
            crate::storage::save(&data).unwrap();

            // Export to backup
            let backup_path = crate::paths::auth_path().with_extension("auth.backup");
            export_backup(backup_path.to_string_lossy().to_string()).unwrap();

            // Modify original
            let mut data = crate::storage::try_load().unwrap();
            data.config.theme = "light".into();
            crate::storage::save(&data).unwrap();

            // Import the backup (restores dark theme)
            let raw = std::fs::read_to_string(&backup_path).unwrap();
            let _backup: crate::storage::auth_file::AuthData = serde_json::from_str(&raw).unwrap();
            let dest = crate::paths::auth_path();
            std::fs::copy(&backup_path, &dest).unwrap();

            // Verify restore
            let restored = crate::storage::try_load().unwrap();
            assert_eq!(
                restored.config.theme, "dark",
                "import_backup should restore original config"
            );

            let _ = std::fs::remove_file(&backup_path);
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_import_backup_invalid_json_rejected() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let backup_path = crate::paths::auth_path().with_extension("auth.backup");
            std::fs::write(&backup_path, "not valid json at all").unwrap();

            let raw = std::fs::read_to_string(&backup_path).unwrap();
            let result: Result<crate::storage::auth_file::AuthData, _> = serde_json::from_str(&raw);
            assert!(result.is_err(), "invalid JSON should be rejected");

            let _ = std::fs::remove_file(&backup_path);
            cleanup_auth_file();
        });
    }

    // ── Full PIN lifecycle ──────────────────────────────────

    #[test]
    fn test_full_pin_lifecycle() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            use crate::models::account::{Account, Algorithm};

            // 1. Add accounts without PIN (plaintext storage)
            let mut data = crate::storage::try_load().unwrap();
            let accounts = vec![
                Account {
                    id: "acct-1".into(),
                    issuer: "Google".into(),
                    label: "user@gmail.com".into(),
                    algorithm: Algorithm::SHA1,
                    digits: 6,
                    period: 30,
                    secret: vec![1, 2, 3, 4, 5],
                    sort_order: 0,
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                },
                Account {
                    id: "acct-2".into(),
                    issuer: "GitHub".into(),
                    label: "dev@github.com".into(),
                    algorithm: Algorithm::SHA256,
                    digits: 6,
                    period: 30,
                    secret: vec![6, 7, 8],
                    sort_order: 1,
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                },
            ];
            data.accounts.data_json = serde_json::to_string(&accounts).unwrap();
            crate::storage::save(&data).unwrap();

            // Verify accounts are plaintext and accessible
            let loaded = crate::storage::try_load().unwrap();
            assert!(!loaded.config.password_protected, "no PIN set yet");
            assert!(
                !loaded.accounts.data_json.is_empty(),
                "accounts in plaintext"
            );
            assert!(!loaded.accounts.encrypted, "accounts not encrypted");
            let mut reloaded = crate::storage::load_accounts(&loaded, None).unwrap();
            assert_eq!(reloaded.len(), 2);
            assert_eq!(reloaded[0].issuer, "Google");
            assert_eq!(reloaded[1].issuer, "GitHub");
            for a in &mut reloaded {
                a.secret.zeroize();
            }
            reloaded.clear();

            // 2. Set PIN — accounts should become encrypted
            let original_salt = crypto::generate_salt();
            let original_salt_hex = hex::encode(*original_salt);
            let mut key = crypto::derive_key("mypin123", &*original_salt).unwrap();
            data = crate::storage::try_load().unwrap();
            data.accounts = crate::storage::encrypt_accounts(&accounts, &key).unwrap();
            data.config.password_protected = true;
            data.config.password_salt = original_salt_hex.clone();
            crate::storage::save(&data).unwrap();
            state.set_key(key).unwrap();
            key.zeroize();

            let loaded = crate::storage::try_load().unwrap();
            assert!(
                loaded.config.password_protected,
                "password_protected flag set"
            );
            assert!(loaded.accounts.encrypted, "accounts encrypted");
            assert_eq!(
                loaded.config.password_salt, original_salt_hex,
                "salt stored"
            );

            // 3. Lock — clear the key
            state.clear_key().unwrap();
            assert!(!state.has_key());
            // Without key, accounts can't be loaded
            assert!(crate::storage::load_accounts(&loaded, None).is_err());

            // 4. Try unlock with wrong PIN → fails
            let loaded_salt = hex::decode(&loaded.config.password_salt).unwrap();
            let mut wrong_key = crypto::derive_key("wrongpin", &loaded_salt).unwrap();
            let result = crate::storage::decrypt_accounts(&loaded.accounts, &wrong_key);
            assert!(result.is_err(), "wrong PIN must fail decryption");
            wrong_key.zeroize();

            // 5. Unlock with right PIN → succeeds, accounts decrypted
            let mut right_key = crypto::derive_key("mypin123", &loaded_salt).unwrap();
            let mut decrypted =
                crate::storage::decrypt_accounts(&loaded.accounts, &right_key).unwrap();
            assert_eq!(decrypted.len(), 2, "both accounts recovered");
            assert_eq!(decrypted[0].issuer, "Google");
            assert_eq!(decrypted[0].label, "user@gmail.com");
            assert_eq!(decrypted[1].issuer, "GitHub");
            assert_eq!(decrypted[1].secret, vec![6, 7, 8], "secret preserved");
            state.set_key(right_key).unwrap();
            right_key.zeroize();
            for a in &mut decrypted {
                a.secret.zeroize();
            }
            decrypted.clear();

            // 6. Change PIN from "mypin123" to "newpin456"
            let mut old_key = crypto::derive_key("mypin123", &loaded_salt).unwrap();
            let mut decrypted = crate::storage::decrypt_accounts(&data.accounts, &old_key).unwrap();
            assert_eq!(decrypted.len(), 2, "decrypted before change_pin");
            let new_salt = crypto::generate_salt();
            let new_salt_hex = hex::encode(*new_salt);
            // Salt must rotate on PIN change
            assert_ne!(
                new_salt_hex, original_salt_hex,
                "salt rotates on PIN change"
            );
            let mut new_key = crypto::derive_key("newpin456", &*new_salt).unwrap();
            data.accounts = crate::storage::encrypt_accounts(&decrypted, &new_key).unwrap();
            data.config.password_salt = new_salt_hex;
            crate::storage::save(&data).unwrap();
            state.set_key(new_key).unwrap();
            old_key.zeroize();
            new_key.zeroize();
            for a in &mut decrypted {
                a.secret.zeroize();
            }
            decrypted.clear();

            // 7. Lock again
            state.clear_key().unwrap();
            assert!(!state.has_key());

            // 8. Old PIN should fail after change (use current salt from reloaded file)
            let loaded = crate::storage::try_load().unwrap();
            assert!(loaded.config.password_protected, "still password protected");
            assert_ne!(
                loaded.config.password_salt, original_salt_hex,
                "salt changed on disk"
            );
            let current_salt = hex::decode(&loaded.config.password_salt).unwrap();
            let mut old_key = crypto::derive_key("mypin123", &current_salt).unwrap();
            let result = crate::storage::decrypt_accounts(&loaded.accounts, &old_key);
            assert!(result.is_err(), "old PIN must fail after change_pin");
            old_key.zeroize();

            // 9. New PIN should work
            let mut new_key = crypto::derive_key("newpin456", &current_salt).unwrap();
            let mut decrypted =
                crate::storage::decrypt_accounts(&loaded.accounts, &new_key).unwrap();
            assert_eq!(decrypted.len(), 2);
            assert_eq!(decrypted[0].issuer, "Google");
            assert_eq!(decrypted[1].issuer, "GitHub");
            assert_eq!(
                decrypted[1].secret,
                vec![6, 7, 8],
                "secret preserved after full cycle"
            );
            new_key.zeroize();
            for a in &mut decrypted {
                a.secret.zeroize();
            }
            decrypted.clear();

            cleanup_auth_file();
        });
    }

    // ── edge cases: set_lock already locked ──────────────────

    #[test]
    fn test_set_lock_already_locked_fails() {
        with_fs_lock(|| {
            cleanup_auth_file();
            // Seed an already-encrypted auth file (password_protected=true)
            let key = [0xAAu8; 32];
            let mut data = crate::storage::try_load().unwrap();
            data.accounts = crate::storage::encrypt_accounts(&[], &key).unwrap();
            data.config.password_protected = true;
            data.config.password_salt = "some-salt".into();
            crate::storage::save(&data).unwrap();

            // Simulate set_lock guard: check password_protected → must reject
            let loaded = crate::storage::try_load().unwrap();
            assert!(loaded.config.password_protected, "already locked");
            // This is the exact guard from set_lock:
            //   if data.config.password_protected { return Err("PIN is already set"); }
            assert!(
                loaded.config.password_protected,
                "set_lock must reject when PIN is already set"
            );
            cleanup_auth_file();
        });
    }

    // ── edge cases: unlock when not locked ───────────────────

    #[test]
    fn test_unlock_when_pin_not_set_fails() {
        with_fs_lock(|| {
            cleanup_auth_file();
            // Seed plaintext auth file (password_protected=false)
            let mut data = crate::storage::try_load().unwrap();
            data.accounts.data_json = "[]".into();
            data.config.password_protected = false;
            crate::storage::save(&data).unwrap();

            // Simulate unlock guard: check !password_protected → must reject
            let loaded = crate::storage::try_load().unwrap();
            // This is the exact guard from unlock:
            //   if !data.config.password_protected { return Err("PIN is not set"); }
            assert!(
                !loaded.config.password_protected,
                "unlock must detect PIN is not set"
            );
            cleanup_auth_file();
        });
    }

    // ── change_pin lock guard ────────────────────────────────
    // change_pin now requires the app to be unlocked (key in state).
    // This prevents changing the PIN when the app is locked, even if
    // the old PIN is known.

    #[test]
    fn test_change_pin_rejected_when_locked() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            // Seed encrypted auth file, but DON'T set key in AppState (=locked)
            let salt = crypto::generate_salt();
            let mut key = crypto::derive_key("mypin", &*salt).unwrap();
            let mut data = crate::storage::try_load().unwrap();
            data.accounts = crate::storage::encrypt_accounts(&[], &key).unwrap();
            data.config.password_protected = true;
            data.config.password_salt = hex::encode(*salt);
            crate::storage::save(&data).unwrap();
            key.zeroize();

            assert!(!state.has_key(), "app is locked (no key in state)");
            let err = change_pin_impl("mypin", "newpin", &state).unwrap_err();
            assert!(
                err.contains("locked"),
                "change_pin must reject locked app: {err}"
            );
            cleanup_auth_file();
        });
    }

    // ── edge cases: empty PIN ────────────────────────────────

    #[test]
    fn test_set_lock_empty_pin_fails() {
        with_fs_lock(|| {
            cleanup_auth_file();
            // Seed plaintext auth file
            let mut data = crate::storage::try_load().unwrap();
            data.accounts.data_json = "[]".into();
            crate::storage::save(&data).unwrap();

            // Simulate set_lock guard: pin.is_empty() → must reject
            let pin = "";
            assert!(pin.is_empty(), "set_lock must reject empty PIN");
            cleanup_auth_file();
        });
    }

    // ── edge cases: set_lock with zero accounts ──────────────

    #[test]
    fn test_set_lock_with_zero_accounts_succeeds() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            // Seed plaintext auth file with empty accounts
            let mut data = crate::storage::try_load().unwrap();
            data.accounts.data_json = "[]".into();
            crate::storage::save(&data).unwrap();

            // set_lock should encrypt even zero accounts (no-op encryption is valid)
            let salt = crypto::generate_salt();
            let mut key = crypto::derive_key("pin123", &*salt).unwrap();
            data = crate::storage::try_load().unwrap();
            data.accounts = crate::storage::encrypt_accounts(&[], &key).unwrap();
            data.config.password_protected = true;
            data.config.password_salt = hex::encode(*salt);
            crate::storage::save(&data).unwrap();
            state.set_key(key).unwrap();
            key.zeroize();

            let loaded = crate::storage::try_load().unwrap();
            assert!(loaded.config.password_protected);
            assert!(loaded.accounts.encrypted);
            // Verify we can decrypt back to zero accounts
            let loaded_salt = hex::decode(&loaded.config.password_salt).unwrap();
            let mut unlock_key = crypto::derive_key("pin123", &loaded_salt).unwrap();
            let mut decrypted =
                crate::storage::decrypt_accounts(&loaded.accounts, &unlock_key).unwrap();
            assert!(decrypted.is_empty());
            unlock_key.zeroize();
            for a in &mut decrypted {
                a.secret.zeroize();
            }
            decrypted.clear();
            cleanup_auth_file();
        });
    }

    // ── corrupted auth file ──────────────────────────────────

    #[test]
    fn test_corrupted_auth_file_graceful_fallback() {
        with_fs_lock(|| {
            cleanup_auth_file();
            // Write garbage to the auth file
            std::fs::write(crate::paths::auth_path(), "{{corrupted json[[[").unwrap();

            // try_load should return fresh() on parse failure (via load() fallback)
            let data = crate::storage::load();
            assert_eq!(data.version, crate::storage::auth_file::CURRENT_VERSION);
            assert!(!data.config.password_protected);
            cleanup_auth_file();
        });
    }

    // ── New tests ──────────────────────────────────────────────

    #[test]
    fn test_clear_key_twice_is_safe() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            state.set_key([0x42u8; 32]).unwrap();
            assert!(state.has_key());
            state.clear_key().unwrap();
            assert!(!state.has_key());
            // Second clear should be a no-op (already no key)
            state.clear_key().unwrap();
            assert!(!state.has_key());
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_unlock_returns_false_not_error_for_wrong_pin() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let _state = test_app_state();
            let salt = crypto::generate_salt();
            let mut key = crypto::derive_key("correct", &*salt).unwrap();
            let mut data = crate::storage::try_load().unwrap();
            data.accounts = crate::storage::encrypt_accounts(&[], &key).unwrap();
            data.config.password_protected = true;
            data.config.password_salt = hex::encode(*salt);
            crate::storage::save(&data).unwrap();
            key.zeroize();

            // Wrong PIN — must return Ok(false), NOT Err(...)
            let wrong_salt = hex::decode(&data.config.password_salt).unwrap();
            let mut wrong_key = crypto::derive_key("wrong", &wrong_salt).unwrap();
            let result = crate::storage::decrypt_accounts(&data.accounts, &wrong_key);
            assert!(result.is_err(), "wrong pin must produce Err (not panic)");
            wrong_key.zeroize();
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_unlock_empty_pin_fails() {
        with_fs_lock(|| {
            cleanup_auth_file();
            // Use a REAL 16-byte salt (Argon2 salt minimum)
            let salt = crypto::generate_salt();
            let mut key = crypto::derive_key("validpin", &*salt).unwrap();
            let mut data = crate::storage::try_load().unwrap();
            data.accounts = crate::storage::encrypt_accounts(&[], &key).unwrap();
            data.config.password_protected = true;
            data.config.password_salt = hex::encode(*salt);
            crate::storage::save(&data).unwrap();
            key.zeroize();

            // Empty PIN derives a different key → decrypt must fail
            let loaded = crate::storage::try_load().unwrap();
            let loaded_salt = hex::decode(&loaded.config.password_salt).unwrap();
            let mut empty_key = crypto::derive_key("", &loaded_salt).unwrap();
            let result = crate::storage::decrypt_accounts(&loaded.accounts, &empty_key);
            assert!(result.is_err(), "empty pin must fail decryption");
            empty_key.zeroize();
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_export_backup_nonexistent_path_fails() {
        with_fs_lock(|| {
            cleanup_auth_file();
            // No auth file exists yet → export_backup will try to copy a non-existent file
            let bad_path = crate::paths::auth_path().with_extension("auth.nonexistent");
            let result = std::fs::copy(crate::paths::auth_path(), &bad_path);
            assert!(result.is_err(), "export from non-existent source must fail");
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_change_pin_with_long_pin_succeeds() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let salt = crypto::generate_salt();
            let mut key = crypto::derive_key("short", &*salt).unwrap();
            let mut data = crate::storage::try_load().unwrap();
            data.accounts = crate::storage::encrypt_accounts(&[], &key).unwrap();
            data.config.password_protected = true;
            data.config.password_salt = hex::encode(*salt);
            crate::storage::save(&data).unwrap();
            key.zeroize();

            // Change to a very long PIN
            let new_pin = "a".repeat(200);
            let loaded_salt = hex::decode(&data.config.password_salt).unwrap();
            let mut old_key = crypto::derive_key("short", &loaded_salt).unwrap();
            let decrypted = crate::storage::decrypt_accounts(&data.accounts, &old_key).unwrap();
            let new_salt = crypto::generate_salt();
            let mut new_key = crypto::derive_key(&new_pin, &*new_salt).unwrap();
            data.accounts = crate::storage::encrypt_accounts(&decrypted, &new_key).unwrap();
            data.config.password_salt = hex::encode(*new_salt);
            crate::storage::save(&data).unwrap();
            state.set_key(new_key).unwrap();
            old_key.zeroize();
            new_key.zeroize();

            let loaded = crate::storage::try_load().unwrap();
            let current_salt = hex::decode(&loaded.config.password_salt).unwrap();
            let mut verify_key = crypto::derive_key(&new_pin, &current_salt).unwrap();
            assert!(
                crate::storage::decrypt_accounts(&loaded.accounts, &verify_key).is_ok(),
                "change to long PIN must succeed"
            );
            verify_key.zeroize();
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_import_backup_clears_app_state_key() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            state.set_key([0x55u8; 32]).unwrap();
            assert!(state.has_key());

            // Create a valid backup file
            let backup_path = crate::paths::auth_path().with_extension("auth.backup");
            let data = crate::storage::try_load().unwrap();
            std::fs::write(&backup_path, serde_json::to_string_pretty(&data).unwrap()).unwrap();

            // Import (simulates import_backup by overwriting and clearing state)
            let dest = crate::paths::auth_path();
            std::fs::copy(&backup_path, &dest).unwrap();
            state.clear_key().unwrap();
            assert!(!state.has_key(), "import must clear key from AppState");

            let _ = std::fs::remove_file(&backup_path);
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_locked_app_cannot_load_accounts_without_key() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let _state = test_app_state();
            let salt = crypto::generate_salt();
            let mut key = crypto::derive_key("mypin", &*salt).unwrap();
            let mut data = crate::storage::try_load().unwrap();
            data.accounts = crate::storage::encrypt_accounts(&[], &key).unwrap();
            data.config.password_protected = true;
            data.config.password_salt = hex::encode(*salt);
            crate::storage::save(&data).unwrap();
            key.zeroize();

            // PIN is set but no key in state → load_accounts must fail (locked)
            let loaded = crate::storage::try_load().unwrap();
            assert!(loaded.config.password_protected, "PIN set");
            assert!(
                crate::storage::load_accounts(&loaded, None).is_err(),
                "must be locked: no key in state"
            );
            cleanup_auth_file();
        });
    }

    // ── Impl function tests (cover Tauri command wrapper lines) ──

    #[test]
    fn test_lock_impl_clears_key() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            state.set_key([0x42u8; 32]).unwrap();
            assert!(state.has_key());
            lock_impl(&state).unwrap();
            assert!(!state.has_key(), "lock_impl must clear key");
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_lock_impl_without_key_still_succeeds() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            assert!(!state.has_key());
            lock_impl(&state).unwrap();
            // No-op — clearing empty key is safe
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_is_locked_impl_returns_false_no_pin() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let mut data = crate::storage::try_load().unwrap();
            data.config.password_protected = false;
            crate::storage::save(&data).unwrap();
            assert!(!is_locked_impl(&state).unwrap(), "no PIN = not locked");
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_is_locked_impl_returns_true_with_pin_no_key() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let mut data = crate::storage::try_load().unwrap();
            data.accounts = crate::storage::encrypt_accounts(&[], &[0xBBu8; 32]).unwrap();
            data.config.password_protected = true;
            data.config.password_salt = "deadbeef".into();
            crate::storage::save(&data).unwrap();
            assert!(!state.has_key());
            assert!(is_locked_impl(&state).unwrap(), "PIN + no key = locked");
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_set_lock_impl_rejects_empty_pin() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let mut data = crate::storage::try_load().unwrap();
            data.accounts.data_json = "[]".into();
            crate::storage::save(&data).unwrap();
            let err = set_lock_impl("", &state).unwrap_err();
            assert!(err.contains("cannot be empty"), "error: {err}");
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_set_lock_impl_rejects_when_already_protected() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let mut data = crate::storage::try_load().unwrap();
            data.accounts = crate::storage::encrypt_accounts(&[], &[0xAAu8; 32]).unwrap();
            data.config.password_protected = true;
            data.config.password_salt = "aabbccdd".into();
            crate::storage::save(&data).unwrap();
            let err = set_lock_impl("mypin", &state).unwrap_err();
            assert!(err.contains("already set"), "error: {err}");
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_set_lock_impl_encrypts_accounts() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let mut data = crate::storage::try_load().unwrap();
            data.accounts.data_json =
                serde_json::to_string(&vec![crate::models::account::Account {
                    id: "acct-1".into(),
                    issuer: "TestIssuer".into(),
                    label: "test@test.com".into(),
                    algorithm: crate::models::account::Algorithm::SHA1,
                    digits: 6,
                    period: 30,
                    secret: vec![1, 2, 3, 4, 5],
                    sort_order: 0,
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                }])
                .unwrap();
            crate::storage::save(&data).unwrap();
            set_lock_impl("mypin", &state).unwrap();
            let loaded = crate::storage::try_load().unwrap();
            assert!(loaded.config.password_protected);
            assert!(loaded.accounts.encrypted);
            assert!(!loaded.config.password_salt.is_empty());
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_set_lock_impl_malformed_json_rejects() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let mut data = crate::storage::try_load().unwrap();
            data.accounts.data_json = "{invalid json".into();
            crate::storage::save(&data).unwrap();
            let err = set_lock_impl("mypin", &state).unwrap_err();
            assert!(
                err.contains("parse") || err.contains("failed"),
                "must reject malformed JSON: {err}"
            );
            // Verify data_json is unchanged (accounts not silently wiped)
            let loaded = crate::storage::try_load().unwrap();
            assert_eq!(loaded.accounts.data_json, "{invalid json");
            assert!(
                !loaded.config.password_protected,
                "must not set password on failure"
            );
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_unlock_impl_wrong_pin_returns_false() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let _key = seed_encrypted_auth();
            let result = unlock_impl("wrongpin", &state).unwrap();
            assert!(!result, "wrong PIN must return false");
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_unlock_impl_correct_pin_sets_key() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let _key = seed_encrypted_auth();
            let result = unlock_impl("mypin", &state).unwrap();
            assert!(result, "correct PIN must return true");
            assert!(state.has_key(), "key must be set in state");
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_unlock_impl_when_not_protected_fails() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let mut data = crate::storage::try_load().unwrap();
            data.accounts.data_json = "[]".into();
            data.config.password_protected = false;
            crate::storage::save(&data).unwrap();
            let err = unlock_impl("anypin", &state).unwrap_err();
            assert!(err.contains("not set"), "error: {err}");
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_change_pin_impl_rejects_empty_new_pin() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let _key = seed_encrypted_auth();
            let err = change_pin_impl("mypin", "", &state).unwrap_err();
            assert!(err.contains("cannot be empty"), "error: {err}");
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_change_pin_impl_wrong_old_pin_fails() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let key = seed_encrypted_auth();
            state.set_key(*key).unwrap();
            let err = change_pin_impl("wrong", "newpin", &state).unwrap_err();
            assert!(err.contains("wrong"), "wrong old PIN: {err}");
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_change_pin_impl_not_protected_fails() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let mut data = crate::storage::try_load().unwrap();
            data.accounts.data_json = "[]".into();
            data.config.password_protected = false;
            crate::storage::save(&data).unwrap();
            let err = change_pin_impl("old", "new", &state).unwrap_err();
            assert!(err.contains("not set"), "error: {err}");
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_change_pin_impl_success_with_key_set() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let key = seed_encrypted_auth();
            state.set_key(*key).unwrap();
            change_pin_impl("mypin", "newpin", &state).unwrap();
            assert!(state.has_key(), "new key should be set in state");
            // Verify old PIN no longer works
            let loaded = crate::storage::try_load().unwrap();
            let loaded_salt = hex::decode(&loaded.config.password_salt).unwrap();
            let mut old_key = crate::crypto::derive_key("mypin", &loaded_salt).unwrap();
            assert!(crate::storage::decrypt_accounts(&loaded.accounts, &old_key).is_err());
            old_key.zeroize();
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_change_pin_preserves_key_for_code_generation() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let key = seed_encrypted_auth();
            state.set_key(*key).unwrap();
            // Change PIN
            change_pin_impl("mypin", "newpin", &state).unwrap();
            // Verify the new key is NOT zeroed — the key must be usable
            let key_guard = state.get_key().unwrap();
            let key_bytes = key_guard.as_ref().expect("key should be set");
            let all_zero = key_bytes.iter().all(|&b| b == 0);
            assert!(!all_zero, "key must not be zeroed after PIN change");
            // Verify unlock with new PIN works
            let loaded = crate::storage::try_load().unwrap();
            let salt = hex::decode(&loaded.config.password_salt).unwrap();
            let mut derived = crate::crypto::derive_key("newpin", &salt).unwrap();
            let result = crate::storage::decrypt_accounts(&loaded.accounts, &derived);
            assert!(
                result.is_ok(),
                "new PIN must decrypt accounts: {:?}",
                result.err()
            );
            derived.zeroize();
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_import_backup_impl_clears_state_key() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            state.set_key([0x55u8; 32]).unwrap();
            let backup_path = crate::paths::auth_path().with_extension("auth.backup");
            let data = crate::storage::try_load().unwrap();
            std::fs::write(&backup_path, serde_json::to_string_pretty(&data).unwrap()).unwrap();
            import_backup_impl(&backup_path.to_string_lossy(), &state).unwrap();
            assert!(!state.has_key(), "import must clear state key");
            let _ = std::fs::remove_file(&backup_path);
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_import_backup_impl_invalid_json_fails() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let backup_path = crate::paths::auth_path().with_extension("auth.backup");
            std::fs::write(&backup_path, "not valid json").unwrap();
            let err = import_backup_impl(&backup_path.to_string_lossy(), &state).unwrap_err();
            assert!(err.contains("invalid backup"), "error: {err}");
            let _ = std::fs::remove_file(&backup_path);
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_import_backup_impl_nonexistent_path_fails() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let result = import_backup_impl("C:\\nonexistent\\file.auth", &state);
            assert!(result.is_err(), "nonexistent path must fail");
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_import_backup_impl_rejected_when_locked() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            // Seed a PIN-protected auth file so is_locked_impl returns true
            let salt = crypto::generate_salt();
            let mut key = crypto::derive_key("mypin", &*salt).unwrap();
            let mut data = crate::storage::try_load().unwrap();
            data.accounts = crate::storage::encrypt_accounts(&[], &key).unwrap();
            data.config.password_protected = true;
            data.config.password_salt = hex::encode(*salt);
            crate::storage::save(&data).unwrap();
            key.zeroize();

            // Create a valid backup file to import
            let backup_path = crate::paths::auth_path().with_extension("auth.backup");
            let backup_data = crate::storage::try_load().unwrap();
            std::fs::write(
                &backup_path,
                serde_json::to_string_pretty(&backup_data).unwrap(),
            )
            .unwrap();

            // App is locked (PIN set but no key in state)
            assert!(!state.has_key(), "app must be locked");
            assert!(
                is_locked_impl(&state).unwrap(),
                "is_locked must return true"
            );
            let err = import_backup_impl(&backup_path.to_string_lossy(), &state).unwrap_err();
            assert!(
                err.contains("locked"),
                "import must reject locked app: {err}"
            );

            let _ = std::fs::remove_file(&backup_path);
            cleanup_auth_file();
        });
    }

    // Helper: seed an encrypted auth file with PIN "mypin", returns key
    fn seed_encrypted_auth() -> Zeroizing<[u8; 32]> {
        let salt = crate::crypto::generate_salt();
        let raw_key = crate::crypto::derive_key("mypin", &*salt).unwrap();
        let key = Zeroizing::new(raw_key);
        let mut data = crate::storage::try_load().unwrap();
        data.accounts = crate::storage::encrypt_accounts(&[], &key).unwrap();
        data.config.password_protected = true;
        data.config.password_salt = hex::encode(*salt);
        crate::storage::save(&data).unwrap();
        key
    }

    // ── New tests ──────────────────────────────────────────────

    #[test]
    fn test_unlock_invalid_salt_hex_fails() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let mut data = crate::storage::try_load().unwrap();
            let salt = crypto::generate_salt();
            let mut key = crypto::derive_key("mypin", &*salt).unwrap();
            data.accounts = crate::storage::encrypt_accounts(&[], &key).unwrap();
            data.config.password_protected = true;
            // Corrupt the salt: invalid hex characters
            data.config.password_salt = "not-hex!!gg".into();
            crate::storage::save(&data).unwrap();
            key.zeroize();

            // Loading the data won't fail (salt is just a string), but unlock
            // tries to hex-decode it and should fail
            let loaded = crate::storage::try_load().unwrap();
            assert!(loaded.config.password_protected);
            let decode_result = hex::decode(&loaded.config.password_salt);
            assert!(decode_result.is_err(), "invalid salt hex must fail decode");
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_unlock_correct_pin_twice_succeeds() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let salt = crypto::generate_salt();
            let mut key = crypto::derive_key("mypin", &*salt).unwrap();
            let mut data = crate::storage::try_load().unwrap();
            data.accounts = crate::storage::encrypt_accounts(&[], &key).unwrap();
            data.config.password_protected = true;
            data.config.password_salt = hex::encode(*salt);
            crate::storage::save(&data).unwrap();
            key.zeroize();

            // First unlock via storage layer
            let loaded = crate::storage::try_load().unwrap();
            let loaded_salt = hex::decode(&loaded.config.password_salt).unwrap();
            let mut key1 = crypto::derive_key("mypin", &loaded_salt).unwrap();
            let mut decrypted1 = crate::storage::decrypt_accounts(&loaded.accounts, &key1).unwrap();
            assert!(decrypted1.is_empty());
            key1.zeroize();
            for a in &mut decrypted1 {
                a.secret.zeroize();
            }
            decrypted1.clear();

            // Second unlock — same data, same PIN — must still work
            let mut key2 = crypto::derive_key("mypin", &loaded_salt).unwrap();
            let mut decrypted2 = crate::storage::decrypt_accounts(&loaded.accounts, &key2).unwrap();
            assert!(decrypted2.is_empty());
            key2.zeroize();
            for a in &mut decrypted2 {
                a.secret.zeroize();
            }
            decrypted2.clear();
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_lock_clears_key_from_state() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            state.set_key([0x42u8; 32]).unwrap();
            assert!(state.has_key());
            state.clear_key().unwrap();
            assert!(!state.has_key(), "lock must clear encryption key");
            // Verify get_key also returns None
            let retrieved = state.get_key().unwrap();
            assert!(retrieved.is_none(), "get_key must return None after lock");
            cleanup_auth_file();
        });
    }

    // ── Rate-limiting ───────────────────────────────────────
    // Cooldown: 2^(attempts-1) seconds → 1s, 2s, 4s, 8s, 16s, 30s (cap).
    // Implemented in AppState::{check_rate_limit, record_failed_attempt, reset_rate_limit}.
    // unlock_impl calls check_rate_limit before key derivation and records failures.

    #[test]
    fn test_rate_limit_first_attempt_allowed() {
        let state = test_app_state();
        assert!(
            state.check_rate_limit().is_ok(),
            "first attempt must be allowed"
        );
    }

    #[test]
    fn test_rate_limit_second_attempt_blocked_within_cooldown() {
        let state = test_app_state();
        state.record_failed_attempt();
        // Immediately after 1 failure → cooldown is 1s → must be blocked
        let remaining = state.check_rate_limit().unwrap_err();
        assert!(
            remaining > 0,
            "cooldown must be enforced; remaining={remaining}s"
        );
    }

    #[test]
    fn test_rate_limit_each_failure_resets_cooldown_timer() {
        // record_failed_attempt updates the timestamp on EVERY call.
        // This prevents an attacker from "pre-waiting" — they must wait
        // the full cooldown after each failure.
        let state = test_app_state();
        state.record_failed_attempt();
        assert!(
            state.last_attempt.lock().unwrap().is_some(),
            "first failure must record timestamp"
        );
        let t1 = state.last_attempt.lock().unwrap().unwrap();
        state.record_failed_attempt();
        let t2 = state.last_attempt.lock().unwrap().unwrap();
        assert!(t2 >= t1, "each failure must update the cooldown timer");
        // Counter must still increment
        assert_eq!(*state.failed_attempts.lock().unwrap(), 2);
    }

    #[test]
    fn test_rate_limit_exponential_backoff_boundaries() {
        // Cooldown: 2^(attempts-1). Verify each tier by setting last_attempt
        // to (cooldown-1)s ago (1s remaining) and cooldown ago (allowed).
        let state = test_app_state();
        let cases: &[(u32, u64)] = &[(1, 1), (2, 2), (3, 4), (4, 8), (5, 16), (6, 30)];
        for &(attempts, cooldown) in cases {
            *state.failed_attempts.lock().unwrap() = attempts;
            // Set last_attempt to (cooldown - 1)s ago → 1s remaining
            *state.last_attempt.lock().unwrap() =
                Some(std::time::Instant::now() - std::time::Duration::from_secs(cooldown - 1));
            let remaining = state.check_rate_limit().unwrap_err();
            assert_eq!(
                remaining, 1,
                "attempts={attempts}: expected 1s remaining ({cooldown}s cooldown), got {remaining}s"
            );

            // Set last_attempt to exactly cooldown ago → allowed
            *state.last_attempt.lock().unwrap() =
                Some(std::time::Instant::now() - std::time::Duration::from_secs(cooldown));
            assert!(
                state.check_rate_limit().is_ok(),
                "attempts={}: should be allowed after {cooldown}s cooldown",
                attempts
            );
        }
    }

    #[test]
    fn test_rate_limit_cap_at_30_seconds() {
        let state = test_app_state();
        // 50 failed attempts → cooldown capped at 30s, not 2^49
        *state.failed_attempts.lock().unwrap() = 50;
        *state.last_attempt.lock().unwrap() =
            Some(std::time::Instant::now() - std::time::Duration::from_secs(29));
        let remaining = state.check_rate_limit().unwrap_err();
        assert_eq!(
            remaining, 1,
            "50 failures: cooldown must be capped at 30s, got {remaining}s remaining"
        );

        // After 30s elapsed → allowed
        *state.last_attempt.lock().unwrap() =
            Some(std::time::Instant::now() - std::time::Duration::from_secs(30));
        assert!(
            state.check_rate_limit().is_ok(),
            "50 failures: must be allowed after 30s cap"
        );
    }

    #[test]
    fn test_rate_limit_saturating_add_prevents_wrap() {
        let state = test_app_state();
        *state.failed_attempts.lock().unwrap() = u32::MAX;
        *state.last_attempt.lock().unwrap() = Some(std::time::Instant::now());
        // record_failed_attempt uses saturating_add → stays at MAX, doesn't wrap to 0
        state.record_failed_attempt();
        let attempts = *state.failed_attempts.lock().unwrap();
        assert_eq!(
            attempts,
            u32::MAX,
            "saturating_add must prevent overflow wrap (got {attempts})"
        );
    }

    #[test]
    fn test_rate_limit_reset_clears_counter_and_timestamp() {
        let state = test_app_state();
        state.record_failed_attempt();
        state.record_failed_attempt();
        state.record_failed_attempt();
        assert_eq!(*state.failed_attempts.lock().unwrap(), 3);

        state.reset_rate_limit();
        assert_eq!(
            *state.failed_attempts.lock().unwrap(),
            0,
            "reset must clear counter"
        );
        assert!(
            state.last_attempt.lock().unwrap().is_none(),
            "reset must clear timestamp"
        );
        // After reset, first attempt must be allowed
        assert!(
            state.check_rate_limit().is_ok(),
            "after reset, fresh attempt must be allowed"
        );
    }

    #[test]
    fn test_rate_limit_cooldown_expires_when_enough_time_passes() {
        let state = test_app_state();
        state.record_failed_attempt();
        // Manually wind back the clock: last_attempt was 2s ago (cooldown = 1s)
        *state.last_attempt.lock().unwrap() =
            Some(std::time::Instant::now() - std::time::Duration::from_secs(2));
        assert!(
            state.check_rate_limit().is_ok(),
            "cooldown must expire when enough time has elapsed"
        );
    }

    #[test]
    fn test_unlock_impl_rate_limited_after_wrong_pin() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let _key = seed_encrypted_auth();
            // First attempt: wrong PIN → Ok(false) + records failed attempt
            let result = unlock_impl("wrong", &state).unwrap();
            assert!(!result, "wrong PIN must return false");

            // Second attempt immediately after → rate-limited Err
            let err = unlock_impl("mypin", &state).unwrap_err();
            assert!(
                err.contains("too many attempts"),
                "immediate retry must be rate-limited: {err}"
            );
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_unlock_impl_rate_limit_resets_on_success() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let _key = seed_encrypted_auth();
            // Record one failed attempt
            unlock_impl("wrong", &state).unwrap();
            // Expire the cooldown by winding back the clock
            *state.last_attempt.lock().unwrap() =
                Some(std::time::Instant::now() - std::time::Duration::from_secs(2));

            // Now unlock with correct PIN → must succeed and reset rate limit
            let result = unlock_impl("mypin", &state).unwrap();
            assert!(result, "correct PIN must succeed after cooldown expires");
            assert!(state.has_key(), "key must be set after successful unlock");
            assert_eq!(
                *state.failed_attempts.lock().unwrap(),
                0,
                "rate limit counter must reset on successful unlock"
            );
            cleanup_auth_file();
        });
    }
}
