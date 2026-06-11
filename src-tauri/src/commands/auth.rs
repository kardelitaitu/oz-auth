use crate::storage::{decrypt_accounts, encrypt_accounts, save, try_load};
use crate::AppState;
use tauri::State;
use zeroize::Zeroize;

#[tauri::command]
pub fn set_lock(pin: String, state: State<'_, AppState>) -> Result<(), String> {
    if pin.is_empty() {
        return Err("PIN cannot be empty".to_string());
    }

    let mut data = try_load()?;
    if data.config.password_protected {
        return Err("PIN is already set".to_string());
    }

    let salt = crate::crypto::generate_salt();
    let salt_hex = hex::encode(salt);
    let mut key = crate::crypto::derive_key(&pin, &salt)?;

    // Parse current plaintext accounts
    let mut accounts: Vec<crate::models::account::Account> =
        serde_json::from_str(&data.accounts.data_json).unwrap_or_default();

    // Re-encrypt
    data.accounts = encrypt_accounts(&accounts, &key)?;
    data.config.password_protected = true;
    data.config.password_salt = salt_hex;
    data.log = crate::diagnostics::flush_to_log_str();
    save(&data)?;
    state.set_key(key)?;
    // Zeroize derived key and account secrets
    key.zeroize();
    for a in &mut accounts {
        a.secret.zeroize();
    }
    accounts.clear();
    crate::diagnostics::event("security", "PIN set");

    Ok(())
}

#[tauri::command]
pub fn unlock(pin: String, state: State<'_, AppState>) -> Result<bool, String> {
    let data = try_load()?;
    if !data.config.password_protected {
        return Err("PIN is not set".to_string());
    }

    let mut salt = hex::decode(&data.config.password_salt)
        .map_err(|e| format!("invalid salt: {e}"))?;
    let mut key = crate::crypto::derive_key(&pin, &salt)?;

    // Try to decrypt — if it fails, wrong PIN
    let result = match decrypt_accounts(&data.accounts, &key) {
        Ok(mut accounts) => {
            // Zeroize decrypted accounts — we only needed them for validation
            for a in &mut accounts {
                a.secret.zeroize();
            }
            accounts.clear();
            // set_key copies the key into the Zeroizing wrapper; our local
            // copy is zeroized below (arrays are Copy in Rust).
            state.set_key(key)?;
            key.zeroize();
            salt.zeroize();
            crate::diagnostics::event("security", "unlocked");
            Ok(true)
        }
        Err(e) => {
            key.zeroize();
            salt.zeroize();
            if e.contains("wrong password") || e.contains("corrupted") {
                Ok(false)
            } else {
                Err(e)
            }
        }
    };

    result
}

#[tauri::command]
pub fn lock(state: State<'_, AppState>) -> Result<(), String> {
    state.clear_key()?;
    crate::diagnostics::event("security", "locked");
    Ok(())
}

/// Check if the app is locked without cloning the encryption key.
#[tauri::command]
pub fn is_locked(state: State<'_, AppState>) -> Result<bool, String> {
    let data = try_load()?;
    if !data.config.password_protected {
        return Ok(false);
    }
    Ok(!state.has_key())
}

#[tauri::command]
pub fn change_pin(
    old_pin: String,
    new_pin: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    if new_pin.is_empty() {
        return Err("new PIN cannot be empty".to_string());
    }

    let mut data = try_load()?;
    if !data.config.password_protected {
        return Err("PIN is not set".to_string());
    }

    let old_salt = hex::decode(&data.config.password_salt)
        .map_err(|e| format!("invalid salt: {e}"))?;
    let mut old_key = crate::crypto::derive_key(&old_pin, &old_salt)?;

    let mut accounts = decrypt_accounts(&data.accounts, &old_key)
        .map_err(|_| "wrong current PIN".to_string())?;

    let new_salt = crate::crypto::generate_salt();
    let mut new_key = crate::crypto::derive_key(&new_pin, &new_salt)?;
    data.accounts = encrypt_accounts(&accounts, &new_key)?;
    data.config.password_salt = hex::encode(new_salt);
    data.log = crate::diagnostics::flush_to_log_str();
    save(&data)?;

    // Zeroize the old key, account secrets, and new key after use
    old_key.zeroize();
    new_key.zeroize();
    for a in &mut accounts {
        a.secret.zeroize();
    }
    accounts.clear();

    state.set_key(new_key)?;
    crate::diagnostics::event("security", "PIN changed");

    Ok(())
}

#[tauri::command]
pub fn export_backup(path: String) -> Result<(), String> {
    let src = crate::paths::auth_path();
    std::fs::copy(&src, &path)
        .map_err(|e| format!("failed to export backup: {e}"))?;
    crate::diagnostics::event("backup", &format!("exported to {path}"));
    Ok(())
}

#[tauri::command]
pub fn import_backup(path: String, state: State<'_, AppState>) -> Result<(), String> {
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| format!("failed to read backup: {e}"))?;
    let _backup: crate::storage::auth_file::AuthData = serde_json::from_str(&raw)
        .map_err(|e| format!("invalid backup file: {e}"))?;

    let dest = crate::paths::auth_path();
    std::fs::copy(&path, &dest)
        .map_err(|e| format!("failed to import backup: {e}"))?;
    state.clear_key()?;
    crate::diagnostics::event("backup", &format!("imported from {path}"));

    Ok(())
}
