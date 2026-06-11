use crate::models::account::{Account, AccountSummary, Algorithm};
use crate::storage::{encrypt_accounts, load_accounts, save, try_load, AuthData};
use crate::AppState;
use base32::Alphabet;
use chrono::Utc;
use tauri::State;
use uuid::Uuid;
use zeroize::Zeroize;

fn save_accounts(
    data: &mut AuthData,
    accounts: &[Account],
    key: Option<[u8; 32]>,
) -> Result<(), String> {
    if data.config.password_protected {
        let k = key.ok_or_else(|| "app is locked".to_string())?;
        data.accounts = encrypt_accounts(accounts, &k)?;
    } else {
        data.accounts.data_json = serde_json::to_string(accounts)
            .map_err(|e| format!("failed to serialize accounts: {e}"))?;
        data.accounts.encrypted = false;
        data.accounts.nonce_hex = None;
        data.accounts.ciphertext_hex = None;
    }
    Ok(())
}

/// Zeroize all account secrets and clear the vector.
fn zeroize_accounts(accounts: &mut Vec<Account>) {
    for a in accounts.iter_mut() {
        a.secret.zeroize();
    }
    accounts.clear();
}

/// Decode a secret that may be base32-encoded (manual entry) or raw bytes.
fn decode_secret(input: &str) -> Result<Vec<u8>, String> {
    let trimmed: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    base32::decode(
        Alphabet::Rfc4648 { padding: false },
        &trimmed.to_uppercase(),
    )
    .ok_or_else(|| "invalid base32 secret".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── decode_secret unit tests ──────────────────────────────

    #[test]
    fn test_decode_secret_valid_base32() {
        // GEZDGNBVGY3TQOJQ is the RFC 6238 test secret in base32 (decodes to "1234567890")
        let result = decode_secret("GEZDGNBVGY3TQOJQ").unwrap();
        assert_eq!(result, b"1234567890");
    }

    #[test]
    fn test_decode_secret_with_whitespace() {
        let result = decode_secret("GEZD GNBV GY3T QOJQ").unwrap();
        assert_eq!(result, b"1234567890");
    }

    #[test]
    fn test_decode_secret_lowercase() {
        let result = decode_secret("gezdgnbvg63tqojq").unwrap();
        // Lowercase base32 decodes to same bytes; verify non-empty
        assert!(!result.is_empty());
    }

    #[test]
    fn test_decode_secret_invalid_chars() {
        assert!(decode_secret("!!!!invalid!!!!").is_err());
    }

    #[test]
    fn test_decode_secret_empty() {
        // Empty string decodes to empty bytes (base32 decodes "" to Some(vec![]))
        let result = decode_secret("").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_decode_secret_rfc4648_standard() {
        let result = decode_secret("HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ").unwrap();
        assert!(!result.is_empty());
    }

    // ── Storage-level integration tests ──────────────────────

    fn cleanup_auth_file() {
        let path = crate::paths::auth_path();
        if path.exists() {
            let _ = std::fs::remove_file(&path);
        }
    }

    fn with_fs_lock(f: impl FnOnce()) {
        let _lock = crate::storage::auth_file::FS_TEST_MUTEX.lock().unwrap();
        f();
    }

    fn test_key() -> [u8; 32] {
        [0xAAu8; 32]
    }

    #[test]
    fn test_save_accounts_plaintext_roundtrip() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let mut data = crate::storage::try_load().unwrap();
            let accounts = vec![Account {
                id: "a1".into(), issuer: "Test".into(), label: "x".into(),
                algorithm: Algorithm::SHA1, digits: 6, period: 30,
                secret: vec![1, 2, 3], sort_order: 0,
                created_at: chrono::Utc::now(), updated_at: chrono::Utc::now(),
            }];
            save_accounts(&mut data, &accounts, None).unwrap();
            crate::storage::save(&data).unwrap();

            let loaded = crate::storage::try_load().unwrap();
            assert!(!loaded.accounts.encrypted, "expected plaintext accounts");
            let mut reloaded = crate::storage::load_accounts(&loaded, None).unwrap();
            assert_eq!(reloaded.len(), 1);
            assert_eq!(reloaded[0].issuer, "Test");
            for a in &mut reloaded { a.secret.zeroize(); }
            reloaded.clear();
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_save_accounts_encrypted_roundtrip() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let mut data = crate::storage::try_load().unwrap();
            data.config.password_protected = true;
            let accounts = vec![Account {
                id: "enc1".into(), issuer: "Enc".into(), label: "e".into(),
                algorithm: Algorithm::SHA256, digits: 8, period: 60,
                secret: vec![9, 8, 7], sort_order: 0,
                created_at: chrono::Utc::now(), updated_at: chrono::Utc::now(),
            }];
            let key = test_key();
            save_accounts(&mut data, &accounts, Some(key)).unwrap();
            crate::storage::save(&data).unwrap();

            let loaded = crate::storage::try_load().unwrap();
            assert!(loaded.accounts.encrypted);
            let mut reloaded = crate::storage::load_accounts(&loaded, Some(key)).unwrap();
            assert_eq!(reloaded.len(), 1);
            assert_eq!(reloaded[0].issuer, "Enc");
            for a in &mut reloaded { a.secret.zeroize(); }
            reloaded.clear();
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_save_accounts_locked_fails() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let mut data = crate::storage::try_load().unwrap();
            data.config.password_protected = true;
            let accounts = vec![];
            assert!(save_accounts(&mut data, &accounts, None).is_err());
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_zeroize_accounts_clears_secrets() {
        let mut accounts = vec![Account {
            id: "z".into(), issuer: "Z".into(), label: "z".into(),
            algorithm: Algorithm::SHA1, digits: 6, period: 30,
            secret: vec![1, 2, 3, 4], sort_order: 0,
            created_at: chrono::Utc::now(), updated_at: chrono::Utc::now(),
        }];
        zeroize_accounts(&mut accounts);
        assert!(accounts.is_empty());
    }
}

#[tauri::command]
pub fn add_account(
    issuer: String,
    label: String,
    secret: String,
    algorithm: Option<String>,
    digits: Option<u8>,
    period: Option<u32>,
    state: State<'_, AppState>,
) -> Result<Account, String> {
    let mut data = try_load()?;
    let key_wrapper = state.get_key()?;
    let key: Option<[u8; 32]> = key_wrapper.as_ref().map(|z| **z);
    let mut accounts = load_accounts(&data, key)?;
    // key_wrapper dropped here → auto-zeroized

    let algo = match algorithm.as_deref() {
        Some("SHA256") => Algorithm::SHA256,
        Some("SHA512") => Algorithm::SHA512,
        _ => Algorithm::SHA1,
    };

    let now = Utc::now();
    let account = Account {
        id: Uuid::new_v4().to_string(),
        issuer,
        label,
        algorithm: algo,
        digits: digits.unwrap_or(6),
        period: period.unwrap_or(30),
        secret: decode_secret(&secret)?,
        sort_order: accounts.len() as u32,
        created_at: now,
        updated_at: now,
    };

    let result = account.clone();
    accounts.push(account);
    save_accounts(&mut data, &accounts, key)?;
    data.log = crate::diagnostics::flush_to_log_str();
    save(&data)?;

    // Zeroize decrypted accounts — they've been re-encrypted
    zeroize_accounts(&mut accounts);
    crate::diagnostics::event("account", &format!("added {}", result.id));

    Ok(result)
}

#[tauri::command]
pub fn add_account_from_uri(
    otpauth_uri: String,
    state: State<'_, AppState>,
) -> Result<Account, String> {
    let parsed = crate::utils::otpauth::parse_uri(&otpauth_uri)?;

    let mut data = try_load()?;
    let key_wrapper = state.get_key()?;
    let key: Option<[u8; 32]> = key_wrapper.as_ref().map(|z| **z);
    let mut accounts = load_accounts(&data, key)?;
    // key_wrapper dropped here → auto-zeroized

    let now = Utc::now();
    let account = Account {
        id: Uuid::new_v4().to_string(),
        issuer: parsed.issuer,
        label: parsed.label,
        algorithm: parsed.algorithm,
        digits: parsed.digits,
        period: parsed.period,
        secret: parsed.secret,
        sort_order: accounts.len() as u32,
        created_at: now,
        updated_at: now,
    };

    let result = account.clone();
    accounts.push(account);
    save_accounts(&mut data, &accounts, key)?;
    data.log = crate::diagnostics::flush_to_log_str();
    save(&data)?;

    zeroize_accounts(&mut accounts);
    crate::diagnostics::event("account", &format!("added from URI {}", result.id));

    Ok(result)
}

#[tauri::command]
pub fn remove_account(account_id: String, state: State<'_, AppState>) -> Result<(), String> {
    let mut data = try_load()?;
    let key_wrapper = state.get_key()?;
    let key: Option<[u8; 32]> = key_wrapper.as_ref().map(|z| **z);
    let mut accounts = load_accounts(&data, key)?;
    // key_wrapper dropped here → auto-zeroized

    accounts.retain(|a| a.id != account_id);
    for (i, a) in accounts.iter_mut().enumerate() {
        a.sort_order = i as u32;
    }

    save_accounts(&mut data, &accounts, key)?;
    data.log = crate::diagnostics::flush_to_log_str();
    save(&data)?;

    zeroize_accounts(&mut accounts);
    crate::diagnostics::event("account", &format!("removed {account_id}"));

    Ok(())
}

#[tauri::command]
pub fn update_account(
    account_id: String,
    issuer: Option<String>,
    label: Option<String>,
    sort_order: Option<u32>,
    state: State<'_, AppState>,
) -> Result<Account, String> {
    let mut data = try_load()?;
    let key_wrapper = state.get_key()?;
    let key: Option<[u8; 32]> = key_wrapper.as_ref().map(|z| **z);
    let mut accounts = load_accounts(&data, key)?;
    // key_wrapper dropped here → auto-zeroized

    let account = accounts
        .iter_mut()
        .find(|a| a.id == account_id)
        .ok_or_else(|| format!("account not found: {account_id}"))?;

    if let Some(v) = issuer {
        account.issuer = v;
    }
    if let Some(v) = label {
        account.label = v;
    }
    if let Some(v) = sort_order {
        account.sort_order = v;
    }
    account.updated_at = Utc::now();

    let result = account.clone();
    save_accounts(&mut data, &accounts, key)?;
    data.log = crate::diagnostics::flush_to_log_str();
    save(&data)?;

    zeroize_accounts(&mut accounts);

    Ok(result)
}

#[tauri::command]
pub fn list_accounts(
    search_query: Option<String>,
    state: State<'_, AppState>,
) -> Result<Vec<AccountSummary>, String> {
    let data = try_load()?;
    let key_wrapper = state.get_key()?;
    let key: Option<[u8; 32]> = key_wrapper.as_ref().map(|z| **z);
    let mut accounts = load_accounts(&data, key)?;
    // key_wrapper dropped here → auto-zeroized

    let mut summaries: Vec<AccountSummary> = accounts.iter().map(AccountSummary::from).collect();

    if let Some(query) = search_query {
        let q = query.to_lowercase();
        summaries.retain(|a| {
            a.issuer.to_lowercase().contains(&q) || a.label.to_lowercase().contains(&q)
        });
    }

    summaries.sort_by_key(|a| a.sort_order);

    // Zeroize secrets — only summaries (without secrets) are returned
    zeroize_accounts(&mut accounts);

    Ok(summaries)
}
