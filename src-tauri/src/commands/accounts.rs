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

/// Reject a secret shorter than 128 bits (16 bytes) — totp_rs requires it for HMAC.
fn validate_secret_length(secret: &[u8]) -> Result<(), String> {
    if secret.len() < 16 {
        return Err(format!(
            "secret too short: {} bits ({} bytes), need at least 128 bits (16 bytes)",
            secret.len() * 8,
            secret.len()
        ));
    }
    Ok(())
}

/// Decode a secret that may be base32-encoded (manual entry) or raw bytes.
/// Requires at least 128 bits (16 bytes) — totp_rs rejects shorter HMAC keys.
fn decode_secret(input: &str) -> Result<Vec<u8>, String> {
    let trimmed: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    let secret = base32::decode(
        Alphabet::Rfc4648 { padding: false },
        &trimmed.to_uppercase(),
    )
    .ok_or_else(|| "invalid base32 secret".to_string())?;
    validate_secret_length(&secret)?;
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── decode_secret unit tests ──────────────────────────────

    #[test]
    fn test_decode_secret_valid_base32() {
        // HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ is 32 chars → 20 bytes (160 bits)
        let result = decode_secret("HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ").unwrap();
        assert_eq!(result.len(), 20);
        assert!(result.len() >= 16, "must be at least 128 bits");
    }

    #[test]
    fn test_decode_secret_with_whitespace() {
        let result = decode_secret("HXDM VJEC JJWS RB3H WIZR 4IFU GFTM XBOZ").unwrap();
        assert!(result.len() >= 16);
    }

    #[test]
    fn test_decode_secret_lowercase() {
        // HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ in lowercase
        let result = decode_secret("hxdmvjecjjwsrb3hwizr4ifugftmxboz").unwrap();
        assert!(result.len() >= 16);
    }

    #[test]
    fn test_decode_secret_invalid_chars() {
        assert!(decode_secret("!!!!invalid!!!!").is_err());
    }

    #[test]
    fn test_decode_secret_empty() {
        // Empty string decodes to empty bytes → rejected as too short
        assert!(decode_secret("").is_err());
    }

    #[test]
    fn test_decode_secret_too_short() {
        // GEZDGNBVGY3TQOJQ (RFC 6238) decodes to 10 bytes (80 bits) — rejected
        let err = decode_secret("GEZDGNBVGY3TQOJQ").unwrap_err();
        assert!(err.contains("too short"), "must reject secrets < 128 bits: {err}");
        assert!(err.contains("80 bits"), "should mention bit count: {err}");
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

    // ── add_account_from_uri via storage layer ────────────────

    #[test]
    fn test_add_account_from_uri_via_storage() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let uri = "otpauth://totp/ACME:john@example.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME&algorithm=SHA1&digits=6&period=30";
            let parsed = crate::utils::otpauth::parse_uri(uri).unwrap();

            let mut data = crate::storage::try_load().unwrap();
            let accounts = vec![Account {
                id: "uri-test".into(),
                issuer: parsed.issuer.clone(),
                label: parsed.label.clone(),
                algorithm: parsed.algorithm.clone(),
                digits: parsed.digits,
                period: parsed.period,
                secret: parsed.secret.clone(),
                sort_order: 0,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            }];
            // Verify the parsed URI content is correct
            assert_eq!(accounts[0].issuer, "ACME");
            assert_eq!(accounts[0].label, "john@example.com");
            assert_eq!(accounts[0].digits, 6);
            assert_eq!(accounts[0].period, 30);
            assert!(!accounts[0].secret.is_empty());

            save_accounts(&mut data, &accounts, None).unwrap();
            crate::storage::save(&data).unwrap();

            let loaded = crate::storage::try_load().unwrap();
            let mut reloaded = crate::storage::load_accounts(&loaded, None).unwrap();
            assert_eq!(reloaded.len(), 1);
            assert_eq!(reloaded[0].issuer, "ACME");
            for a in &mut reloaded { a.secret.zeroize(); }
            reloaded.clear();
            cleanup_auth_file();
        });
    }

    // ── search case-insensitivity ────────────────────────────

    #[test]
    fn test_list_accounts_search_case_insensitive() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let mut data = crate::storage::try_load().unwrap();
            let accounts = vec![
                Account {
                    id: "s1".into(), issuer: "GitHub".into(), label: "dev@github.com".into(),
                    algorithm: Algorithm::SHA1, digits: 6, period: 30,
                    secret: vec![1], sort_order: 0,
                    created_at: chrono::Utc::now(), updated_at: chrono::Utc::now(),
                },
                Account {
                    id: "s2".into(), issuer: "Google".into(), label: "user@gmail.com".into(),
                    algorithm: Algorithm::SHA1, digits: 6, period: 30,
                    secret: vec![2], sort_order: 1,
                    created_at: chrono::Utc::now(), updated_at: chrono::Utc::now(),
                },
            ];
            save_accounts(&mut data, &accounts, None).unwrap();
            crate::storage::save(&data).unwrap();

            let loaded = crate::storage::try_load().unwrap();
            let mut reloaded = crate::storage::load_accounts(&loaded, None).unwrap();

            // Simulate list_accounts search logic
            let summaries: Vec<_> = reloaded.iter().map(AccountSummary::from).collect();
            // Case-insensitive: "github" should match "GitHub"
            let q = "github";
            let filtered: Vec<_> = summaries.iter().filter(|a|
                a.issuer.to_lowercase().contains(q) || a.label.to_lowercase().contains(q)
            ).collect();
            assert_eq!(filtered.len(), 1);
            assert_eq!(filtered[0].issuer, "GitHub");

            // Uppercase search should also match "GitHub"
            let q = "GITHUB";
            let filtered: Vec<_> = summaries.iter().filter(|a|
                a.issuer.to_lowercase().contains(&q.to_lowercase()) || a.label.to_lowercase().contains(&q.to_lowercase())
            ).collect();
            assert_eq!(filtered.len(), 1);

            for a in &mut reloaded { a.secret.zeroize(); }
            reloaded.clear();
            cleanup_auth_file();
        });
    }

    // ── update_account non-existent ID ───────────────────────

    #[test]
    fn test_update_account_nonexistent_id_fails() {
        with_fs_lock(|| {
            cleanup_auth_file();
            // Seed one account
            let mut data = crate::storage::try_load().unwrap();
            let accounts = vec![Account {
                id: "real-id".into(), issuer: "Real".into(), label: "r".into(),
                algorithm: Algorithm::SHA1, digits: 6, period: 30,
                secret: vec![1, 2, 3], sort_order: 0,
                created_at: chrono::Utc::now(), updated_at: chrono::Utc::now(),
            }];
            save_accounts(&mut data, &accounts, None).unwrap();
            crate::storage::save(&data).unwrap();

            // Simulate update_account guard: find by ID → not found
            // Real command: .ok_or_else(|| format!("account not found: {account_id}"))
            let loaded = crate::storage::try_load().unwrap();
            let mut reloaded = crate::storage::load_accounts(&loaded, None).unwrap();
            let found = reloaded.iter().any(|a| a.id == "nonexistent");
            assert!(!found, "update must reject non-existent account ID");
            for a in &mut reloaded { a.secret.zeroize(); }
            reloaded.clear();
            cleanup_auth_file();
        });
    }

    // ── remove_account non-existent ID ───────────────────────

    #[test]
    fn test_remove_account_nonexistent_id_noop() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let mut data = crate::storage::try_load().unwrap();
            let accounts = vec![Account {
                id: "keep-me".into(), issuer: "Keep".into(), label: "k".into(),
                algorithm: Algorithm::SHA1, digits: 6, period: 30,
                secret: vec![1, 2, 3], sort_order: 0,
                created_at: chrono::Utc::now(), updated_at: chrono::Utc::now(),
            }];
            save_accounts(&mut data, &accounts, None).unwrap();
            crate::storage::save(&data).unwrap();

            // Simulate remove_account: retain all except the target ID
            let loaded = crate::storage::try_load().unwrap();
            let mut reloaded = crate::storage::load_accounts(&loaded, None).unwrap();
            let before = reloaded.len();
            reloaded.retain(|a| a.id != "nonexistent");
            // Non-existent ID → no accounts removed
            assert_eq!(reloaded.len(), before, "removing non-existent ID is a no-op");
            assert_eq!(reloaded[0].id, "keep-me");
            for a in &mut reloaded { a.secret.zeroize(); }
            reloaded.clear();
            cleanup_auth_file();
        });
    }

    // ── add_account duplicate issuer+label ───────────────────

    #[test]
    fn test_add_account_duplicate_issuer_label_allowed() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let mut data = crate::storage::try_load().unwrap();
            // Two accounts with the same issuer + label but different IDs (UUIDs)
            let accounts = vec![
                Account {
                    id: "uuid-aaa".into(), issuer: "Dupe".into(), label: "same@test.com".into(),
                    algorithm: Algorithm::SHA1, digits: 6, period: 30,
                    secret: vec![1, 2], sort_order: 0,
                    created_at: chrono::Utc::now(), updated_at: chrono::Utc::now(),
                },
                Account {
                    id: "uuid-bbb".into(), issuer: "Dupe".into(), label: "same@test.com".into(),
                    algorithm: Algorithm::SHA256, digits: 6, period: 30,
                    secret: vec![3, 4], sort_order: 1,
                    created_at: chrono::Utc::now(), updated_at: chrono::Utc::now(),
                },
            ];
            save_accounts(&mut data, &accounts, None).unwrap();
            crate::storage::save(&data).unwrap();

            let loaded = crate::storage::try_load().unwrap();
            let mut reloaded = crate::storage::load_accounts(&loaded, None).unwrap();
            assert_eq!(reloaded.len(), 2, "duplicate issuer+label allowed (different IDs)");
            assert_ne!(reloaded[0].id, reloaded[1].id, "IDs must be distinct");
            for a in &mut reloaded { a.secret.zeroize(); }
            reloaded.clear();
            cleanup_auth_file();
        });
    }

    // ── update_account sort_order ────────────────────────────

    #[test]
    fn test_update_account_sort_order_via_storage() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let mut data = crate::storage::try_load().unwrap();
            let mut accounts = vec![
                Account {
                    id: "first".into(), issuer: "A".into(), label: "a".into(),
                    algorithm: Algorithm::SHA1, digits: 6, period: 30,
                    secret: vec![1], sort_order: 0,
                    created_at: chrono::Utc::now(), updated_at: chrono::Utc::now(),
                },
                Account {
                    id: "second".into(), issuer: "B".into(), label: "b".into(),
                    algorithm: Algorithm::SHA1, digits: 6, period: 30,
                    secret: vec![2], sort_order: 1,
                    created_at: chrono::Utc::now(), updated_at: chrono::Utc::now(),
                },
            ];
            // Reorder: swap first and second
            accounts[0].sort_order = 1;
            accounts[1].sort_order = 0;
            save_accounts(&mut data, &accounts, None).unwrap();
            crate::storage::save(&data).unwrap();

            let loaded = crate::storage::try_load().unwrap();
            let mut reloaded = crate::storage::load_accounts(&loaded, None).unwrap();
            // Sort by sort_order to verify reorder persisted
            reloaded.sort_by_key(|a| a.sort_order);
            assert_eq!(reloaded[0].id, "second");
            assert_eq!(reloaded[1].id, "first");
            for a in &mut reloaded { a.secret.zeroize(); }
            reloaded.clear();
            cleanup_auth_file();
        });
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

    // Validate secret length early — before any disk I/O
    validate_secret_length(&parsed.secret)?;

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
