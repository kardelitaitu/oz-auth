//! Combined `.auth` file storage: config + encrypted accounts + log.
//!
//! Format: JSON with version field for future evolution.
//!
//! ```json
//! { "version": 1, "config": {...}, "accounts": {...}, "log": "..." }
//! ```
//!
//! # Memory security
//! All plaintext serialized JSON and decrypted buffers are zeroized
//! after use to prevent secret recovery from memory dumps.

use crate::crypto;
use crate::models::account::Account;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthData {
    pub version: u32,
    pub config: crate::config::Config,
    pub accounts: AccountsPayload,
    pub log: String,
}

/// On-disk representation of the accounts payload (supports encrypted + plaintext).
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AccountsPayload {
    /// Whether the content is AES-256-GCM encrypted.
    #[serde(default)]
    pub encrypted: bool,

    /// Hex-encoded 12-byte nonce (present when encrypted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce_hex: Option<String>,

    /// Hex-encoded ciphertext (present when encrypted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ciphertext_hex: Option<String>,

    /// Plaintext accounts JSON (present when NOT encrypted).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub data_json: String,
}

const CURRENT_VERSION: u32 = 1;

/// Mutex that serializes tests touching the shared `.auth` file.
#[cfg(test)]
pub static FS_TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

// ── Public API ──────────────────────────────────────────────

pub fn auth_path() -> std::path::PathBuf {
    crate::paths::auth_path()
}

pub fn exists() -> bool {
    auth_path().exists()
}

pub fn load() -> AuthData {
    try_load().unwrap_or_else(|_| fresh())
}

pub fn try_load() -> Result<AuthData, String> {
    let path = auth_path();
    if !path.exists() {
        return Ok(fresh());
    }

    let raw = std::fs::read_to_string(&path)
        .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    let mut data: AuthData = serde_json::from_str(&raw)
        .map_err(|e| format!("failed to parse {}: {e}", path.display()))?;

    if reconcile_invariants(&mut data) {
        save(&data)?;
    }

    Ok(data)
}

pub fn save(data: &AuthData) -> Result<(), String> {
    let json = serde_json::to_string_pretty(data)
        .map_err(|e| format!("failed to serialize auth data: {e}"))?;
    std::fs::write(auth_path(), &json)
        .map_err(|e| format!("failed to write {}: {e}", auth_path().display()))
}

pub fn encrypt_accounts(accounts: &[Account], key: &[u8; 32]) -> Result<AccountsPayload, String> {
    let mut json = serde_json::to_string(accounts)
        .map_err(|e| format!("failed to serialize accounts: {e}"))?;
    let (nonce, ciphertext) = crypto::encrypt(&json, key)?;
    // Zeroize the plaintext JSON immediately after encryption
    json.zeroize();
    Ok(AccountsPayload {
        encrypted: true,
        nonce_hex: Some(hex::encode(&nonce)),
        ciphertext_hex: Some(hex::encode(&ciphertext)),
        data_json: String::new(),
    })
}

pub fn decrypt_accounts(payload: &AccountsPayload, key: &[u8; 32]) -> Result<Vec<Account>, String> {
    if !payload.encrypted {
        return serde_json::from_str(&payload.data_json)
            .map_err(|e| format!("failed to parse accounts: {e}"));
    }

    let nonce_hex = payload
        .nonce_hex
        .as_deref()
        .ok_or_else(|| "missing nonce_hex in encrypted accounts".to_string())?;
    let ct_hex = payload
        .ciphertext_hex
        .as_deref()
        .ok_or_else(|| "missing ciphertext_hex in encrypted accounts".to_string())?;
    let mut nonce = hex::decode(nonce_hex).map_err(|e| format!("invalid nonce hex: {e}"))?;
    let mut ciphertext = hex::decode(ct_hex).map_err(|e| format!("invalid ciphertext hex: {e}"))?;
    let mut plaintext = crypto::decrypt(&ciphertext, &nonce, key)?;
    let accounts: Vec<Account> = serde_json::from_str(&plaintext)
        .map_err(|e| format!("failed to parse decrypted accounts: {e}"))?;
    // Zeroize all intermediate buffers
    nonce.zeroize();
    ciphertext.zeroize();
    plaintext.zeroize();
    Ok(accounts)
}

/// Load accounts from AuthData, handling both encrypted and plaintext.
///
/// Caller is responsible for zeroizing the returned Vec<Account> after use.
pub fn load_accounts(data: &AuthData, key: Option<[u8; 32]>) -> Result<Vec<Account>, String> {
    if data.accounts.encrypted {
        let k = key.ok_or_else(|| "app is locked".to_string())?;
        decrypt_accounts(&data.accounts, &k)
    } else {
        serde_json::from_str(&data.accounts.data_json)
            .map_err(|e| format!("failed to parse accounts: {e}"))
    }
}

// ── Internals ───────────────────────────────────────────────

fn fresh() -> AuthData {
    AuthData {
        version: CURRENT_VERSION,
        config: crate::config::Config::default(),
        accounts: AccountsPayload {
            encrypted: false,
            nonce_hex: None,
            ciphertext_hex: None,
            data_json: String::from("[]"),
        },
        log: String::new(),
    }
}

fn reconcile_invariants(data: &mut AuthData) -> bool {
    let mut changed = false;

    if data.accounts.encrypted && !data.config.password_protected {
        data.config.password_protected = true;
        changed = true;
    }

    if !data.accounts.encrypted && data.config.password_protected {
        data.config.password_protected = false;
        changed = true;
    }

    if !data.config.password_protected && !data.config.password_salt.is_empty() {
        data.config.password_salt.clear();
        changed = true;
    }

    // Normalize empty data_json to valid empty JSON array (migration from before
    // fresh() used "[]" — empty string would cause "EOF while parsing a value")
    if !data.accounts.encrypted && data.accounts.data_json.is_empty() {
        data.accounts.data_json = String::from("[]");
        changed = true;
    }

    changed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_account() -> Account {
        Account {
            id: "test-id".into(),
            issuer: "Test".into(),
            label: "test@test.com".into(),
            algorithm: crate::models::account::Algorithm::SHA1,
            digits: 6,
            period: 30,
            secret: vec![1, 2, 3],
            sort_order: 0,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn test_fresh_defaults() {
        let data = fresh();
        assert_eq!(data.version, 1);
        assert!(!data.config.password_protected);
        assert!(!data.accounts.encrypted);
        assert_eq!(
            data.accounts.data_json, "[]",
            "fresh data_json must be valid empty JSON array, not empty string"
        );
        assert!(data.accounts.nonce_hex.is_none());
        assert!(data.accounts.ciphertext_hex.is_none());
        // Verify fresh() can be parsed as accounts (regression: empty string would fail)
        let accounts: Vec<Account> = serde_json::from_str(&data.accounts.data_json).unwrap();
        assert!(accounts.is_empty());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0xABu8; 32];
        let accounts = vec![test_account()];
        let payload = encrypt_accounts(&accounts, &key).unwrap();
        assert!(payload.encrypted);
        assert!(payload.nonce_hex.is_some());
        assert!(payload.ciphertext_hex.is_some());
        assert!(payload.data_json.is_empty());
        let mut decrypted = decrypt_accounts(&payload, &key).unwrap();
        assert_eq!(decrypted.len(), 1);
        assert_eq!(decrypted[0].id, "test-id");
        // Zeroize decrypted accounts
        for a in &mut decrypted {
            a.secret.zeroize();
        }
        decrypted.clear();
    }

    #[test]
    fn test_json_roundtrip() {
        let data = fresh();
        let json = serde_json::to_string_pretty(&data).unwrap();
        let restored: AuthData = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.version, 1);
        assert!(!restored.config.password_protected);
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let key = [0xAAu8; 32];
        let wrong_key = [0xBBu8; 32];
        let accounts = vec![test_account()];
        let payload = encrypt_accounts(&accounts, &key).unwrap();
        assert!(decrypt_accounts(&payload, &wrong_key).is_err());
    }

    #[test]
    fn test_decrypt_plaintext_payload() {
        let key = [0xCCu8; 32];
        let plaintext = AccountsPayload {
            encrypted: false,
            nonce_hex: None,
            ciphertext_hex: None,
            data_json: serde_json::to_string(&vec![test_account()]).unwrap(),
        };
        let mut accounts = decrypt_accounts(&plaintext, &key).unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].id, "test-id");
        for a in &mut accounts {
            a.secret.zeroize();
        }
        accounts.clear();
    }

    #[test]
    fn test_reconcile_invariants_encrypted_but_not_protected() {
        let mut data = fresh();
        data.accounts.encrypted = true;
        data.config.password_protected = false;
        assert!(reconcile_invariants(&mut data));
        assert!(data.config.password_protected);
    }

    #[test]
    fn test_reconcile_invariants_protected_but_not_encrypted() {
        let mut data = fresh();
        data.accounts.encrypted = false;
        data.config.password_protected = true;
        assert!(reconcile_invariants(&mut data));
        assert!(!data.config.password_protected);
    }

    #[test]
    fn test_reconcile_invariants_salt_cleared_when_unprotected() {
        let mut data = fresh();
        data.config.password_salt = "old-salt".into();
        reconcile_invariants(&mut data);
        assert!(data.config.password_salt.is_empty());
    }

    #[test]
    fn test_reconcile_invariants_no_change() {
        let mut data = fresh();
        assert!(!reconcile_invariants(&mut data));
    }

    #[test]
    fn test_load_accounts_encrypted_without_key_fails() {
        let key = [0xDDu8; 32];
        let accounts = vec![test_account()];
        let payload = encrypt_accounts(&accounts, &key).unwrap();
        let data = AuthData {
            version: 1,
            config: crate::config::Config::default(),
            accounts: payload,
            log: String::new(),
        };
        assert!(load_accounts(&data, None).is_err());
    }

    #[test]
    fn test_load_accounts_plaintext_without_key_succeeds() {
        let data = AuthData {
            version: 1,
            config: crate::config::Config::default(),
            accounts: AccountsPayload {
                encrypted: false,
                nonce_hex: None,
                ciphertext_hex: None,
                data_json: serde_json::to_string(&vec![test_account()]).unwrap(),
            },
            log: String::new(),
        };
        let mut accounts = load_accounts(&data, None).unwrap();
        assert_eq!(accounts.len(), 1);
        for a in &mut accounts {
            a.secret.zeroize();
        }
        accounts.clear();
    }

    #[test]
    fn test_encrypt_multiple_accounts() {
        let key = [0xEEu8; 32];
        let mut accounts = vec![test_account()];
        accounts.push(Account {
            id: "second".into(),
            issuer: "Org".into(),
            label: "org@org.com".into(),
            algorithm: crate::models::account::Algorithm::SHA256,
            digits: 8,
            period: 60,
            secret: vec![9, 8, 7],
            sort_order: 1,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        });
        let payload = encrypt_accounts(&accounts, &key).unwrap();
        let mut decrypted = decrypt_accounts(&payload, &key).unwrap();
        assert_eq!(decrypted.len(), 2);
        assert_eq!(decrypted[1].issuer, "Org");
        for a in &mut decrypted {
            a.secret.zeroize();
        }
        decrypted.clear();
    }

    #[test]
    fn test_stress_encrypt_decrypt_100_accounts() {
        let key = [0x42u8; 32];
        let now = chrono::Utc::now();

        // Build 100 accounts with deterministic-but-unique secrets and varied params
        let mut accounts = Vec::with_capacity(100);
        for i in 0u8..100u8 {
            let algo = match i % 3 {
                0 => crate::models::account::Algorithm::SHA1,
                1 => crate::models::account::Algorithm::SHA256,
                _ => crate::models::account::Algorithm::SHA512,
            };
            let digits = if i % 2 == 0 { 6 } else { 8 };
            let period = match i % 3 {
                0 => 30u32,
                1 => 60,
                _ => 90,
            };
            // Each account gets a unique secret: [i, i+1, i+2, ... i+9] (10 bytes)
            let secret: Vec<u8> = (0u8..10).map(|j| i.wrapping_add(j)).collect();
            accounts.push(Account {
                id: format!("stress-{i:03}"),
                issuer: format!("Issuer{i}"),
                label: format!("user{i}@example.com"),
                algorithm: algo,
                digits,
                period,
                secret: secret.clone(),
                sort_order: i as u32,
                created_at: now,
                updated_at: now,
            });
        }

        // Encrypt all 100
        let payload = encrypt_accounts(&accounts, &key).unwrap();
        assert!(payload.encrypted);
        assert!(payload.nonce_hex.is_some());
        assert!(payload.ciphertext_hex.is_some());
        assert!(payload.data_json.is_empty());

        // Decrypt all 100
        let mut decrypted = decrypt_accounts(&payload, &key).unwrap();
        assert_eq!(decrypted.len(), 100, "all 100 accounts recovered");

        // Verify every field on every account
        for (i, a) in decrypted.iter().enumerate() {
            let expected_id = format!("stress-{i:03}");
            assert_eq!(a.id, expected_id, "id mismatch at index {i}");
            assert_eq!(
                a.issuer,
                format!("Issuer{i}"),
                "issuer mismatch at index {i}"
            );
            assert_eq!(
                a.label,
                format!("user{i}@example.com"),
                "label mismatch at index {i}"
            );

            // Verify secret survived encrypt→decrypt cycle
            let expected_secret: Vec<u8> = (0u8..10).map(|j| (i as u8).wrapping_add(j)).collect();
            assert_eq!(a.secret, expected_secret, "secret mismatch at index {i}");

            assert_eq!(a.sort_order, i as u32);

            // Verify digits and period survived the encrypt→decrypt cycle
            let expected_digits = if i % 2 == 0 { 6u8 } else { 8u8 };
            assert_eq!(a.digits, expected_digits, "digits mismatch at index {i}");
            let expected_period = match i % 3 {
                0 => 30u32,
                1 => 60,
                _ => 90,
            };
            assert_eq!(a.period, expected_period, "period mismatch at index {i}");

            match i % 3 {
                0 => assert!(matches!(
                    a.algorithm,
                    crate::models::account::Algorithm::SHA1
                )),
                1 => assert!(matches!(
                    a.algorithm,
                    crate::models::account::Algorithm::SHA256
                )),
                _ => assert!(matches!(
                    a.algorithm,
                    crate::models::account::Algorithm::SHA512
                )),
            }
        }

        // Zeroize all secrets
        for a in &mut decrypted {
            a.secret.zeroize();
        }
        decrypted.clear();
    }

    // ── New tests ──────────────────────────────────────────────

    #[test]
    fn test_decrypt_accounts_missing_nonce_hex_fails() {
        let payload = AccountsPayload {
            encrypted: true,
            nonce_hex: None,
            ciphertext_hex: Some("aabb".into()),
            data_json: String::new(),
        };
        let key = [0xAAu8; 32];
        assert!(
            decrypt_accounts(&payload, &key).is_err(),
            "missing nonce must fail"
        );
    }

    #[test]
    fn test_decrypt_accounts_missing_ciphertext_hex_fails() {
        let payload = AccountsPayload {
            encrypted: true,
            nonce_hex: Some("aabb".into()),
            ciphertext_hex: None,
            data_json: String::new(),
        };
        let key = [0xAAu8; 32];
        assert!(
            decrypt_accounts(&payload, &key).is_err(),
            "missing ciphertext must fail"
        );
    }

    #[test]
    fn test_decrypt_accounts_invalid_nonce_hex_fails() {
        let payload = AccountsPayload {
            encrypted: true,
            nonce_hex: Some("not-hex!!".into()),
            ciphertext_hex: Some("aabbcc".into()),
            data_json: String::new(),
        };
        let key = [0xAAu8; 32];
        assert!(
            decrypt_accounts(&payload, &key).is_err(),
            "invalid nonce hex must fail"
        );
    }

    #[test]
    fn test_reconcile_invariants_empty_data_json_fixed() {
        let mut data = fresh();
        data.accounts.encrypted = false;
        data.accounts.data_json = String::new(); // empty string, not "[]"
        assert!(
            reconcile_invariants(&mut data),
            "empty data_json should be fixed"
        );
        assert_eq!(data.accounts.data_json, "[]", "should be normalized to []");
    }

    #[test]
    fn test_load_accounts_encrypted_payload_nonce_short() {
        // Payload marked encrypted but with garbage hex values
        let payload = AccountsPayload {
            encrypted: true,
            nonce_hex: Some("00".into()), // 1 byte, not 12
            ciphertext_hex: Some("aabbcc".into()),
            data_json: String::new(),
        };
        let key = [0xAAu8; 32];
        // Will fail at hex decode stage — nonce_hex decodes to 1 byte
        let result = decrypt_accounts(&payload, &key);
        assert!(result.is_err(), "short nonce should be detected and fail");
    }

    #[test]
    fn test_encrypt_accounts_empty_list_produces_valid_payload() {
        let key = [0x42u8; 32];
        let payload = encrypt_accounts(&[], &key).unwrap();
        assert!(payload.encrypted);
        assert!(payload.nonce_hex.is_some());
        assert!(payload.ciphertext_hex.is_some());
        // Decrypt back — should be empty JSON array
        let mut decrypted = decrypt_accounts(&payload, &key).unwrap();
        assert!(
            decrypted.is_empty(),
            "encrypted empty list → empty decrypted"
        );
        decrypted.clear();
    }

    // ── New tests ──────────────────────────────────────────────

    #[test]
    fn test_fresh_returns_valid_data() {
        // fresh() always returns a valid AuthData regardless of disk state
        let data = fresh();
        assert_eq!(data.version, 1, "fresh data version must be 1");
        assert!(!data.config.password_protected);
        assert_eq!(data.accounts.data_json, "[]");
    }

    #[test]
    fn test_save_then_load_roundtrip_empty_log() {
        let mut data = fresh();
        data.log = String::new();
        let json = serde_json::to_string_pretty(&data).unwrap();
        let restored: AuthData = serde_json::from_str(&json).unwrap();
        assert!(restored.log.is_empty(), "fresh log should be empty");
        assert_eq!(restored.version, 1);
    }

    #[test]
    fn test_reconcile_both_invariants_at_once() {
        // encrypted=true + password_protected=false + salt non-empty
        // reconcile_invariants processes sequentially:
        // 1. encrypted && !protected → set protected=true
        // 2. After step 1, protected=true, so salt clear condition (!protected && salt) is NOT met
        let mut data = fresh();
        data.accounts.encrypted = true;
        data.config.password_protected = false;
        data.config.password_salt = "should-remain".into();
        assert!(
            reconcile_invariants(&mut data),
            "should trigger encrypted→protected fix"
        );
        assert!(data.config.password_protected, "should become protected");
        // Salt is NOT cleared because password_protected is now true after step 1
        assert_eq!(
            data.config.password_salt, "should-remain",
            "salt NOT cleared because password_protected was set to true in step 1"
        );
    }

    #[test]
    fn test_decrypt_accounts_encrypted_with_invalid_ciphertext_hex_fails() {
        let payload = AccountsPayload {
            encrypted: true,
            nonce_hex: Some("0102030405060708090a0b0c".into()), // 12 bytes
            ciphertext_hex: Some("not-hex!!".into()),
            data_json: String::new(),
        };
        let key = [0xAAu8; 32];
        assert!(
            decrypt_accounts(&payload, &key).is_err(),
            "invalid ciphertext hex must fail"
        );
    }

    #[test]
    fn test_load_accounts_encrypted_with_wrong_key_reports_error() {
        let key = [0x11u8; 32];
        let wrong_key = [0x22u8; 32];
        let accounts = vec![test_account()];
        let payload = encrypt_accounts(&accounts, &key).unwrap();
        let data = AuthData {
            version: 1,
            config: crate::config::Config::default(),
            accounts: payload,
            log: String::new(),
        };
        let result = load_accounts(&data, Some(wrong_key));
        assert!(result.is_err(), "wrong key must fail decryption");
    }

    #[test]
    fn test_encrypt_accounts_preserves_all_fields_in_accounts() {
        // Verify that account fields survive encrypt→decrypt roundtrip
        let key = [0x33u8; 32];
        let now = chrono::Utc::now();
        let mut account = test_account();
        account.id = "fields-test".into();
        account.issuer = "Multi-Field".into();
        account.label = "multi@test.com".into();
        account.algorithm = crate::models::account::Algorithm::SHA512;
        account.digits = 8;
        account.period = 90;
        account.secret = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
        account.sort_order = 42;
        account.created_at = now;
        account.updated_at = now;

        let payload = encrypt_accounts(&[account], &key).unwrap();
        let mut decrypted = decrypt_accounts(&payload, &key).unwrap();
        assert_eq!(decrypted.len(), 1);
        assert_eq!(decrypted[0].id, "fields-test");
        assert_eq!(decrypted[0].issuer, "Multi-Field");
        assert_eq!(decrypted[0].label, "multi@test.com");
        assert!(matches!(
            decrypted[0].algorithm,
            crate::models::account::Algorithm::SHA512
        ));
        assert_eq!(decrypted[0].digits, 8);
        assert_eq!(decrypted[0].period, 90);
        assert_eq!(
            decrypted[0].secret,
            vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE]
        );
        assert_eq!(decrypted[0].sort_order, 42);
        for a in &mut decrypted {
            a.secret.zeroize();
        }
        decrypted.clear();
    }

    #[test]
    fn test_try_load_reconcile_saves_to_disk() {
        let _lock = FS_TEST_MUTEX.lock().unwrap();
        // Remove any existing auth file
        let path = auth_path();
        let _ = std::fs::remove_file(&path);

        // Manually write an inconsistent .auth file:
        // encrypted=true but password_protected=false
        let mut data = fresh();
        data.accounts.encrypted = true;
        data.config.password_protected = false;
        let json = serde_json::to_string_pretty(&data).unwrap();
        std::fs::write(&path, &json).unwrap();

        // try_load reads it → reconcile_invariants fixes it → save persists the fix
        let loaded = try_load().unwrap();
        assert!(
            loaded.config.password_protected,
            "reconcile should have set password_protected=true"
        );

        // Verify the fix was persisted to disk (not just in-memory)
        let raw = std::fs::read_to_string(&path).unwrap();
        let saved: AuthData = serde_json::from_str(&raw).unwrap();
        assert!(
            saved.config.password_protected,
            "fixed password_protected must be saved to disk"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_exists_returns_false_when_no_file() {
        let _lock = FS_TEST_MUTEX.lock().unwrap();
        let path = auth_path();
        let _ = std::fs::remove_file(&path);
        assert!(!exists(), "exists() should return false when no .auth file");
    }

    #[test]
    fn test_exists_returns_true_when_file_present() {
        let _lock = FS_TEST_MUTEX.lock().unwrap();
        let path = auth_path();
        let _ = std::fs::remove_file(&path);
        // Create a fresh auth file
        let data = fresh();
        let json = serde_json::to_string_pretty(&data).unwrap();
        std::fs::write(&path, &json).unwrap();
        assert!(exists(), "exists() should return true when .auth file exists");
        let _ = std::fs::remove_file(&path);
    }
}
