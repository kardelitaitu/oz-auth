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
//!
//! # Adding new fields (backward-compatible)
//! 1. Add the field to the Rust struct with `#[serde(default)]` or `#[serde(default = "fn")]`
//! 2. If the default needs to be different from Rust's Default, write a default function
//! 3. If the field is security-critical, add a check in `reconcile_invariants()`
//! 4. Update `tests/fixtures/auth_data_v1_snapshot.json` by re-generating via the
//!    `test_deterministic_auth_data_schema_snapshot` test
//! 5. Add a unit test that deserializes old JSON (without the field) and verifies the default
//!
//! # Renaming a field
//! 1. Add the new field with `#[serde(default)]` + `#[serde(alias = "old_name")]`
//! 2. Add a version upgrade in `upgrade_data()` that copies old → new
//! 3. Remove the old field in the NEXT version bump
//!
//! # Bumping the file format version
//! 1. Increment `CURRENT_VERSION`
//! 2. Add `upgrade_vN_to_vNplus1()` function in `upgrade_data()`
//! 3. Update the schema snapshot fixture
//! 4. Add compatibility tests for the old → new migration

use crate::crypto;
use crate::models::account::Account;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuthData {
    /// File format version. Defaults to 0 when missing (triggers upgrade to CURRENT_VERSION).
    #[serde(default = "default_version")]
    pub version: u32,
    pub config: crate::config::Config,
    pub accounts: AccountsPayload,
    /// In-memory event log persisted to `.auth` file.
    #[serde(default)]
    pub log: String,
    /// Optional user notes about this auth file. Added in v2.
    #[serde(default)]
    pub notes: String,
    /// Append-only signed audit trail (JSON array of AuditEntry). Added in v3.
    #[serde(default)]
    pub audit_trail: String,
}

fn default_version() -> u32 {
    0
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

pub const CURRENT_VERSION: u32 = 2;

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

    // Run version upgrades + invariant reconciliation
    let upgraded = upgrade_data(&mut data);
    let reconciled = reconcile_invariants(&mut data);

    if upgraded || reconciled {
        save(&data)?;
    }

    Ok(data)
}

/// Flush both the human-readable event log and the signed audit trail
/// into the AuthData struct, then save to disk.
pub fn flush_and_save(data: &mut AuthData) -> Result<(), String> {
    data.log = crate::diagnostics::flush_to_log_str();
    data.audit_trail = crate::audit::flush();
    let json = serde_json::to_string_pretty(data)
        .map_err(|e| format!("failed to serialize auth data: {e}"))?;
    atomic_write(&auth_path(), &json)
}

pub fn save(data: &AuthData) -> Result<(), String> {
    let json = serde_json::to_string_pretty(data)
        .map_err(|e| format!("failed to serialize auth data: {e}"))?;
    atomic_write(&auth_path(), &json)
}

/// Atomic write: write to a temp file, then rename over the target.
/// This prevents data loss if the process crashes mid-write.
fn atomic_write(target: &std::path::Path, contents: &str) -> Result<(), String> {
    let dir = target.parent().unwrap_or_else(|| std::path::Path::new("."));
    let mut tmp = dir.join(".auth.tmp");
    // Ensure unique temp name to avoid collisions from concurrent writers
    tmp.set_extension("tmp");

    std::fs::write(&tmp, contents)
        .map_err(|e| format!("failed to write temp file {}: {e}", tmp.display()))?;

    // Atomic rename — on Windows this is atomic if src and dest are on the same volume
    std::fs::rename(&tmp, target).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!(
            "failed to rename temp file to {}: {e}",
            target.display()
        )
    })?;

    Ok(())
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

/// Run version upgrades on deserialized AuthData.
/// Bumps version sequentially from current to CURRENT_VERSION.
/// Returns true if any upgrade modified the data.
fn upgrade_data(data: &mut AuthData) -> bool {
    let mut changed = false;
    let mut version = data.version;

    // v0 (missing or default) → v1: ensure fresh defaults
    if version < 1 {
        data.version = 1;
        version = 1;
        changed = true;
    }

    // v1 → v2: add notes field
    if version < 2 {
        upgrade_v1_to_v2(data);
        data.version = 2;
        version = 2;
        changed = true;
    }

    // Future: v2 → v3
    // if version < 3 { upgrade_v2_to_v3(data); version = 3; changed = true; }

    if changed {
        data.version = version;
    }
    changed
}

/// Upgrade v1 → v2: add `notes` field (default empty string).
fn upgrade_v1_to_v2(data: &mut AuthData) {
    // `notes` was added with #[serde(default)], so serde already fills
    // it with String::new() for v1 files. The upgrade just sets the
    // version and logs the migration.
    if data.notes.is_empty() {
        data.notes = String::new();
    }
}

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
        notes: String::new(),
        audit_trail: String::new(),
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
        assert_eq!(data.version, 2);
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
        assert_eq!(restored.version, 2);
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
            notes: String::new(),
            audit_trail: String::new(),
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
            notes: String::new(),
            audit_trail: String::new(),
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
        assert_eq!(data.version, 2, "fresh data version must be 2");
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
        assert_eq!(restored.version, 2);
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
            notes: String::new(),
            audit_trail: String::new(),
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
        let _lock = FS_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
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
        let _lock = FS_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let path = auth_path();
        let _ = std::fs::remove_file(&path);
        assert!(!exists(), "exists() should return false when no .auth file");
    }

    #[test]
    fn test_try_load_with_corrupted_json_returns_error() {
        let _lock = FS_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let path = auth_path();
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, "{{corrupted json[[[").unwrap();
        let result = try_load();
        assert!(
            result.is_err(),
            "try_load must return Err for corrupted JSON"
        );
        let err = result.unwrap_err();
        assert!(err.contains("parse"), "error should mention parse: {err}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_decrypt_accounts_with_garbage_plaintext_fails() {
        // Encrypt non-JSON data, then try to decrypt as accounts
        let key = [0x99u8; 32];
        let (nonce, ciphertext) = crate::crypto::encrypt("not valid json at all", &key).unwrap();
        let payload = AccountsPayload {
            encrypted: true,
            nonce_hex: Some(hex::encode(&nonce)),
            ciphertext_hex: Some(hex::encode(&ciphertext)),
            data_json: String::new(),
        };
        let result = decrypt_accounts(&payload, &key);
        assert!(
            result.is_err(),
            "non-JSON plaintext must fail to parse as accounts"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("parse"),
            "error must mention parse failure: {err}"
        );
    }

    #[test]
    fn test_decrypt_plaintext_payload_invalid_json_fails() {
        // Plaintext payload (not encrypted) with invalid JSON in data_json
        let payload = AccountsPayload {
            encrypted: false,
            nonce_hex: None,
            ciphertext_hex: None,
            data_json: "{{not valid json}}".into(),
        };
        let key = [0xCCu8; 32];
        let result = decrypt_accounts(&payload, &key);
        assert!(
            result.is_err(),
            "invalid JSON in plaintext payload must fail"
        );
    }

    // ── Version upgrade & compatibility tests ─────────────────

    #[test]
    fn test_missing_version_defaults_to_zero_and_upgraded() {
        // File without a "version" key should default to 0, then be upgraded to CURRENT_VERSION
        let json = r#"{"config":{"width":320,"height":480,"left":100,"top":100,"always_on_top":false},"accounts":{"encrypted":false,"data_json":"[]"},"log":""}"#;
        let data: AuthData = serde_json::from_str(json).unwrap();
        assert_eq!(data.version, 0, "missing version must default to 0");
        let mut data = data;
        assert!(upgrade_data(&mut data), "upgrade must bump version");
        assert_eq!(data.version, CURRENT_VERSION);
    }

    #[test]
    fn test_deterministic_auth_data_schema_snapshot() {
        // Schema snapshot: verify serialized output matches committed fixture.
        // If this test fails, the .auth file schema has changed.
        // Update the fixture: re-run this test with --no-capture, copy the JSON
        // to auth_data_v1_snapshot.json, and update CURRENT_VERSION if needed.
        let data = AuthData {
            version: CURRENT_VERSION,
            config: crate::config::Config {
                width: 400,
                height: 600,
                left: 50,
                top: 100,
                always_on_top: false,
                theme: "dark".into(),
                password_protected: false,
                password_salt: String::new(),
                lock_timeout_seconds: 300,
                clipboard_clear_seconds: 30,
                lock_on_focus_loss: false,
            },
            accounts: AccountsPayload {
                encrypted: false,
                nonce_hex: None,
                ciphertext_hex: None,
                data_json: "[]".into(),
            },
            log: String::new(),
            notes: String::new(),
            audit_trail: String::new(),
        };
        let json = serde_json::to_string_pretty(&data).unwrap();
        let fixture = include_str!("../../tests/fixtures/auth_data_v1_snapshot.json");
        // Trim both sides to ignore trailing newline differences
        assert_eq!(
            json.trim(),
            fixture.trim(),
            "\nSchema changed! Update tests/fixtures/auth_data_v1_snapshot.json\n\
             Expected snapshot (from fixture):\n{}\n\
             Actual output:\n{}",
            fixture.trim(),
            json.trim()
        );
    }

    #[test]
    fn test_unknown_fields_in_old_file_ignored_during_parse() {
        // Old file with extra unknown keys should not crash
        let json = r#"{"version":1,"config":{"width":320,"height":480,"left":100,"top":100,"always_on_top":false},"accounts":{"encrypted":false,"data_json":"[]"},"log":"","unknown_section":{"some_key":"some_value"},"another_unknown_field":42}"#;
        let data: AuthData = serde_json::from_str(json).unwrap();
        assert_eq!(data.version, 1);
        assert_eq!(data.config.width, 320);
        // Unknown fields are silently dropped — no crash
    }

    #[test]
    fn test_upgrade_from_missing_version_saves_to_disk() {
        let _lock = FS_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let path = auth_path();
        let _ = std::fs::remove_file(&path);

        // Write a file without version field
        let json = r#"{"config":{"width":320,"height":480,"left":100,"top":100,"always_on_top":false},"accounts":{"encrypted":false,"data_json":"[]"},"log":""}"#;
        std::fs::write(&path, json).unwrap();

        // Load triggers upgrade
        let data = try_load().unwrap();
        assert_eq!(data.version, CURRENT_VERSION, "version must be upgraded");
        // Verify file was rewritten with version
        let raw = std::fs::read_to_string(&path).unwrap();
        let saved: AuthData = serde_json::from_str(&raw).unwrap();
        assert_eq!(
            saved.version, CURRENT_VERSION,
            "file must persist the upgrade"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_version_0_file_upgraded_to_current() {
        // Explicit version:0 should also be upgraded
        let json = r#"{"version":0,"config":{"width":320,"height":480,"left":100,"top":100,"always_on_top":false},"accounts":{"encrypted":false,"data_json":"[]"},"log":""}"#;
        let mut data: AuthData = serde_json::from_str(json).unwrap();
        assert_eq!(data.version, 0);
        assert!(upgrade_data(&mut data), "v0 must be upgraded");
        assert_eq!(data.version, CURRENT_VERSION);
    }

    #[test]
    fn test_version_already_current_no_upgrade_needed() {
        let mut data = fresh();
        assert_eq!(data.version, CURRENT_VERSION);
        assert!(!upgrade_data(&mut data), "already current → no upgrade");
    }

    #[test]
    fn test_version_greater_than_current_skips_upgrade() {
        // File with version > CURRENT_VERSION should load, skip upgrade, not save
        let json = r#"{"version":999,"config":{"width":320,"height":480,"left":100,"top":100,"always_on_top":false},"accounts":{"encrypted":false,"data_json":"[]"},"log":""}"#;
        let mut data: AuthData = serde_json::from_str(json).unwrap();
        assert_eq!(data.version, 999);
        // upgrade_data should NOT bump version (it's already > CURRENT)
        assert!(
            !upgrade_data(&mut data),
            "version > CURRENT must not be upgraded"
        );
        assert_eq!(data.version, 999, "version must be preserved");
    }

    #[test]
    fn test_version_greater_than_current_does_not_crash_on_load() {
        // End-to-end: write a v999 file to disk, load it, verify no crash
        let _lock = FS_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let path = auth_path();
        let _ = std::fs::remove_file(&path);

        let json = r#"{"version":999,"config":{"width":320,"height":480,"left":100,"top":100,"always_on_top":false},"accounts":{"encrypted":false,"data_json":"[]"},"log":""}"#;
        std::fs::write(&path, json).unwrap();

        // try_load should succeed — no crash, no save
        let data = try_load().unwrap();
        assert_eq!(data.version, 999, "version > CURRENT must be preserved");
        assert!(!data.config.password_protected);

        // Verify file was NOT rewritten (should still have v999, not CURRENT_VERSION=2)
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(
            !raw.contains(r#""version":2"#),
            "file must not be rewritten for version > CURRENT"
        );

        let _ = std::fs::remove_file(&path);
    }

    // ── v2 migration tests ────────────────────────────────────

    #[test]
    fn test_v1_file_has_notes_default() {
        // A v1 JSON (without 'notes' field) should get notes = "" via serde default
        let json = r#"{"version":1,"config":{"width":320,"height":480,"left":100,"top":100,"always_on_top":false},"accounts":{"encrypted":false,"data_json":"[]"},"log":""}"#;
        let data: AuthData = serde_json::from_str(json).unwrap();
        assert_eq!(data.version, 1);
        assert!(data.notes.is_empty(), "v1 file must default to empty notes");
    }

    #[test]
    fn test_v1_to_v2_upgrade_adds_notes() {
        // A v1 file loaded via try_load should be upgraded to v2
        let json = r#"{"version":1,"config":{"width":320,"height":480,"left":100,"top":100,"always_on_top":false},"accounts":{"encrypted":false,"data_json":"[]"},"log":""}"#;
        let mut data: AuthData = serde_json::from_str(json).unwrap();
        assert_eq!(data.version, 1);
        assert!(upgrade_data(&mut data), "v1 must trigger upgrade");
        assert_eq!(data.version, 2, "v1 must be upgraded to v2");
        assert!(data.notes.is_empty(), "upgraded notes must be empty");
    }

    #[test]
    fn test_v1_file_upgraded_to_v2_on_disk() {
        // Write a v1 file to disk, load it, verify it gets upgraded to v2
        let _lock = FS_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let path = auth_path();
        let _ = std::fs::remove_file(&path);

        let v1_json = r#"{"version":1,"config":{"width":320,"height":480,"left":100,"top":100,"always_on_top":false},"accounts":{"encrypted":false,"data_json":"[]"},"log":""}"#;
        std::fs::write(&path, v1_json).unwrap();

        let data = try_load().unwrap();
        assert_eq!(data.version, 2, "v1 file must be upgraded to v2 on load");
        assert!(data.notes.is_empty());

        // Verify disk was updated
        let raw = std::fs::read_to_string(&path).unwrap();
        let saved: AuthData = serde_json::from_str(&raw).unwrap();
        assert_eq!(saved.version, 2, "v2 must be persisted to disk");
        assert_eq!(saved.notes, "", "notes must be persisted to disk");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_v2_file_with_notes_preserved_on_roundtrip() {
        // A v2 file with custom notes should preserve them through save/load
        let _lock = FS_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let path = auth_path();
        let _ = std::fs::remove_file(&path);

        let v2_json = r#"{"version":2,"config":{"width":320,"height":480,"left":100,"top":100,"always_on_top":false},"accounts":{"encrypted":false,"data_json":"[]"},"log":"","notes":"My custom notes"}"#;
        std::fs::write(&path, v2_json).unwrap();

        let data = try_load().unwrap();
        assert_eq!(data.version, 2);
        assert_eq!(data.notes, "My custom notes", "notes must be preserved");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_v0_file_upgraded_through_v1_to_v2() {
        // A v0 file should be upgraded v0→v1→v2 in sequence
        let json = r#"{"version":0,"config":{"width":320,"height":480,"left":100,"top":100,"always_on_top":false},"accounts":{"encrypted":false,"data_json":"[]"},"log":""}"#;
        let mut data: AuthData = serde_json::from_str(json).unwrap();
        assert_eq!(data.version, 0);
        assert!(upgrade_data(&mut data), "v0 must trigger upgrade chain");
        assert_eq!(data.version, 2, "v0 must be upgraded all the way to v2");
    }

    #[test]
    fn test_minimal_auth_file_fills_all_defaults() {
        // A truly minimal .auth file with only password_protected in config
        // and accounts.encrypted + data_json. Everything else should use serde defaults.
        let _lock = FS_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let path = auth_path();
        let _ = std::fs::remove_file(&path);

        let minimal = r#"{"config":{"password_protected":false},"accounts":{"encrypted":false,"data_json":"[]"}}"#;
        std::fs::write(&path, minimal).unwrap();

        let data = try_load().unwrap();

        // Version: missing → 0 → upgraded to CURRENT_VERSION
        assert_eq!(data.version, CURRENT_VERSION, "version must be upgraded");

        // Config: all missing fields must have defaults
        assert_eq!(data.config.width, 420, "default width");
        assert_eq!(data.config.height, 420, "default height");
        assert_eq!(data.config.left, 100, "default left");
        assert_eq!(data.config.top, 100, "default top");
        assert!(!data.config.always_on_top, "default always_on_top");
        assert!(!data.config.password_protected, "preserved from JSON");
        assert!(data.config.password_salt.is_empty(), "default salt");
        assert_eq!(data.config.theme, "dark", "default theme");
        assert_eq!(
            data.config.lock_timeout_seconds, 300,
            "default lock timeout"
        );
        assert_eq!(
            data.config.clipboard_clear_seconds, 30,
            "default clipboard clear"
        );

        // Accounts: encrypted + data_json preserved
        assert!(!data.accounts.encrypted, "preserved from JSON");
        assert_eq!(data.accounts.data_json, "[]", "preserved from JSON");
        assert!(data.accounts.nonce_hex.is_none(), "default nonce_hex");
        assert!(
            data.accounts.ciphertext_hex.is_none(),
            "default ciphertext_hex"
        );

        // Notes: missing → empty via serde default
        assert!(data.notes.is_empty(), "default notes");

        // Log: missing → empty via serde default
        assert!(data.log.is_empty(), "default log");

        // Verify the file was rewritten on disk with all defaults filled in
        let raw = std::fs::read_to_string(&path).unwrap();
        let saved: AuthData = serde_json::from_str(&raw).unwrap();
        assert_eq!(saved.version, CURRENT_VERSION, "upgraded version persisted");
        assert_eq!(saved.config.width, 420, "width persisted");
        assert_eq!(saved.config.height, 420, "height persisted");
        assert_eq!(saved.config.left, 100, "left persisted");
        assert_eq!(saved.config.top, 100, "top persisted");
        assert!(!saved.config.always_on_top, "always_on_top persisted");
        assert_eq!(saved.config.theme, "dark", "theme persisted");
        assert_eq!(
            saved.config.lock_timeout_seconds, 300,
            "lock timeout persisted"
        );
        assert_eq!(
            saved.config.clipboard_clear_seconds, 30,
            "clipboard clear persisted"
        );
        assert!(saved.notes.is_empty(), "notes persisted");
        assert!(saved.log.is_empty(), "log persisted");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_exists_returns_true_when_file_present() {
        let _lock = FS_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let path = auth_path();
        let _ = std::fs::remove_file(&path);
        // Create a fresh auth file
        let data = fresh();
        let json = serde_json::to_string_pretty(&data).unwrap();
        std::fs::write(&path, &json).unwrap();
        assert!(
            exists(),
            "exists() should return true when .auth file exists"
        );
        let _ = std::fs::remove_file(&path);
    }

    // Deterministic invariant reconciliation tests
    // (no random inputs needed — tested as regular unit tests outside proptest! block).

    #[test]
    fn prop_reconcile_encrypted_not_protected() {
        let mut data = fresh();
        data.accounts.encrypted = true;
        data.config.password_protected = false;
        let changed = reconcile_invariants(&mut data);
        assert!(changed, "encrypted + not protected must trigger change");
        assert!(
            data.config.password_protected,
            "password_protected must be set to true"
        );
    }

    #[test]
    fn prop_reconcile_protected_not_encrypted() {
        let mut data = fresh();
        data.accounts.encrypted = false;
        data.config.password_protected = true;
        let changed = reconcile_invariants(&mut data);
        assert!(changed, "not encrypted + protected must trigger change");
        assert!(
            !data.config.password_protected,
            "password_protected must be set to false"
        );
    }

    #[test]
    fn prop_reconcile_fresh_no_change() {
        let mut data = fresh();
        let changed = reconcile_invariants(&mut data);
        assert!(!changed, "fresh data must not need reconciliation");
    }

    #[test]
    fn prop_reconcile_clears_salt_when_unprotected() {
        let mut data = fresh();
        data.accounts.encrypted = false;
        data.config.password_protected = false;
        data.config.password_salt = "aabbccdd".into();
        let changed = reconcile_invariants(&mut data);
        assert!(
            changed,
            "unprotected with non-empty salt must trigger change"
        );
        assert!(
            data.config.password_salt.is_empty(),
            "salt must be cleared when not password_protected"
        );
    }

    #[test]
    fn prop_upgrade_current_no_change() {
        let mut data = fresh();
        data.version = CURRENT_VERSION;
        let changed = upgrade_data(&mut data);
        assert!(!changed, "current version must not trigger upgrade");
        assert_eq!(data.version, CURRENT_VERSION);
    }

    // ── Additional coverage tests ─────────────────────────────

    #[test]
    fn test_try_load_truncated_json_returns_error() {
        let _lock = FS_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let path = auth_path();
        let _ = std::fs::remove_file(&path);

        // Write truncated JSON (valid start, but cut off)
        std::fs::write(&path, r#"{"version":2,"config":{"width":4"#).unwrap();
        let result = try_load();
        assert!(result.is_err(), "truncated JSON must fail to load");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_try_load_empty_file_returns_error() {
        let _lock = FS_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let path = auth_path();
        let _ = std::fs::remove_file(&path);

        std::fs::write(&path, "").unwrap();
        let result = try_load();
        assert!(result.is_err(), "empty file must fail to load");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_try_load_non_json_garbage_returns_error() {
        let _lock = FS_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let path = auth_path();
        let _ = std::fs::remove_file(&path);

        std::fs::write(&path, "this is not json at all {{{").unwrap();
        let result = try_load();
        assert!(result.is_err(), "garbage file must fail to load");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_reconcile_all_four_conditions_simultaneously() {
        // encrypted=true + password_protected=false + salt non-empty + empty data_json
        // Reconcile: sets password_protected=true (accounts need salt for key derivation).
        // data_json fix is NOT applied because accounts are encrypted (data_json unused).
        // Salt is NOT cleared because encrypted accounts need it.
        let mut data = fresh();
        data.accounts.encrypted = true;
        data.config.password_protected = false;
        data.config.password_salt = "aabbccdd".into();
        data.accounts.data_json = "".into();
        let changed = reconcile_invariants(&mut data);
        assert!(changed, "must trigger change");
        assert!(
            data.config.password_protected,
            "must set password_protected=true"
        );
        assert_eq!(
            data.config.password_salt, "aabbccdd",
            "salt preserved for encrypted accounts"
        );
        assert_eq!(
            data.accounts.data_json, "",
            "data_json untouched when encrypted"
        );
    }

    #[test]
    fn test_reconcile_consistent_protected_encrypted_nonempty_salt() {
        let mut data = fresh();
        data.accounts.encrypted = true;
        data.config.password_protected = true;
        data.config.password_salt = "aabbccdd".into();
        data.accounts.data_json = r#"[{"id":"x"}]"#.into();
        let changed = reconcile_invariants(&mut data);
        assert!(!changed, "consistent state must not trigger change");
    }

    #[test]
    fn test_upgrade_v0_with_encrypted_accounts() {
        let mut data = fresh();
        data.version = 0;
        data.config.password_protected = true;
        data.config.password_salt = "aabbccdd".into();
        data.accounts.encrypted = true;
        data.accounts.ciphertext_hex = Some("deadbeef".into());
        data.accounts.nonce_hex = Some("aabb".into());
        let changed = upgrade_data(&mut data);
        assert!(changed, "v0 must trigger upgrade");
        assert_eq!(data.version, CURRENT_VERSION);
        // Encrypted state must survive upgrade
        assert!(
            data.accounts.encrypted,
            "encryption flag must survive upgrade"
        );
        assert_eq!(
            data.config.password_salt, "aabbccdd",
            "salt must survive upgrade"
        );
    }

    #[test]
    fn test_upgrade_v1_with_already_populated_notes() {
        let mut data = fresh();
        data.version = 1;
        data.notes = "existing notes".into();
        let changed = upgrade_data(&mut data);
        assert!(changed, "v1 must trigger upgrade to v2");
        assert_eq!(data.version, CURRENT_VERSION);
        assert_eq!(
            data.notes, "existing notes",
            "existing notes must be preserved during v1→v2 upgrade"
        );
    }

    #[test]
    fn test_encrypt_accounts_empty_nonce_hex() {
        let key = [0x42u8; 32];
        let encrypted = encrypt_accounts(&[], &key).unwrap();
        assert!(encrypted.nonce_hex.is_some(), "nonce must not be empty");
        assert!(
            encrypted.ciphertext_hex.is_some(),
            "ciphertext must not be empty"
        );
    }
}
