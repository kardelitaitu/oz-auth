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
            data_json: String::new(),
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
        assert!(data.accounts.data_json.is_empty());
        assert!(data.accounts.nonce_hex.is_none());
        assert!(data.accounts.ciphertext_hex.is_none());
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
}
