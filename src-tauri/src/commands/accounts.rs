// ── Sub-module declarations ──────────────────────────────────
pub mod crud;
pub mod qr;

// NOTE: Tauri commands live in sub-modules (crud, qr).
// lib.rs invoke_handler uses accounts::crud::* and accounts::qr::* paths.
// pub use re-exports don't work with #[tauri::command] — the generate_handler!
// macro needs the direct module path where the attribute is applied.

// ── Shared dependencies ──────────────────────────────────────
use crate::models::account::{Account, Algorithm};
use crate::storage::{encrypt_accounts, load_accounts, save, AuthData};
use crate::AppState;
use base32::Alphabet;
use zeroize::Zeroize;

// ── Shared helpers ───────────────────────────────────────────

pub(crate) fn save_accounts(
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
pub(crate) fn zeroize_accounts(accounts: &mut Vec<Account>) {
    for a in accounts.iter_mut() {
        a.secret.zeroize();
    }
    accounts.clear();
}

/// Reject empty secrets. totp_rs::TOTP::new_unchecked accepts any non-empty secret.
pub(crate) fn validate_secret_length(secret: &[u8]) -> Result<(), String> {
    if secret.is_empty() {
        return Err("secret cannot be empty".to_string());
    }
    Ok(())
}

/// Decode a secret that may be base32-encoded (standard TOTP) or hexadecimal.
/// Tries base32 first — the standard, and also the preferred interpretation when a
/// string is valid in both formats (e.g. only A-F + 2-7 characters).
/// Falls back to hex if base32 fails.
/// Requires at least 128 bits (16 bytes) — totp_rs rejects shorter HMAC keys.
pub fn decode_secret(input: &str) -> Result<Vec<u8>, String> {
    let trimmed: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    let upper = trimmed.to_uppercase();

    // Try base32 first — the standard encoding for TOTP secrets
    if let Some(secret) = base32::decode(Alphabet::Rfc4648 { padding: false }, &upper) {
        validate_secret_length(&secret)?;
        return Ok(secret);
    }

    // Try hexadecimal as a fallback
    if let Ok(secret) = hex::decode(&trimmed) {
        validate_secret_length(&secret)?;
        return Ok(secret);
    }

    Err("invalid secret: not valid base32 or hex".to_string())
}

// ── Shared test infrastructure ───────────────────────────────

#[cfg(test)]
fn test_app_state() -> AppState {
    AppState {
        encryption_key: std::sync::Mutex::new(None),
        failed_attempts: std::sync::Mutex::new(0),
        last_attempt: std::sync::Mutex::new(None),
        cached_data: std::sync::Mutex::new(None),
    }
}

#[cfg(test)]
fn cleanup_auth_file() {
    let path = crate::paths::auth_path();
    if path.exists() {
        let _ = std::fs::remove_file(&path);
    }
}

#[cfg(test)]
fn with_fs_lock(f: impl FnOnce()) {
    let _lock = crate::storage::auth_file::FS_TEST_MUTEX
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    f();
}

#[cfg(test)]
fn test_key() -> [u8; 32] {
    [0xAAu8; 32]
}

// ── Shared tests ─────────────────────────────────────────────

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
        let result = decode_secret("hxdmvjecjjwsrb3hwizr4ifugftmxboz").unwrap();
        assert!(result.len() >= 16);
    }

    #[test]
    fn test_decode_secret_invalid_chars() {
        let err = decode_secret("!!!!invalid!!!!").unwrap_err();
        assert!(
            err.contains("invalid secret"),
            "error should mention invalid: {err}"
        );
    }

    #[test]
    fn test_decode_secret_valid_hex() {
        let result = decode_secret("0123456789abcdef0123456789abcdef").unwrap();
        assert_eq!(result.len(), 16);
    }

    #[test]
    fn test_decode_secret_hex_uppercase() {
        let result = decode_secret("0123456789ABCDEF0123456789ABCDEF").unwrap();
        assert_eq!(result.len(), 16);
    }

    #[test]
    fn test_decode_secret_hex_short() {
        let result = decode_secret("fb22358758f92429257e").unwrap();
        assert_eq!(result.len(), 10, "should decode to 10 bytes");
    }

    #[test]
    fn test_decode_secret_empty() {
        assert!(decode_secret("").is_err());
    }

    #[test]
    fn test_decode_secret_short_base32() {
        let result = decode_secret("GEZDGNBVGY3TQOJQ").unwrap();
        assert_eq!(result.len(), 10, "should decode to 10 bytes");
    }

    #[test]
    fn test_decode_secret_base32_single_char_fails() {
        assert!(decode_secret("").is_err(), "empty must be rejected");
    }

    #[test]
    fn test_decode_secret_mixed_base32_and_hex() {
        let result = decode_secret("JBSWY3DPEE").unwrap();
        assert_eq!(result.len(), 6, "JBSWY3DPEE = 6 bytes via base32");
    }

    #[test]
    fn test_decode_secret_pure_numeric_succeeds_as_hex() {
        let result = decode_secret("12345678").unwrap();
        assert!(!result.is_empty(), "numeric hex should decode");
    }

    #[test]
    fn test_decode_secret_hex_with_0x_prefix() {
        let err = decode_secret("0xdeadbeef").unwrap_err();
        assert!(
            err.contains("invalid secret"),
            "0x prefix should fail: {err}"
        );
    }

    #[test]
    fn test_decode_secret_very_long_base32() {
        let long = "HXDMVJECJJWSRB3H".repeat(62);
        let result = decode_secret(&long).unwrap();
        assert!(!result.is_empty(), "long valid base32 should decode");
        assert_eq!(result.len(), 62 * 10, "each 16-char block = 10 bytes");
    }

    #[test]
    fn test_decode_secret_leading_trailing_whitespace() {
        let result = decode_secret("  HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ  ").unwrap();
        assert!(
            !result.is_empty(),
            "should decode with surrounding whitespace"
        );
    }

    #[test]
    fn test_decode_secret_newlines_and_tabs() {
        let result = decode_secret("HXDM\nVJEC\tJJWS RB3H").unwrap();
        assert!(!result.is_empty(), "newlines/tabs should be stripped");
        assert_eq!(result.len(), 10, "16 base32 chars = 10 bytes");
    }

    // ── Edge cases: whitespace, mixed case, short ─────────────

    #[test]
    fn test_decode_secret_only_whitespace_fails() {
        let err = decode_secret("   \t\n  ").unwrap_err();
        assert!(
            err.contains("invalid secret") || err.contains("empty"),
            "only whitespace should fail: {err}"
        );
    }

    #[test]
    fn test_decode_secret_mixed_case_base32() {
        let result = decode_secret("HxdmVjecJjwSrB3hWizR4iFugFtMxBoZ").unwrap();
        assert_eq!(result.len(), 20, "mixed-case base32 should decode");
    }

    #[test]
    fn test_decode_secret_single_char_fails_as_invalid() {
        let err = decode_secret("F").unwrap_err();
        assert!(
            err.contains("cannot be empty"),
            "single base32 char should result in empty secret error: {err}"
        );
    }

    #[test]
    fn test_decode_secret_short_base32_two_chars() {
        let result = decode_secret("GE").unwrap();
        assert_eq!(result.len(), 1, "2 base32 chars = 1 byte");
    }

    #[test]
    fn test_decode_secret_only_padding_chars() {
        let err = decode_secret("====").unwrap_err();
        assert!(
            err.contains("invalid secret") || err.contains("empty"),
            "only padding chars should fail: {err}"
        );
    }

    // ── validate_secret_length ───────────────────────────────

    #[test]
    fn test_validate_secret_length_zero() {
        assert!(validate_secret_length(&[]).is_err());
    }

    #[test]
    fn test_validate_secret_length_one_byte() {
        assert!(validate_secret_length(&[0x01u8]).is_ok());
    }

    #[test]
    fn test_validate_secret_length_16_bytes() {
        assert!(validate_secret_length(&[0u8; 16]).is_ok());
    }

    // ── Storage-level integration tests ──────────────────────

    #[test]
    fn test_save_accounts_plaintext_roundtrip() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let mut data = crate::storage::try_load().unwrap();
            let accounts = vec![Account {
                id: "a1".into(),
                issuer: "Test".into(),
                label: "x".into(),
                algorithm: Algorithm::SHA1,
                digits: 6,
                period: 30,
                secret: vec![1, 2, 3],
                sort_order: 0,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            }];
            save_accounts(&mut data, &accounts, None).unwrap();
            crate::storage::save(&data).unwrap();

            let loaded = crate::storage::try_load().unwrap();
            assert!(!loaded.accounts.encrypted, "expected plaintext accounts");
            let mut reloaded = crate::storage::load_accounts(&loaded, None).unwrap();
            assert_eq!(reloaded.len(), 1);
            assert_eq!(reloaded[0].issuer, "Test");
            for a in &mut reloaded {
                a.secret.zeroize();
            }
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
                id: "enc1".into(),
                issuer: "Enc".into(),
                label: "e".into(),
                algorithm: Algorithm::SHA256,
                digits: 8,
                period: 60,
                secret: vec![9, 8, 7],
                sort_order: 0,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            }];
            let key = test_key();
            save_accounts(&mut data, &accounts, Some(key)).unwrap();
            crate::storage::save(&data).unwrap();

            let loaded = crate::storage::try_load().unwrap();
            assert!(loaded.accounts.encrypted);
            let mut reloaded = crate::storage::load_accounts(&loaded, Some(key)).unwrap();
            assert_eq!(reloaded.len(), 1);
            assert_eq!(reloaded[0].issuer, "Enc");
            for a in &mut reloaded {
                a.secret.zeroize();
            }
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
            let accounts: Vec<Account> = vec![];
            assert!(save_accounts(&mut data, &accounts, None).is_err());
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_zeroize_accounts_clears_secrets() {
        let mut accounts = vec![Account {
            id: "z".into(),
            issuer: "Z".into(),
            label: "z".into(),
            algorithm: Algorithm::SHA1,
            digits: 6,
            period: 30,
            secret: vec![1, 2, 3, 4],
            sort_order: 0,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }];
        zeroize_accounts(&mut accounts);
        assert!(accounts.is_empty());
    }
}
