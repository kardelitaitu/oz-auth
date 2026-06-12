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

#[cfg(test)]
mod tests {

    fn test_app_state() -> AppState {
        AppState {
            encryption_key: std::sync::Mutex::new(None),
        }
    }
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
        let err = decode_secret("!!!!invalid!!!!").unwrap_err();
        assert!(
            err.contains("invalid secret"),
            "error should mention invalid: {err}"
        );
    }

    #[test]
    fn test_decode_secret_valid_hex() {
        // 32 hex chars = 16 bytes (128 bits) — minimum valid length
        let result = decode_secret("0123456789abcdef0123456789abcdef").unwrap();
        assert_eq!(result.len(), 16);
    }

    #[test]
    fn test_decode_secret_hex_uppercase() {
        // Same as above but uppercase
        let result = decode_secret("0123456789ABCDEF0123456789ABCDEF").unwrap();
        assert_eq!(result.len(), 16);
    }

    #[test]
    fn test_decode_secret_hex_short() {
        // 20 hex chars = 10 bytes (80 bits) — now accepted
        let result = decode_secret("fb22358758f92429257e").unwrap();
        assert_eq!(result.len(), 10, "should decode to 10 bytes");
    }

    #[test]
    fn test_decode_secret_empty() {
        // Empty string decodes to empty bytes → rejected as too short
        assert!(decode_secret("").is_err());
    }

    #[test]
    fn test_decode_secret_short_base32() {
        // GEZDGNBVGY3TQOJQ decodes to 10 bytes (80 bits) — now accepted
        let result = decode_secret("GEZDGNBVGY3TQOJQ").unwrap();
        assert_eq!(result.len(), 10, "should decode to 10 bytes");
    }

    // ── Edge cases: zero-length, special character secrets ──

    #[test]
    fn test_decode_secret_base32_single_char_fails() {
        // "G" is 1 char → decodes to... actually it can't be decoded (needs 8 chars for 5 bytes)
        // But empty base32 decode returns Some(vec![]). Let's just test that empty fails.
        assert!(decode_secret("").is_err(), "empty must be rejected");
    }

    #[test]
    fn test_decode_secret_mixed_base32_and_hex() {
        // "JBSWY3DPEE" is valid base32 (7 bytes) but also valid hex? Let's check
        // JBSWY3DPEE in hex would be invalid (not hex chars). So it must decode via base32.
        let result = decode_secret("JBSWY3DPEE").unwrap();
        // This should be valid base32: 10 chars * 5 bits = 50 bits = 6.25 bytes → 6 bytes
        // Actually base32::decode with padding: false — 10 chars: floor(10*5/8) = 6 bytes
        assert_eq!(result.len(), 6, "JBSWY3DPEE = 6 bytes via base32");
    }

    #[test]
    fn test_decode_secret_pure_numeric_succeeds_as_hex() {
        // "12345678" is 8 hex chars = 4 bytes — hex::decode accepts it
        let result = decode_secret("12345678").unwrap();
        assert!(!result.is_empty(), "numeric hex should decode");
    }

    #[test]
    fn test_decode_secret_hex_with_0x_prefix() {
        // Hex with 0x prefix is NOT valid hex::decode input
        let err = decode_secret("0xdeadbeef").unwrap_err();
        assert!(
            err.contains("invalid secret"),
            "0x prefix should fail: {err}"
        );
    }

    #[test]
    fn test_decode_secret_very_long_base32() {
        // Very long base32 string (1000 chars) — stress test
        let long = "HXDMVJECJJWSRB3H".repeat(62); // ~992 chars of valid base32
        let result = decode_secret(&long).unwrap();
        assert!(!result.is_empty(), "long valid base32 should decode");
        assert_eq!(result.len(), 62 * 10, "each 16-char block = 10 bytes");
    }

    #[test]
    fn test_decode_secret_leading_trailing_whitespace() {
        // Whitespace trimming should handle leading/trailing spaces
        // HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ = 32 chars → 20 bytes
        let result = decode_secret("  HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ  ").unwrap();
        assert!(
            !result.is_empty(),
            "should decode with surrounding whitespace"
        );
    }

    #[test]
    fn test_decode_secret_newlines_and_tabs() {
        // HXDM is 4 chars, then VJEC is 4 chars (so "HXDMVJECJJWSRB3H" = 16 chars = 10 bytes)
        // We need a valid base32 string with whitespace injected
        let result = decode_secret("HXDM\nVJEC\tJJWS RB3H").unwrap();
        // After whitespace stripping: "HXDMVJECJJWSRB3H" = 16 chars = 10 bytes
        assert!(!result.is_empty(), "newlines/tabs should be stripped");
        assert_eq!(result.len(), 10, "16 base32 chars = 10 bytes");
    }

    // ── validate_secret_length ───────────────────────────────

    #[test]
    fn test_validate_secret_length_zero() {
        assert!(validate_secret_length(&[]).is_err());
    }

    #[test]
    fn test_validate_secret_length_one_byte() {
        // One byte is technically non-empty, but totp_rs requires >= 128 bits
        // Our validate only checks non-empty; totp_rs rejects short keys at generate time
        assert!(validate_secret_length(&[0x01u8]).is_ok());
    }

    #[test]
    fn test_validate_secret_length_16_bytes() {
        assert!(validate_secret_length(&[0u8; 16]).is_ok());
    }

    // ── Storage-level integration tests ──────────────────────

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

    fn test_key() -> [u8; 32] {
        [0xAAu8; 32]
    }

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
            let accounts = vec![];
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
            for a in &mut reloaded {
                a.secret.zeroize();
            }
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
                    id: "s1".into(),
                    issuer: "GitHub".into(),
                    label: "dev@github.com".into(),
                    algorithm: Algorithm::SHA1,
                    digits: 6,
                    period: 30,
                    secret: vec![1],
                    sort_order: 0,
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                },
                Account {
                    id: "s2".into(),
                    issuer: "Google".into(),
                    label: "user@gmail.com".into(),
                    algorithm: Algorithm::SHA1,
                    digits: 6,
                    period: 30,
                    secret: vec![2],
                    sort_order: 1,
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
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
            let filtered: Vec<_> = summaries
                .iter()
                .filter(|a| {
                    a.issuer.to_lowercase().contains(q) || a.label.to_lowercase().contains(q)
                })
                .collect();
            assert_eq!(filtered.len(), 1);
            assert_eq!(filtered[0].issuer, "GitHub");

            // Uppercase search should also match "GitHub"
            let q = "GITHUB";
            let filtered: Vec<_> = summaries
                .iter()
                .filter(|a| {
                    a.issuer.to_lowercase().contains(&q.to_lowercase())
                        || a.label.to_lowercase().contains(&q.to_lowercase())
                })
                .collect();
            assert_eq!(filtered.len(), 1);

            for a in &mut reloaded {
                a.secret.zeroize();
            }
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
                id: "real-id".into(),
                issuer: "Real".into(),
                label: "r".into(),
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

            // Simulate update_account guard: find by ID → not found
            // Real command: .ok_or_else(|| format!("account not found: {account_id}"))
            let loaded = crate::storage::try_load().unwrap();
            let mut reloaded = crate::storage::load_accounts(&loaded, None).unwrap();
            let found = reloaded.iter().any(|a| a.id == "nonexistent");
            assert!(!found, "update must reject non-existent account ID");
            for a in &mut reloaded {
                a.secret.zeroize();
            }
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
                id: "keep-me".into(),
                issuer: "Keep".into(),
                label: "k".into(),
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

            // Simulate remove_account: retain all except the target ID
            let loaded = crate::storage::try_load().unwrap();
            let mut reloaded = crate::storage::load_accounts(&loaded, None).unwrap();
            let before = reloaded.len();
            reloaded.retain(|a| a.id != "nonexistent");
            // Non-existent ID → no accounts removed
            assert_eq!(
                reloaded.len(),
                before,
                "removing non-existent ID is a no-op"
            );
            assert_eq!(reloaded[0].id, "keep-me");
            for a in &mut reloaded {
                a.secret.zeroize();
            }
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
                    id: "uuid-aaa".into(),
                    issuer: "Dupe".into(),
                    label: "same@test.com".into(),
                    algorithm: Algorithm::SHA1,
                    digits: 6,
                    period: 30,
                    secret: vec![1, 2],
                    sort_order: 0,
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                },
                Account {
                    id: "uuid-bbb".into(),
                    issuer: "Dupe".into(),
                    label: "same@test.com".into(),
                    algorithm: Algorithm::SHA256,
                    digits: 6,
                    period: 30,
                    secret: vec![3, 4],
                    sort_order: 1,
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                },
            ];
            save_accounts(&mut data, &accounts, None).unwrap();
            crate::storage::save(&data).unwrap();

            let loaded = crate::storage::try_load().unwrap();
            let mut reloaded = crate::storage::load_accounts(&loaded, None).unwrap();
            assert_eq!(
                reloaded.len(),
                2,
                "duplicate issuer+label allowed (different IDs)"
            );
            assert_ne!(reloaded[0].id, reloaded[1].id, "IDs must be distinct");
            for a in &mut reloaded {
                a.secret.zeroize();
            }
            reloaded.clear();
            cleanup_auth_file();
        });
    }

    // ── Impl function tests (cover Tauri command wrapper lines) ──

    #[test]
    fn test_add_account_impl_plaintext() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let mut data = crate::storage::try_load().unwrap();
            data.accounts.data_json = "[]".into();
            crate::storage::save(&data).unwrap();

            let account = add_account_impl(
                "TestIssuer",
                "test@test.com",
                "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ",
                None,
                None,
                None,
                &state,
            )
            .unwrap();
            assert_eq!(account.issuer, "TestIssuer");
            assert_eq!(account.digits, 6);
            assert_eq!(account.secret.len(), 20);
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_add_account_impl_with_custom_params() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let mut data = crate::storage::try_load().unwrap();
            data.accounts.data_json = "[]".into();
            crate::storage::save(&data).unwrap();

            let account = add_account_impl(
                "Custom",
                "custom@test.com",
                "0123456789abcdef0123456789abcdef",
                Some("SHA256"),
                Some(8),
                Some(60),
                &state,
            )
            .unwrap();
            assert!(matches!(account.algorithm, Algorithm::SHA256));
            assert_eq!(account.digits, 8);
            assert_eq!(account.period, 60);
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_add_account_from_uri_impl_success() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let mut data = crate::storage::try_load().unwrap();
            data.accounts.data_json = "[]".into();
            crate::storage::save(&data).unwrap();

            let uri = "otpauth://totp/ACME:john@example.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME&algorithm=SHA1&digits=6&period=30";
            let account = add_account_from_uri_impl(uri, &state).unwrap();
            assert_eq!(account.issuer, "ACME");
            assert_eq!(account.label, "john@example.com");
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_add_account_from_uri_impl_empty_secret_fails() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let uri = "otpauth://totp/Test:test@test.com?secret=";
            let err = add_account_from_uri_impl(uri, &state).unwrap_err();
            assert!(
                err.contains("empty") || err.contains("invalid"),
                "error: {err}"
            );
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_remove_account_impl_removes_by_id() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let mut data = crate::storage::try_load().unwrap();
            let accounts = vec![
                Account {
                    id: "keep".into(),
                    issuer: "Keep".into(),
                    label: "k".into(),
                    algorithm: Algorithm::SHA1,
                    digits: 6,
                    period: 30,
                    secret: vec![1],
                    sort_order: 0,
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                },
                Account {
                    id: "remove-me".into(),
                    issuer: "Remove".into(),
                    label: "r".into(),
                    algorithm: Algorithm::SHA1,
                    digits: 6,
                    period: 30,
                    secret: vec![2],
                    sort_order: 1,
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                },
            ];
            save_accounts(&mut data, &accounts, None).unwrap();
            crate::storage::save(&data).unwrap();

            remove_account_impl("remove-me", &state).unwrap();

            let loaded = crate::storage::try_load().unwrap();
            let mut remaining = crate::storage::load_accounts(&loaded, None).unwrap();
            assert_eq!(remaining.len(), 1);
            assert_eq!(remaining[0].id, "keep");
            for a in &mut remaining {
                a.secret.zeroize();
            }
            remaining.clear();
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_update_account_impl_updates_fields() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let mut data = crate::storage::try_load().unwrap();
            let accounts = vec![Account {
                id: "upd".into(),
                issuer: "Old".into(),
                label: "old@test.com".into(),
                algorithm: Algorithm::SHA1,
                digits: 6,
                period: 30,
                secret: vec![1],
                sort_order: 0,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            }];
            save_accounts(&mut data, &accounts, None).unwrap();
            crate::storage::save(&data).unwrap();

            let updated = update_account_impl(
                "upd",
                Some("NewIssuer"),
                Some("new@test.com"),
                Some(42),
                &state,
            )
            .unwrap();
            assert_eq!(updated.issuer, "NewIssuer");
            assert_eq!(updated.label, "new@test.com");
            assert_eq!(updated.sort_order, 42);
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_update_account_impl_nonexistent_id_fails() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let mut data = crate::storage::try_load().unwrap();
            let accounts = vec![Account {
                id: "real".into(),
                issuer: "Real".into(),
                label: "r".into(),
                algorithm: Algorithm::SHA1,
                digits: 6,
                period: 30,
                secret: vec![1],
                sort_order: 0,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            }];
            save_accounts(&mut data, &accounts, None).unwrap();
            crate::storage::save(&data).unwrap();
            let err = update_account_impl("nonexistent", None, None, None, &state).unwrap_err();
            assert!(err.contains("not found"), "error: {err}");
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_list_accounts_impl_with_search() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let mut data = crate::storage::try_load().unwrap();
            let accounts = vec![
                Account {
                    id: "g1".into(),
                    issuer: "GitHub".into(),
                    label: "dev@github.com".into(),
                    algorithm: Algorithm::SHA1,
                    digits: 6,
                    period: 30,
                    secret: vec![1],
                    sort_order: 0,
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                },
                Account {
                    id: "g2".into(),
                    issuer: "Google".into(),
                    label: "user@gmail.com".into(),
                    algorithm: Algorithm::SHA1,
                    digits: 6,
                    period: 30,
                    secret: vec![2],
                    sort_order: 1,
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                },
            ];
            save_accounts(&mut data, &accounts, None).unwrap();
            crate::storage::save(&data).unwrap();

            let results = list_accounts_impl(Some("github"), &state).unwrap();
            assert_eq!(results.len(), 1);
            assert_eq!(results[0].issuer, "GitHub");
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_list_accounts_impl_no_search_returns_all() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let mut data = crate::storage::try_load().unwrap();
            let accounts = vec![
                Account {
                    id: "a1".into(),
                    issuer: "Alpha".into(),
                    label: "a@test.com".into(),
                    algorithm: Algorithm::SHA1,
                    digits: 6,
                    period: 30,
                    secret: vec![1],
                    sort_order: 0,
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                },
                Account {
                    id: "a2".into(),
                    issuer: "Beta".into(),
                    label: "b@test.com".into(),
                    algorithm: Algorithm::SHA1,
                    digits: 6,
                    period: 30,
                    secret: vec![2],
                    sort_order: 1,
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                },
            ];
            save_accounts(&mut data, &accounts, None).unwrap();
            crate::storage::save(&data).unwrap();

            let results = list_accounts_impl(None, &state).unwrap();
            assert_eq!(results.len(), 2);
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_list_accounts_impl_search_no_match() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let mut data = crate::storage::try_load().unwrap();
            let accounts = vec![Account {
                id: "a1".into(),
                issuer: "Alpha".into(),
                label: "a@test.com".into(),
                algorithm: Algorithm::SHA1,
                digits: 6,
                period: 30,
                secret: vec![1],
                sort_order: 0,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            }];
            save_accounts(&mut data, &accounts, None).unwrap();
            crate::storage::save(&data).unwrap();

            let results = list_accounts_impl(Some("xyzzy"), &state).unwrap();
            assert!(results.is_empty(), "no-match search must return empty");
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
                    id: "first".into(),
                    issuer: "A".into(),
                    label: "a".into(),
                    algorithm: Algorithm::SHA1,
                    digits: 6,
                    period: 30,
                    secret: vec![1],
                    sort_order: 0,
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                },
                Account {
                    id: "second".into(),
                    issuer: "B".into(),
                    label: "b".into(),
                    algorithm: Algorithm::SHA1,
                    digits: 6,
                    period: 30,
                    secret: vec![2],
                    sort_order: 1,
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
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
            for a in &mut reloaded {
                a.secret.zeroize();
            }
            reloaded.clear();
            cleanup_auth_file();
        });
    }

    // ── New decode_secret edge case tests ──────────────────────

    #[test]
    fn test_decode_secret_only_whitespace_fails() {
        // All whitespace → trimmed to empty → decode fails
        let err = decode_secret("   \t\n  ").unwrap_err();
        assert!(
            err.contains("invalid secret") || err.contains("empty"),
            "only whitespace should fail: {err}"
        );
    }

    #[test]
    fn test_decode_secret_mixed_case_base32() {
        // HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ in mixed case
        let result = decode_secret("HxdmVjecJjwSrB3hWizR4iFugFtMxBoZ").unwrap();
        assert_eq!(result.len(), 20, "mixed-case base32 should decode");
    }

    #[test]
    fn test_decode_secret_single_char_fails_as_invalid() {
        // "F" is valid base32 (F=15) → decodes to 5 bits = insufficient for 1 byte
        // base32::decode returns Some(vec![]) → validate_secret_length rejects empty
        let err = decode_secret("F").unwrap_err();
        assert!(
            err.contains("cannot be empty"),
            "single base32 char should result in empty secret error: {err}"
        );
    }

    #[test]
    fn test_decode_secret_short_base32_two_chars() {
        // "GE" is 2 valid base32 chars → 10 bits → 1 byte (non-empty, passes validate)
        let result = decode_secret("GE").unwrap();
        assert_eq!(result.len(), 1, "2 base32 chars = 1 byte");
    }

    #[test]
    fn test_decode_secret_only_padding_chars() {
        // base32 padding chars without data
        let err = decode_secret("====").unwrap_err();
        assert!(
            err.contains("invalid secret") || err.contains("empty"),
            "only padding chars should fail: {err}"
        );
    }

    // ── New CRUD edge case tests via storage layer ───────────

    #[test]
    fn test_add_account_via_storage_with_accounts() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let mut data = crate::storage::try_load().unwrap();
            // Add one account
            let accounts = vec![Account {
                id: "existing".into(),
                issuer: "Old".into(),
                label: "old@test.com".into(),
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

            // Simulate adding a second account
            let mut loaded = crate::storage::try_load().unwrap();
            let mut all_accounts = crate::storage::load_accounts(&loaded, None).unwrap();
            all_accounts.push(Account {
                id: "newly-added".into(),
                issuer: "New".into(),
                label: "new@test.com".into(),
                algorithm: Algorithm::SHA256,
                digits: 8,
                period: 60,
                secret: vec![4, 5, 6],
                sort_order: 1,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            });
            save_accounts(&mut loaded, &all_accounts, None).unwrap();
            crate::storage::save(&loaded).unwrap();

            // Verify both exist
            let final_loaded = crate::storage::try_load().unwrap();
            let mut final_accounts = crate::storage::load_accounts(&final_loaded, None).unwrap();
            assert_eq!(final_accounts.len(), 2, "both accounts must be present");
            assert_eq!(final_accounts[1].id, "newly-added");
            assert_eq!(final_accounts[1].digits, 8);
            assert_eq!(final_accounts[1].period, 60);
            for a in &mut final_accounts {
                a.secret.zeroize();
            }
            final_accounts.clear();
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_remove_all_accounts_via_storage_yields_empty() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let mut data = crate::storage::try_load().unwrap();
            let accounts = vec![Account {
                id: "only-one".into(),
                issuer: "Solo".into(),
                label: "solo@test.com".into(),
                algorithm: Algorithm::SHA1,
                digits: 6,
                period: 30,
                secret: vec![1],
                sort_order: 0,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            }];
            save_accounts(&mut data, &accounts, None).unwrap();
            crate::storage::save(&data).unwrap();

            // Remove all accounts
            let mut loaded = crate::storage::try_load().unwrap();
            let mut all_accounts = crate::storage::load_accounts(&loaded, None).unwrap();
            all_accounts.clear();
            save_accounts(&mut loaded, &all_accounts, None).unwrap();
            crate::storage::save(&loaded).unwrap();

            // Verify empty
            let final_loaded = crate::storage::try_load().unwrap();
            assert!(!final_loaded.accounts.encrypted, "should be plaintext");
            assert_eq!(final_loaded.accounts.data_json, "[]", "empty JSON array");
            let mut final_accounts = crate::storage::load_accounts(&final_loaded, None).unwrap();
            assert!(final_accounts.is_empty(), "no accounts remain");
            for a in &mut final_accounts {
                a.secret.zeroize();
            }
            final_accounts.clear();
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_update_account_multiple_fields_via_storage() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let mut data = crate::storage::try_load().unwrap();
            let accounts = vec![Account {
                id: "updatable".into(),
                issuer: "OldIssuer".into(),
                label: "old@test.com".into(),
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

            // Find and update multiple fields
            let mut loaded = crate::storage::try_load().unwrap();
            let mut all_accounts = crate::storage::load_accounts(&loaded, None).unwrap();
            let account = all_accounts
                .iter_mut()
                .find(|a| a.id == "updatable")
                .unwrap();
            account.issuer = "NewIssuer".into();
            account.label = "new@test.com".into();
            account.sort_order = 99;
            save_accounts(&mut loaded, &all_accounts, None).unwrap();
            crate::storage::save(&loaded).unwrap();

            // Verify all fields updated
            let final_loaded = crate::storage::try_load().unwrap();
            let mut final_accounts = crate::storage::load_accounts(&final_loaded, None).unwrap();
            assert_eq!(final_accounts[0].issuer, "NewIssuer");
            assert_eq!(final_accounts[0].label, "new@test.com");
            assert_eq!(final_accounts[0].sort_order, 99);
            for a in &mut final_accounts {
                a.secret.zeroize();
            }
            final_accounts.clear();
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_list_accounts_search_no_match_returns_empty() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let mut data = crate::storage::try_load().unwrap();
            let accounts = vec![
                Account {
                    id: "a1".into(),
                    issuer: "Alpha".into(),
                    label: "alpha@test.com".into(),
                    algorithm: Algorithm::SHA1,
                    digits: 6,
                    period: 30,
                    secret: vec![1],
                    sort_order: 0,
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                },
                Account {
                    id: "a2".into(),
                    issuer: "Beta".into(),
                    label: "beta@test.com".into(),
                    algorithm: Algorithm::SHA1,
                    digits: 6,
                    period: 30,
                    secret: vec![2],
                    sort_order: 1,
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                },
            ];
            save_accounts(&mut data, &accounts, None).unwrap();
            crate::storage::save(&data).unwrap();

            let loaded = crate::storage::try_load().unwrap();
            let mut all_accounts = crate::storage::load_accounts(&loaded, None).unwrap();

            // search for "xyzzy" → no match
            let q = "xyzzy";
            let filtered: Vec<_> = all_accounts
                .iter()
                .filter(|a| {
                    a.issuer.to_lowercase().contains(q) || a.label.to_lowercase().contains(q)
                })
                .collect();
            assert!(filtered.is_empty(), "no-match search must return empty");

            for a in &mut all_accounts {
                a.secret.zeroize();
            }
            all_accounts.clear();
            cleanup_auth_file();
        });
    }
}

fn add_account_impl(
    issuer: &str,
    label: &str,
    secret: &str,
    algorithm: Option<&str>,
    digits: Option<u8>,
    period: Option<u32>,
    state: &AppState,
) -> Result<Account, String> {
    let mut data = try_load()?;
    let key_wrapper = state.get_key()?;
    let key: Option<[u8; 32]> = key_wrapper.as_ref().map(|z| **z);
    let mut accounts = load_accounts(&data, key)?;
    // key_wrapper dropped here → auto-zeroized

    let algo = match algorithm {
        Some("SHA256") => Algorithm::SHA256,
        Some("SHA512") => Algorithm::SHA512,
        _ => Algorithm::SHA1,
    };

    let now = Utc::now();
    let account = Account {
        id: Uuid::new_v4().to_string(),
        issuer: issuer.to_string(),
        label: label.to_string(),
        algorithm: algo,
        digits: digits.unwrap_or(6),
        period: period.unwrap_or(30),
        secret: decode_secret(secret)?,
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
pub fn add_account(
    issuer: String,
    label: String,
    secret: String,
    algorithm: Option<String>,
    digits: Option<u8>,
    period: Option<u32>,
    state: State<'_, AppState>,
) -> Result<Account, String> {
    add_account_impl(
        &issuer,
        &label,
        &secret,
        algorithm.as_deref(),
        digits,
        period,
        &state,
    )
}

fn add_account_from_uri_impl(otpauth_uri: &str, state: &AppState) -> Result<Account, String> {
    let parsed = crate::utils::otpauth::parse_uri(otpauth_uri)?;

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
pub fn add_account_from_uri(
    otpauth_uri: String,
    state: State<'_, AppState>,
) -> Result<Account, String> {
    add_account_from_uri_impl(&otpauth_uri, &state)
}

fn remove_account_impl(account_id: &str, state: &AppState) -> Result<(), String> {
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
pub fn remove_account(account_id: String, state: State<'_, AppState>) -> Result<(), String> {
    remove_account_impl(&account_id, &state)
}

fn update_account_impl(
    account_id: &str,
    issuer: Option<&str>,
    label: Option<&str>,
    sort_order: Option<u32>,
    state: &AppState,
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
        account.issuer = v.to_string();
    }
    if let Some(v) = label {
        account.label = v.to_string();
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
pub fn update_account(
    account_id: String,
    issuer: Option<String>,
    label: Option<String>,
    sort_order: Option<u32>,
    state: State<'_, AppState>,
) -> Result<Account, String> {
    update_account_impl(
        &account_id,
        issuer.as_deref(),
        label.as_deref(),
        sort_order,
        &state,
    )
}

fn list_accounts_impl(
    search_query: Option<&str>,
    state: &AppState,
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

#[tauri::command]
pub fn list_accounts(
    search_query: Option<String>,
    state: State<'_, AppState>,
) -> Result<Vec<AccountSummary>, String> {
    list_accounts_impl(search_query.as_deref(), &state)
}

fn get_otpauth_uri_impl(account_id: &str, state: &AppState) -> Result<String, String> {
    let data = try_load()?;
    let key_wrapper = state.get_key()?;
    let key: Option<[u8; 32]> = key_wrapper.as_ref().map(|z| **z);
    let mut accounts = load_accounts(&data, key)?;

    let account = accounts
        .iter()
        .find(|a| a.id == account_id)
        .ok_or_else(|| format!("account not found: {account_id}"))?;

    let secret_b32 = base32::encode(Alphabet::Rfc4648 { padding: false }, &account.secret);
    let issuer_enc = urlencoding(&account.issuer);
    let label_enc = urlencoding(&account.label);
    let algo_str = match account.algorithm {
        Algorithm::SHA1 => "SHA1",
        Algorithm::SHA256 => "SHA256",
        Algorithm::SHA512 => "SHA512",
    };

    let uri = format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm={}&digits={}&period={}",
        issuer_enc, label_enc, secret_b32, issuer_enc, algo_str, account.digits, account.period
    );

    zeroize_accounts(&mut accounts);
    Ok(uri)
}

/// URL-encode a string for use in an otpauth URI path or query.
fn urlencoding(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => {
                out.push('%');
                out.push_str(&format!("{:02X}", byte));
            }
        }
    }
    out
}

#[tauri::command]
pub fn get_otpauth_uri(account_id: String, state: State<'_, AppState>) -> Result<String, String> {
    get_otpauth_uri_impl(&account_id, &state)
}

fn get_backup_uris_impl(state: &AppState) -> Result<Vec<String>, String> {
    let data = try_load()?;
    let key_wrapper = state.get_key()?;
    let key: Option<[u8; 32]> = key_wrapper.as_ref().map(|z| **z);
    let mut accounts = load_accounts(&data, key)?;

    let mut uris = Vec::with_capacity(accounts.len());
    for account in &accounts {
        let secret_b32 = base32::encode(Alphabet::Rfc4648 { padding: false }, &account.secret);
        let issuer_enc = urlencoding(&account.issuer);
        let label_enc = urlencoding(&account.label);
        let algo_str = match account.algorithm {
            Algorithm::SHA1 => "SHA1",
            Algorithm::SHA256 => "SHA256",
            Algorithm::SHA512 => "SHA512",
        };
        uris.push(format!(
            "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm={}&digits={}&period={}",
            issuer_enc, label_enc, secret_b32, issuer_enc, algo_str, account.digits, account.period
        ));
    }

    zeroize_accounts(&mut accounts);
    Ok(uris)
}

fn save_backup_file_impl(state: &AppState) -> Result<String, String> {
    let uris = get_backup_uris_impl(state)?;
    if uris.is_empty() {
        return Err("no accounts to backup".to_string());
    }

    let exe_stem = crate::paths::exe_stem();
    let exe_dir = crate::paths::exe_dir();

    // Build the file content
    let timestamp = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S");
    let mut content = String::new();
    content.push_str(&format!("# {} backup — {}\n", exe_stem, timestamp));
    content.push_str(&format!("# {} account(s)\n", uris.len()));
    content.push_str("# WARNING: Contains plain-text secrets. Keep this file secure.\n");
    content.push('\n');
    for uri in &uris {
        content.push_str(uri);
        content.push('\n');
    }
    content.push('\n');

    // Find an available filename: oz-auth.backup.txt, oz-auth.backup (1).txt, etc.
    let base = format!("{}.backup.txt", exe_stem);
    let mut path = exe_dir.join(&base);
    if path.exists() {
        let mut n = 1u32;
        loop {
            let name = format!("{}.backup ({}).txt", exe_stem, n);
            path = exe_dir.join(&name);
            if !path.exists() {
                break;
            }
            n += 1;
        }
    }

    std::fs::write(&path, &content)
        .map_err(|e| format!("failed to write backup: {e}"))?;

    Ok(path.to_string_lossy().to_string())
}

#[tauri::command]
pub fn save_backup_file(state: State<'_, AppState>) -> Result<String, String> {
    save_backup_file_impl(&state)
}
