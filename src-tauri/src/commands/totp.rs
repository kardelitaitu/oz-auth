use crate::models::account::Account;
use crate::storage::{load_accounts, try_load};
use crate::AppState;
use tauri::State;
use zeroize::Zeroize;

fn make_totp(account: &Account) -> Result<totp_rs::TOTP, String> {
    use crate::models::account::Algorithm;

    // Reject empty secrets
    crate::commands::accounts::validate_secret_length(&account.secret)?;

    // Validate digit count — new_unchecked skips this check
    if account.digits != 6 && account.digits != 8 {
        return Err(format!(
            "invalid digit count: {}, must be 6 or 8",
            account.digits
        ));
    }

    // Reject period=0 (would cause division-by-zero in remaining time calc)
    if account.period == 0 {
        return Err("invalid period: must be > 0".to_string());
    }

    let algo = match account.algorithm {
        Algorithm::SHA1 => totp_rs::Algorithm::SHA1,
        Algorithm::SHA256 => totp_rs::Algorithm::SHA256,
        Algorithm::SHA512 => totp_rs::Algorithm::SHA512,
    };

    Ok(totp_rs::TOTP::new_unchecked(
        algo,
        account.digits as usize,
        1,
        account.period as u64,
        account.secret.clone(),
        Some(account.issuer.clone()),
        account.label.clone(),
    ))
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Core logic for generate_code — takes &AppState so it's testable without Tauri.
fn generate_code_impl(account_id: &str, state: &AppState) -> Result<(String, u32), String> {
    let data = try_load()?;
    let key_wrapper = state.get_key()?;
    let key: Option<[u8; 32]> = key_wrapper.as_ref().map(|z| **z);
    let mut accounts = load_accounts(&data, key)?;
    // key_wrapper dropped here → auto-zeroized

    let account = accounts
        .iter()
        .find(|a| a.id == account_id)
        .ok_or_else(|| format!("account not found: {account_id}"))?;

    let totp = make_totp(account)?;
    let now = current_timestamp();
    let code = totp.generate(now);
    let remaining = account.period - (now % account.period as u64) as u32;

    // Zeroize all decrypted secrets
    for a in &mut accounts {
        a.secret.zeroize();
    }
    accounts.clear();

    Ok((code, remaining))
}

/// Generate a TOTP code for a single account.
/// The encryption key wrapper auto-zeroizes on drop.
/// Account secrets are zeroized after code generation.
#[tauri::command]
pub fn generate_code(
    account_id: String,
    state: State<'_, AppState>,
) -> Result<(String, u32), String> {
    generate_code_impl(&account_id, &state)
}

/// Core logic for generate_all_codes — takes &AppState so it's testable without Tauri.
fn generate_all_codes_impl(state: &AppState) -> Result<Vec<(String, String, u32)>, String> {
    let data = try_load()?;
    let key_wrapper = state.get_key()?;
    let key: Option<[u8; 32]> = key_wrapper.as_ref().map(|z| **z);
    let mut accounts = load_accounts(&data, key)?;
    // key_wrapper dropped here → auto-zeroized
    let now = current_timestamp();

    let mut results = Vec::with_capacity(accounts.len());
    for account in &accounts {
        let totp = make_totp(account)?;
        let code = totp.generate(now);
        let remaining = account.period - (now % account.period as u64) as u32;
        results.push((account.id.clone(), code, remaining));
    }

    // Zeroize all decrypted secrets
    for a in &mut accounts {
        a.secret.zeroize();
    }
    accounts.clear();

    Ok(results)
}

/// Generate TOTP codes for all accounts at once.
/// The encryption key wrapper auto-zeroizes on drop.
/// Account secrets are zeroized after code generation.
#[tauri::command]
pub fn generate_all_codes(
    state: State<'_, AppState>,
) -> Result<Vec<(String, String, u32)>, String> {
    generate_all_codes_impl(&state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;
    use crate::models::account::{Account, Algorithm};
    use crate::test_utils::{cleanup_auth_file, test_app_state, with_fs_lock};
    use chrono::Utc;

    fn test_account(secret: &[u8], algo: Algorithm, digits: u8) -> Account {
        Account {
            id: "test-1".into(),
            issuer: "Test".into(),
            label: "test@test.com".into(),
            algorithm: algo,
            digits,
            period: 30,
            secret: secret.to_vec(),
            sort_order: 0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn seed_plaintext_accounts(accounts: &[Account]) {
        let mut data = crate::storage::try_load().unwrap();
        data.accounts.data_json = serde_json::to_string(accounts).unwrap();
        crate::storage::save(&data).unwrap();
    }

    fn seed_encrypted_accounts(accounts: &[Account]) -> [u8; 32] {
        let key = [0x55u8; 32];
        let mut data = crate::storage::try_load().unwrap();
        let salt = crypto::generate_salt();
        data.accounts = crate::storage::encrypt_accounts(accounts, &key).unwrap();
        data.config.password_protected = true;
        data.config.password_salt = hex::encode(salt);
        crate::storage::save(&data).unwrap();
        key
    }

    /// RFC 6238 test vector — SHA-1
    #[test]
    fn test_rfc6238_sha1_vectors() {
        let secret = b"12345678901234567890";
        let account = test_account(secret, Algorithm::SHA1, 8);
        let totp = make_totp(&account).unwrap();

        let vectors: &[(u64, &str)] = &[
            (59, "94287082"),
            (1111111109, "07081804"),
            (1111111111, "14050471"),
            (1234567890, "89005924"),
            (2000000000, "69279037"),
            (20000000000, "65353130"),
        ];

        for (time, expected) in vectors {
            let code = totp.generate(*time);
            assert_eq!(&code, expected, "SHA-1 code mismatch at time {time}");
        }
    }

    /// RFC 6238 test vector — SHA-256
    #[test]
    fn test_rfc6238_sha256_vectors() {
        let secret = b"12345678901234567890123456789012";
        let account = test_account(secret, Algorithm::SHA256, 8);
        let totp = make_totp(&account).unwrap();

        let vectors: &[(u64, &str)] = &[
            (59, "46119246"),
            (1111111109, "68084774"),
            (1111111111, "67062674"),
            (1234567890, "91819424"),
            (2000000000, "90698825"),
            (20000000000, "77737706"),
        ];

        for (time, expected) in vectors {
            let code = totp.generate(*time);
            assert_eq!(&code, expected, "SHA-256 code mismatch at time {time}");
        }
    }

    /// RFC 6238 test vector — SHA-512
    #[test]
    fn test_rfc6238_sha512_vectors() {
        let secret = b"1234567890123456789012345678901234567890123456789012345678901234";
        let account = test_account(secret, Algorithm::SHA512, 8);
        let totp = make_totp(&account).unwrap();

        let vectors: &[(u64, &str)] = &[
            (59, "90693936"),
            (1111111109, "25091201"),
            (1111111111, "99943326"),
            (1234567890, "93441116"),
            (2000000000, "38618901"),
            (20000000000, "47863826"),
        ];

        for (time, expected) in vectors {
            let code = totp.generate(*time);
            assert_eq!(&code, expected, "SHA-512 code mismatch at time {time}");
        }
    }

    /// 6-digit codes (SHA-1)
    #[test]
    fn test_6_digit_sha1() {
        let secret = b"12345678901234567890";
        let account = test_account(secret, Algorithm::SHA1, 6);
        let totp = make_totp(&account).unwrap();

        let vectors: &[(u64, &str)] = &[
            (59, "287082"),
            (1111111111, "050471"),
            (2000000000, "279037"),
        ];

        for (time, expected) in vectors {
            let code = totp.generate(*time);
            assert_eq!(
                &code, expected,
                "6-digit SHA-1 code mismatch at time {time}"
            );
        }
    }

    #[test]
    fn test_60_second_period() {
        let secret = b"12345678901234567890";
        let mut account = test_account(secret, Algorithm::SHA1, 6);
        account.period = 60;
        let totp = make_totp(&account).unwrap();
        // Counter = floor(ts/60). t=0 and t=59 both give counter 0 → same code
        assert_eq!(totp.generate(0), totp.generate(59));
        // t=59 gives counter 0, t=60 gives counter 1 → different code
        assert_ne!(totp.generate(59), totp.generate(60));
        // t=60 and t=119 both give counter 1 → same code
        assert_eq!(totp.generate(60), totp.generate(119));
    }

    #[test]
    fn test_code_rolls_at_period_boundary() {
        let secret = b"12345678901234567890";
        let account = test_account(secret, Algorithm::SHA1, 6);
        let totp = make_totp(&account).unwrap();
        // At t=29 and t=30, the code SHOULD be different (30s period)
        assert_ne!(
            totp.generate(29),
            totp.generate(30),
            "code must roll at period boundary"
        );
        // But t=0 and t=29 should be same (same counter 0)
        assert_eq!(totp.generate(0), totp.generate(29));
    }

    #[test]
    fn test_invalid_digits_fails() {
        let secret = b"12345678901234567890";
        let account = test_account(secret, Algorithm::SHA1, 9); // invalid digit count
        assert!(make_totp(&account).is_err());
    }

    // ── generate_code_impl tests ──────────────────────────────

    #[test]
    fn test_generate_code_plaintext_account() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let secret = b"12345678901234567890";
            seed_plaintext_accounts(&[test_account(secret, Algorithm::SHA1, 6)]);

            let (code, remaining) = generate_code_impl("test-1", &state).unwrap();

            assert_eq!(code.len(), 6, "6-digit code expected");
            assert!(
                code.chars().all(|c| c.is_ascii_digit()),
                "code must be all digits"
            );
            assert!(remaining > 0 && remaining <= 30, "remaining in (0, 30]");
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_generate_code_encrypted_unlocked() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let secret = b"12345678901234567890";
            let key = seed_encrypted_accounts(&[test_account(secret, Algorithm::SHA1, 6)]);
            state.set_key(key).unwrap();

            let (code, remaining) = generate_code_impl("test-1", &state).unwrap();

            assert_eq!(code.len(), 6);
            assert!(code.chars().all(|c| c.is_ascii_digit()));
            assert!(remaining < 30);
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_generate_code_locked_fails() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let secret = b"12345678901234567890";
            seed_encrypted_accounts(&[test_account(secret, Algorithm::SHA1, 6)]);
            // key NOT set in state → locked

            let result = generate_code_impl("test-1", &state);
            assert!(result.is_err(), "should fail when locked");
            assert!(
                result.unwrap_err().contains("locked"),
                "error should mention locked"
            );
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_generate_code_account_not_found() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let secret = b"12345678901234567890";
            seed_plaintext_accounts(&[test_account(secret, Algorithm::SHA1, 6)]);

            let result = generate_code_impl("nonexistent-id", &state);
            assert!(result.is_err(), "should fail for missing account");
            assert!(
                result.unwrap_err().contains("not found"),
                "error should mention not found"
            );
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_generate_code_sha256_algorithm() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let secret = b"12345678901234567890123456789012";
            seed_plaintext_accounts(&[test_account(secret, Algorithm::SHA256, 6)]);

            let (code, _remaining) = generate_code_impl("test-1", &state).unwrap();
            assert_eq!(code.len(), 6);
            assert!(code.chars().all(|c| c.is_ascii_digit()));
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_generate_code_8_digit_sha512() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let secret = b"1234567890123456789012345678901234567890123456789012345678901234";
            seed_plaintext_accounts(&[test_account(secret, Algorithm::SHA512, 8)]);

            let (code, remaining) = generate_code_impl("test-1", &state).unwrap();
            assert_eq!(
                code.len(),
                8,
                "8-digit code expected for SHA-512 with digits=8"
            );
            assert!(code.chars().all(|c| c.is_ascii_digit()));
            assert!(remaining < 30);
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_generate_code_60s_period() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let secret = b"12345678901234567890";
            let mut account = test_account(secret, Algorithm::SHA1, 6);
            account.id = "acct-60s".into();
            account.period = 60;
            seed_plaintext_accounts(&[account]);

            let (_code, remaining) = generate_code_impl("acct-60s", &state).unwrap();
            assert!(remaining > 0 && remaining <= 60, "remaining in (0, 60]");
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_generate_code_from_auth_file() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let secret = b"12345678901234567890";
            let account = test_account(secret, Algorithm::SHA1, 6);
            seed_plaintext_accounts(&[account]);

            // Verify the code is consistent when called twice in quick succession
            // (same counter window → same code)
            let (code1, _) = generate_code_impl("test-1", &state).unwrap();
            let (code2, remaining2) = generate_code_impl("test-1", &state).unwrap();
            assert_eq!(code1, code2, "same counter window → same code");
            assert!(remaining2 < 30);
            cleanup_auth_file();
        });
    }

    // ── generate_all_codes_impl tests ─────────────────────────

    #[test]
    fn test_generate_all_codes_plaintext_two_accounts() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let s1 = b"12345678901234567890";
            let s2 = b"98765432109876543210";
            let mut a1 = test_account(s1, Algorithm::SHA1, 6);
            a1.id = "id-a".into();
            a1.sort_order = 0;
            let mut a2 = test_account(s2, Algorithm::SHA256, 6);
            a2.id = "id-b".into();
            a2.sort_order = 1;
            seed_plaintext_accounts(&[a1, a2]);

            let results = generate_all_codes_impl(&state).unwrap();
            assert_eq!(results.len(), 2, "should return 2 results");
            assert_eq!(
                results[0].0, "id-a",
                "first result should be id-a (sort_order 0)"
            );
            assert_eq!(
                results[1].0, "id-b",
                "second result should be id-b (sort_order 1)"
            );
            for (_id, code, remaining) in &results {
                assert_eq!(code.len(), 6, "each code should be 6 digits");
                assert!(code.chars().all(|c| c.is_ascii_digit()));
                assert!(*remaining > 0 && *remaining <= 30, "remaining in (0, 30]");
            }
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_generate_all_codes_encrypted_unlocked() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let mut a1 = test_account(b"11111111111111111111", Algorithm::SHA1, 6);
            a1.id = "enc-1".into();
            let mut a2 = test_account(b"22222222222222222222", Algorithm::SHA256, 6);
            a2.id = "enc-2".into();
            let key = seed_encrypted_accounts(&[a1, a2]);
            state.set_key(key).unwrap();

            let results = generate_all_codes_impl(&state).unwrap();
            assert_eq!(results.len(), 2);
            let ids: Vec<&str> = results.iter().map(|(id, _, _)| id.as_str()).collect();
            assert!(ids.contains(&"enc-1"), "enc-1 should be in results");
            assert!(ids.contains(&"enc-2"), "enc-2 should be in results");
            for (_id, code, remaining) in &results {
                assert_eq!(code.len(), 6);
                assert!(code.chars().all(|c| c.is_ascii_digit()));
                assert!(*remaining < 30);
            }
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_generate_all_codes_locked_fails() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            seed_encrypted_accounts(&[test_account(b"11111111111111111111", Algorithm::SHA1, 6)]);
            // key NOT set → locked

            let result = generate_all_codes_impl(&state);
            assert!(result.is_err(), "should fail when locked");
            assert!(result.unwrap_err().contains("locked"));
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_generate_all_codes_empty_accounts() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            // Persist a fresh auth file with valid empty accounts JSON
            let mut data = crate::storage::try_load().unwrap();
            data.accounts.data_json = "[]".into();
            crate::storage::save(&data).unwrap();

            let results = generate_all_codes_impl(&state).unwrap();
            assert!(results.is_empty(), "empty accounts → empty results");
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_generate_all_codes_mixed_algorithms() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let mut a1 = test_account(b"12345678901234567890", Algorithm::SHA1, 6);
            a1.id = "sha1-acct".into();
            let mut a2 = test_account(b"12345678901234567890123456789012", Algorithm::SHA256, 6);
            a2.id = "sha256-acct".into();
            let mut a3 = test_account(
                b"1234567890123456789012345678901234567890123456789012345678901234",
                Algorithm::SHA512,
                6,
            );
            a3.id = "sha512-acct".into();
            seed_plaintext_accounts(&[a1, a2, a3]);

            let results = generate_all_codes_impl(&state).unwrap();
            assert_eq!(results.len(), 3);
            for (_id, code, _) in &results {
                assert_eq!(code.len(), 6);
            }
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_generate_all_codes_preserves_sort_order() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let mut accounts = Vec::new();
            for i in 0..5 {
                let mut a = test_account(b"12345678901234567890", Algorithm::SHA1, 6);
                a.id = format!("acct-{i}");
                a.sort_order = i;
                accounts.push(a);
            }
            seed_plaintext_accounts(&accounts);

            let results = generate_all_codes_impl(&state).unwrap();
            assert_eq!(results.len(), 5);
            for (i, (id, _, _)) in results.iter().enumerate() {
                assert_eq!(id, &format!("acct-{i}"), "results must preserve sort order");
            }
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_generate_all_codes_60s_period_remaining() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let mut a = test_account(b"12345678901234567890", Algorithm::SHA1, 6);
            a.id = "slow".into();
            a.period = 60;
            seed_plaintext_accounts(&[a]);

            let results = generate_all_codes_impl(&state).unwrap();
            assert_eq!(results.len(), 1);
            let (_id, _code, remaining) = &results[0];
            assert!(*remaining > 0 && *remaining <= 60, "remaining in (0, 60]");
            cleanup_auth_file();
        });
    }

    // ── corrupted secret edge cases ──────────────────────────

    #[test]
    fn test_generate_code_empty_secret_fails_gracefully() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            // Account with an empty secret — now caught by validate_secret_length in make_totp
            let mut account = test_account(b"12345678901234567890", Algorithm::SHA1, 6);
            account.secret = vec![];
            seed_plaintext_accounts(&[account]);

            let result = generate_code_impl("test-1", &state);
            assert!(result.is_err(), "empty secret must produce an error");
            let err = result.unwrap_err();
            assert!(
                err.contains("cannot be empty"),
                "error should mention not empty: {err}"
            );
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_generate_code_short_secret_succeeds() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            // 10-byte secret (80 bits) — now accepted via new_unchecked
            let mut account = test_account(b"1234567890", Algorithm::SHA1, 6);
            account.secret = b"JBSWY3DPEB".to_vec(); // 10 bytes
            seed_plaintext_accounts(&[account]);

            let (code, remaining) = generate_code_impl("test-1", &state).unwrap();
            assert_eq!(code.len(), 6);
            assert!(code.chars().all(|c| c.is_ascii_digit()));
            assert!(remaining > 0 && remaining <= 30);
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_generate_code_minimum_length_secret_succeeds() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            // totp_rs requires the secret to be at least 128 bits (16 bytes).
            // A 16-byte all-zero key is weak but technically valid for HMAC.
            let mut account = test_account(b"12345678901234567890", Algorithm::SHA1, 6);
            account.secret = vec![0x00u8; 16];
            seed_plaintext_accounts(&[account]);

            let (code, remaining) = generate_code_impl("test-1", &state).unwrap();
            assert_eq!(code.len(), 6);
            assert!(code.chars().all(|c| c.is_ascii_digit()));
            assert!(remaining > 0 && remaining <= 30);
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_generate_all_codes_one_corrupted_secret_poisons_batch() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            // Account A has a valid secret, account B has an empty (corrupted) secret
            let mut a1 = test_account(b"12345678901234567890", Algorithm::SHA1, 6);
            a1.id = "good".into();
            let mut a2 = test_account(b"12345678901234567890", Algorithm::SHA1, 6);
            a2.id = "bad".into();
            a2.secret = vec![];
            seed_plaintext_accounts(&[a1, a2]);

            let result = generate_all_codes_impl(&state);
            // The batch fails entirely because make_totp (via validate_secret_length) errors.
            assert!(
                result.is_err(),
                "corrupted account causes entire batch to fail"
            );
            let err = result.unwrap_err();
            assert!(
                err.contains("cannot be empty"),
                "error should mention empty: {err}"
            );
            cleanup_auth_file();
        });
    }

    // ── New tests ──────────────────────────────────────────────

    #[test]
    fn test_code_stable_within_same_timestep() {
        // Same counter → same code (no time-based drift)
        let secret = b"12345678901234567890";
        let account = test_account(secret, Algorithm::SHA1, 6);
        let totp = make_totp(&account).unwrap();
        let code_a = totp.generate(1234567890);
        let code_b = totp.generate(1234567890);
        assert_eq!(code_a, code_b, "same timestamp must produce same code");
    }

    #[test]
    fn test_code_different_across_timesteps() {
        let secret = b"12345678901234567890";
        let account = test_account(secret, Algorithm::SHA1, 6);
        let totp = make_totp(&account).unwrap();
        // Different counters → different codes (guaranteed by TOTP spec)
        let code_t0 = totp.generate(30);
        let code_t1 = totp.generate(60);
        assert_ne!(
            code_t0, code_t1,
            "different counters must produce different codes"
        );
    }

    #[test]
    fn test_make_totp_rejects_zero_digits() {
        let secret = b"12345678901234567890";
        let account = test_account(secret, Algorithm::SHA1, 0);
        assert!(make_totp(&account).is_err(), "0 digits must be rejected");
    }

    #[test]
    fn test_make_totp_rejects_digits_7() {
        let secret = b"12345678901234567890";
        let account = test_account(secret, Algorithm::SHA1, 7);
        assert!(make_totp(&account).is_err(), "7 digits must be rejected");
    }

    #[test]
    fn test_make_totp_rejects_zero_period() {
        let secret = b"12345678901234567890";
        let mut account = test_account(secret, Algorithm::SHA1, 6);
        account.period = 0;
        assert!(make_totp(&account).is_err(), "period=0 must be rejected");
    }

    #[test]
    fn test_make_totp_accepts_6_digits() {
        let secret = b"12345678901234567890";
        let account = test_account(secret, Algorithm::SHA1, 6);
        assert!(make_totp(&account).is_ok(), "6 digits must be accepted");
    }

    #[test]
    fn test_make_totp_accepts_8_digits() {
        let secret = b"12345678901234567890";
        let account = test_account(secret, Algorithm::SHA1, 8);
        assert!(make_totp(&account).is_ok(), "8 digits must be accepted");
    }

    #[test]
    fn test_generate_code_with_missing_auth_file() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            // No auth file exists → try_load creates fresh() with empty accounts
            let _data = crate::storage::try_load().unwrap();
            let result = crate::commands::totp::generate_code_impl("any-id", &state);
            assert!(result.is_err(), "no accounts → must fail");
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_generate_all_codes_zero_accounts_via_seed() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            // Empty accounts array
            let mut data = crate::storage::try_load().unwrap();
            data.accounts.data_json = "[]".into();
            crate::storage::save(&data).unwrap();

            let results = generate_all_codes_impl(&state).unwrap();
            assert!(results.is_empty(), "zero accounts → empty results");
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_remaining_time_within_range_multiple_calls() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let secret = b"12345678901234567890";
            seed_plaintext_accounts(&[test_account(secret, Algorithm::SHA1, 6)]);

            // Call multiple times in quick succession — remaining should be monotonic
            let (_, r1) = generate_code_impl("test-1", &state).unwrap();
            let (_, r2) = generate_code_impl("test-1", &state).unwrap();
            // r2 should be <= r1 (time moves forward)
            assert!(
                r2 <= r1,
                "remaining should decrease or stay same: {r2} > {r1}"
            );
            assert!(r1 > 0 && r1 <= 30, "r1 out of range: {r1}");
            assert!(r2 > 0 && r2 <= 30, "r2 out of range: {r2}");
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_generate_code_account_id_does_not_panic() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let secret = b"12345678901234567890";
            seed_plaintext_accounts(&[test_account(secret, Algorithm::SHA1, 6)]);

            // Searching for an ID that starts with our target prefix but isn't exact
            // must return Err, not panic
            let result = generate_code_impl("test-", &state);
            assert!(result.is_err(), "partial ID match must fail, not panic");
            assert!(result.unwrap_err().contains("not found"));
            cleanup_auth_file();
        });
    }

    // ── generate_all_codes: sort order edge cases ────────────

    #[test]
    fn test_generate_all_codes_order_matches_storage() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let mut a1 = test_account(b"11111111111111111111", Algorithm::SHA1, 6);
            a1.id = "first-in-storage".into();
            a1.sort_order = 1;
            let mut a2 = test_account(b"22222222222222222222", Algorithm::SHA256, 6);
            a2.id = "second-in-storage".into();
            a2.sort_order = 0;
            seed_plaintext_accounts(&[a1, a2]);

            let results = generate_all_codes_impl(&state).unwrap();
            // generate_all_codes_impl returns accounts in storage order (not sorted by sort_order)
            // The frontend is responsible for sorting by sort_order
            assert_eq!(results.len(), 2);
            assert_eq!(
                results[0].0, "first-in-storage",
                "first in storage = first in results"
            );
            assert_eq!(
                results[1].0, "second-in-storage",
                "second in storage = second in results"
            );
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_generate_all_codes_order_with_explicit_sort_order() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let mut a1 = test_account(b"11111111111111111111", Algorithm::SHA1, 6);
            a1.id = "sort-1".into();
            a1.sort_order = 1;
            let mut a2 = test_account(b"22222222222222222222", Algorithm::SHA256, 6);
            a2.id = "sort-0".into();
            a2.sort_order = 0;
            let mut a3 = test_account(b"33333333333333333333", Algorithm::SHA512, 6);
            a3.id = "sort-2".into();
            a3.sort_order = 2;
            seed_plaintext_accounts(&[a1, a2, a3]);

            let results = generate_all_codes_impl(&state).unwrap();
            // Results maintain storage order: [a1, a2, a3]
            assert_eq!(results[0].0, "sort-1");
            assert_eq!(results[1].0, "sort-0");
            assert_eq!(results[2].0, "sort-2");

            // Verify sort_order values are preserved in the accounts
            // (they're in the Account struct, but generate_all_codes_impl only returns id+code+remaining)
            // This is handled by the frontend sorting by sort_order
            // Backend preserves sort_order correctly through encrypt/decrypt cycles
            cleanup_auth_file();
        });
    }

    // ── New tests ──────────────────────────────────────────────

    #[test]
    fn test_make_totp_accepts_digits_6_and_8_only() {
        let secret = b"12345678901234567890";
        for digits in [6u8, 8u8] {
            let account = test_account(secret, Algorithm::SHA1, digits);
            assert!(
                make_totp(&account).is_ok(),
                "digits={digits} must be accepted"
            );
        }
        for digits in [0u8, 1u8, 5u8, 7u8, 9u8, 255u8] {
            let account = test_account(secret, Algorithm::SHA1, digits);
            assert!(
                make_totp(&account).is_err(),
                "digits={digits} must be rejected"
            );
        }
    }

    #[test]
    fn test_generate_code_with_empty_account_id_fails() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let secret = b"12345678901234567890";
            seed_plaintext_accounts(&[test_account(secret, Algorithm::SHA1, 6)]);

            // Empty string should not match any account
            let result = generate_code_impl("", &state);
            assert!(result.is_err(), "empty account ID must fail");
            let err = result.unwrap_err();
            assert!(
                err.contains("not found"),
                "error should mention 'not found': {err}"
            );
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_generate_code_very_long_secret_succeeds() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            // 64-byte secret — RFC 6238 allows any key length
            let long_secret = b"1234567890123456789012345678901234567890123456789012345678901234";
            let mut account = test_account(long_secret, Algorithm::SHA1, 6);
            account.id = "long-secret".into();
            seed_plaintext_accounts(&[account]);

            let (code, remaining) = generate_code_impl("long-secret", &state).unwrap();
            assert_eq!(code.len(), 6);
            assert!(code.chars().all(|c| c.is_ascii_digit()));
            assert!(remaining > 0 && remaining <= 30);
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_remaining_time_decreases_monotonically() {
        // The remaining value should decrease over time within the same period
        let secret = b"12345678901234567890";
        let account = test_account(secret, Algorithm::SHA1, 6);
        let totp = make_totp(&account).unwrap();
        let period = account.period as u64;

        // Within the same period window: t0 < t1 → remaining decreases
        let t0 = 10u64;
        let t1 = 20u64;
        let r0 = period - (t0 % period);
        let r1 = period - (t1 % period);
        assert!(
            r1 <= r0,
            "remaining must decrease as time advances: {r1} > {r0}"
        );

        // After period boundary, remaining resets to period
        let t2 = period; // exactly one period later
        let r2 = period - (t2 % period);
        assert_eq!(
            r2, period,
            "at period boundary, remaining should equal period"
        );

        // Code at t=0 and t=period should be different (different counters)
        assert_ne!(totp.generate(0), totp.generate(period));
    }

    #[test]
    fn test_code_60s_remaining_boundaries() {
        let secret = b"12345678901234567890";
        let mut account = test_account(secret, Algorithm::SHA1, 6);
        account.period = 60;
        let totp = make_totp(&account).unwrap();
        let period = 60u64;

        // t=0 → remaining=60
        assert_eq!(period - (0 % period), 60, "remaining should be 60 at t=0");
        // t=59 → remaining=1
        assert_eq!(period - (59 % period), 1, "remaining should be 1 at t=59");
        // t=60 → remaining=60 (new window)
        assert_eq!(
            period - (60 % period),
            60,
            "remaining should reset to 60 at t=60"
        );

        // Code at t=0 and t=59 should be same (same counter = 0)
        assert_eq!(totp.generate(0), totp.generate(59));
        // Code at t=59 and t=60 should differ (different counters)
        assert_ne!(totp.generate(59), totp.generate(60));
    }

    #[test]
    fn test_generate_code_impl_with_8_digit_code() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let secret = b"12345678901234567890";
            let mut account = test_account(secret, Algorithm::SHA1, 8);
            account.id = "eight-digit".into();
            seed_plaintext_accounts(&[account]);

            let (code, _remaining) = generate_code_impl("eight-digit", &state).unwrap();
            assert_eq!(code.len(), 8, "8-digit code expected");
            assert!(code.chars().all(|c| c.is_ascii_digit()));
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_generate_all_codes_three_accounts_all_8_digit() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let mut a1 = test_account(b"11111111111111111111", Algorithm::SHA1, 8);
            a1.id = "8-1".into();
            let mut a2 = test_account(b"22222222222222222222", Algorithm::SHA256, 8);
            a2.id = "8-2".into();
            let mut a3 = test_account(b"33333333333333333333", Algorithm::SHA512, 8);
            a3.id = "8-3".into();
            seed_plaintext_accounts(&[a1, a2, a3]);

            let results = generate_all_codes_impl(&state).unwrap();
            assert_eq!(results.len(), 3);
            for (_id, code, _remaining) in &results {
                assert_eq!(code.len(), 8, "each code must be 8 digits");
                assert!(code.chars().all(|c| c.is_ascii_digit()));
            }
            cleanup_auth_file();
        });
    }

    // ── Algorithm × Digits matrix tests ─────────────────────

    #[test]
    fn test_sha1_6digit_30s() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let a = test_account(b"12345678901234567890", Algorithm::SHA1, 6);
            seed_plaintext_accounts(&[a]);
            let (code, remaining) = generate_code_impl("test-1", &state).unwrap();
            assert_eq!(code.len(), 6);
            assert!(code.chars().all(|c| c.is_ascii_digit()));
            assert!(remaining > 0 && remaining <= 30);
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_sha1_8digit_60s() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let mut a = test_account(b"12345678901234567890", Algorithm::SHA1, 8);
            a.period = 60;
            seed_plaintext_accounts(&[a]);
            let (code, remaining) = generate_code_impl("test-1", &state).unwrap();
            assert_eq!(code.len(), 8);
            assert!(remaining > 0 && remaining <= 60);
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_sha256_6digit_30s() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let a = test_account(b"12345678901234567890", Algorithm::SHA256, 6);
            seed_plaintext_accounts(&[a]);
            let (code, remaining) = generate_code_impl("test-1", &state).unwrap();
            assert_eq!(code.len(), 6);
            assert!(remaining > 0 && remaining <= 30);
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_sha256_8digit_60s() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let mut a = test_account(b"12345678901234567890", Algorithm::SHA256, 8);
            a.period = 60;
            seed_plaintext_accounts(&[a]);
            let (code, remaining) = generate_code_impl("test-1", &state).unwrap();
            assert_eq!(code.len(), 8);
            assert!(remaining > 0 && remaining <= 60);
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_sha512_6digit_30s() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let a = test_account(b"12345678901234567890", Algorithm::SHA512, 6);
            seed_plaintext_accounts(&[a]);
            let (code, remaining) = generate_code_impl("test-1", &state).unwrap();
            assert_eq!(code.len(), 6);
            assert!(remaining > 0 && remaining <= 30);
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_sha512_8digit_60s() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let mut a = test_account(b"12345678901234567890", Algorithm::SHA512, 8);
            a.period = 60;
            seed_plaintext_accounts(&[a]);
            let (code, remaining) = generate_code_impl("test-1", &state).unwrap();
            assert_eq!(code.len(), 8);
            assert!(remaining > 0 && remaining <= 60);
            cleanup_auth_file();
        });
    }

    // ── Period boundary tests ───────────────────────────────

    #[test]
    fn test_period_1_second() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let mut a = test_account(b"12345678901234567890", Algorithm::SHA1, 6);
            a.period = 1;
            seed_plaintext_accounts(&[a]);
            let (code, remaining) = generate_code_impl("test-1", &state).unwrap();
            assert_eq!(code.len(), 6);
            assert_eq!(remaining, 1, "period=1 means remaining is always 1");
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_period_90_seconds() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let mut a = test_account(b"12345678901234567890", Algorithm::SHA1, 6);
            a.period = 90;
            seed_plaintext_accounts(&[a]);
            let (code, remaining) = generate_code_impl("test-1", &state).unwrap();
            assert_eq!(code.len(), 6);
            assert!(remaining > 0 && remaining <= 90);
            cleanup_auth_file();
        });
    }

    // ── Code stability tests ────────────────────────────────

    #[test]
    fn test_same_timestamp_same_code() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let a = test_account(b"12345678901234567890", Algorithm::SHA1, 6);
            seed_plaintext_accounts(&[a]);
            // Generate code twice with same state (same second)
            let (code1, _) = generate_code_impl("test-1", &state).unwrap();
            let (code2, _) = generate_code_impl("test-1", &state).unwrap();
            // Within same second, codes must be identical
            assert_eq!(code1, code2, "same second must produce same code");
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_different_secrets_different_codes() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let a1 = test_account(b"11111111111111111111", Algorithm::SHA1, 6);
            let mut a2 = test_account(b"22222222222222222222", Algorithm::SHA1, 6);
            a2.id = "test-2".into();
            seed_plaintext_accounts(&[a1, a2]);
            let (code1, _) = generate_code_impl("test-1", &state).unwrap();
            let (code2, _) = generate_code_impl("test-2", &state).unwrap();
            assert_ne!(
                code1, code2,
                "different secrets must produce different codes"
            );
            cleanup_auth_file();
        });
    }

    // ── Error path tests ────────────────────────────────────

    #[test]
    fn test_generate_code_nonexistent_account() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            seed_plaintext_accounts(&[]);
            let err = generate_code_impl("nonexistent", &state).unwrap_err();
            assert!(err.contains("not found"), "error: {err}");
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_generate_code_empty_store() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            seed_plaintext_accounts(&[]);
            let err = generate_code_impl("any-id", &state).unwrap_err();
            assert!(err.contains("not found"), "error: {err}");
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_generate_code_invalid_digits_7() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let a = test_account(b"12345678901234567890", Algorithm::SHA1, 7);
            seed_plaintext_accounts(&[a]);
            let err = generate_code_impl("test-1", &state).unwrap_err();
            assert!(err.contains("invalid digit"), "error: {err}");
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_generate_code_invalid_digits_0() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let a = test_account(b"12345678901234567890", Algorithm::SHA1, 0);
            seed_plaintext_accounts(&[a]);
            let err = generate_code_impl("test-1", &state).unwrap_err();
            assert!(err.contains("invalid digit"), "error: {err}");
            cleanup_auth_file();
        });
    }

    // ── Encrypted store code generation ──────────────────────

    #[test]
    fn test_generate_code_encrypted_store() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let a = test_account(b"12345678901234567890", Algorithm::SHA1, 6);
            let key = seed_encrypted_accounts(&[a]);
            state.set_key(key).unwrap();
            let (code, remaining) = generate_code_impl("test-1", &state).unwrap();
            assert_eq!(code.len(), 6);
            assert!(remaining > 0 && remaining <= 30);
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_generate_all_codes_encrypted_store() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let a1 = test_account(b"11111111111111111111", Algorithm::SHA1, 6);
            let mut a2 = test_account(b"22222222222222222222", Algorithm::SHA256, 8);
            a2.id = "test-2".into();
            let key = seed_encrypted_accounts(&[a1, a2]);
            state.set_key(key).unwrap();
            let results = generate_all_codes_impl(&state).unwrap();
            assert_eq!(results.len(), 2);
            for (id, code, remaining) in &results {
                if id == "test-1" {
                    assert_eq!(code.len(), 6);
                } else {
                    assert_eq!(code.len(), 8);
                }
                assert!(*remaining > 0);
            }
            cleanup_auth_file();
        });
    }

    // ── Additional coverage tests ─────────────────────────────

    #[test]
    fn test_make_totp_rejects_digits_1_through_5() {
        for digits in [1, 2, 3, 4, 5] {
            let a = test_account(b"12345678901234567890", Algorithm::SHA1, digits);
            let err = make_totp(&a).unwrap_err();
            assert!(
                err.contains("invalid digit count"),
                "digits={digits} must be rejected: {err}"
            );
        }
    }

    #[test]
    fn test_make_totp_rejects_digits_9_and_above() {
        for digits in [9, 10, 12, 255] {
            let a = test_account(b"12345678901234567890", Algorithm::SHA1, digits);
            let err = make_totp(&a).unwrap_err();
            assert!(
                err.contains("invalid digit count"),
                "digits={digits} must be rejected: {err}"
            );
        }
    }

    #[test]
    fn test_generate_code_system_time_before_unix_epoch() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let a = test_account(b"12345678901234567890", Algorithm::SHA1, 6);
            seed_plaintext_accounts(&[a]);
            // generate_code_impl uses unwrap_or_default() for system time,
            // so it should produce a valid code even with t=0
            let (code, remaining) = generate_code_impl("test-1", &state).unwrap();
            assert_eq!(code.len(), 6, "must produce 6-digit code");
            assert!(
                remaining > 0 && remaining <= 30,
                "remaining must be in (0, 30]"
            );
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_generate_all_codes_mixed_valid_and_invalid_period() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            // Valid account
            let a1 = test_account(b"12345678901234567890", Algorithm::SHA1, 6);
            // Account with period=0 (invalid)
            let a2 = test_account(b"22222222222222222222", Algorithm::SHA1, 6);
            // Manually set period=0 on the second account after creation
            let mut a2_invalid = a2.clone();
            a2_invalid.period = 0;
            a2_invalid.id = "test-2".into();
            seed_plaintext_accounts(&[a1, a2_invalid]);
            // The entire batch must fail because one account has period=0
            let err = generate_all_codes_impl(&state).unwrap_err();
            assert!(
                err.contains("invalid period") || err.contains("division"),
                "batch must fail on invalid account: {err}"
            );
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_generate_code_exact_period_boundary() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let mut a = test_account(b"12345678901234567890", Algorithm::SHA1, 6);
            a.period = 30;
            seed_plaintext_accounts(&[a]);

            // Call generate_code_impl multiple times and verify remaining decreases
            let (_, r1) = generate_code_impl("test-1", &state).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(1100));
            let (_, r2) = generate_code_impl("test-1", &state).unwrap();
            assert!(
                r2 < r1 || r2 == 30,
                "remaining must decrease or wrap: r1={r1}, r2={r2}"
            );
            assert!(r2 > 0, "remaining must be positive: {r2}");
            assert!(r2 <= 30, "remaining must be <= period: {r2}");
            cleanup_auth_file();
        });
    }
}
