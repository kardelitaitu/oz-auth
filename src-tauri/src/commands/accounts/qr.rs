// ── QR code + backup operations ──────────────────────────────
//
// Depends on shared helpers from super (save_accounts, zeroize_accounts,
// validate_secret_length).

use super::*;
use crate::models::account::Algorithm;
use base32::Alphabet;
use tauri::State;

// ── urlencoding helper ──────────────────────────────────────

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

// ── get_otpauth_uri ─────────────────────────────────────────

fn get_otpauth_uri_impl(account_id: &str, state: &AppState) -> Result<String, String> {
    let data = state.load_data()?;
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

#[tauri::command]
pub fn get_otpauth_uri(account_id: String, state: State<'_, AppState>) -> Result<String, String> {
    get_otpauth_uri_impl(&account_id, &state)
}

// ── get_backup_uris ─────────────────────────────────────────

fn get_backup_uris_impl(state: &AppState) -> Result<Vec<String>, String> {
    let data = state.load_data()?;
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

// ── save_backup_file ────────────────────────────────────────

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

    std::fs::write(&path, &content).map_err(|e| format!("failed to write backup: {e}"))?;

    Ok(path.to_string_lossy().to_string())
}

#[tauri::command]
pub fn save_backup_file(state: State<'_, AppState>) -> Result<String, String> {
    save_backup_file_impl(&state)
}

// ── Tests ────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::account::Algorithm;

    fn backup_paths_cleanup() {
        let exe_dir = crate::paths::exe_dir();
        let exe_stem = crate::paths::exe_stem();
        let base = format!("{}.backup.txt", exe_stem);
        let base_path = exe_dir.join(&base);
        if base_path.exists() {
            let _ = std::fs::remove_file(&base_path);
        }
        for n in 1u32..=10 {
            let name = format!("{}.backup ({}).txt", exe_stem, n);
            let path = exe_dir.join(&name);
            if path.exists() {
                let _ = std::fs::remove_file(&path);
            }
        }
    }

    // ── urlencoding unit tests ────────────────────────────────

    #[test]
    fn test_urlencoding_plain_ascii_unchanged() {
        assert_eq!(urlencoding("GitHub"), "GitHub");
        assert_eq!(urlencoding("ACME"), "ACME");
        assert_eq!(urlencoding("MyApp"), "MyApp");
    }

    #[test]
    fn test_urlencoding_empty_string() {
        assert_eq!(urlencoding(""), "");
    }

    #[test]
    fn test_urlencoding_space_encoded() {
        assert_eq!(urlencoding("My App"), "My%20App");
        assert_eq!(urlencoding("hello world"), "hello%20world");
    }

    #[test]
    fn test_urlencoding_at_sign_encoded() {
        assert_eq!(urlencoding("user@example.com"), "user%40example.com");
    }

    #[test]
    fn test_urlencoding_colon_encoded() {
        assert_eq!(urlencoding("A:B"), "A%3AB");
    }

    #[test]
    fn test_urlencoding_slash_encoded() {
        assert_eq!(urlencoding("a/b"), "a%2Fb");
    }

    #[test]
    fn test_urlencoding_question_mark_encoded() {
        assert_eq!(urlencoding("a?b"), "a%3Fb");
    }

    #[test]
    fn test_urlencoding_special_chars_mixed() {
        let result = urlencoding("Test@Site!");
        assert!(result.contains("%40"), "@ should be encoded: {result}");
        assert!(result.contains("%21"), "! should be encoded: {result}");
    }

    #[test]
    fn test_urlencoding_numeric_and_dots_unchanged() {
        assert_eq!(urlencoding("user.123@test.com"), "user.123%40test.com");
    }

    #[test]
    fn test_urlencoding_unicode_chars_encoded() {
        let result = urlencoding("café");
        // é = 0xC3 0xA9 in UTF-8
        assert!(
            result.contains("%C3") && result.contains("%A9"),
            "é should be encoded: {result}"
        );
    }

    // ── get_otpauth_uri_impl tests ────────────────────────────

    #[test]
    fn test_get_otpauth_uri_success() {
        super::super::with_fs_lock(|| {
            super::super::cleanup_auth_file();
            let state = super::super::test_app_state();
            let mut data = crate::storage::try_load().unwrap();
            let accounts = vec![Account {
                id: "uri-test-1".into(),
                issuer: "GitHub".into(),
                label: "dev@github.com".into(),
                algorithm: Algorithm::SHA1,
                digits: 6,
                period: 30,
                secret: vec![1u8; 20],
                sort_order: 0,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            }];
            save_accounts(&mut data, &accounts, None).unwrap();
            crate::storage::save(&data).unwrap();

            let uri = get_otpauth_uri_impl("uri-test-1", &state).unwrap();
            assert!(uri.starts_with("otpauth://totp/"), "uri: {uri}");
            assert!(uri.contains("GitHub"), "uri should contain issuer: {uri}");
            assert!(
                uri.contains("%40github.com"),
                "uri should contain encoded @: {uri}"
            );
            assert!(uri.contains("secret="), "uri must have secret param: {uri}");
            assert!(
                uri.contains("algorithm=SHA1"),
                "uri must have algorithm: {uri}"
            );
            assert!(uri.contains("digits=6"), "uri must have digits: {uri}");
            assert!(uri.contains("period=30"), "uri must have period: {uri}");

            super::super::cleanup_auth_file();
        });
    }

    #[test]
    fn test_get_otpauth_uri_not_found() {
        super::super::with_fs_lock(|| {
            super::super::cleanup_auth_file();
            let state = super::super::test_app_state();
            let mut data = crate::storage::try_load().unwrap();
            let accounts = vec![Account {
                id: "real".into(),
                issuer: "Real".into(),
                label: "r@test.com".into(),
                algorithm: Algorithm::SHA1,
                digits: 6,
                period: 30,
                secret: vec![1u8; 20],
                sort_order: 0,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            }];
            save_accounts(&mut data, &accounts, None).unwrap();
            crate::storage::save(&data).unwrap();

            let err = get_otpauth_uri_impl("nonexistent", &state).unwrap_err();
            assert!(err.contains("not found"), "error: {err}");

            super::super::cleanup_auth_file();
        });
    }

    #[test]
    fn test_get_otpauth_uri_sha256_algorithm_in_uri() {
        super::super::with_fs_lock(|| {
            super::super::cleanup_auth_file();
            let state = super::super::test_app_state();
            let mut data = crate::storage::try_load().unwrap();
            let accounts = vec![Account {
                id: "sha256-acc".into(),
                issuer: "MyApp".into(),
                label: "user@myapp.com".into(),
                algorithm: Algorithm::SHA256,
                digits: 8,
                period: 60,
                secret: vec![2u8; 20],
                sort_order: 0,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            }];
            save_accounts(&mut data, &accounts, None).unwrap();
            crate::storage::save(&data).unwrap();

            let uri = get_otpauth_uri_impl("sha256-acc", &state).unwrap();
            assert!(uri.contains("algorithm=SHA256"), "uri: {uri}");
            assert!(uri.contains("digits=8"), "uri: {uri}");
            assert!(uri.contains("period=60"), "uri: {uri}");

            super::super::cleanup_auth_file();
        });
    }

    #[test]
    fn test_get_otpauth_uri_sha512_algorithm_in_uri() {
        super::super::with_fs_lock(|| {
            super::super::cleanup_auth_file();
            let state = super::super::test_app_state();
            let mut data = crate::storage::try_load().unwrap();
            let accounts = vec![Account {
                id: "sha512-acc".into(),
                issuer: "SecureApp".into(),
                label: "admin@secure.com".into(),
                algorithm: Algorithm::SHA512,
                digits: 6,
                period: 30,
                secret: vec![3u8; 20],
                sort_order: 0,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            }];
            save_accounts(&mut data, &accounts, None).unwrap();
            crate::storage::save(&data).unwrap();

            let uri = get_otpauth_uri_impl("sha512-acc", &state).unwrap();
            assert!(uri.contains("algorithm=SHA512"), "uri: {uri}");

            super::super::cleanup_auth_file();
        });
    }

    #[test]
    fn test_get_otpauth_uri_secret_is_base32() {
        super::super::with_fs_lock(|| {
            super::super::cleanup_auth_file();
            let state = super::super::test_app_state();
            let mut data = crate::storage::try_load().unwrap();
            let known_hex = hex::decode("3132333435363738393031323334353637383930").unwrap(); // 20 bytes
            let accounts = vec![Account {
                id: "b32-test".into(),
                issuer: "Test".into(),
                label: "t@t.com".into(),
                algorithm: Algorithm::SHA1,
                digits: 6,
                period: 30,
                secret: known_hex,
                sort_order: 0,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            }];
            save_accounts(&mut data, &accounts, None).unwrap();
            crate::storage::save(&data).unwrap();

            let uri = get_otpauth_uri_impl("b32-test", &state).unwrap();

            let secret_start = uri.find("secret=").unwrap() + 7;
            let secret_end = uri[secret_start..]
                .find('&')
                .map(|i| secret_start + i)
                .unwrap_or(uri.len());
            let secret_b32 = &uri[secret_start..secret_end];

            let decoded = base32::decode(Alphabet::Rfc4648 { padding: false }, secret_b32);
            assert!(
                decoded.is_some(),
                "secret should be valid base32: {secret_b32}"
            );

            super::super::cleanup_auth_file();
        });
    }

    #[test]
    fn test_get_otpauth_uri_issuer_with_spaces_encoded() {
        super::super::with_fs_lock(|| {
            super::super::cleanup_auth_file();
            let state = super::super::test_app_state();
            let mut data = crate::storage::try_load().unwrap();
            let accounts = vec![Account {
                id: "spaces".into(),
                issuer: "My Big Corp".into(),
                label: "admin@bigcorp.com".into(),
                algorithm: Algorithm::SHA1,
                digits: 6,
                period: 30,
                secret: vec![1u8; 20],
                sort_order: 0,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            }];
            save_accounts(&mut data, &accounts, None).unwrap();
            crate::storage::save(&data).unwrap();

            let uri = get_otpauth_uri_impl("spaces", &state).unwrap();
            assert!(
                uri.contains("My%20Big%20Corp"),
                "spaces should be %20: {uri}"
            );
            assert!(
                !uri.contains("My Big Corp"),
                "raw spaces should not appear: {uri}"
            );

            super::super::cleanup_auth_file();
        });
    }

    // ── get_backup_uris_impl tests ────────────────────────────

    #[test]
    fn test_get_backup_uris_returns_all_accounts() {
        super::super::with_fs_lock(|| {
            super::super::cleanup_auth_file();
            let state = super::super::test_app_state();
            let mut data = crate::storage::try_load().unwrap();
            let accounts = vec![
                Account {
                    id: "backup-1".into(),
                    issuer: "GitHub".into(),
                    label: "dev@github.com".into(),
                    algorithm: Algorithm::SHA1,
                    digits: 6,
                    period: 30,
                    secret: vec![1u8; 20],
                    sort_order: 0,
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                },
                Account {
                    id: "backup-2".into(),
                    issuer: "Google".into(),
                    label: "user@gmail.com".into(),
                    algorithm: Algorithm::SHA256,
                    digits: 6,
                    period: 30,
                    secret: vec![2u8; 20],
                    sort_order: 1,
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                },
            ];
            save_accounts(&mut data, &accounts, None).unwrap();
            crate::storage::save(&data).unwrap();

            let uris = get_backup_uris_impl(&state).unwrap();
            assert_eq!(uris.len(), 2, "should return 2 URIs");
            assert!(uris[0].contains("GitHub"), "first URI: {}", uris[0]);
            assert!(uris[1].contains("Google"), "second URI: {}", uris[1]);

            for uri in &uris {
                assert!(
                    uri.starts_with("otpauth://totp/"),
                    "not a valid otpauth URI: {uri}"
                );
                assert!(uri.contains("secret="), "missing secret: {uri}");
            }

            super::super::cleanup_auth_file();
        });
    }

    #[test]
    fn test_get_backup_uris_empty_when_no_accounts() {
        super::super::with_fs_lock(|| {
            super::super::cleanup_auth_file();
            let state = super::super::test_app_state();
            let mut data = crate::storage::try_load().unwrap();
            data.accounts.data_json = "[]".into();
            crate::storage::save(&data).unwrap();

            let uris = get_backup_uris_impl(&state).unwrap();
            assert!(uris.is_empty(), "no accounts → empty vec");

            super::super::cleanup_auth_file();
        });
    }

    #[test]
    fn test_get_backup_uris_single_account() {
        super::super::with_fs_lock(|| {
            super::super::cleanup_auth_file();
            let state = super::super::test_app_state();
            let mut data = crate::storage::try_load().unwrap();
            let accounts = vec![Account {
                id: "single".into(),
                issuer: "Solo".into(),
                label: "only@solo.com".into(),
                algorithm: Algorithm::SHA1,
                digits: 6,
                period: 30,
                secret: vec![9u8; 20],
                sort_order: 0,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            }];
            save_accounts(&mut data, &accounts, None).unwrap();
            crate::storage::save(&data).unwrap();

            let uris = get_backup_uris_impl(&state).unwrap();
            assert_eq!(uris.len(), 1);
            assert!(uris[0].contains("Solo"));
            assert!(uris[0].contains("%40solo.com"));

            super::super::cleanup_auth_file();
        });
    }

    // ── save_backup_file_impl tests ──────────────────────────

    #[test]
    fn test_save_backup_file_creates_file() {
        super::super::with_fs_lock(|| {
            super::super::cleanup_auth_file();
            backup_paths_cleanup();
            let state = super::super::test_app_state();
            let mut data = crate::storage::try_load().unwrap();
            let accounts = vec![Account {
                id: "bk1".into(),
                issuer: "TestIssuer".into(),
                label: "test@test.com".into(),
                algorithm: Algorithm::SHA1,
                digits: 6,
                period: 30,
                secret: vec![1u8; 20],
                sort_order: 0,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            }];
            save_accounts(&mut data, &accounts, None).unwrap();
            crate::storage::save(&data).unwrap();

            let saved_path = save_backup_file_impl(&state).unwrap();
            let path = std::path::Path::new(&saved_path);
            assert!(path.exists(), "backup file should exist at: {saved_path}");

            let content = std::fs::read_to_string(&saved_path).unwrap();
            assert!(content.starts_with('#'), "should start with comment header");
            assert!(content.contains("1 account(s)"), "should show count");
            assert!(
                content.contains("WARNING"),
                "should have warning: {content}"
            );
            assert!(
                content.contains("plain-text secrets"),
                "should mention plain-text"
            );
            assert!(
                content.contains("otpauth://totp/"),
                "should contain otpauth URIs"
            );

            super::super::cleanup_auth_file();
            backup_paths_cleanup();
        });
    }

    #[test]
    fn test_save_backup_file_empty_accounts_fails() {
        super::super::with_fs_lock(|| {
            super::super::cleanup_auth_file();
            let state = super::super::test_app_state();
            let mut data = crate::storage::try_load().unwrap();
            data.accounts.data_json = "[]".into();
            crate::storage::save(&data).unwrap();

            let err = save_backup_file_impl(&state).unwrap_err();
            assert!(err.contains("no accounts"), "error: {err}");

            super::super::cleanup_auth_file();
        });
    }

    #[test]
    fn test_save_backup_file_auto_increment_filename() {
        super::super::with_fs_lock(|| {
            super::super::cleanup_auth_file();
            backup_paths_cleanup();

            let state = super::super::test_app_state();
            let mut data = crate::storage::try_load().unwrap();
            let accounts = vec![Account {
                id: "inc1".into(),
                issuer: "Inc".into(),
                label: "inc@test.com".into(),
                algorithm: Algorithm::SHA1,
                digits: 6,
                period: 30,
                secret: vec![1u8; 20],
                sort_order: 0,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            }];
            save_accounts(&mut data, &accounts, None).unwrap();
            crate::storage::save(&data).unwrap();

            let path1 = save_backup_file_impl(&state).unwrap();
            assert!(
                path1.ends_with("oz-auth.backup.txt") || path1.ends_with("backup.txt"),
                "first backup path: {path1}"
            );

            let exe_dir = crate::paths::exe_dir();
            let exe_stem = crate::paths::exe_stem();
            let second_variant = exe_dir.join(format!("{}.backup (1).txt", exe_stem));
            std::fs::write(&second_variant, "fake").unwrap();

            let path2 = save_backup_file_impl(&state).unwrap();
            assert!(
                path2.contains("(2)"),
                "second backup should use (2): {path2}"
            );

            super::super::cleanup_auth_file();
            backup_paths_cleanup();
        });
    }

    #[test]
    fn test_save_backup_file_content_has_multiple_uris() {
        super::super::with_fs_lock(|| {
            super::super::cleanup_auth_file();
            backup_paths_cleanup();
            let state = super::super::test_app_state();
            let mut data = crate::storage::try_load().unwrap();
            let accounts = vec![
                Account {
                    id: "m1".into(),
                    issuer: "Alpha".into(),
                    label: "a@alpha.com".into(),
                    algorithm: Algorithm::SHA1,
                    digits: 6,
                    period: 30,
                    secret: vec![1u8; 20],
                    sort_order: 0,
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                },
                Account {
                    id: "m2".into(),
                    issuer: "Beta".into(),
                    label: "b@beta.com".into(),
                    algorithm: Algorithm::SHA256,
                    digits: 8,
                    period: 60,
                    secret: vec![2u8; 20],
                    sort_order: 1,
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                },
            ];
            save_accounts(&mut data, &accounts, None).unwrap();
            crate::storage::save(&data).unwrap();

            let saved_path = save_backup_file_impl(&state).unwrap();
            let content = std::fs::read_to_string(&saved_path).unwrap();

            assert!(content.contains("2 account(s)"), "should show count 2");
            assert!(content.contains("Alpha"), "should contain Alpha: {content}");
            assert!(content.contains("Beta"), "should contain Beta: {content}");
            assert!(
                content.contains("algorithm=SHA256"),
                "should contain SHA256: {content}"
            );
            assert!(
                content.contains("digits=8"),
                "should contain digits=8: {content}"
            );
            assert!(
                content.contains("period=60"),
                "should contain period=60: {content}"
            );

            super::super::cleanup_auth_file();
            backup_paths_cleanup();
        });
    }

    #[test]
    fn test_save_backup_file_locked_fails() {
        super::super::with_fs_lock(|| {
            super::super::cleanup_auth_file();
            backup_paths_cleanup();
            let state = super::super::test_app_state();
            let mut data = crate::storage::try_load().unwrap();
            data.config.password_protected = true;
            let key = super::super::test_key();
            let accounts = vec![Account {
                id: "locked-bk".into(),
                issuer: "Locked".into(),
                label: "l@locked.com".into(),
                algorithm: Algorithm::SHA1,
                digits: 6,
                period: 30,
                secret: vec![1u8; 20],
                sort_order: 0,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            }];
            save_accounts(&mut data, &accounts, Some(key)).unwrap();
            crate::storage::save(&data).unwrap();

            let err = save_backup_file_impl(&state).unwrap_err();
            assert!(
                err.contains("locked") || err.contains("key"),
                "locked app should fail backup: {err}"
            );

            super::super::cleanup_auth_file();
            backup_paths_cleanup();
        });
    }
}
