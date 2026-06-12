// ── CRUD operations for accounts ─────────────────────────────
//
// Depends on shared helpers from super (save_accounts, zeroize_accounts,
// validate_secret_length, decode_secret).

use super::*;
use crate::models::account::{Account, AccountSummary};
use chrono::Utc;
use tauri::State;

// ── add_account ──────────────────────────────────────────────

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
        id: uuid::Uuid::new_v4().to_string(),
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

// ── add_account_from_uri ─────────────────────────────────────

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
        id: uuid::Uuid::new_v4().to_string(),
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

// ── remove_account ───────────────────────────────────────────

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

// ── update_account ───────────────────────────────────────────

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

// ── list_accounts ────────────────────────────────────────────

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

// ── Tests ────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::account::Algorithm;

    // ── add_account_impl tests ────────────────────────────────

    #[test]
    fn test_add_account_impl_plaintext() {
        super::super::with_fs_lock(|| {
            super::super::cleanup_auth_file();
            let state = super::super::test_app_state();
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
            super::super::cleanup_auth_file();
        });
    }

    #[test]
    fn test_add_account_impl_with_custom_params() {
        super::super::with_fs_lock(|| {
            super::super::cleanup_auth_file();
            let state = super::super::test_app_state();
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
            super::super::cleanup_auth_file();
        });
    }

    // ── add_account_from_uri_impl tests ───────────────────────

    #[test]
    fn test_add_account_from_uri_impl_success() {
        super::super::with_fs_lock(|| {
            super::super::cleanup_auth_file();
            let state = super::super::test_app_state();
            let mut data = crate::storage::try_load().unwrap();
            data.accounts.data_json = "[]".into();
            crate::storage::save(&data).unwrap();

            let uri = "otpauth://totp/ACME:john@example.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME&algorithm=SHA1&digits=6&period=30";
            let account = add_account_from_uri_impl(uri, &state).unwrap();
            assert_eq!(account.issuer, "ACME");
            assert_eq!(account.label, "john@example.com");
            super::super::cleanup_auth_file();
        });
    }

    #[test]
    fn test_add_account_from_uri_impl_empty_secret_fails() {
        super::super::with_fs_lock(|| {
            super::super::cleanup_auth_file();
            let state = super::super::test_app_state();
            let uri = "otpauth://totp/Test:test@test.com?secret=";
            let err = add_account_from_uri_impl(uri, &state).unwrap_err();
            assert!(
                err.contains("empty") || err.contains("invalid"),
                "error: {err}"
            );
            super::super::cleanup_auth_file();
        });
    }

    // ── remove_account_impl tests ─────────────────────────────

    #[test]
    fn test_remove_account_impl_removes_by_id() {
        super::super::with_fs_lock(|| {
            super::super::cleanup_auth_file();
            let state = super::super::test_app_state();
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
            super::super::cleanup_auth_file();
        });
    }

    #[test]
    fn test_remove_account_nonexistent_id_noop() {
        super::super::with_fs_lock(|| {
            super::super::cleanup_auth_file();
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

            let loaded = crate::storage::try_load().unwrap();
            let mut reloaded = crate::storage::load_accounts(&loaded, None).unwrap();
            let before = reloaded.len();
            reloaded.retain(|a| a.id != "nonexistent");
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
            super::super::cleanup_auth_file();
        });
    }

    // ── update_account_impl tests ─────────────────────────────

    #[test]
    fn test_update_account_impl_updates_fields() {
        super::super::with_fs_lock(|| {
            super::super::cleanup_auth_file();
            let state = super::super::test_app_state();
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
            super::super::cleanup_auth_file();
        });
    }

    #[test]
    fn test_update_account_impl_nonexistent_id_fails() {
        super::super::with_fs_lock(|| {
            super::super::cleanup_auth_file();
            let state = super::super::test_app_state();
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
            super::super::cleanup_auth_file();
        });
    }

    // ── list_accounts_impl tests ──────────────────────────────

    #[test]
    fn test_list_accounts_impl_with_search() {
        super::super::with_fs_lock(|| {
            super::super::cleanup_auth_file();
            let state = super::super::test_app_state();
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
            super::super::cleanup_auth_file();
        });
    }

    #[test]
    fn test_list_accounts_impl_no_search_returns_all() {
        super::super::with_fs_lock(|| {
            super::super::cleanup_auth_file();
            let state = super::super::test_app_state();
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
            super::super::cleanup_auth_file();
        });
    }

    #[test]
    fn test_list_accounts_impl_search_no_match() {
        super::super::with_fs_lock(|| {
            super::super::cleanup_auth_file();
            let state = super::super::test_app_state();
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
            super::super::cleanup_auth_file();
        });
    }

    // ── Storage-level CRUD integration tests ──────────────────

    #[test]
    fn test_add_account_via_storage_with_accounts() {
        super::super::with_fs_lock(|| {
            super::super::cleanup_auth_file();
            let mut data = crate::storage::try_load().unwrap();
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
            super::super::cleanup_auth_file();
        });
    }

    #[test]
    fn test_remove_all_accounts_via_storage_yields_empty() {
        super::super::with_fs_lock(|| {
            super::super::cleanup_auth_file();
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

            let mut loaded = crate::storage::try_load().unwrap();
            let mut all_accounts = crate::storage::load_accounts(&loaded, None).unwrap();
            all_accounts.clear();
            save_accounts(&mut loaded, &all_accounts, None).unwrap();
            crate::storage::save(&loaded).unwrap();

            let final_loaded = crate::storage::try_load().unwrap();
            assert!(!final_loaded.accounts.encrypted, "should be plaintext");
            assert_eq!(final_loaded.accounts.data_json, "[]", "empty JSON array");
            let mut final_accounts = crate::storage::load_accounts(&final_loaded, None).unwrap();
            assert!(final_accounts.is_empty(), "no accounts remain");
            for a in &mut final_accounts {
                a.secret.zeroize();
            }
            final_accounts.clear();
            super::super::cleanup_auth_file();
        });
    }

    #[test]
    fn test_update_account_multiple_fields_via_storage() {
        super::super::with_fs_lock(|| {
            super::super::cleanup_auth_file();
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

            let final_loaded = crate::storage::try_load().unwrap();
            let mut final_accounts = crate::storage::load_accounts(&final_loaded, None).unwrap();
            assert_eq!(final_accounts[0].issuer, "NewIssuer");
            assert_eq!(final_accounts[0].label, "new@test.com");
            assert_eq!(final_accounts[0].sort_order, 99);
            for a in &mut final_accounts {
                a.secret.zeroize();
            }
            final_accounts.clear();
            super::super::cleanup_auth_file();
        });
    }

    #[test]
    fn test_list_accounts_search_case_insensitive() {
        super::super::with_fs_lock(|| {
            super::super::cleanup_auth_file();
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

            let summaries: Vec<_> = reloaded.iter().map(AccountSummary::from).collect();
            let q = "github";
            let filtered: Vec<_> = summaries
                .iter()
                .filter(|a| {
                    a.issuer.to_lowercase().contains(q) || a.label.to_lowercase().contains(q)
                })
                .collect();
            assert_eq!(filtered.len(), 1);
            assert_eq!(filtered[0].issuer, "GitHub");

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
            super::super::cleanup_auth_file();
        });
    }

    #[test]
    fn test_list_accounts_search_no_match_returns_empty() {
        super::super::with_fs_lock(|| {
            super::super::cleanup_auth_file();
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
            super::super::cleanup_auth_file();
        });
    }

    #[test]
    fn test_add_account_duplicate_issuer_label_allowed() {
        super::super::with_fs_lock(|| {
            super::super::cleanup_auth_file();
            let mut data = crate::storage::try_load().unwrap();
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
            super::super::cleanup_auth_file();
        });
    }

    #[test]
    fn test_update_account_sort_order_via_storage() {
        super::super::with_fs_lock(|| {
            super::super::cleanup_auth_file();
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
            accounts[0].sort_order = 1;
            accounts[1].sort_order = 0;
            save_accounts(&mut data, &accounts, None).unwrap();
            crate::storage::save(&data).unwrap();

            let loaded = crate::storage::try_load().unwrap();
            let mut reloaded = crate::storage::load_accounts(&loaded, None).unwrap();
            reloaded.sort_by_key(|a| a.sort_order);
            assert_eq!(reloaded[0].id, "second");
            assert_eq!(reloaded[1].id, "first");
            for a in &mut reloaded {
                a.secret.zeroize();
            }
            reloaded.clear();
            super::super::cleanup_auth_file();
        });
    }

    #[test]
    fn test_update_account_nonexistent_id_fails() {
        super::super::with_fs_lock(|| {
            super::super::cleanup_auth_file();
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

            let loaded = crate::storage::try_load().unwrap();
            let mut reloaded = crate::storage::load_accounts(&loaded, None).unwrap();
            let found = reloaded.iter().any(|a| a.id == "nonexistent");
            assert!(!found, "update must reject non-existent account ID");
            for a in &mut reloaded {
                a.secret.zeroize();
            }
            reloaded.clear();
            super::super::cleanup_auth_file();
        });
    }

    #[test]
    fn test_add_account_from_uri_via_storage() {
        super::super::with_fs_lock(|| {
            super::super::cleanup_auth_file();
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
            super::super::cleanup_auth_file();
        });
    }
}
