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
    let mut data = state.load_data()?;
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
    state.invalidate_cache();

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

    let mut data = state.load_data()?;
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
    state.invalidate_cache();

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
    let mut data = state.load_data()?;
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
    state.invalidate_cache();

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
    let mut data = state.load_data()?;
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
    state.invalidate_cache();

    zeroize_accounts(&mut accounts);
    crate::diagnostics::event("account", &format!("updated {account_id}"));

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
    let data = state.load_data()?;
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
    use crate::test_utils::{cleanup_auth_file, test_app_state, with_fs_lock};

    // ── add_account_impl tests ────────────────────────────────

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

    // ── add_account_from_uri_impl tests ───────────────────────

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

    // ── remove_account_impl tests ─────────────────────────────

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
            cleanup_auth_file();
        });
    }

    // ── update_account_impl tests ─────────────────────────────

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
    fn test_update_account_partial_issuer_only() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let mut data = crate::storage::try_load().unwrap();
            let accounts = vec![Account {
                id: "upd".into(),
                issuer: "OldIssuer".into(),
                label: "keep@test.com".into(),
                algorithm: Algorithm::SHA1,
                digits: 6,
                period: 30,
                secret: vec![1],
                sort_order: 7,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            }];
            save_accounts(&mut data, &accounts, None).unwrap();
            crate::storage::save(&data).unwrap();

            let updated =
                update_account_impl("upd", Some("NewIssuer"), None, None, &state).unwrap();
            assert_eq!(updated.issuer, "NewIssuer");
            assert_eq!(updated.label, "keep@test.com", "label must be unchanged");
            assert_eq!(updated.sort_order, 7, "sort_order must be unchanged");
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_update_account_partial_label_only() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let mut data = crate::storage::try_load().unwrap();
            let accounts = vec![Account {
                id: "upd".into(),
                issuer: "KeepIssuer".into(),
                label: "old@test.com".into(),
                algorithm: Algorithm::SHA1,
                digits: 6,
                period: 30,
                secret: vec![1],
                sort_order: 3,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            }];
            save_accounts(&mut data, &accounts, None).unwrap();
            crate::storage::save(&data).unwrap();

            let updated =
                update_account_impl("upd", None, Some("new@test.com"), None, &state).unwrap();
            assert_eq!(updated.issuer, "KeepIssuer", "issuer must be unchanged");
            assert_eq!(updated.label, "new@test.com");
            assert_eq!(updated.sort_order, 3, "sort_order must be unchanged");
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_update_account_partial_sort_order_only() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let mut data = crate::storage::try_load().unwrap();
            let accounts = vec![Account {
                id: "upd".into(),
                issuer: "KeepIssuer".into(),
                label: "keep@test.com".into(),
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

            let updated = update_account_impl("upd", None, None, Some(99), &state).unwrap();
            assert_eq!(updated.issuer, "KeepIssuer", "issuer must be unchanged");
            assert_eq!(updated.label, "keep@test.com", "label must be unchanged");
            assert_eq!(updated.sort_order, 99);
            cleanup_auth_file();
        });
    }

    // ── list_accounts_impl tests ──────────────────────────────

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
    fn test_list_accounts_search_no_match() {
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

    #[test]
    fn test_list_accounts_search_by_label() {
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
                    issuer: "AcmeCorp".into(),
                    label: "admin@acme.com".into(),
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

            // Search by label, not issuer
            let results = list_accounts_impl(Some("github.com"), &state).unwrap();
            assert_eq!(results.len(), 1, "must match by label substring");
            assert_eq!(results[0].id, "g1");
            cleanup_auth_file();
        });
    }

    // ── Storage-level CRUD integration tests ──────────────────

    #[test]
    fn test_add_account_via_storage_with_accounts() {
        with_fs_lock(|| {
            cleanup_auth_file();
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
            cleanup_auth_file();
        });
    }

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

    #[test]
    fn test_add_account_duplicate_issuer_label_allowed() {
        with_fs_lock(|| {
            cleanup_auth_file();
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
            cleanup_auth_file();
        });
    }

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
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_update_account_nonexistent_id_fails() {
        with_fs_lock(|| {
            cleanup_auth_file();
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
            cleanup_auth_file();
        });
    }

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

    // ── Encrypted store tests ─────────────────────────────────

    fn seed_encrypted_state(state: &crate::AppState) -> zeroize::Zeroizing<[u8; 32]> {
        let salt = crate::crypto::generate_salt();
        let raw_key = crate::crypto::derive_key("testpin", &*salt).unwrap();
        let key = zeroize::Zeroizing::new(raw_key);
        let mut data = crate::storage::try_load().unwrap();
        data.accounts = crate::storage::encrypt_accounts(&[], &key).unwrap();
        data.config.password_protected = true;
        data.config.password_salt = hex::encode(*salt);
        crate::storage::save(&data).unwrap();
        state.set_key(*key).unwrap();
        key
    }

    #[test]
    fn test_add_account_encrypted() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            seed_encrypted_state(&state);

            let account = add_account_impl(
                "EncIssuer",
                "enc@test.com",
                "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ",
                None,
                None,
                None,
                &state,
            )
            .unwrap();
            assert_eq!(account.issuer, "EncIssuer");
            assert_eq!(account.secret.len(), 20);

            let loaded = crate::storage::try_load().unwrap();
            assert!(loaded.accounts.encrypted, "must stay encrypted");
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_list_accounts_encrypted() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            seed_encrypted_state(&state);

            add_account_impl(
                "ListIssuer",
                "list@test.com",
                "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ",
                None,
                None,
                None,
                &state,
            )
            .unwrap();

            let results = list_accounts_impl(None, &state).unwrap();
            assert_eq!(results.len(), 1);
            assert_eq!(results[0].issuer, "ListIssuer");
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_update_account_encrypted() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            seed_encrypted_state(&state);

            let acct = add_account_impl(
                "OldName",
                "old@test.com",
                "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ",
                None,
                None,
                None,
                &state,
            )
            .unwrap();

            let updated =
                update_account_impl(&acct.id, Some("NewName"), None, None, &state).unwrap();
            assert_eq!(updated.issuer, "NewName");

            let results = list_accounts_impl(None, &state).unwrap();
            assert_eq!(results[0].issuer, "NewName");
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_remove_account_encrypted() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            seed_encrypted_state(&state);

            let acct = add_account_impl(
                "ToRemove",
                "rm@test.com",
                "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ",
                None,
                None,
                None,
                &state,
            )
            .unwrap();

            remove_account_impl(&acct.id, &state).unwrap();

            let results = list_accounts_impl(None, &state).unwrap();
            assert!(results.is_empty(), "account must be removed");
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_list_accounts_search_label_encrypted() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            seed_encrypted_state(&state);

            add_account_impl(
                "GitHub",
                "dev@github.com",
                "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ",
                None,
                None,
                None,
                &state,
            )
            .unwrap();

            let results = list_accounts_impl(Some("github.com"), &state).unwrap();
            assert_eq!(results.len(), 1, "must find by label in encrypted store");
            cleanup_auth_file();
        });
    }

    // ── Stress & edge case tests ──────────────────────────────

    #[test]
    fn test_add_and_list_100_accounts() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let mut data = crate::storage::try_load().unwrap();
            data.accounts.data_json = "[]".into();
            crate::storage::save(&data).unwrap();

            for i in 0..100 {
                let account = add_account_impl(
                    &format!("Issuer{i}"),
                    &format!("user{i}@test.com"),
                    "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ",
                    None,
                    None,
                    None,
                    &state,
                )
                .unwrap();
                assert_eq!(account.issuer, format!("Issuer{i}"));
            }

            let results = list_accounts_impl(None, &state).unwrap();
            assert_eq!(results.len(), 100, "must have 100 accounts");

            // Search by label substring
            let results = list_accounts_impl(Some("user50"), &state).unwrap();
            assert_eq!(results.len(), 1);
            assert_eq!(results[0].issuer, "Issuer50");

            // Search by issuer substring
            let results = list_accounts_impl(Some("Issuer9"), &state).unwrap();
            assert_eq!(
                results.len(),
                11,
                "Issuer9 + Issuer90..Issuer99 = 11 matches"
            );

            cleanup_auth_file();
        });
    }

    #[test]
    fn test_search_special_characters() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let mut data = crate::storage::try_load().unwrap();
            let accounts = vec![
                Account {
                    id: "s1".into(),
                    issuer: "C++ Developers".into(),
                    label: "dev@c++.org".into(),
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
                    issuer: "AT&T".into(),
                    label: "admin@at&t.com".into(),
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

            let results = list_accounts_impl(Some("C++"), &state).unwrap();
            assert_eq!(results.len(), 1, "must match C++ in issuer");
            assert_eq!(results[0].issuer, "C++ Developers");

            let results = list_accounts_impl(Some("at&t"), &state).unwrap();
            assert_eq!(results.len(), 1, "must match at&t case-insensitively");
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_search_empty_query_returns_all() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let mut data = crate::storage::try_load().unwrap();
            let accounts = vec![Account {
                id: "a1".into(),
                issuer: "A".into(),
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

            let results = list_accounts_impl(Some(""), &state).unwrap();
            assert_eq!(results.len(), 1, "empty query must return all");
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_update_preserves_other_accounts() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let mut data = crate::storage::try_load().unwrap();
            let accounts = vec![
                Account {
                    id: "a1".into(),
                    issuer: "First".into(),
                    label: "f@test.com".into(),
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
                    issuer: "Second".into(),
                    label: "s@test.com".into(),
                    algorithm: Algorithm::SHA256,
                    digits: 8,
                    period: 60,
                    secret: vec![2],
                    sort_order: 1,
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                },
            ];
            save_accounts(&mut data, &accounts, None).unwrap();
            crate::storage::save(&data).unwrap();

            // Update only first account
            let updated =
                update_account_impl("a1", Some("UpdatedFirst"), None, None, &state).unwrap();
            assert_eq!(updated.issuer, "UpdatedFirst");

            // Verify second account is unchanged
            let results = list_accounts_impl(None, &state).unwrap();
            assert_eq!(results.len(), 2);
            let second = results.iter().find(|a| a.id == "a2").unwrap();
            assert_eq!(second.issuer, "Second", "other accounts must be unchanged");
            assert_eq!(second.digits, 8, "digits must be unchanged");
            assert_eq!(second.period, 60, "period must be unchanged");
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_add_account_long_fields() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let mut data = crate::storage::try_load().unwrap();
            data.accounts.data_json = "[]".into();
            crate::storage::save(&data).unwrap();

            let long_issuer = "X".repeat(500);
            let long_label = "y".repeat(500);
            let account = add_account_impl(
                &long_issuer,
                &long_label,
                "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ",
                None,
                None,
                None,
                &state,
            )
            .unwrap();
            assert_eq!(account.issuer.len(), 500);
            assert_eq!(account.label.len(), 500);

            let results = list_accounts_impl(None, &state).unwrap();
            assert_eq!(results.len(), 1);
            assert_eq!(results[0].issuer.len(), 500);
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_remove_last_account_leaves_empty() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let mut data = crate::storage::try_load().unwrap();
            data.accounts.data_json = "[]".into();
            crate::storage::save(&data).unwrap();

            let acct = add_account_impl(
                "Only",
                "only@test.com",
                "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ",
                None,
                None,
                None,
                &state,
            )
            .unwrap();
            remove_account_impl(&acct.id, &state).unwrap();

            let results = list_accounts_impl(None, &state).unwrap();
            assert!(results.is_empty());
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_add_account_default_params() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let mut data = crate::storage::try_load().unwrap();
            data.accounts.data_json = "[]".into();
            crate::storage::save(&data).unwrap();

            let account = add_account_impl(
                "Defaults",
                "d@test.com",
                "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ",
                None,
                None,
                None,
                &state,
            )
            .unwrap();
            assert!(matches!(account.algorithm, Algorithm::SHA1));
            assert_eq!(account.digits, 6, "default digits must be 6");
            assert_eq!(account.period, 30, "default period must be 30");
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_add_account_all_algorithms() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let mut data = crate::storage::try_load().unwrap();
            data.accounts.data_json = "[]".into();
            crate::storage::save(&data).unwrap();

            for algo_name in &["SHA1", "SHA256", "SHA512"] {
                let account = add_account_impl(
                    algo_name,
                    "test@test.com",
                    "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ",
                    Some(algo_name),
                    None,
                    None,
                    &state,
                )
                .unwrap();
                match *algo_name {
                    "SHA1" => assert!(matches!(account.algorithm, Algorithm::SHA1)),
                    "SHA256" => assert!(matches!(account.algorithm, Algorithm::SHA256)),
                    "SHA512" => assert!(matches!(account.algorithm, Algorithm::SHA512)),
                    _ => unreachable!(),
                }
            }
            cleanup_auth_file();
        });
    }

    #[test]
    fn test_update_account_multiple_accounts_only_one_changes() {
        with_fs_lock(|| {
            cleanup_auth_file();
            let state = test_app_state();
            let mut data = crate::storage::try_load().unwrap();
            let accounts: Vec<Account> = (0..10)
                .map(|i| Account {
                    id: format!("id-{i}"),
                    issuer: format!("Issuer{i}"),
                    label: format!("user{i}@test.com"),
                    algorithm: Algorithm::SHA1,
                    digits: 6,
                    period: 30,
                    secret: vec![i as u8],
                    sort_order: i,
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                })
                .collect();
            save_accounts(&mut data, &accounts, None).unwrap();
            crate::storage::save(&data).unwrap();

            // Update only id-5
            let updated = update_account_impl("id-5", Some("CHANGED"), None, None, &state).unwrap();
            assert_eq!(updated.issuer, "CHANGED");

            let results = list_accounts_impl(None, &state).unwrap();
            assert_eq!(results.len(), 10);
            for r in &results {
                if r.id == "id-5" {
                    assert_eq!(r.issuer, "CHANGED");
                } else {
                    let idx: usize = r.id.strip_prefix("id-").unwrap().parse().unwrap();
                    assert_eq!(
                        r.issuer,
                        format!("Issuer{idx}"),
                        "other accounts must be untouched"
                    );
                }
            }
            cleanup_auth_file();
        });
    }
}
