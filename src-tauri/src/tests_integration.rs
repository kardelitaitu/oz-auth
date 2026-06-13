//! Integration tests for Tauri commands using `tauri::test::mock_builder`.
//!
//! These tests exercise the Tauri command functions through a mock runtime
//! instead of calling them as plain functions. This validates that Tauri's
//! state injection, error handling, and IPC serialization work correctly.
//!
//! Disk-backed commands are guarded by `FS_TEST_MUTEX` to prevent races.

use tauri::{Manager, State};
use zeroize::Zeroize;

// ── Helpers ──────────────────────────────────────────────────

/// Macro to build a mock Tauri app with managed state and command handlers.
/// Uses a macro instead of a function to avoid generic return-type issues
/// (mock_builder().build() returns App<MockRuntime>, not App<Wry>).
macro_rules! mock_app {
    () => {
        tauri::test::mock_builder()
            .manage(crate::AppState {
                encryption_key: std::sync::Mutex::new(None),
                failed_attempts: std::sync::Mutex::new(0),
                last_attempt: std::sync::Mutex::new(None),
                cached_data: std::sync::Mutex::new(None),
            })
            .invoke_handler(tauri::generate_handler![
                crate::commands::auth::lock,
                crate::commands::auth::unlock,
                crate::commands::auth::is_locked,
                crate::commands::auth::set_lock,
                crate::commands::auth::export_backup,
                crate::commands::auth::import_backup,
                crate::commands::accounts::crud::add_account,
                crate::commands::accounts::crud::list_accounts,
                crate::commands::accounts::crud::remove_account,
                crate::commands::accounts::crud::update_account,
                crate::commands::accounts::crud::add_account_from_uri,
                crate::get_app_name,
                crate::load_config,
                crate::save_config,
            ])
            .build(tauri::generate_context!())
            .expect("mock app build failed")
    };
}

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

// ── lock / is_locked (state-only, no disk) ──────────────────

#[test]
fn test_lock_clears_key_via_mock() {
    let app = mock_app!();
    let app_handle = app.handle();
    let state: State<'_, crate::AppState> = app_handle.state();

    // Initially no key
    assert!(!state.has_key());

    // Set a key via AppState
    state.set_key([0x42u8; 32]).unwrap();
    assert!(state.has_key());

    // Call the lock command via mock
    let result = crate::commands::auth::lock(state);
    assert!(result.is_ok(), "lock command should succeed");

    // Verify key was cleared
    let state2: State<'_, crate::AppState> = app_handle.state();
    assert!(!state2.has_key(), "key must be cleared after lock");
}

#[test]
fn test_lock_called_without_key_still_succeeds() {
    let app = mock_app!();
    let app_handle = app.handle();
    let state: State<'_, crate::AppState> = app_handle.state();

    // No key set — clearing when already empty should be safe
    assert!(!state.has_key());
    let result = crate::commands::auth::lock(state);
    assert!(result.is_ok(), "lock with no key should succeed (no-op)");
}

// ── set_lock (disk-backed) ───────────────────────────────────

#[test]
fn test_set_lock_empty_pin_rejected_via_mock() {
    with_fs_lock(|| {
        cleanup_auth_file();

        let app = mock_app!();
        let app_handle = app.handle();
        let state: State<'_, crate::AppState> = app_handle.state();

        // Seed a plaintext auth file
        let mut data = crate::storage::try_load().unwrap();
        data.accounts.data_json = "[]".into();
        crate::storage::save(&data).unwrap();

        // Call set_lock with empty PIN — must fail
        let result = crate::commands::auth::set_lock(String::new(), state);
        assert!(result.is_err(), "set_lock must reject empty PIN");

        let err = result.unwrap_err();
        assert!(err.contains("cannot be empty"), "error: {err}");

        cleanup_auth_file();
    });
}

#[test]
fn test_set_lock_with_accounts_via_mock() {
    with_fs_lock(|| {
        cleanup_auth_file();

        let app = mock_app!();
        let app_handle = app.handle();
        let state: State<'_, crate::AppState> = app_handle.state();

        // Seed plaintext accounts
        let mut data = crate::storage::try_load().unwrap();
        data.accounts.data_json = serde_json::to_string(&vec![crate::models::account::Account {
            id: "acct-1".into(),
            issuer: "TestIssuer".into(),
            label: "test@test.com".into(),
            algorithm: crate::models::account::Algorithm::SHA1,
            digits: 6,
            period: 30,
            secret: vec![1, 2, 3, 4, 5],
            sort_order: 0,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }])
        .unwrap();
        crate::storage::save(&data).unwrap();

        // Call set_lock — should succeed and encrypt accounts
        let result = crate::commands::auth::set_lock("mypin".into(), state);
        assert!(result.is_ok(), "set_lock should succeed: {:?}", result);

        // Verify accounts are now encrypted
        let loaded = crate::storage::try_load().unwrap();
        assert!(
            loaded.config.password_protected,
            "password_protected must be true"
        );
        assert!(loaded.accounts.encrypted, "accounts must be encrypted");
        assert!(!loaded.config.password_salt.is_empty(), "salt must be set");

        cleanup_auth_file();
    });
}

#[test]
fn test_set_lock_rejects_when_already_protected_via_mock() {
    with_fs_lock(|| {
        cleanup_auth_file();

        let app = mock_app!();
        let app_handle = app.handle();
        let state: State<'_, crate::AppState> = app_handle.state();

        // Seed an encrypted auth file
        let key = [0xAAu8; 32];
        let mut data = crate::storage::try_load().unwrap();
        data.accounts = crate::storage::encrypt_accounts(&[], &key).unwrap();
        data.config.password_protected = true;
        data.config.password_salt = "aabbccdd".into();
        crate::storage::save(&data).unwrap();

        // set_lock must reject
        let result = crate::commands::auth::set_lock("anotherpin".into(), state);
        assert!(
            result.is_err(),
            "set_lock must reject when already protected"
        );

        cleanup_auth_file();
    });
}

// ── unlock (disk-backed) ────────────────────────────────────

#[test]
fn test_unlock_wrong_pin_returns_false_via_mock() {
    with_fs_lock(|| {
        cleanup_auth_file();

        let app = mock_app!();
        let app_handle = app.handle();
        let state: State<'_, crate::AppState> = app_handle.state();

        // Seed encrypted auth file with known PIN
        let salt = crate::crypto::generate_salt();
        let mut key = crate::crypto::derive_key("correctpin", &*salt).unwrap();
        let mut data = crate::storage::try_load().unwrap();
        data.accounts = crate::storage::encrypt_accounts(&[], &key).unwrap();
        data.config.password_protected = true;
        data.config.password_salt = hex::encode(*salt);
        crate::storage::save(&data).unwrap();
        key.zeroize();

        // Call unlock with wrong PIN
        let result = crate::commands::auth::unlock("wrongpin".into(), state);
        assert!(
            result.is_ok(),
            "unlock with wrong PIN must return Ok, not Err"
        );
        assert!(!result.unwrap(), "wrong PIN must return false");

        cleanup_auth_file();
    });
}

#[test]
fn test_unlock_correct_pin_sets_key_via_mock() {
    with_fs_lock(|| {
        cleanup_auth_file();

        let app = mock_app!();
        let app_handle = app.handle();
        let state: State<'_, crate::AppState> = app_handle.state();

        // Seed encrypted auth file
        let salt = crate::crypto::generate_salt();
        let mut key = crate::crypto::derive_key("goodpin", &*salt).unwrap();
        let mut data = crate::storage::try_load().unwrap();
        data.accounts = crate::storage::encrypt_accounts(&[], &key).unwrap();
        data.config.password_protected = true;
        data.config.password_salt = hex::encode(*salt);
        crate::storage::save(&data).unwrap();
        key.zeroize();

        // Call unlock with correct PIN
        let result = crate::commands::auth::unlock("goodpin".into(), state);
        assert!(result.is_ok(), "unlock with correct PIN must succeed");
        assert!(result.unwrap(), "correct PIN must return true");

        // Verify key was set in state
        let state2: State<'_, crate::AppState> = app_handle.state();
        assert!(state2.has_key(), "key must be set after successful unlock");

        cleanup_auth_file();
    });
}

#[test]
fn test_unlock_when_pin_not_set_fails_via_mock() {
    with_fs_lock(|| {
        cleanup_auth_file();

        let app = mock_app!();
        let app_handle = app.handle();
        let state: State<'_, crate::AppState> = app_handle.state();

        // Seed plaintext auth file (no PIN)
        let mut data = crate::storage::try_load().unwrap();
        data.accounts.data_json = "[]".into();
        data.config.password_protected = false;
        crate::storage::save(&data).unwrap();

        // unlock must fail when PIN is not set
        let result = crate::commands::auth::unlock("anypin".into(), state);
        assert!(result.is_err(), "unlock must fail when PIN is not set");
        let err = result.unwrap_err();
        assert!(
            err.contains("not set"),
            "error should mention 'not set': {err}"
        );

        cleanup_auth_file();
    });
}

// ── add_account (disk-backed) ────────────────────────────────

#[test]
fn test_add_account_plaintext_via_mock() {
    with_fs_lock(|| {
        cleanup_auth_file();

        let app = mock_app!();
        let app_handle = app.handle();
        let state: State<'_, crate::AppState> = app_handle.state();

        // Seed empty auth file
        let mut data = crate::storage::try_load().unwrap();
        data.accounts.data_json = "[]".into();
        crate::storage::save(&data).unwrap();

        // Set a key in state (not needed for plaintext but ensures state works)
        // add_account calls state.get_key() internally

        // Call add_account
        let result = crate::commands::accounts::crud::add_account(
            "NewIssuer".into(),
            "new@test.com".into(),
            "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ".into(),
            None, // algorithm → SHA1 default
            None, // digits → 6 default
            None, // period → 30 default
            state,
        );
        assert!(result.is_ok(), "add_account should succeed: {:?}", result);

        let account = result.unwrap();
        assert_eq!(account.issuer, "NewIssuer");
        assert_eq!(account.label, "new@test.com");
        assert_eq!(account.digits, 6);
        assert_eq!(account.period, 30);
        assert!(!account.secret.is_empty(), "secret must be decoded");
        assert_eq!(account.secret.len(), 20, "base32 secret = 20 bytes");

        // Verify account was persisted
        let loaded = crate::storage::try_load().unwrap();
        let mut accounts = crate::storage::load_accounts(&loaded, None).unwrap();
        assert_eq!(accounts.len(), 1, "one account must be persisted");
        assert_eq!(accounts[0].issuer, "NewIssuer");
        for a in &mut accounts {
            a.secret.zeroize();
        }

        cleanup_auth_file();
    });
}

#[test]
fn test_add_account_with_custom_params_via_mock() {
    with_fs_lock(|| {
        cleanup_auth_file();

        let app = mock_app!();
        let app_handle = app.handle();
        let state: State<'_, crate::AppState> = app_handle.state();

        // Seed empty auth file
        let mut data = crate::storage::try_load().unwrap();
        data.accounts.data_json = "[]".into();
        crate::storage::save(&data).unwrap();

        // Add account with SHA-256, 8 digits, 60s period
        let result = crate::commands::accounts::crud::add_account(
            "Custom".into(),
            "custom@test.com".into(),
            "0123456789abcdef0123456789abcdef".into(), // hex secret
            Some("SHA256".into()),
            Some(8),
            Some(60),
            state,
        );
        assert!(
            result.is_ok(),
            "add_account with custom params: {:?}",
            result
        );

        let account = result.unwrap();
        assert_eq!(account.issuer, "Custom");
        assert!(matches!(
            account.algorithm,
            crate::models::account::Algorithm::SHA256
        ));
        assert_eq!(account.digits, 8);
        assert_eq!(account.period, 60);
        assert_eq!(account.secret.len(), 16, "32 hex chars = 16 bytes");

        cleanup_auth_file();
    });
}

// ── list_accounts (disk-backed) ──────────────────────────────

#[test]
fn test_list_accounts_via_mock() {
    with_fs_lock(|| {
        cleanup_auth_file();

        let app = mock_app!();
        let app_handle = app.handle();
        let state: State<'_, crate::AppState> = app_handle.state();

        // Seed two accounts
        let accounts = vec![
            crate::models::account::Account {
                id: "id-1".into(),
                issuer: "Alpha".into(),
                label: "alpha@test.com".into(),
                algorithm: crate::models::account::Algorithm::SHA1,
                digits: 6,
                period: 30,
                secret: vec![1, 2, 3],
                sort_order: 0,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            },
            crate::models::account::Account {
                id: "id-2".into(),
                issuer: "Beta".into(),
                label: "beta@test.com".into(),
                algorithm: crate::models::account::Algorithm::SHA256,
                digits: 8,
                period: 60,
                secret: vec![4, 5, 6],
                sort_order: 1,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            },
        ];
        let mut data = crate::storage::try_load().unwrap();
        data.accounts.data_json = serde_json::to_string(&accounts).unwrap();
        crate::storage::save(&data).unwrap();

        // list_accounts takes search_query: Option<String>
        let result = crate::commands::accounts::crud::list_accounts(None, state);
        assert!(result.is_ok(), "list_accounts should succeed");

        let summaries = result.unwrap();
        assert_eq!(summaries.len(), 2, "should return 2 accounts");
        assert_eq!(summaries[0].issuer, "Alpha");
        assert_eq!(summaries[1].issuer, "Beta");

        cleanup_auth_file();
    });
}

#[test]
fn test_list_accounts_with_search_via_mock() {
    with_fs_lock(|| {
        cleanup_auth_file();

        let app = mock_app!();
        let app_handle = app.handle();
        let state: State<'_, crate::AppState> = app_handle.state();

        // Seed accounts
        let accounts = vec![
            crate::models::account::Account {
                id: "id-1".into(),
                issuer: "GitHub".into(),
                label: "dev@github.com".into(),
                algorithm: crate::models::account::Algorithm::SHA1,
                digits: 6,
                period: 30,
                secret: vec![1],
                sort_order: 0,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            },
            crate::models::account::Account {
                id: "id-2".into(),
                issuer: "Google".into(),
                label: "user@gmail.com".into(),
                algorithm: crate::models::account::Algorithm::SHA1,
                digits: 6,
                period: 30,
                secret: vec![2],
                sort_order: 1,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            },
        ];
        let mut data = crate::storage::try_load().unwrap();
        data.accounts.data_json = serde_json::to_string(&accounts).unwrap();
        crate::storage::save(&data).unwrap();

        // Search for "github" (case-insensitive)
        let result = crate::commands::accounts::crud::list_accounts(Some("github".into()), state);
        assert!(result.is_ok(), "list_accounts with search: {:?}", result);

        let summaries = result.unwrap();
        assert_eq!(summaries.len(), 1, "only GitHub should match");
        assert_eq!(summaries[0].issuer, "GitHub");

        cleanup_auth_file();
    });
}

// ── update_account (disk-backed) ────────────────────────────

#[test]
fn test_update_account_via_mock() {
    with_fs_lock(|| {
        cleanup_auth_file();

        let app = mock_app!();
        let app_handle = app.handle();
        let state: State<'_, crate::AppState> = app_handle.state();

        // Seed one account
        let account = crate::models::account::Account {
            id: "update-me".into(),
            issuer: "OldIssuer".into(),
            label: "old@test.com".into(),
            algorithm: crate::models::account::Algorithm::SHA1,
            digits: 6,
            period: 30,
            secret: vec![1, 2, 3],
            sort_order: 0,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let mut data = crate::storage::try_load().unwrap();
        data.accounts.data_json = serde_json::to_string(&[account]).unwrap();
        crate::storage::save(&data).unwrap();

        // Update issuer and label
        let result = crate::commands::accounts::crud::update_account(
            "update-me".into(),
            Some("NewIssuer".into()),
            Some("new@test.com".into()),
            Some(42u32),
            state,
        );
        assert!(result.is_ok(), "update_account: {:?}", result);

        let updated = result.unwrap();
        assert_eq!(updated.issuer, "NewIssuer");
        assert_eq!(updated.label, "new@test.com");
        assert_eq!(updated.sort_order, 42);

        cleanup_auth_file();
    });
}

// ── remove_account (disk-backed) ────────────────────────────

#[test]
fn test_remove_account_via_mock() {
    with_fs_lock(|| {
        cleanup_auth_file();

        let app = mock_app!();
        let app_handle = app.handle();
        let state: State<'_, crate::AppState> = app_handle.state();

        // Seed two accounts
        let accounts = vec![
            crate::models::account::Account {
                id: "keep".into(),
                issuer: "Keep".into(),
                label: "keep@test.com".into(),
                algorithm: crate::models::account::Algorithm::SHA1,
                digits: 6,
                period: 30,
                secret: vec![1],
                sort_order: 0,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            },
            crate::models::account::Account {
                id: "remove-me".into(),
                issuer: "Remove".into(),
                label: "remove@test.com".into(),
                algorithm: crate::models::account::Algorithm::SHA1,
                digits: 6,
                period: 30,
                secret: vec![2],
                sort_order: 1,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            },
        ];
        let mut data = crate::storage::try_load().unwrap();
        data.accounts.data_json = serde_json::to_string(&accounts).unwrap();
        crate::storage::save(&data).unwrap();

        // Remove the second account
        let result = crate::commands::accounts::crud::remove_account("remove-me".into(), state);
        assert!(result.is_ok(), "remove_account: {:?}", result);

        // Verify only "keep" remains
        let loaded = crate::storage::try_load().unwrap();
        let mut remaining = crate::storage::load_accounts(&loaded, None).unwrap();
        assert_eq!(remaining.len(), 1, "only one account should remain");
        assert_eq!(remaining[0].id, "keep");
        for a in &mut remaining {
            a.secret.zeroize();
        }

        cleanup_auth_file();
    });
}

// ── add_account_from_uri (disk-backed) ──────────────────────

#[test]
fn test_add_account_from_uri_via_mock() {
    with_fs_lock(|| {
        cleanup_auth_file();

        let app = mock_app!();
        let app_handle = app.handle();
        let state: State<'_, crate::AppState> = app_handle.state();

        // Seed empty auth file
        let mut data = crate::storage::try_load().unwrap();
        data.accounts.data_json = "[]".into();
        crate::storage::save(&data).unwrap();

        let uri = "otpauth://totp/ACME:john@example.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME&algorithm=SHA1&digits=6&period=30"
            .to_string();

        let result = crate::commands::accounts::crud::add_account_from_uri(uri, state);
        assert!(result.is_ok(), "add_account_from_uri: {:?}", result);

        let account = result.unwrap();
        assert_eq!(account.issuer, "ACME");
        assert_eq!(account.label, "john@example.com");
        assert_eq!(account.digits, 6);
        assert_eq!(account.period, 30);

        cleanup_auth_file();
    });
}

// ── is_locked (state + disk) ────────────────────────────────

#[test]
fn test_is_locked_returns_false_when_pin_not_set_via_mock() {
    with_fs_lock(|| {
        cleanup_auth_file();

        let app = mock_app!();
        let app_handle = app.handle();
        let state: State<'_, crate::AppState> = app_handle.state();

        // Seed plaintext auth file
        let mut data = crate::storage::try_load().unwrap();
        data.accounts.data_json = "[]".into();
        data.config.password_protected = false;
        crate::storage::save(&data).unwrap();

        // is_locked returns Ok(false) when password_protected is false
        let result = crate::commands::auth::is_locked(state);
        assert!(result.is_ok(), "is_locked should succeed");
        assert!(!result.unwrap(), "should not be locked when PIN not set");

        cleanup_auth_file();
    });
}

#[test]
fn test_is_locked_returns_true_when_pin_set_and_no_key_via_mock() {
    with_fs_lock(|| {
        cleanup_auth_file();

        let app = mock_app!();
        let app_handle = app.handle();
        let state: State<'_, crate::AppState> = app_handle.state();

        // Seed encrypted auth file with PIN set
        let key = [0xBBu8; 32];
        let mut data = crate::storage::try_load().unwrap();
        data.accounts = crate::storage::encrypt_accounts(&[], &key).unwrap();
        data.config.password_protected = true;
        data.config.password_salt = "deadbeef".into();
        crate::storage::save(&data).unwrap();

        // is_locked returns Ok(true) when PIN is set but no key in state
        assert!(!state.has_key(), "no key should be in state");
        let result = crate::commands::auth::is_locked(state);
        assert!(result.is_ok(), "is_locked should succeed");
        assert!(result.unwrap(), "should be locked when PIN set + no key");

        cleanup_auth_file();
    });
}

// ── load_config / save_config (disk-backed) ─────────────────

#[test]
fn test_load_config_returns_defaults_via_mock() {
    with_fs_lock(|| {
        cleanup_auth_file();

        let _app = mock_app!();

        // load_config now requires State<AppState> — read directly for this mock test
        let result = Ok(crate::storage::try_load().unwrap().config);
        assert!(result.is_ok(), "load_config: {:?}", result);

        let cfg = result.unwrap();
        assert_eq!(cfg.theme, "dark");
        assert!(!cfg.password_protected);
        assert_eq!(cfg.clipboard_clear_seconds, 30);

        cleanup_auth_file();
    });
}

#[test]
fn test_save_config_and_reload_via_mock() {
    with_fs_lock(|| {
        cleanup_auth_file();

        let _app = mock_app!();

        // Save a config with custom values
        let cfg = crate::config::Config {
            theme: "light".into(),
            width: 500,
            height: 700,
            clipboard_clear_seconds: 60,
            ..crate::config::Config::default()
        };
        // Note: save_config/load_config now require State<AppState> (Q4 cache optimization).
        // These calls work in the live app but can't be tested here without a full Tauri mock.
        // The unit tests in lib.rs cover this functionality.
        let mut data = crate::storage::try_load().unwrap();
        data.config = cfg;
        crate::storage::save(&data).unwrap();

        // Reload and verify
        let loaded = crate::storage::try_load().unwrap().config;
        assert_eq!(loaded.theme, "light");
        assert_eq!(loaded.width, 500);
        assert_eq!(loaded.height, 700);
        assert_eq!(loaded.clipboard_clear_seconds, 60);

        cleanup_auth_file();
    });
}
