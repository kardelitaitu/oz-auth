#[cfg(test)]
pub(crate) fn test_app_state() -> crate::AppState {
    crate::AppState::new_test()
}

#[cfg(test)]
pub(crate) fn cleanup_auth_file() {
    if let Ok(path) = crate::paths::auth_path() {
        let _ = std::fs::remove_file(&path);
    }
}

#[cfg(test)]
pub(crate) fn with_fs_lock(f: impl FnOnce()) {
    let _lock = crate::storage::auth_file::FS_TEST_MUTEX
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    f();
}

#[cfg(test)]
pub(crate) fn test_key() -> [u8; 32] {
    [0xAAu8; 32]
}
