//! Exe-relative path resolution — makes the app fully portable.
//!
//! All data file paths are derived from the executable's location.
//! Panics if the executable path is unavailable (fail-fast).

use std::path::PathBuf;

/// Returns the executable's file stem (filename without `.exe`).
pub fn exe_stem() -> String {
    std::env::current_exe()
        .expect("failed to get exe path")
        .file_stem()
        .expect("failed to get exe stem")
        .to_string_lossy()
        .to_string()
}

/// Returns the directory containing the executable.
pub fn exe_dir() -> PathBuf {
    std::env::current_exe()
        .expect("failed to get exe path")
        .parent()
        .expect("failed to get exe parent")
        .to_path_buf()
}

/// Path to the `.auth` data file (alongside the .exe).
pub fn auth_path() -> PathBuf {
    exe_dir().join(format!("{}.auth", exe_stem()))
}

/// Verify path functions work without panicking.
pub fn verify() -> Result<(), String> {
    let _ = exe_stem();
    let _ = exe_dir();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exe_stem_returns_string() {
        let stem = exe_stem();
        assert!(!stem.is_empty());
    }

    #[test]
    fn test_auth_path_ends_with_auth() {
        let path = auth_path();
        assert!(path.to_string_lossy().ends_with(".auth"));
    }
}
