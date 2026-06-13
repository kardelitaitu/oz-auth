//! Exe-relative path resolution — makes the app fully portable.
//!
//! All data file paths are derived from the executable's location.
//! Returns `Result` instead of panicking so callers can choose fallback behavior.

use std::path::PathBuf;

/// Returns the executable's file stem (filename without `.exe`).
pub fn exe_stem() -> Result<String, String> {
    let exe = std::env::current_exe()
        .map_err(|e| format!("failed to get exe path: {e}"))?;
    let stem = exe
        .file_stem()
        .ok_or_else(|| "failed to get exe stem: no file name in path".to_string())?
        .to_string_lossy()
        .to_string();
    Ok(stem)
}

/// Returns the directory containing the executable.
pub fn exe_dir() -> Result<PathBuf, String> {
    let exe = std::env::current_exe()
        .map_err(|e| format!("failed to get exe path: {e}"))?;
    let dir = exe
        .parent()
        .ok_or_else(|| "failed to get exe parent: no parent directory".to_string())?
        .to_path_buf();
    Ok(dir)
}

/// Path to the `.auth` data file (alongside the .exe).
pub fn auth_path() -> Result<PathBuf, String> {
    let dir = exe_dir()?;
    let stem = exe_stem()?;
    Ok(dir.join(format!("{}.auth", stem)))
}

/// Verify path functions work without errors.
pub fn verify() -> Result<(), String> {
    let _ = exe_stem()?;
    let _ = exe_dir()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exe_stem_returns_string() {
        let stem = exe_stem().unwrap();
        assert!(!stem.is_empty());
    }

    #[test]
    fn test_auth_path_ends_with_auth() {
        let path = auth_path().unwrap();
        assert!(path.to_string_lossy().ends_with(".auth"));
    }

    #[test]
    fn test_exe_dir_returns_path() {
        let dir = exe_dir().unwrap();
        assert!(dir.is_absolute(), "exe_dir must be an absolute path");
    }

    #[test]
    fn test_auth_path_matches_exe_stem() {
        let stem = exe_stem().unwrap();
        let auth = auth_path().unwrap();
        let auth_stem = auth.file_stem().unwrap().to_string_lossy().to_string();
        assert_eq!(auth_stem, stem, "auth file stem must match exe stem");
    }

    #[test]
    fn test_exe_stem_no_path_separator() {
        let stem = exe_stem().unwrap();
        assert!(
            !stem.contains('/') && !stem.contains('\\'),
            "exe_stem must not contain path separators: {stem}"
        );
    }

    #[test]
    fn test_auth_path_parent_is_exe_dir() {
        let auth = auth_path().unwrap();
        let parent = auth.parent().unwrap();
        assert_eq!(parent, &exe_dir().unwrap(), "auth file parent must equal exe dir");
    }

    #[test]
    fn test_verify_returns_ok() {
        let result = verify();
        assert!(result.is_ok(), "verify() should return Ok");
    }
}
