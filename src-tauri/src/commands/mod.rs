pub mod accounts;
pub mod auth;
pub mod totp;

// ── IPC input length limits ────────────────────────────────

/// Minimum PIN length (must be ≥4 characters)
pub(crate) const MIN_PIN_LEN: usize = 4;
/// Maximum PIN length (Argon2id handles up to 128 bytes with padding)
pub(crate) const MAX_PIN_LEN: usize = 128;
/// Maximum issuer length
pub(crate) const MAX_ISSUER_LEN: usize = 128;
/// Maximum label length (email addresses can be long)
pub(crate) const MAX_LABEL_LEN: usize = 256;
/// Maximum raw secret (base32/hex string) length before decoding
pub(crate) const MAX_SECRET_STR_LEN: usize = 1024;
/// Maximum otpauth URI length
pub(crate) const MAX_URI_LEN: usize = 4096;
/// Maximum file path length
pub(crate) const MAX_PATH_LEN: usize = 4096;
/// Maximum account ID length (UUIDs are 36 chars)
pub(crate) const MAX_ID_LEN: usize = 128;
/// Maximum search query length
pub(crate) const MAX_QUERY_LEN: usize = 256;

/// Validate that a string field's length is within allowed bounds.
/// Returns Err with a descriptive message on violation.
pub(crate) fn validate_length(value: &str, min: usize, max: usize, field_name: &str) -> Result<(), String> {
    let len = value.len();
    if len < min {
        return Err(format!(
            "{} too short: got {} bytes, minimum is {}",
            field_name, len, min
        ));
    }
    if len > max {
        return Err(format!(
            "{} too long: got {} bytes, maximum is {}",
            field_name, len, max
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_length_ok() {
        assert!(validate_length("hello", 1, 10, "test").is_ok());
        assert!(validate_length("a", 1, 10, "test").is_ok());
        assert!(validate_length("1234567890", 1, 10, "test").is_ok());
    }

    #[test]
    fn test_validate_length_too_short() {
        let err = validate_length("ab", 3, 10, "field").unwrap_err();
        assert!(err.contains("too short"));
        assert!(err.contains("field"));
    }

    #[test]
    fn test_validate_length_too_long() {
        let long = "a".repeat(20);
        let err = validate_length(&long, 1, 10, "field").unwrap_err();
        assert!(err.contains("too long"));
        assert!(err.contains("field"));
    }

    #[test]
    fn test_validate_length_empty_rejected() {
        let err = validate_length("", 1, 10, "field").unwrap_err();
        assert!(err.contains("too short"));
    }

    #[test]
    fn test_validate_length_boundary() {
        assert!(validate_length("", 0, 10, "field").is_ok(), "min=0 should accept empty");
        assert!(validate_length(&"a".repeat(10), 1, 10, "field").is_ok(), "exactly max should pass");
        assert!(validate_length(&"a".repeat(11), 1, 10, "field").is_err(), "exceed max should fail");
    }
}
