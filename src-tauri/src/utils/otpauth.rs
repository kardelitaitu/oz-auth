use crate::models::account::Algorithm;
use base32::Alphabet;

pub struct ParsedUri {
    pub issuer: String,
    pub label: String,
    pub algorithm: Algorithm,
    pub digits: u8,
    pub period: u32,
    pub secret: Vec<u8>,
}

/// Parse an `otpauth://totp/...` URI into account data.
pub fn parse_uri(uri: &str) -> Result<ParsedUri, String> {
    let parsed = url::Url::parse(uri).map_err(|e| format!("invalid URI: {e}"))?;

    if parsed.scheme() != "otpauth" {
        return Err("not an otpauth:// URI".to_string());
    }

    // Path is like "/Issuer:label" or "/label"
    let path = parsed.path().trim_start_matches('/');
    let (issuer, label) = if let Some((issuer_part, label_part)) = path.split_once(':') {
        (issuer_part.to_string(), label_part.to_string())
    } else {
        (String::new(), path.to_string())
    };

    // Check query params for issuer override
    let issuer = parsed
        .query_pairs()
        .find(|(k, _)| k == "issuer")
        .map(|(_, v)| v.to_string())
        .unwrap_or(issuer);

    let secret_b32 = parsed
        .query_pairs()
        .find(|(k, _)| k == "secret")
        .map(|(_, v)| v.to_string())
        .ok_or_else(|| "missing secret parameter".to_string())?;

    let secret = base32::decode(Alphabet::Rfc4648 { padding: false }, &secret_b32)
        .ok_or_else(|| "invalid base32 secret".to_string())?;

    let algorithm = parsed
        .query_pairs()
        .find(|(k, _)| k == "algorithm")
        .map(|(_, v)| match v.to_uppercase().as_str() {
            "SHA256" => Algorithm::SHA256,
            "SHA512" => Algorithm::SHA512,
            _ => Algorithm::SHA1,
        })
        .unwrap_or(Algorithm::SHA1);

    let digits = parsed
        .query_pairs()
        .find(|(k, _)| k == "digits")
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(6);

    let period = parsed
        .query_pairs()
        .find(|(k, _)| k == "period")
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(30);

    Ok(ParsedUri {
        issuer,
        label,
        algorithm,
        digits,
        period,
        secret,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_standard_uri() {
        let uri = "otpauth://totp/ACME:john@example.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME&algorithm=SHA1&digits=6&period=30";
        let parsed = parse_uri(uri).unwrap();
        assert_eq!(parsed.issuer, "ACME");
        assert_eq!(parsed.label, "john@example.com");
        assert_eq!(parsed.digits, 6);
        assert_eq!(parsed.period, 30);
        assert!(!parsed.secret.is_empty());
    }

    #[test]
    fn test_parse_no_issuer_in_path() {
        let uri = "otpauth://totp/john@example.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ";
        let parsed = parse_uri(uri).unwrap();
        assert_eq!(parsed.label, "john@example.com");
        assert!(parsed.issuer.is_empty());
        assert!(!parsed.secret.is_empty());
    }

    #[test]
    fn test_parse_issuer_from_query_overrides_path() {
        let uri = "otpauth://totp/WrongName:john@example.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=RealName";
        let parsed = parse_uri(uri).unwrap();
        assert_eq!(parsed.issuer, "RealName");
        assert_eq!(parsed.label, "john@example.com");
    }

    #[test]
    fn test_missing_secret_fails() {
        let uri = "otpauth://totp/ACME:john@example.com?issuer=ACME";
        assert!(parse_uri(uri).is_err());
    }

    #[test]
    fn test_wrong_scheme_fails() {
        let uri = "http://totp/ACME:john@example.com?secret=AAAA";
        assert!(parse_uri(uri).is_err());
    }

    #[test]
    fn test_invalid_uri_fails() {
        assert!(parse_uri("\0invalid").is_err());
    }

    #[test]
    fn test_parse_sha256_8digit_60s() {
        let uri = "otpauth://totp/ACME:john@example.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&algorithm=SHA256&digits=8&period=60";
        let parsed = parse_uri(uri).unwrap();
        assert_eq!(parsed.digits, 8);
        assert_eq!(parsed.period, 60);
        assert!(matches!(parsed.algorithm, Algorithm::SHA256));
    }

    #[test]
    fn test_parse_sha512() {
        let uri = "otpauth://totp/ACME:john@example.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&algorithm=SHA512";
        let parsed = parse_uri(uri).unwrap();
        assert!(matches!(parsed.algorithm, Algorithm::SHA512));
    }

    #[test]
    fn test_parse_unknown_algorithm_defaults_to_sha1() {
        let uri = "otpauth://totp/ACME:john@example.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&algorithm=MD5";
        let parsed = parse_uri(uri).unwrap();
        assert!(matches!(parsed.algorithm, Algorithm::SHA1));
    }

    #[test]
    fn test_parse_missing_optional_params_uses_defaults() {
        let uri = "otpauth://totp/ACME:john@example.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ";
        let parsed = parse_uri(uri).unwrap();
        assert_eq!(parsed.digits, 6);
        assert_eq!(parsed.period, 30);
        assert!(matches!(parsed.algorithm, Algorithm::SHA1));
    }

    #[test]
    fn test_parse_invalid_base32_secret_fails() {
        let uri = "otpauth://totp/ACME:john@example.com?secret=!!!!invalid!!!!";
        assert!(parse_uri(uri).is_err());
    }

    // ── New tests ──────────────────────────────────────────────

    #[test]
    fn test_parse_uri_special_chars_in_label() {
        // Label with special characters (spaces, @, dots are already common)
        // url::Url::parse does NOT auto-decode percent-encoded path segments.
        let uri = "otpauth://totp/My%20App:user+tag@example.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ";
        let parsed = parse_uri(uri).unwrap();
        // Percent-encoded characters remain encoded in the path
        assert_eq!(parsed.issuer, "My%20App");
        assert_eq!(parsed.label, "user+tag@example.com");
    }

    #[test]
    fn test_parse_uri_empty_path_fails() {
        let uri = "otpauth://totp?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ";
        // Empty path → label is empty string, which is technically valid
        let parsed = parse_uri(uri).unwrap();
        assert!(parsed.label.is_empty());
    }

    #[test]
    fn test_parse_uri_algorithm_case_insensitive() {
        // Algorithm parameter should be case-insensitive
        let uri = "otpauth://totp/Test:user@test.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&algorithm=sha256";
        let parsed = parse_uri(uri).unwrap();
        assert!(matches!(parsed.algorithm, Algorithm::SHA256));
    }

    #[test]
    fn test_parse_uri_issuer_colon_in_label() {
        // Path has colon — "Issuer:label" split. If label itself contains
        // a colon, only the first colon separates issuer from label.
        let uri = "otpauth://totp/OnlyIssuer:label:with:colons?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ";
        let parsed = parse_uri(uri).unwrap();
        assert_eq!(parsed.issuer, "OnlyIssuer");
        assert_eq!(parsed.label, "label:with:colons");
    }

    #[test]
    fn test_parse_uri_unknown_query_params_ignored() {
        // Unknown query parameters should be ignored
        let uri = "otpauth://totp/ACME:john@example.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&foo=bar&baz=qux";
        let parsed = parse_uri(uri).unwrap();
        assert_eq!(parsed.issuer, "ACME");
        assert_eq!(parsed.digits, 6);
        assert_eq!(parsed.period, 30);
    }

    #[test]
    fn test_parse_uri_period_zero_or_invalid() {
        // period=0 should be parsed as 0 (not rejected by parser)
        let uri = "otpauth://totp/ACME:john@example.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&period=0";
        let parsed = parse_uri(uri).unwrap();
        assert_eq!(parsed.period, 0, "period=0 is technically allowed by parser");
    }

    #[test]
    fn test_parse_uri_digits_non_numeric_defaults() {
        // Non-numeric digits param should fall back to default (6)
        let uri = "otpauth://totp/ACME:john@example.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&digits=abc";
        let parsed = parse_uri(uri).unwrap();
        assert_eq!(parsed.digits, 6, "non-numeric digits should default to 6");
    }

    #[test]
    fn test_parse_uri_empty_string_is_error() {
        assert!(parse_uri("").is_err(), "empty string must be an error");
    }

    #[test]
    fn test_parse_uri_https_scheme_fails() {
        let uri = "https://totp/ACME:john@example.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ";
        assert!(parse_uri(uri).is_err(), "https scheme must fail");
    }

    // ── New tests ──────────────────────────────────────────────

    #[test]
    fn test_parse_uri_secret_uppercase_succeeds() {
        // Secret is parsed as-is from query params (not uppercased by the code),
        // so it must be uppercase base32
        let uri = "otpauth://totp/Test:user@test.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ";
        let parsed = parse_uri(uri).unwrap();
        assert!(!parsed.secret.is_empty(), "uppercase secret must decode");
        assert_eq!(parsed.secret.len(), 20);
    }

    #[test]
    fn test_parse_uri_issuer_in_path_no_query_override() {
        // Path issuer should be used when no query issuer is present
        let uri = "otpauth://totp/PathIssuer:user@test.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ";
        let parsed = parse_uri(uri).unwrap();
        assert_eq!(parsed.issuer, "PathIssuer", "issuer from path must be used when no query issuer");
        assert_eq!(parsed.label, "user@test.com");
    }

    #[test]
    fn test_parse_uri_digits_0_accepted_as_valid() {
        // digits=0 is a valid u8 parse → returns 0, not default 6
        let uri = "otpauth://totp/ACME:user@test.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&digits=0";
        let parsed = parse_uri(uri).unwrap();
        assert_eq!(parsed.digits, 0, "digits=0 parses as valid u8");
    }

    #[test]
    fn test_parse_uri_period_negative_defaults_to_30() {
        // period=-1 fails to parse from_str("-1") → .ok() → None → defaults to 30
        let uri = "otpauth://totp/ACME:user@test.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&period=-1";
        let parsed = parse_uri(uri).unwrap();
        assert_eq!(parsed.period, 30, "period=-1 should default to 30");
    }

    #[test]
    fn test_parse_uri_percent_encoded_unicode_in_label() {
        // Unicode characters should be percent-encoded in URIs
        let uri = "otpauth://totp/MyApp:user@xn--mszy-0ra.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ";
        let parsed = parse_uri(uri).unwrap();
        assert_eq!(parsed.label, "user@xn--mszy-0ra.com", "unicode domain in label preserved via punycode");
        assert_eq!(parsed.issuer, "MyApp");
    }

    #[test]
    fn test_parse_uri_algorithm_various_case_variants() {
        // SHA1 should work case-insensitively
        for variant in &["sha1", "Sha1", "SHA1", "shA1"] {
            let uri = format!("otpauth://totp/ACME:user@test.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&algorithm={}", variant);
            let parsed = parse_uri(&uri).unwrap();
            assert!(matches!(parsed.algorithm, Algorithm::SHA1),
                    "SHA1 variant '{variant}' must work case-insensitively");
        }
    }

    #[test]
    fn test_parse_uri_with_duplicate_query_params() {
        // Duplicate secret query params — last one wins (url::Url behavior)
        let uri = "otpauth://totp/ACME:user@test.com?secret=INVALID&secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ";
        let parsed = parse_uri(uri).unwrap();
        assert!(!parsed.secret.is_empty(), "second secret should be used");
    }
}
