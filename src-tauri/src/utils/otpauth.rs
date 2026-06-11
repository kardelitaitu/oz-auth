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
}
