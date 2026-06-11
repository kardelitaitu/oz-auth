use crate::models::account::Account;
use crate::storage::{load_accounts, try_load};
use crate::AppState;
use tauri::State;

fn make_totp(account: &Account) -> Result<totp_rs::TOTP, String> {
    use crate::models::account::Algorithm;
    let algo = match account.algorithm {
        Algorithm::SHA1 => totp_rs::Algorithm::SHA1,
        Algorithm::SHA256 => totp_rs::Algorithm::SHA256,
        Algorithm::SHA512 => totp_rs::Algorithm::SHA512,
    };
    totp_rs::TOTP::new(
        algo,
        account.digits as usize,
        1,
        account.period as u64,
        account.secret.clone(),
        Some(account.issuer.clone()),
        account.label.clone(),
    )
    .map_err(|e| format!("totp error: {e}"))
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Generate a TOTP code for a single account.
#[tauri::command]
pub fn generate_code(
    account_id: String,
    state: State<'_, AppState>,
) -> Result<(String, u32), String> {
    let data = try_load()?;
    let key = state.get_key()?;
    let accounts = load_accounts(&data, key)?;

    let account = accounts
        .iter()
        .find(|a| a.id == account_id)
        .ok_or_else(|| format!("account not found: {account_id}"))?;

    let totp = make_totp(account)?;
    let now = current_timestamp();
    let code = totp.generate(now);
    let remaining = account.period - (now % account.period as u64) as u32;

    Ok((code, remaining))
}

/// Generate TOTP codes for all accounts at once.
#[tauri::command]
pub fn generate_all_codes(
    state: State<'_, AppState>,
) -> Result<Vec<(String, String, u32)>, String> {
    let data = try_load()?;
    let key = state.get_key()?;
    let accounts = load_accounts(&data, key)?;
    let now = current_timestamp();

    let mut results = Vec::new();
    for account in &accounts {
        let totp = make_totp(account)?;
        let code = totp.generate(now);
        let remaining = account.period - (now % account.period as u64) as u32;
        results.push((account.id.clone(), code, remaining));
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::account::{Account, Algorithm};
    use chrono::Utc;

    fn test_account(secret: &[u8], algo: Algorithm, digits: u8) -> Account {
        Account {
            id: "test-1".into(),
            issuer: "Test".into(),
            label: "test@test.com".into(),
            algorithm: algo,
            digits,
            period: 30,
            secret: secret.to_vec(),
            sort_order: 0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    /// RFC 6238 test vector — SHA-1
    /// Secret: "12345678901234567890" (base32)
    /// Expected codes at specific timestamps
    #[test]
    fn test_rfc6238_sha1_vectors() {
        let secret = b"12345678901234567890";
        let account = test_account(secret, Algorithm::SHA1, 8);
        let totp = make_totp(&account).unwrap();

        let vectors: &[(u64, &str)] = &[
            (59, "94287082"),
            (1111111109, "07081804"),
            (1111111111, "14050471"),
            (1234567890, "89005924"),
            (2000000000, "69279037"),
            (20000000000, "65353130"),
        ];

        for (time, expected) in vectors {
            let code = totp.generate(*time);
            assert_eq!(&code, expected, "SHA-1 code mismatch at time {time}");
        }
    }

    /// RFC 6238 test vector — SHA-256
    #[test]
    fn test_rfc6238_sha256_vectors() {
        let secret = b"12345678901234567890123456789012";
        let account = test_account(secret, Algorithm::SHA256, 8);
        let totp = make_totp(&account).unwrap();

        let vectors: &[(u64, &str)] = &[
            (59, "46119246"),
            (1111111109, "68084774"),
            (1111111111, "67062674"),
            (1234567890, "91819424"),
            (2000000000, "90698825"),
            (20000000000, "77737706"),
        ];

        for (time, expected) in vectors {
            let code = totp.generate(*time);
            assert_eq!(&code, expected, "SHA-256 code mismatch at time {time}");
        }
    }

    /// RFC 6238 test vector — SHA-512
    #[test]
    fn test_rfc6238_sha512_vectors() {
        let secret = b"1234567890123456789012345678901234567890123456789012345678901234";
        let account = test_account(secret, Algorithm::SHA512, 8);
        let totp = make_totp(&account).unwrap();

        let vectors: &[(u64, &str)] = &[
            (59, "90693936"),
            (1111111109, "25091201"),
            (1111111111, "99943326"),
            (1234567890, "93441116"),
            (2000000000, "38618901"),
            (20000000000, "47863826"),
        ];

        for (time, expected) in vectors {
            let code = totp.generate(*time);
            assert_eq!(&code, expected, "SHA-512 code mismatch at time {time}");
        }
    }

    /// 6-digit codes (SHA-1)
    #[test]
    fn test_6_digit_sha1() {
        let secret = b"12345678901234567890";
        let account = test_account(secret, Algorithm::SHA1, 6);
        let totp = make_totp(&account).unwrap();

        let vectors: &[(u64, &str)] = &[
            (59, "287082"),
            (1111111111, "050471"),
            (2000000000, "279037"),
        ];

        for (time, expected) in vectors {
            let code = totp.generate(*time);
            assert_eq!(&code, expected, "6-digit SHA-1 code mismatch at time {time}");
        }
    }
}
