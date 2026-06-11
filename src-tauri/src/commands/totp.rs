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
