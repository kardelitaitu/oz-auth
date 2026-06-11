use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub id: String,     // UUID v4
    pub issuer: String, // "Google", "GitHub", etc.
    pub label: String,  // "user@example.com"
    pub algorithm: Algorithm,
    pub digits: u8,      // 6 or 8
    pub period: u32,     // 30 (seconds)
    pub secret: Vec<u8>, // Raw secret key bytes
    pub sort_order: u32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Frontend-safe view — no secret field exposed over IPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountSummary {
    pub id: String,
    pub issuer: String,
    pub label: String,
    pub algorithm: Algorithm,
    pub digits: u8,
    pub period: u32,
    pub sort_order: u32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Algorithm {
    SHA1,
    SHA256,
    SHA512,
}

impl From<&Account> for AccountSummary {
    fn from(a: &Account) -> Self {
        Self {
            id: a.id.clone(),
            issuer: a.issuer.clone(),
            label: a.label.clone(),
            algorithm: a.algorithm.clone(),
            digits: a.digits,
            period: a.period,
            sort_order: a.sort_order,
            created_at: a.created_at,
            updated_at: a.updated_at,
        }
    }
}
