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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_summary_excludes_secret() {
        let account = Account {
            id: "abc123".into(),
            issuer: "Google".into(),
            label: "user@gmail.com".into(),
            algorithm: Algorithm::SHA1,
            digits: 6,
            period: 30,
            secret: vec![1, 2, 3, 4, 5],
            sort_order: 0,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let summary = AccountSummary::from(&account);
        assert_eq!(summary.id, "abc123");
        assert_eq!(summary.issuer, "Google");
        assert_eq!(summary.label, "user@gmail.com");
        assert_eq!(summary.digits, 6);
        assert_eq!(summary.period, 30);
        assert_eq!(summary.sort_order, 0);
        // Secret must NOT be present in the summary struct
        // (compile-time guarantee — AccountSummary has no secret field)
    }

    #[test]
    fn test_summary_preserves_algorithm() {
        for algo in [Algorithm::SHA1, Algorithm::SHA256, Algorithm::SHA512] {
            let account = Account {
                id: "test".into(),
                issuer: "X".into(),
                label: "x".into(),
                algorithm: algo.clone(),
                digits: 6,
                period: 30,
                secret: vec![],
                sort_order: 0,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            };
            let summary = AccountSummary::from(&account);
            assert_eq!(
                format!("{:?}", summary.algorithm),
                format!("{:?}", algo)
            );
        }
    }

    #[test]
    fn test_summary_roundtrip_json() {
        let account = Account {
            id: "json-test".into(),
            issuer: "GitHub".into(),
            label: "dev@github.com".into(),
            algorithm: Algorithm::SHA256,
            digits: 8,
            period: 60,
            secret: vec![10, 20, 30],
            sort_order: 3,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let summary = AccountSummary::from(&account);
        let json = serde_json::to_string(&summary).unwrap();
        let restored: AccountSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.id, "json-test");
        assert_eq!(restored.issuer, "GitHub");
        assert_eq!(restored.digits, 8);
        assert_eq!(restored.period, 60);
        assert_eq!(restored.sort_order, 3);
    }
}
