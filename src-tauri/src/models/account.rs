use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub id: String,     // UUID v4
    pub issuer: String, // "Google", "GitHub", etc.
    pub label: String,  // "user@example.com"
        #[serde(default)]
    pub algorithm: Algorithm,
    #[serde(default = "default_digits")]
    pub digits: u8,      // 6 or 8
    #[serde(default = "default_period")]
    pub period: u32,     // 30 (seconds)
    pub secret: Vec<u8>, // Raw secret key bytes
    #[serde(default)]
    pub sort_order: u32,
    #[serde(default = "default_created_at")]
    pub created_at: DateTime<Utc>,
    #[serde(default = "default_updated_at")]
    pub updated_at: DateTime<Utc>,
}/// Frontend-safe view — no secret field exposed over IPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountSummary {
    pub id: String,
    pub issuer: String,
    pub label: String,
        #[serde(default)]
    pub algorithm: Algorithm,
    #[serde(default = "default_digits")]
    pub digits: u8,
    #[serde(default = "default_period")]
    pub period: u32,
    #[serde(default)]
    pub sort_order: u32,
    #[serde(default = "default_created_at")]
    pub created_at: DateTime<Utc>,
    #[serde(default = "default_updated_at")]
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub enum Algorithm {
    #[default]
    SHA1,
    SHA256,
    SHA512,
}

fn default_digits() -> u8 {
    6
}

fn default_period() -> u32 {
    30
}

fn default_created_at() -> DateTime<Utc> {
    Utc::now()
}

fn default_updated_at() -> DateTime<Utc> {
    Utc::now()
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
            assert_eq!(format!("{:?}", summary.algorithm), format!("{:?}", algo));
        }
    }

    #[test]
    fn test_account_missing_algorithm_defaults_to_sha1() {
        // Old file without algorithm field should default to SHA1
        let json = r#"{"id":"no-algo","issuer":"Test","label":"t@t.com","digits":6,"period":30,"secret":[1,2,3],"sort_order":0,"created_at":"2024-01-01T00:00:00Z","updated_at":"2024-01-01T00:00:00Z"}"#;
        let account: Account = serde_json::from_str(json).unwrap();
        assert!(
            matches!(account.algorithm, Algorithm::SHA1),
            "missing algorithm must default to SHA1"
        );
        assert_eq!(account.id, "no-algo");
        assert_eq!(account.digits, 6);
    }

    #[test]
    fn test_account_summary_missing_algorithm_defaults_to_sha1() {
        let json = r#"{"id":"no-algo-summary","issuer":"Test","label":"t@t.com","digits":6,"period":30,"sort_order":0,"created_at":"2024-01-01T00:00:00Z","updated_at":"2024-01-01T00:00:00Z"}"#;
        let summary: AccountSummary = serde_json::from_str(json).unwrap();
        assert!(
            matches!(summary.algorithm, Algorithm::SHA1),
            "missing algorithm must default to SHA1"
        );
        assert_eq!(summary.id, "no-algo-summary");
    }

    #[test]
    fn test_account_missing_all_optionals_uses_defaults() {
        // Minimal Account JSON — only core identity fields and secret
        let json = r#"{"id":"minimal","issuer":"X","label":"x@x.com","secret":[1,2,3]}"#;
        let account: Account = serde_json::from_str(json).unwrap();
        assert!(matches!(account.algorithm, Algorithm::SHA1));
        assert_eq!(account.digits, 6);
        assert_eq!(account.period, 30);
        assert_eq!(account.sort_order, 0);
        // created_at and updated_at are set to Utc::now() — just verify they parse
        assert!(account.created_at.timestamp() > 0, "created_at should have a valid timestamp");
        assert!(account.updated_at.timestamp() > 0, "updated_at should have a valid timestamp");
    }

    #[test]
    fn test_account_summary_missing_all_optionals_uses_defaults() {
        let json = r#"{"id":"minimal-summary","issuer":"Y","label":"y@y.com"}"#;
        let summary: AccountSummary = serde_json::from_str(json).unwrap();
        assert!(matches!(summary.algorithm, Algorithm::SHA1));
        assert_eq!(summary.digits, 6);
        assert_eq!(summary.period, 30);
        assert_eq!(summary.sort_order, 0);
        assert!(summary.created_at.timestamp() > 0, "created_at should have a valid timestamp");
        assert!(summary.updated_at.timestamp() > 0, "updated_at should have a valid timestamp");
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
