use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub width: u32,
    pub height: u32,
    pub left: i32,
    pub top: i32,
    pub always_on_top: bool,
    #[serde(default = "default_theme")]
    pub theme: String,
    #[serde(default)]
    pub password_protected: bool,
    #[serde(default)]
    pub password_salt: String,
    #[serde(default = "default_lock_timeout")]
    pub lock_timeout_minutes: u32,
    #[serde(default = "default_clipboard_clear_seconds")]
    pub clipboard_clear_seconds: u32,
}

fn default_theme() -> String {
    "dark".to_string()
}

fn default_lock_timeout() -> u32 {
    5
}

fn default_clipboard_clear_seconds() -> u32 {
    30
}

impl Default for Config {
    fn default() -> Self {
        Self {
            width: 320,
            height: 480,
            left: 100,
            top: 100,
            always_on_top: false,
            theme: default_theme(),
            password_protected: false,
            password_salt: String::new(),
            lock_timeout_minutes: default_lock_timeout(),
            clipboard_clear_seconds: default_clipboard_clear_seconds(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_defaults() {
        let cfg = Config::default();
        assert_eq!(cfg.width, 320);
        assert_eq!(cfg.height, 480);
        assert!(!cfg.always_on_top);
        assert!(!cfg.password_protected);
        assert_eq!(cfg.theme, "dark");
        assert_eq!(cfg.lock_timeout_minutes, 5);
        assert_eq!(cfg.clipboard_clear_seconds, 30);
        assert!(cfg.password_salt.is_empty());
    }

    #[test]
    fn test_json_roundtrip() {
        let cfg = Config {
            width: 400,
            height: 600,
            left: 50,
            top: 80,
            always_on_top: true,
            theme: "light".to_string(),
            password_protected: true,
            password_salt: "aabbccdd".to_string(),
            lock_timeout_minutes: 10,
            clipboard_clear_seconds: 15,
        };
        let json = serde_json::to_string_pretty(&cfg).unwrap();
        let restored: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.width, 400);
        assert_eq!(restored.theme, "light");
        assert!(restored.password_protected);
        assert_eq!(restored.lock_timeout_minutes, 10);
        assert_eq!(restored.clipboard_clear_seconds, 15);
        assert_eq!(restored.password_salt, "aabbccdd");
    }

    #[test]
    fn test_serde_defaults_for_missing_fields() {
        // Simulate an old config file without newer fields
        let json = r#"{"width":400,"height":600,"left":50,"top":80,"always_on_top":false,"password_protected":false,"password_salt":""}"#;
        let cfg: Config = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.theme, "dark");
        assert_eq!(cfg.lock_timeout_minutes, 5);
        assert_eq!(cfg.clipboard_clear_seconds, 30);
    }

    #[test]
    fn test_clipboard_clear_seconds_range() {
        // Config doesn't enforce range in Rust — that's a frontend concern.
        // But we test that any u32 value round-trips.
        let cfg = Config {
            clipboard_clear_seconds: 300,
            ..Config::default()
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let restored: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.clipboard_clear_seconds, 300);
    }

    #[test]
    fn test_always_on_top_roundtrip() {
        let mut cfg = Config::default();
        assert!(!cfg.always_on_top);
        cfg.always_on_top = true;
        let json = serde_json::to_string(&cfg).unwrap();
        let restored: Config = serde_json::from_str(&json).unwrap();
        assert!(restored.always_on_top);
    }
}
