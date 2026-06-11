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
}

fn default_theme() -> String {
    "dark".to_string()
}

fn default_lock_timeout() -> u32 {
    5
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
        };
        let json = serde_json::to_string_pretty(&cfg).unwrap();
        let restored: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.width, 400);
        assert_eq!(restored.theme, "light");
        assert!(restored.password_protected);
    }
}
