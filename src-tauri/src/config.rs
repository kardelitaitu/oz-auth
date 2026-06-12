use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    #[serde(default = "default_width")]
    pub width: u32,
    #[serde(default = "default_height")]
    pub height: u32,
    #[serde(default = "default_left")]
    pub left: i32,
    #[serde(default = "default_top")]
    pub top: i32,
    #[serde(default)]
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

fn default_width() -> u32 {
    320
}

fn default_height() -> u32 {
    480
}

fn default_left() -> i32 {
    100
}

fn default_top() -> i32 {
    100
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

    // ── New tests ──────────────────────────────────────────────

    #[test]
    fn test_config_lock_timeout_default_minimum() {
        let cfg = Config::default();
        assert_eq!(
            cfg.lock_timeout_minutes, 5,
            "default lock timeout should be 5 minutes"
        );
    }

    #[test]
    fn test_config_clipboard_clear_default() {
        let cfg = Config::default();
        assert_eq!(
            cfg.clipboard_clear_seconds, 30,
            "default clipboard clear should be 30 seconds"
        );
    }

    #[test]
    fn test_config_partial_update_preserves_other_fields() {
        let cfg = Config {
            width: 800,
            ..Config::default()
        };
        // Default height should be preserved (480)
        assert_eq!(cfg.height, 480, "partial update must preserve height");
    }

    #[test]
    fn test_config_theme_default_is_dark() {
        let cfg = Config::default();
        assert_eq!(cfg.theme, "dark");
    }

    #[test]
    fn test_config_window_size_custom_values() {
        let cfg = Config {
            width: 500,
            height: 700,
            ..Config::default()
        };
        assert_eq!(cfg.width, 500);
        assert_eq!(cfg.height, 700);
    }

    // ── New tests ──────────────────────────────────────────────

    #[test]
    fn test_config_serde_unknown_fields_ignored() {
        // Serde ignores unknown fields by default (no #[serde(deny_unknown_fields)])
        let json = r#"{"width":400,"height":600,"left":50,"top":80,"always_on_top":false,"password_protected":false,"password_salt":"","unknown_field":"should be ignored"}"#;
        let cfg: Config = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.width, 400);
        // unknown_field is silently ignored
    }

    #[test]
    fn test_config_left_top_can_be_negative() {
        // Window position can be negative on multi-monitor setups
        let cfg = Config {
            left: -1920,
            top: -100,
            ..Config::default()
        };
        assert_eq!(cfg.left, -1920);
        assert_eq!(cfg.top, -100);
        let json = serde_json::to_string(&cfg).unwrap();
        let restored: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.left, -1920);
        assert_eq!(restored.top, -100);
    }

    #[test]
    fn test_config_serde_defaults_for_missing_window_fields() {
        // Config JSON without width/height/left/top/always_on_top should use defaults
        let json = r#"{"password_protected":false}"#;
        let cfg: Config = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.width, 320, "missing width must default to 320");
        assert_eq!(cfg.height, 480, "missing height must default to 480");
        assert_eq!(cfg.left, 100, "missing left must default to 100");
        assert_eq!(cfg.top, 100, "missing top must default to 100");
        assert!(!cfg.always_on_top, "missing always_on_top must default to false");
        assert_eq!(cfg.theme, "dark");
    }

    #[test]
    fn test_config_maximum_u32_values() {
        // All u32 fields accept maximum u32 value
        let cfg = Config {
            width: u32::MAX,
            height: u32::MAX,
            lock_timeout_minutes: u32::MAX,
            clipboard_clear_seconds: u32::MAX,
            ..Config::default()
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let restored: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.width, u32::MAX);
        assert_eq!(restored.height, u32::MAX);
        assert_eq!(restored.lock_timeout_minutes, u32::MAX);
        assert_eq!(restored.clipboard_clear_seconds, u32::MAX);
        assert_eq!(restored.left, 100); // from struct default, not Default trait
        assert_eq!(restored.top, 100);
    }
}
