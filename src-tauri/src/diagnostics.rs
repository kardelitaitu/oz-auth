//! Crash reporting and event logging — all local, no network.
//!
//! - Panics caught via `set_hook` → written to `{exe}.crash`
//! - Events stored in-memory, flushed to the `.auth` file on save.

use std::sync::Mutex;

static LOG_BUF: Mutex<Option<String>> = Mutex::new(None);

/// Initialize the crash reporter. Call once at startup.
pub fn init() {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let stem = crate::paths::exe_stem();
        let dir = crate::paths::exe_dir();
        let bt = std::backtrace::Backtrace::capture();
        let report = format!(
            "=== CRASH ===\nTime: {}\nPanic: {}\n\nBacktrace:\n{:?}\n",
            timestamp(),
            info,
            bt
        );
        let _ = std::fs::write(dir.join(format!("{stem}.crash")), &report);
        eprintln!("{}", report);
        prev(info);
    }));

    event("startup", "Application started");
}

/// Append a major event to the in-memory log buffer.
pub fn event(category: &str, message: &str) {
    let line = format!("[{}] {}: {}\n", timestamp(), category, message);
    if let Ok(mut guard) = LOG_BUF.lock() {
        let buf = guard.get_or_insert_with(String::new);
        buf.push_str(&line);
    }
}

/// Flush the in-memory log to a string for persisting (capped at ~10 KB).
pub fn flush_to_log_str() -> String {
    if let Ok(mut guard) = LOG_BUF.lock() {
        let buf = guard.take().unwrap_or_default();
        if buf.len() > 10_000 {
            if let Some(_pos) = buf.rfind('\n') {
                let trimmed = &buf[buf.len() - 9_000..];
                let first_newline = trimmed.find('\n').unwrap_or(0);
                return format!("[log trimmed]\n{}", &trimmed[first_newline + 1..]);
            }
        }
        buf
    } else {
        String::new()
    }
}

/// Restore previously persisted log entries back into the in-memory buffer.
pub fn restore_from_log_str(saved: &str) {
    if saved.is_empty() {
        return;
    }
    if let Ok(mut guard) = LOG_BUF.lock() {
        let buf = guard.get_or_insert_with(String::new);
        *buf = format!("{}\n{}", saved.trim(), buf);
    }
}

fn timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_writes_startup_event() {
        let _ = flush_to_log_str();
        init();
        let log = flush_to_log_str();
        assert!(log.contains("startup"));
        assert!(log.contains("Application started"));
    }

    #[test]
    fn test_event_appends() {
        let _ = flush_to_log_str();
        event("test", "hello world");
        let log = flush_to_log_str();
        assert!(log.contains("test: hello world"));
    }

    #[test]
    fn test_flush_clears_buffer() {
        let _ = flush_to_log_str();
        event("cat", "msg");
        let first = flush_to_log_str();
        assert!(!first.is_empty());
        let second = flush_to_log_str();
        assert!(second.is_empty());
    }

    #[test]
    fn test_restore_from_log_str() {
        let _ = flush_to_log_str();
        restore_from_log_str("[100] prev: old event");
        event("curr", "new event");
        let log = flush_to_log_str();
        assert!(log.contains("old event"));
        assert!(log.contains("new event"));
    }
}
