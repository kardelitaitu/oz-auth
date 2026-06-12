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

    // ── New tests ──────────────────────────────────────────────

    #[test]
    fn test_flush_to_log_str_empty_when_no_events() {
        let _ = flush_to_log_str();
        let log = flush_to_log_str();
        assert!(log.is_empty(), "no events → empty log");
    }

    #[test]
    fn test_flush_after_no_events_returns_empty() {
        let _ = flush_to_log_str();
        // Flush twice should give empty
        let _ = flush_to_log_str();
        let log = flush_to_log_str();
        assert!(log.is_empty());
    }

    #[test]
    fn test_restore_empty_string_noop() {
        let _ = flush_to_log_str();
        restore_from_log_str("");
        event("test", "event");
        let log = flush_to_log_str();
        assert!(!log.contains("restored"));
        assert!(log.contains("event"));
    }

    #[test]
    fn test_log_trimming_at_limit() {
        let _ = flush_to_log_str();
        // Generate more than 10k bytes of events
        for i in 0..500 {
            event("bulk", &format!("event number {i}"));
        }
        let log = flush_to_log_str();
        // Should be trimmed to ~9k bytes with "[log trimmed]" prefix
        if log.len() > 10_000 {
            panic!("log exceeds 10k limit: {} bytes", log.len());
        }
    }

    #[test]
    fn test_multiple_events_preserve_order() {
        // Flush any events left over from previous tests (e.g. crash hooks)
        let _ = flush_to_log_str();
        // Flush again to ensure buffer is empty
        let _ = flush_to_log_str();
        event("first", "event A");
        event("second", "event B");
        event("third", "event C");
        let log = flush_to_log_str();
        let lines: Vec<&str> = log.lines().collect();
        assert!(lines.len() >= 3, "should have at least 3 lines, got {}", lines.len());
        assert!(lines[0].contains("first"), "first line: {:?}", lines[0]);
        assert!(lines[1].contains("second"), "second line: {:?}", lines[1]);
        assert!(lines[2].contains("third"), "third line: {:?}", lines[2]);
    }

    // ── New tests ──────────────────────────────────────────────

    #[test]
    fn test_multiple_flushes_return_empty() {
        let _ = flush_to_log_str();
        let _ = flush_to_log_str();
        let _ = flush_to_log_str();
        let log = flush_to_log_str();
        assert!(log.is_empty(), "multiple flushes should all return empty after first");
    }

    #[test]
    fn test_event_with_empty_category() {
        let _ = flush_to_log_str();
        // Empty category should still produce a line
        event("", "some message");
        let log = flush_to_log_str();
        assert!(!log.is_empty(), "empty category should still log");
        assert!(log.contains(": some message"), "should contain message: {log}");
    }

    #[test]
    fn test_event_with_empty_message() {
        let _ = flush_to_log_str();
        event("cat", "");
        let log = flush_to_log_str();
        assert!(log.contains("cat:"), "should contain category even with empty message");
    }

    #[test]
    fn test_restore_from_log_str_with_newlines() {
        let _ = flush_to_log_str();
        // Restore multi-line log
        let saved = "[100] first: line1\n[101] second: line2\n[102] third: line3";
        restore_from_log_str(saved);
        event("curr", "new");
        let log = flush_to_log_str();
        assert!(log.contains("line1"));
        assert!(log.contains("line2"));
        assert!(log.contains("line3"));
        assert!(log.contains("new"));
    }
}
