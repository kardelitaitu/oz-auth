//! Crash reporting and event logging — all local, no network.
//!
//! - Panics caught via `set_hook` → written to `{exe}.crash`
//! - Events stored in-memory, flushed to the `.auth` file on save.

use std::sync::Mutex;

static LOG_BUF: Mutex<Option<String>> = Mutex::new(None);

/// Mutex that serializes tests touching the shared log buffer.
#[cfg(test)]
pub static LOG_BUF_TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

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

/// Append a major event to the in-memory log buffer and audit trail.
pub fn event(category: &str, message: &str) {
    let line = format!("[{}] {}: {}\n", timestamp(), category, message);
    if let Ok(mut guard) = LOG_BUF.lock() {
        let buf = guard.get_or_insert_with(String::new);
        buf.push_str(&line);
    }
    // Also push to the signed audit trail
    crate::audit::push(category, message);
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

    fn with_log_lock(f: impl FnOnce()) {
        let _lock = LOG_BUF_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        // Recover LOG_BUF if poisoned by a panicking test — otherwise
        // every event() call silently drops its data and tests fail.
        // into_inner() gives us the guard but does NOT clear the poison bit;
        // clear_poison() (Rust 1.77+) resets it so future lock() calls succeed.
        let _guard = LOG_BUF.lock().unwrap_or_else(|e| e.into_inner());
        drop(_guard);
        LOG_BUF.clear_poison();
        let _ = flush_to_log_str(); // clear any leftover from previous tests
        f();
    }

    #[test]
    fn test_init_writes_startup_event() {
        with_log_lock(|| {
            init();
            let log = flush_to_log_str();
            assert!(log.contains("startup"));
            assert!(log.contains("Application started"));
        });
    }

    #[test]
    fn test_event_appends() {
        with_log_lock(|| {
            event("test", "hello world");
            let log = flush_to_log_str();
            assert!(log.contains("test: hello world"));
        });
    }

    #[test]
    fn test_flush_clears_buffer() {
        with_log_lock(|| {
            event("cat", "msg");
            let first = flush_to_log_str();
            assert!(!first.is_empty());
            let second = flush_to_log_str();
            assert!(second.is_empty());
        });
    }

    #[test]
    fn test_restore_from_log_str() {
        with_log_lock(|| {
            restore_from_log_str("[100] prev: old event");
            event("curr", "new event");
            let log = flush_to_log_str();
            assert!(log.contains("old event"));
            assert!(log.contains("new event"));
        });
    }

    // ── New tests ──────────────────────────────────────────────

    #[test]
    fn test_flush_to_log_str_empty_when_no_events() {
        with_log_lock(|| {
            let log = flush_to_log_str();
            assert!(log.is_empty(), "no events → empty log");
        });
    }

    #[test]
    fn test_flush_after_no_events_returns_empty() {
        with_log_lock(|| {
            let _ = flush_to_log_str();
            let log = flush_to_log_str();
            assert!(log.is_empty());
        });
    }

    #[test]
    fn test_restore_empty_string_noop() {
        with_log_lock(|| {
            restore_from_log_str("");
            event("test", "event");
            let log = flush_to_log_str();
            assert!(!log.contains("restored"));
            assert!(log.contains("event"));
        });
    }

    #[test]
    fn test_log_trimming_at_limit() {
        with_log_lock(|| {
            // Generate more than 10k bytes of events
            for i in 0..500 {
                event("bulk", &format!("event number {i}"));
            }
            let log = flush_to_log_str();
            // Should be trimmed to ~9k bytes with "[log trimmed]" prefix
            if log.len() > 10_000 {
                panic!("log exceeds 10k limit: {} bytes", log.len());
            }
        });
    }

    #[test]
    fn test_multiple_events_preserve_order() {
        with_log_lock(|| {
            event("first", "event A");
            event("second", "event B");
            event("third", "event C");
            let log = flush_to_log_str();
            let lines: Vec<&str> = log.lines().collect();
            assert!(
                lines.len() >= 3,
                "should have at least 3 lines, got {}",
                lines.len()
            );
            assert!(lines[0].contains("first"), "first line: {:?}", lines[0]);
            assert!(lines[1].contains("second"), "second line: {:?}", lines[1]);
            assert!(lines[2].contains("third"), "third line: {:?}", lines[2]);
        });
    }

    // ── New tests ──────────────────────────────────────────────

    #[test]
    fn test_multiple_flushes_return_empty() {
        with_log_lock(|| {
            let _ = flush_to_log_str();
            let _ = flush_to_log_str();
            let log = flush_to_log_str();
            assert!(
                log.is_empty(),
                "multiple flushes should all return empty after first"
            );
        });
    }

    #[test]
    fn test_event_with_empty_category() {
        with_log_lock(|| {
            event("", "some message");
            let log = flush_to_log_str();
            assert!(!log.is_empty(), "empty category should still log");
            assert!(
                log.contains(": some message"),
                "should contain message: {log}"
            );
        });
    }

    #[test]
    fn test_event_with_empty_message() {
        with_log_lock(|| {
            event("cat", "");
            let log = flush_to_log_str();
            assert!(
                log.contains("cat:"),
                "should contain category even with empty message"
            );
        });
    }

    #[test]
    fn test_restore_from_log_str_with_newlines() {
        with_log_lock(|| {
            // Restore multi-line log
            let saved = "[100] first: line1\n[101] second: line2\n[102] third: line3";
            restore_from_log_str(saved);
            event("curr", "new");
            let log = flush_to_log_str();
            assert!(log.contains("line1"));
            assert!(log.contains("line2"));
            assert!(log.contains("line3"));
            assert!(log.contains("new"));
        });
    }

    #[test]
    fn test_init_panic_hook_writes_crash_file() {
        let crash_path =
            crate::paths::exe_dir().join(format!("{}.crash", crate::paths::exe_stem()));
        let _ = std::fs::remove_file(&crash_path);

        with_log_lock(|| {
            let prev_hook = std::panic::take_hook();
            init();

            let handle = std::thread::spawn(|| {
                panic!("test crash for coverage");
            });
            let _ = handle.join();

            // Recover LOG_BUF poisoned by the spawned thread's panic
            let _recovered = LOG_BUF.lock().unwrap_or_else(|e| e.into_inner());

            // Verify the crash file INSIDE the lock — other tests running
            // in parallel can also trigger our globally-installed hook and
            // overwrite the file if we check after releasing the lock.
            assert!(
                crash_path.exists(),
                "crash file should exist after panic: {}",
                crash_path.display()
            );
            let report = std::fs::read_to_string(&crash_path).unwrap();
            assert!(
                report.contains("=== CRASH ==="),
                "report header missing, got: {:?}",
                &report[..report.len().min(200)]
            );

            // Restore hook BEFORE releasing LOG_BUF_TEST_MUTEX so other tests
            // don't see our hook firing during their panics.
            std::panic::set_hook(prev_hook);
        });

        let _ = std::fs::remove_file(&crash_path);
    }

    #[test]
    fn test_flush_with_no_newlines_in_buffer_falls_through() {
        with_log_lock(|| {
            // Write a >10KB buffer with NO newlines directly (bypassing event())
            // This exercises the fallthrough after rfind('\n') returns None
            {
                let mut guard = LOG_BUF.lock().unwrap_or_else(|e| e.into_inner());
                *guard = Some("A".repeat(12_000));
            }
            let log = flush_to_log_str();
            // Should fall through to `buf` (no trimming applied since no newline found)
            assert_eq!(log.len(), 12_000, "buffer should be returned as-is");
        });
    }

    /// Poison the mutex, test graceful degradation, then ALWAYS recover.
    /// Uses catch_unwind so recovery runs even if assertions fail.
    #[test]
    fn test_flush_poisoned_mutex_returns_empty() {
        let _ser_lock = LOG_BUF_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let _ = flush_to_log_str();

        let result = std::panic::catch_unwind(|| {
            // Poison LOG_BUF by panicking while holding its lock
            let _ = std::thread::spawn(|| {
                let _guard = LOG_BUF.lock().unwrap_or_else(|e| e.into_inner());
                panic!("deliberately poison LOG_BUF for coverage test");
            })
            .join();

            // Now LOG_BUF is poisoned — flush should hit the else branch
            let log = flush_to_log_str();
            assert!(
                log.is_empty(),
                "poisoned mutex should return empty: {log:?}"
            );
        });

        // ALWAYS recover the mutex and clear poison so subsequent tests aren't
        // affected. into_inner() gives us the guard but does NOT clear the
        // poison bit; clear_poison() (Rust 1.77+) resets it.
        let _recovered = LOG_BUF.lock().unwrap_or_else(|e| e.into_inner());
        drop(_recovered);
        LOG_BUF.clear_poison();

        if let Err(e) = result {
            std::panic::resume_unwind(e);
        }
    }

    #[test]
    fn test_log_trimming_output_format() {
        with_log_lock(|| {
            // Generate events exceeding 10KB to trigger trimming
            for i in 0..600 {
                event(
                    "bulk",
                    &format!("event number {i:04} padding xxxxxxxxxxxxxx"),
                );
            }
            let log = flush_to_log_str();
            assert!(
                log.len() <= 10_000,
                "log must be <= 10KB after trimming: {} bytes",
                log.len()
            );
            assert!(
                log.starts_with("[log trimmed]\n"),
                "must have [log trimmed] prefix, got: {}",
                &log[..log.len().min(40)]
            );
            // Most recent events should survive trimming
            assert!(
                log.contains("event number 0599") || log.contains("event number 059"),
                "recent events should survive trimming"
            );
        });
    }
}
