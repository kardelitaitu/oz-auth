# Test Coverage Improvement Plan

> Target: `storage/auth_file.rs` (96.1% → 100%), `commands/totp.rs` (93.0% → 100%), `diagnostics.rs` (75.0% → 100%)

---

## Current State

| Module | Coverage | Uncovered Lines | Gap |
|--------|----------|-----------------|-----|
| `storage/auth_file.rs` | 96.1% (73/76) | 3 lines | Error paths in `try_load()` / `save()` |
| `commands/totp.rs` | 93.0% (53/57) | 4 lines | `#[tauri::command]` wrappers |
| `diagnostics.rs` | 75.0% (27/36) | 9 lines | Panic hook, log trimming, mutex fallback |

---

## 1. `storage/auth_file.rs` — 3 uncovered lines

### Analysis

The 3 uncovered lines are error-handling paths that require filesystem failure simulation:

| Line(s) | Function | What's Uncovered |
|---------|----------|------------------|
| 73 | `try_load()` | `map_err` on `std::fs::read_to_string` failure (file read error) |
| 75 | `try_load()` | `map_err` on `serde_json::from_str` failure (parse error) — **BUT** this IS hit by `lib.rs::test_load_config_corrupted_auth_file_returns_error`, so coverage may already count it |
| 78 | `try_load()` | `save(&data)?` inside the `reconcile_invariants` → `true` branch |
| 86 | `save()` | `map_err` on `serde_json::to_string_pretty` failure (serialization error) |
| 88 | `save()` | `map_err` on `std::fs::write` failure (file write error) |

### Plan

#### Test 1: `test_try_load_reconcile_saves_to_disk`
Trigger the reconcile → save path inside `try_load()`:

```rust
#[test]
fn test_try_load_reconcile_saves_to_disk() {
    let _lock = FS_TEST_MUTEX.lock().unwrap();
    cleanup_auth_file();
    // Manually write an inconsistent .auth file:
    // encrypted=true but password_protected=false
    let mut data = fresh();
    data.accounts.encrypted = true;
    data.config.password_protected = false;
    let json = serde_json::to_string_pretty(&data).unwrap();
    std::fs::write(auth_path(), &json).unwrap();

    // try_load reads it, reconcile_invariants fixes it, then saves
    let loaded = try_load().unwrap();
    assert!(loaded.config.password_protected, "reconcile should have set password_protected=true");

    // Verify it was persisted (re-saved)
    let raw = std::fs::read_to_string(auth_path()).unwrap();
    let saved: AuthData = serde_json::from_str(&raw).unwrap();
    assert!(saved.config.password_protected);
    cleanup_auth_file();
}
```

**Covers:** Lines 77-79 (reconcile + save branch in `try_load`)

#### Test 2: Error path coverage strategy
The `map_err` closures on lines 73, 86, 88 are error formatting. These are hit by error conditions that are hard to force in unit tests (filesystem permissions, disk full). Options:

1. **Accept as untestable** — These are simple `format!` strings on error paths. The error behavior is already verified by tests that check `is_err()` on try_load/save with corrupted files.
2. **If targeting 100% strictly**, refactor `try_load` and `save` to accept a `std::io::Result` injection point (e.g., a trait), but this adds complexity for minimal benefit.

**Recommendation:** Accept these 2-3 error-formatting lines as inherently untestable without filesystem mocking. Focus effort on the reconcile path (Test 1 above).

---

## 2. `commands/totp.rs` — 4 uncovered lines

### Analysis

The 4 uncovered lines are the `#[tauri::command]` wrapper functions:

| Lines | Function | Why Untestable |
|-------|----------|----------------|
| 76-81 | `generate_code()` | Takes `State<'_, AppState>` — requires Tauri runtime |
| 112-117 | `generate_all_codes()` | Takes `State<'_, AppState>` — requires Tauri runtime |

The actual logic is in `generate_code_impl()` and `generate_all_codes_impl()` which are thoroughly tested (30+ tests).

### Plan

**Option A: Accept as untestable (Recommended)**
The wrappers are single-line delegations:
```rust
pub fn generate_code(account_id: String, state: State<'_, AppState>) -> Result<(String, u32), String> {
    generate_code_impl(&account_id, &state)  // <-- 1 line
}
```
These are verified at compile time (correct signature) and by integration tests. The 4 uncovered lines are:
- `generate_code` signature + body (lines 76-81 = ~4 lines with attrs)
- `generate_all_codes` signature + body (lines 112-117 = ~4 lines with attrs)

Wait, 4 lines uncovered total means only parts of these wrappers. Likely the `#[tauri::command]` attribute lines and the function bodies.

**Option B: Manual integration test**
Create a test in `tests/integration.rs` that builds the Tauri app and invokes commands through the IPC layer. This is heavy infrastructure for 4 lines.

**Recommendation:** Accept these as Tauri-runtime-dependent. The `_impl` functions cover 100% of the logic.

---

## 3. `diagnostics.rs` — 9 uncovered lines (highest ROI)

### Analysis

| Lines | Function | What's Uncovered |
|-------|----------|------------------|
| 12-26 | `init()` | The panic hook closure body (set_hook, Backtrace::capture, crash report write) |
| 44-48 | `flush_to_log_str()` | The trimming branch: `buf.len() > 10_000` → `rfind('\n')` → slice logic |
| 52-54 | `flush_to_log_str()` | The `else` branch when mutex is poisoned |

### Plan

#### Test 3: `test_log_trimming_preserves_recent_entries` (covers lines 44-48)
The existing `test_log_trimming_at_limit` generates 500 events but doesn't verify the trimming output format. Enhance it:

```rust
#[test]
fn test_log_trimming_preserves_recent_entries() {
    let _ = flush_to_log_str();
    // Generate events that exceed 10KB
    for i in 0..500 {
        event("bulk", &format!("event number {i:04} with padding xxxxxxxxxx"));
    }
    let log = flush_to_log_str();
    assert!(log.len() <= 10_000, "log must be <= 10KB after trimming: {}", log.len());
    assert!(log.starts_with("[log trimmed]\n"), "must have trimmed prefix");
    // The most recent events should still be present
    assert!(log.contains("event number 0499") || log.contains("event number 049"),
        "recent events should survive trimming");
}
```

**Covers:** Lines 44-48 (trimming branch in `flush_to_log_str`)

#### Test 4: `test_init_panic_hook_writes_crash_file` (covers lines 12-26)
The panic hook is installed by `init()` but never triggered in tests. To cover it:

```rust
#[test]
fn test_init_panic_hook_writes_crash_file() {
    // This test verifies init() installs a hook that writes a crash file.
    // We can't safely trigger a panic and catch it in the same process,
    // but we CAN verify the hook is installed by checking that the panic hook
    // chain has been modified.
    
    // Alternative: Use std::panic::catch_unwind to trigger a test panic
    let crash_path = crate::paths::exe_dir().join(format!("{}.crash", crate::paths::exe_stem()));
    let _ = std::fs::remove_file(&crash_path);
    
    init(); // installs the hook
    
    // Trigger a panic inside catch_unwind — the hook should write the crash file
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        panic!("test crash for coverage");
    }));
    assert!(result.is_err(), "panic should have been caught");
    
    // Verify the crash file was written
    assert!(crash_path.exists(), "crash file should exist after panic");
    let report = std::fs::read_to_string(&crash_path).unwrap();
    assert!(report.contains("=== CRASH ==="), "report should have crash header");
    assert!(report.contains("test crash for coverage"), "report should contain panic message");
    
    let _ = std::fs::remove_file(&crash_path);
}
```

**Covers:** Lines 12-26 (panic hook setup + closure body including Backtrace::capture, format!, fs::write, eprintln, prev(info))

#### Test 5: Mutex poisoning fallback (lines 52-54)
The `else` branch in `flush_to_log_str()` is hit when `LOG_BUF.lock()` returns `Err` (poisoned mutex). This is extremely hard to trigger in tests because it requires another thread to panic while holding the lock.

**Recommendation:** Accept as untestable. The mutex poisoning path is a defensive fallback that returns `String::new()`. The cost of testing (spawning a thread, deliberately panicking, etc.) outweighs the value.

---

## Summary: Prioritized Action Items

### High Impact (do these)
| # | File | Test | Covers | Difficulty |
|---|------|------|--------|------------|
| 1 | `diagnostics.rs` | `test_init_panic_hook_writes_crash_file` | Lines 12-26 (9 lines) | Medium |
| 2 | `diagnostics.rs` | `test_log_trimming_preserves_recent_entries` (enhance existing) | Lines 44-48 (3 lines) | Easy |
| 3 | `auth_file.rs` | `test_try_load_reconcile_saves_to_disk` | Line 78 (1 line) | Easy |

### Low Impact (accept as untestable)
| File | Lines | Reason |
|------|-------|--------|
| `commands/totp.rs` | 76-81, 112-117 | `#[tauri::command]` wrappers need Tauri runtime |
| `diagnostics.rs` | 52-54 | Mutex poisoning fallback |
| `storage/auth_file.rs` | 73, 86, 88 | Filesystem I/O error formatting |

### Expected Result After Changes
| Module | Before | After | Notes |
|--------|--------|-------|-------|
| `storage/auth_file.rs` | 96.1% | ~97.4% (74/76) | +1 line from reconcile test |
| `commands/totp.rs` | 93.0% | 93.0% (53/57) | No change (Tauri wrappers untestable) |
| `diagnostics.rs` | 75.0% | ~97.2% (35/36) | +8 lines from panic hook + trimming |
| **Overall** | **56.0%** | ~**61%** | Significant improvement |

### Implementation Order
1. `diagnostics.rs` tests (highest ROI: 2 tests → +8 lines)
2. `auth_file.rs` reconcile test (1 test → +1 line)
3. Run `cargo test` to verify
4. Run `cargo tarpaulin` to confirm new coverage numbers
