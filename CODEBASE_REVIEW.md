# CODEBASE_REVIEW.md

Auditor: OpenCode - Deepseek v4 Flash

## Summary

This document summarizes the security review findings, fixes, and upcoming review areas for the Tauri Authenticator project (oz-auth). The review process has identified and addressed critical security issues while planning for future improvements.

## Areas to Review

### 1. Crypto + Storage (`crypto.rs`, `storage/auth_file.rs`, `paths.rs`)
**Why this first:** The security foundation — any bug here breaks everything

- `crypto.rs`: Key derivation, encryption, Argon2id
- `storage/auth_file.rs`: `.auth` file I/O, atomic writes, audit trail
- `paths.rs`: Runtime path resolution, .exe-relative paths

### 2. Data Models + Config (`models/account.rs`, `config.rs`, `audit.rs`)
**Why second:** Shapes all serialization and persistence

- `models/account.rs`: Account structure, secret handling
- `config.rs`: App configuration, window state
- `audit.rs`: Signed audit trail, integrity verification

### 3. Commands (auth) (`commands/auth.rs`)
**Why third:** PIN lifecycle, lock/unlock — the auth barrier

- `commands/auth.rs`: PIN operations, key management, authentication

### 4. Commands (accounts + totp) (`commands/accounts.rs`, `accounts/crud.rs`, `accounts/qr.rs`, `commands/totp.rs`)
**Why fourth:** Core app logic — CRUD, TOTP generation

- `commands/accounts.rs`: Account management
- `accounts/crud.rs`: Account CRUD operations
- `accounts/qr.rs`: QR code generation
- `commands/totp.rs`: TOTP code generation

### 5. App bootstrap (`main.rs`, `lib.rs`, `tray.rs`, `diagnostics.rs`)
**Why fifth:** Entry points, state wiring, tray, crash handling

- `main.rs`: Entry point, process mitigation
- `lib.rs`: App state management
- `tray.rs`: System tray functionality
- `diagnostics.rs`: Crash logging, event log

### 6. Frontend (`main.js`, `js/*.js`)
**Why sixth:** All UI logic and IPC calls

- `main.js`: Entry point, Tauri event listeners
- `js/*.js`: Individual modules (totp.js, accounts.js, clipboard.js, dragdrop.js, lock.js, settings.js)

### 7. Configuration + CI (`tauri.conf.json`, `Cargo.toml`, `vite.config.js`, `capabilities/`)
**Why seventh:** Build, permissions, deployment

- `tauri.conf.json`: Tauri configuration
- `Cargo.toml`: Rust dependencies and build configuration
- `vite.config.js`: Vite configuration
- `capabilities/`: Tauri capability definitions
- CI workflows: Build and deployment pipelines

## Current Review Status

### Fixed Issues (v0.1.1 - v0.1.5)

The following **7 critical/high/medium/low severity bugs** have been identified and fixed:

| Severity | Fix | Description |
|----------|-----|-------------|
| **Critical** | PIN change key zeroization order | `change_pin_impl` zeroed the new key before storing it, breaking the app after PIN change. Fixed by reordering: store key first, then zeroize old key. |
| **High** | TOTP period=0 division-by-zero | `make_totp()` panics when `period=0`. Now validated and rejected before code generation. |
| **High** | Silent data loss on lock | `set_lock_impl` used `unwrap_or_default()` on malformed JSON, wiping accounts during PIN setup. Now returns an explicit error. |
| **Medium** | Clipboard auto-clear fires immediately | `setTimeout(..., 0)` wiped the code instantly when timeout was 0. Now only clears when timeout > 0. |
| **Medium** | Settings save race condition | Shared debounce timer across inputs caused rapid changes to cancel earlier saves. Now uses per-field timers. |
| **Medium** | Account IDs not HTML-escaped | Raw account IDs injected into HTML `data-id` attributes. Now escaped via `escapeHtml()`. |
| **Low** | parse_uri accepted hotp URIs | `otpauth://hotp/...` URIs were silently accepted. Now only `totp` type is accepted. |

### Planned Improvements (Future Work)

The following **7 planned improvements** are documented in SECURITY.md but not yet implemented:

| Priority | Item | Status | Description |
|----------|------|--------|-------------|
| **High** | IPC input length validation | Planned | Add max-length checks on all string IPC inputs (PIN, issuer, label, secret, URI, path) to prevent memory exhaustion DoS. |
| **High** | `derive_key()` return type | Planned | Change return type from `[u8; 32]` to `Zeroizing<[u8; 32]>` to prevent accidental key copies on the stack. |
| **Medium** | `Account.secret` Zeroizing | Planned | Change `secret: Vec<u8>` to `secret: Zeroizing<Vec<u8>>` for automatic zeroization. |
| **Medium** | `paths.rs` error handling | Planned | Convert 4 `.expect()` calls to `Result` returns to prevent panics on exe path resolution failure. |
| **Medium** | PIN strength guidance | Planned | Add optional PIN complexity check (min 6 digits, reject common PINs) with user override. |
| **Low** | `Config.password_salt` Zeroizing | Planned | Wrap salt in `Zeroizing<String>` for defense-in-depth (salt is not secret, but zeroizing reduces exposure window). |
| **Low** | File locking on .auth | Planned | Use advisory file locking during read/write to prevent TOCTOU race conditions between concurrent access. |

## What's Fixed (v0.1.5)

### Area #1: Crypto + Storage (Completed)

**Fixed Findings:**
- **C-1:** `derive_key()` return type → `Zeroizing<[u8; 32]>` (type-level enforcement for accidental key copies)
- **C-2:** Atomic writes with random temp filenames (`.auth.{random}.tmp`) to prevent race conditions
- **C-3:** `try_load()` flushes audit trail on upgrade/save (ensures audit trail integrity)
- **H-1:** CSP tightened (removed `http://localhost:1420` and `ws://localhost:1420` from production)
- **H-2:** Plaintext account fallback mode (accepted risk — user-controlled)
- **H-3:** PIN truncation at 128 bytes (low practical risk)
- **H-4:** Clipboard backend uses `invokeFn` to call `generate_code` backend
- **H-5:** Config save queue (`pendingConfig`/`updateConfig`) prevents race conditions
- **H-6:** Settings dialog uses `verify_pin` instead of `unlock` for read-only validation
- **H-7:** Argon2id params match library defaults (explicit params document intent without breaking PINs)
- **H-8:** Cache usage (`load_data()`/`invalidate_cache()`) prevents stale reads
- **H-9:** Clipboard timeout=0 handled (only clears when timeout > 0)
- **H-10:** Settings debounce race condition fixed (per-field timers)
- **M-1:** Version sync, M-15: Windows CI (low priority)

**Implementation Details:**
- `crypto.rs`: `derive_key()` returns `Zeroizing<[u8; 32]>`
- `auth.rs`: All `set_key(key)` calls updated to `set_key(*key)` with proper deref
- `auth_file.rs`: `atomic_write()` uses random hex temp names; `try_load()` calls `flush_and_save()` on upgrade
- `crud.rs`: Removed double-wrapping in `seed_encrypted_state`
- `clipboard.js`: Uses `invokeFn` param to call backend
- `settings.js`: Backup flow uses `verify_pin`
- `auth.rs`: Settings dialog uses `verify_pin` for read-only validation

### Area #2: Data Models + Config (In Progress)

**Status:** Under review

**Files:**
- `models/account.rs`
- `config.rs`
- `audit.rs`

**C-4:** Refactor settings HTML to DOM APIs (remaining high-priority item)

## Upcoming Area to Review

### Area #2: Data Models + Config

**Current Focus:** Review `models/account.rs`, `config.rs`, and `audit.rs`

**Key Areas:**
1. **Account Model (`models/account.rs`)**
   - Review `Account` model structure
   - Verify `AccountSummary` vs `Account` separation
   - Check secret field handling and zeroization

2. **Config Model (`config.rs`)**
   - Review configuration structure
   - Verify window state management
   - Check settings validation

3. **Audit Trail (`audit.rs`)**
   - Review audit trail implementation
   - Verify integrity checks
   - Check event logging

**Priority:** High

**Dependencies:**
- Must complete Area #1 fixes before starting Area #2
- All tests must pass before proceeding

## Test Results

### Current Status (v0.1.5)
- **480 Rust tests** + **104 Vitest** = **584 total tests**
- **All tests passing**
- **Clippy clean** (no warnings)
- **Build clean** (cargo check)

### Test Coverage
- Rust: 480 unit/integration tests
- JavaScript: 104 Vitest tests
- Total: 584 tests

### CI Status
- All CI workflows passing
- Security workflow includes npm audit
- Rust cache enabled for faster builds

## Code Quality Metrics

### Security Hardening
- Atomic writes for .auth file
- Zeroizing key material
- CSP hardening
- Input validation
- Audit trail integrity

### Code Quality
- Clippy clean
- All tests passing
- No remaining TODO/FIXME/HACK comments
- Consistent error handling

## Open Issues

### High Priority
- **C-4:** Refactor settings HTML to DOM APIs (settings.js still uses `innerHTML` with template literals)

### Medium Priority
- **M-13:** Version sync
- **M-15:** Windows CI

### Low Priority
- **H-2:** Plaintext account fallback mode (accepted risk)
- **H-3:** PIN truncation at 128 bytes (low practical risk)
- **Low items from SECURITY.md:** All planned improvements

## Next Steps

1. **Complete Area #1 fixes** (crypto + storage)
2. **Push to main branch**
3. **Start Area #2 review** (data models + config)
4. **Implement remaining high-priority items**
5. **Update SECURITY.md with completed items**
6. **Prepare v0.1.6 release**

## References

- SECURITY.md — Primary source of review findings
- CHANGELOG.md — Bug fixes documentation
- AGENTS.md — AI agent instructions
- PLAN.md — Project planning and architecture