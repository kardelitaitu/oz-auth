# CODEBASE_REVIEW.md

Auditor: OpenCode - Deepseek v4 Flash

## Summary

This document summarizes the security review findings, fixes, and review status for the Tauri Authenticator project (oz-auth). All 7 review areas have been completed across 10 phases. The codebase is production-ready with 589 total tests passing and clippy clean.

## Areas Reviewed (All Complete)

### Area #1: Crypto + Storage — ✅ Reviewed (Phase 1)
**Files:** `crypto.rs`, `storage/auth_file.rs`, `paths.rs`

- `crypto.rs`: Key derivation, encryption, Argon2id — sound
- `storage/auth_file.rs`: `.auth` file I/O, atomic writes, advisory file locking — sound
- `paths.rs`: Runtime path resolution, .exe-relative paths — 4 `.expect()` calls → `Result`

### Area #2: Data Models + Config — ✅ Reviewed (Phase 2)
**Files:** `models/account.rs`, `config.rs`, `audit.rs`

- `models/account.rs`: `secret: Vec<u8>` → `Zeroizing<Vec<u8>>`, `AccountSummary`/`Account` separation enforced
- `config.rs`: `password_salt: String` → `Zeroizing<String>`, defaults and migration verified
- `audit.rs`: SHA-256 hash chain integrity model verified — 17 unit tests + 6 proptests

### Area #3: Commands (auth) — ✅ Reviewed (Phase 5)
**File:** `commands/auth.rs`

- PIN lifecycle (set/lock/unlock/change/verify) — sound
- Key zeroization — complete on all paths
- Rate limiting — exponential backoff, 30s cap, saturating add
- 38+ unit tests covering all edge cases

### Area #4: Commands (accounts + totp) — ✅ Reviewed (Phase 6)
**Files:** `commands/accounts.rs`, `accounts/crud.rs`, `accounts/qr.rs`, `commands/totp.rs`

- CRUD operations — all validated, zeroization complete
- TOTP code generation — RFC 6238 compliance verified (19 test vectors)
- `decode_secret` — handles base32 + hex + edge cases
- URI generation — proper base32 encoding, URL-safe

### Area #5: App Bootstrap — ✅ Reviewed (Phase 7)
**Files:** `main.rs`, `lib.rs`, `tray.rs`, `diagnostics.rs`

- `main.rs`: Process mitigations (dynamic code policy, DLL injection prevention)
- `lib.rs`: `AppState` with `Zeroizing<[u8; 32]>` key + `VirtualLock`, mtime-based cache staleness
- `tray.rs`: Pixel-perfect pie chart tray icon, left-click toggle
- `diagnostics.rs`: Panic hook → crash file, event log buffer (10KB cap)
- Startup double-read optimization: `.auth` file loaded once instead of twice

### Area #6: Frontend — ✅ Reviewed (Phase 8)
**Files:** `main.js`, `js/*.js`

- `main.js`: Tauri IPC, window tracking, keyboard shortcuts, auto-lock — all correct
- `totp.js`: Code display + countdown via `setInterval` at 1s granularity
- `clipboard.js`: Auto-clear with random-noise overwrite, lock-clear
- `dragdrop.js`: Handle-only drag, cleanup on cancel/blur
- `lock.js`: Show/hide, unlock (correct/wrong/error), Enter key, close button
- Zero `innerHTML` with user-controlled content after Phases 4a-4b

### Area #7: Configuration + CI — ✅ Reviewed (Phase 9 + 10)
**Files:** `tauri.conf.json`, `Cargo.toml`, `vite.config.js`, `capabilities/`

- CSP: `default-src 'self'` — strong, no bypasses
- Dependencies: All current versions, no duplicates
- IPC permissions: Minimal allow-list, no unnecessary capabilities
- CI: Linux + Windows workflows, `cargo audit`, `cargo clippy`, `cargo test`, `npm audit`, `vitest`

---

## All Issues Fixed (v0.1.1 — v0.1.6)

### Phase 1 — Crypto + Storage Fixes

| Fix | Description |
|-----|-------------|
| `derive_key()` → `Zeroizing<[u8; 32]>` | Type-level enforcement prevents accidental key copies |
| Atomic writes with random temp filenames | `.auth.{random}.tmp` prevents race conditions |
| `try_load()` flushes audit trail on upgrade | Ensures audit trail integrity on version migration |
| CSP tightened | Removed `http://localhost:1420` and `ws://localhost:1420` from production |

### Phase 2 — Data Models + Config

| Fix | Description |
|-----|-------------|
| `Account.secret` → `Zeroizing<Vec<u8>>` | Automatic zeroization on drop for all secret fields |
| `AccountSummary`/`Account` separation enforced | Frontend never receives `secret` field over IPC |
| `Config.password_salt` → `Zeroizing<String>` | Defense-in-depth for salt in memory |
| Audit trail hash chain verified | 17 unit tests + 6 proptests confirming integrity |

### Phase 3 — Security Hardening

| Fix | Description |
|-----|-------------|
| IPC input length validation | `validate_length()` on all IPC commands (PIN 4-128, issuer 1-128, etc.) |
| `paths.rs` error handling | 4 `.expect()` calls → `Result` returns |
| PIN strength indicator | Visual bar (Weak/Medium/Strong/Very Strong) in settings, informational only |

### Phase 4 — Frontend DOM Refactoring

| Fix | Description |
|-----|-------------|
| `settings.js` innerHTML → DOM APIs | Zero `innerHTML` in settings build |
| `accounts.js` innerHTML → DOM APIs | SVG with `createElementNS`, textContent, event listeners on elements |
| All test assertions updated | `innerHTML` → `textContent` / `children` |

### Phase 5-8 — Reviews (No Code Changes Needed)

| Area | Verdict |
|------|---------|
| `commands/auth.rs` — PIN lifecycle | Sound — no issues found |
| `commands/accounts.rs` + `totp.rs` — CRUD + TOTP | Sound — no issues found |
| `main.rs`, `lib.rs`, `tray.rs`, `diagnostics.rs` — Bootstrap | Sound — startup double-read optimized |
| Frontend (`main.js`, `js/*.js`) — UI | Sound — 104 tests passing, zero `innerHTML` with user content |

### Phase 9-10 — Configuration + Remaining Items

| Fix | Description |
|-----|-------------|
| Advisory file locking | `fs2` crate — exclusive lock on writes, shared lock on reads (TOCTOU prevention) |
| Version sync | `tauri.conf.json` → `0.1.6` matching `Cargo.toml` and `package.json` |
| Windows CI | `.github/workflows/windows.yml` — build + test + clippy on `windows-latest` |
| CSS theme variable dedup | Removed duplicate dark theme variables from `main.css` (single source: `themes.css`) |
| CSS section header consistency | PIN strength meter header unified to `===` convention |
| SECURITY.md updated | 8 items marked complete, supported version bumped to 0.1.6 |

---

## Remaining Backlog

Items deferred to future releases (documented in `SECURITY.md`):

| Priority | Item | Status | Description |
|----------|------|--------|-------------|
| Medium | PIN strength enforcement | Backlog | Optional minimum length/complexity requirement (indicator exists, no enforcement) |
| Future | TPM-backed keystore | Backlog | Windows DPAPI/TPM to protect encryption key, eliminating cold-boot attack |
| Future | Encrypted backup format | Backlog | Export/import with user-supplied passphrase (separate from PIN) |
| Future | `cargo-vet` integration | Backlog | Third-party dependency auditing beyond `cargo-audit`/`cargo-deny` |

---

## Test Results

### Current Status (v0.1.6)
- **485 Rust tests** + **104 Vitest** = **589 total tests**
- **All tests passing**
- **Clippy clean** (zero warnings)
- **Build clean** (`cargo check`)

### CI Status
| Workflow | Platform | Checks |
|----------|----------|--------|
| `security.yml` | Ubuntu | clippy, test, fmt, build, `cargo audit` |
| `windows.yml` | Windows | clippy, test, fmt, build, `npm audit`, vitest |

---

## Code Quality Metrics

### Security Hardening
- Atomic writes for `.auth` file (temp + rename)
- Advisory file locking (`fs2` — exclusive on write, shared on read)
- `Zeroizing` wrappers on all secret material (key, salt, account secrets)
- CSP: `default-src 'self'` with minimal exceptions
- Process mitigation policies (Windows: dynamic code, image load, signature)
- `VirtualLock` on encryption key (prevents paging to disk)
- Rate limiting with exponential backoff on PIN attempts
- SHA-256 hash chain audit trail (append-only, frontend read-only)
- No `innerHTML` with user-controlled content in frontend

### Code Quality
- Clippy clean (zero warnings)
- All 589 tests passing
- No TODO/FIXME/HACK comments in source
- Consistent `_impl` → `#[tauri::command]` wrapper pattern
- Consistent error handling via `Result<T, String>`

## References

- SECURITY.md — Threat model, security architecture, cryptographic primitives
- CHANGELOG.md — Release history and bug fixes
- CHECKLIST.md — Actionable completion checklist
- AGENTS.md — AI agent instructions
- PLAN.md — Project planning and architecture
