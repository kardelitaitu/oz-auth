# Next Agenda Checklist

> Actionable checklist derived from `CODEBASE_REVIEW.md` review findings.
> **Status:** Open items only. ✓ = completed.

---

## Phase 1: Complete Area #1 — Push to Main

Items from the working tree crypto+storage fixes ready to merge:

- [x] **1.1** Push v0.1.6 branch with all Phase 2-10 changes to `origin` (commit `11024ec`)
- [ ] **1.2** Verify all 584 tests pass on CI after merge

---

## Phase 2: Area #2 — Data Models + Config Review 🔜 NEXT

### 2a. Account Model — `models/account.rs` ✓

- [x] **2a.1** Review `Account` model structure — is secret handling correct?
- [x] **2a.2** Wrap `secret: Vec<u8>` → `Zeroizing<Vec<u8>>` for automatic zeroization on drop
- [x] **2a.3** Verify `AccountSummary` (no secret) vs `Account` (with secret) separation is enforced
- [x] **2a.4** Check serde round-trip safety for all fields

### 2b. Config Model — `config.rs` ✓

- [x] **2b.1** Review config structure, defaults, and migration logic (`lock_timeout_minutes` → `lock_timeout_seconds`)
- [x] **2b.2** Wrap `password_salt: String` → `Zeroizing<String>` (defense-in-depth, low priority)
- [x] **2b.3** Verify window state persistence works correctly

### 2c. Audit Trail — `audit.rs` ✓

- [x] **2c.1** Review SHA256 hash chain integrity model — sound, 17 unit tests + 6 proptests
- [x] **2c.2** Verify `restore()` + `verify_chain()` end-to-end — correct, graceful error handling
- [x] **2c.3** Check all security events are logged — 6 categories all covered
- [x] **2c.4** Confirm audit log display works in settings UI — works, XSS-safe with `esc()`

---

## Phase 3: Security Hardening (High Priority)

### 3a. IPC Input Validation — All Commands ✓

- [x] **3a.1** PIN inputs (set_lock, unlock, change_pin, verify_pin) — MIN 4, MAX 128
- [x] **3a.2** Issuer (1-128), label (1-256), secret string (1-1024)
- [x] **3a.3** URI input (1-4096), account_id (1-128), search query (0-256)
- [x] **3a.4** File path (1-4096) — export_backup, import_backup

### 3b. Error Handling — `paths.rs` ✓

- [x] **3b.1** Convert 4 `.expect()` calls to `Result` returns
- [x] **3b.2** Handle `current_exe()` failure gracefully instead of panicking

### 3c. PIN Strength Indicator ✓

- [x] **3c.1** Added visual PIN strength bar (Weak/Medium/Strong/Very Strong) in settings UI
- [x] **3c.2** No minimum enforced — purely informational, user choice respected
- [x] **3c.3** Live-updating bar with score, level-based colors, common PIN detection

---

## Phase 4: Frontend Refactoring (High Priority)

### 4a. C-4: `settings.js` — Replace innerHTML with DOM APIs ✓

- [x] **4a.1** Refactored main settings HTML build → DOM APIs (`createElement`, `textContent`, `appendChild`)
- [x] **4a.2** Refactored audit log rows + error row → DOM construction (zero innerHTML)
- [x] **4a.3** Updated all test assertions from `innerHTML` → `textContent` / `children`
- [x] **4a.4** All 104 frontend tests pass

### 4b. `accounts.js` — Review card.innerHTML Usage ✓

- [x] **4b.1** Refactored `card.innerHTML` template → DOM APIs (createElement, textContent, SVG with createElementNS)
- [x] **4b.2** Empty state uses createElement + textContent (no innerHTML)
- [x] **4b.3** SVG countdown ring built with proper SVG namespace
- [x] **4b.4** `escapeHtml` kept as exported utility; test assertions updated from `innerHTML` to `textContent`

---

## Phase 5: Area #3 — Commands (auth) Review ✓

- [x] **5.1** Reviewed `commands/auth.rs` — PIN lifecycle sound, no issues found
- [x] **5.2** Verified key derivation, zeroization, rate limiting — all correct
- [x] **5.3** Checked edge cases — 38+ unit tests cover all scenarios, no gaps

---

## Phase 6: Area #4 — Commands (accounts + totp) Review

- [x] **6.1** Review `commands/accounts.rs` — account management entry points
- [x] **6.2** Review `accounts/crud.rs` — CRUD operations, sort order, validation
- [x] **6.3** Review `accounts/qr.rs` — QR code scanning/parsing
- [x] **6.4** Review `commands/totp.rs` — TOTP code generation, period validation

---

## Phase 7: Area #5 — App Bootstrap Review

- [x] **7.1** Review `main.rs` — entry point, `windows_subsystem`, panic hook
- [x] **7.2** Review `lib.rs` — `AppState`, plugin registration, wiring
- [x] **7.3** Review `tray.rs` — system tray icon, menu, left-click toggle
- [x] **7.4** Review `diagnostics.rs` — crash logging, event log buffer

---

## Phase 8: Area #6 — Frontend Review

- [x] **8.1** Review `main.js` — Tauri event listeners, window tracking, init flow
- [x] **8.2** Review `totp.js` — code display, countdown timers
- [x] **8.3** Review `clipboard.js` — copy-to-clipboard with auto-clear
- [x] **8.4** Review `dragdrop.js` — drag-and-drop reordering
- [x] **8.5** Review `lock.js` — lock screen, PIN entry, unlock flow

---

## Phase 9: Area #7 — Configuration + CI Review ✓

- [x] **9.1** Review `tauri.conf.json` — window config, security headers
- [x] **9.2** Review `Cargo.toml` — dependency audit, feature flags
- [x] **9.3** Review `capabilities/default.json` — IPC permissions
- [x] **9.4** Review CI workflows — build, test, security audit

---

## Phase 10: Remaining Items ✓

- [x] **10.1** File locking on `.auth` — advisory file lock during read/write to prevent TOCTOU races
- [x] **10.2** Version sync (M-13) — sync version across Cargo.toml, package.json, and about dialog
- [x] **10.3** Windows CI (M-15) — set up Windows CI runner
- [x] **10.4** Update `SECURITY.md` — mark completed items, add new findings
- [x] **10.5** Prepare v0.1.6 release — changelog, branch, push

---

## Legend

| Priority | Label |
|----------|-------|
| 🔜 NEXT | Current focus area |
| High | Security-critical or blocking |
| Medium | Important but not blocking |
| Low | Nice-to-have / defense-in-depth |
