# TODO.md — Development Checklist

> **Tauri Authenticator** — Portable Windows TOTP authenticator (like Google Authenticator, on desktop).
> Check off items as they're implemented. Each phase builds on the previous one.

---

## Phase 1: Project Skeleton 🏗️

### Tauri Init & Config
- [x] Run `npm init` / create `package.json` with `"type": "module"`
- [x] Install frontend deps: `npm install @tauri-apps/api`
- [x] Install Vite: `npm install -D vite`
- [x] Create `vite.config.js` (port 1420, `TAURI_` env prefix, esnext target)
- [x] Create `index.html` (Vite entry point, script type="module")
- [x] Create `src-tauri/Cargo.toml` with all deps from PLAN.md §7.1
- [x] Create `src-tauri/tauri.conf.json`:
  - `decorations: false`, `visible: false`
  - `devUrl: "http://localhost:1420"`, `beforeDevCommand: "npm run dev"`
  - `beforeBuildCommand: "npm run build"`
  - CSP: `null` (for inline styles in WebView)
  - Bundle: set `productName`, `identifier`, icon paths
- [x] Create `src-tauri/build.rs` (calls `tauri_build::build()`)
- [x] Create `src-tauri/capabilities/default.json`:
  - `"identifier": "default"`
  - `"windows": ["main"]`
  - Permissions: `core:default`, `core:window:allow-close`, `core:window:allow-minimize`, `core:window:allow-outer-size`, `core:window:allow-outer-position`, `core:window:allow-set-position`, `core:window:allow-set-size`, `core:window:allow-set-always-on-top`, `core:window:allow-start-dragging`, `core:window:allow-center`

### Rust Core Modules
- [x] `src-tauri/src/main.rs` — entry point with `#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]`
- [x] `src-tauri/src/lib.rs` — `run()` function, `AppState` struct (Mutex<Option<[u8; 32]>> for encryption key)
- [x] `src-tauri/src/paths.rs` — `exe_stem()`, `exe_dir()`, `auth_path()` (returns `{exe_dir}/{stem}.auth`)
- [x] `src-tauri/src/diagnostics.rs` — panic hook → `{exe}.crash`, `event()` / `flush_to_log_str()` / `restore_from_log_str()`
- [x] `src-tauri/src/config.rs` — `Config` struct with serde defaults (width, height, left, top, always_on_top, theme, password fields, lock_timeout)
- [x] `src-tauri/src/crypto.rs` — Argon2id key derivation + AES-256-GCM

### Frontend Skeleton
- [x] `src/main.js` — `import { invoke } from "@tauri-apps/api/core"`, init sequence, window tracking
- [x] `src/styles/main.css` — reset, custom titlebar styles, editor area, scrollbar
- [x] `src/styles/themes.css` — dark + light theme CSS variables
- [x] Custom frameless titlebar HTML/CSS/JS:
  - `data-tauri-drag-region` on titlebar div
  - Pin button (always-on-top toggle)
  - Minimize button
  - Close button
  - App title (from `get_app_name` command)

### Window Behavior
- [x] Window hidden on launch (`visible: false`)
- [x] Rust `setup` hook restores window position/size from `.auth` config
- [x] `get_app_name` command returns exe stem for titlebar display
- [x] Track resize/move → debounce 500ms → save to config

### Verify
- [x] `cargo check` passes
- [x] `cargo test` — `Config::default()` returns sensible values, JSON roundtrip works
- [x] `cargo test` — `paths::exe_stem()` non-empty, `auth_path()` ends with `.auth`
- [x] `cargo test` — `diagnostics::init()` writes startup event, `flush_to_log_str()` returns it
- [x] `npm run dev` starts Vite
- [x] `cargo tauri dev` launches window with custom titlebar
- [x] Window draggable, minimize/close/pin buttons work

---

## Phase 2: TOTP Engine ⏱️

### Rust Backend
- [x] `src-tauri/src/commands/mod.rs` — register command modules
- [x] `src-tauri/src/commands/totp.rs`:
  - `generate_code(account_id) → (String, u32)` — uses `totp-rs` to generate current code + seconds_remaining
  - `generate_all_codes() → Vec<(String, String, u32)>` — all codes at once
- [x] Register TOTP commands in `lib.rs` `invoke_handler`

### Data Model
- [x] `src-tauri/src/models/mod.rs`
- [x] `src-tauri/src/models/account.rs`:
  - `Account` struct (id, issuer, label, algorithm, digits, period, secret, sort_order, created_at, updated_at)
  - `AccountSummary` struct (same minus `secret`) — safe for frontend IPC
  - `Algorithm` enum (SHA1, SHA256, SHA512)
- [x] `src-tauri/src/utils/mod.rs`
- [x] `src-tauri/src/utils/otpauth.rs` — parse `otpauth://` URIs into `Account` data

### Frontend TOTP Display
- [x] `src/js/totp.js` — functions for formatting codes, rendering countdown progress bars
- [x] Account card component: issuer, label, 6/8 digit code (spaced pairs), copy button, countdown bar
- [x] 1s `setInterval` tick — updates countdown on all cards, calls `generate_all_codes` on cycle
- [x] Copy-to-clipboard on code click or copy button press

### Verify
- [x] `cargo test` — TOTP generation tests pass (use hardcoded test `Account` struct, not the add-account flow)
- [x] Verify codes match phone authenticator for known test secrets (SHA-1, SHA-256, SHA-512, 8-digit)
- [x] `cargo clippy` on TOTP command module — zero warnings

---

## Phase 3: Account Management 💾

### Storage Layer
- [x] `src-tauri/src/storage/mod.rs`
- [x] `src-tauri/src/storage/auth_file.rs`:
  - `AuthData` struct (version, config, accounts encrypted payload, log)
  - `load()` / `try_load()` — read + auto-repair invariants
  - `save()` — serialize + write to `.auth` file
  - `fresh()` — default empty state
  - `AccountsEncrypted` struct (encrypted bool, nonce_hex, ciphertext_hex)
  - `encrypt_accounts(accounts, key)` / `decrypt_accounts(payload, key)`

### Account CRUD Commands
- [x] `src-tauri/src/commands/accounts.rs`:
  - `add_account(issuer, label, secret, algorithm?, digits?, period?) → Account`
  - `add_account_from_uri(otpauth_uri) → Account` (uses parser from Phase 2)
  - `remove_account(account_id)`
  - `update_account(account_id, issuer?, label?, sort_order?) → Account`
  - `list_accounts(search_query?) → Vec<AccountSummary>` (NO secrets!)

### Frontend Account UI
- [x] `src/js/accounts.js` — CRUD operations calling Tauri commands
- [x] Account list rendering — cards sorted by `sort_order`
- [x] Add account dialog (see PLAN.md §6.2):
  - Manual entry fields: issuer, label, secret, algorithm dropdown, digits dropdown, period dropdown
  - Submit calls `add_account`
- [x] Edit account (inline or dialog)
- [x] Delete account with confirmation
- [x] Drag & drop reorder (updates `sort_order`)

### Verify
- [x] `cargo test` — storage roundtrip, encrypt/decrypt, CRUD tests pass
- [x] Add accounts manually → persist across app restart → codes still generate
- [x] `otpauth://` URI parsing works for real-world URIs
- [x] Account summaries NEVER expose secrets to frontend

---

## Phase 4: QR Code Scanning 📷

> **Note:** QR scanning was intentionally removed for security reasons. Accounts are added via manual entry or `otpauth://` URI paste only.

### ~~Camera Access~~ (Skipped)
- [ ] ~~`src/js/qr-scanner.js`~~ — Removed for security

### ~~Image Paste~~ (Skipped)
- [ ] ~~Clipboard paste event listener~~ — Not implemented

### ~~UI~~ (Skipped)
- [ ] ~~QR scan button in add-account dialog~~ — Not implemented

### Verify
- [x] Manual entry works correctly
- [x] `otpauth://` URI paste works

---

## Phase 5: Security 🔒

### App Lock (PIN Protection)
- [x] `src-tauri/src/commands/auth.rs`:
  - `set_lock(pin) → ()` — generate salt, derive key, encrypt existing accounts, save
  - `unlock(pin) → bool` — derive key from stored salt, attempt decrypt, cache key in AppState
  - `lock() → ()` — clear cached key from AppState
  - `is_locked() → bool`
  - `change_pin(old_pin, new_pin) → ()` — verify old, re-encrypt with new

### Lock Screen UI
- [x] `src/js/lock.js`:
  - Lock overlay (blurred background, centered PIN input card)
  - Submit on Enter key
  - Error state: "Wrong PIN. Try again."
  - Lock on launch if `password_protected` is true
- [x] Auto-lock timer (configurable timeout, default 5 min of inactivity)
- [x] Lock immediately from system tray or keyboard shortcut

### Clipboard Security
- [x] `src/js/clipboard.js`:
  - Copy code to clipboard
  - Set timeout (configurable, default 30s) to clear clipboard
  - Track last copied code → schedule clear
  - Cancel previous clear on new copy

### Backup / Export
- [x] `export_backup(path)` — copy `.auth` file to user-chosen destination
- [x] `import_backup(path)` — validate .auth file, replace current data
- [x] Confirmation dialogs for import (overwrites current data)

### Verify
- [x] `cargo test` — set/unlock/lock/change_pin, wrong PIN rejection, auto-repair tests
- [x] PIN protection toggles correctly (set → lock → unlock → remove)
- [x] Wrong PIN cannot unlock
- [x] Clipboard auto-clears after timeout
- [x] Export → delete .auth → import → accounts restored

---

## Phase 6: Polish ✨

### System Tray
- [x] `src-tauri/src/tray.rs`:
  - Build tray with `TrayIconBuilder` (tray-icon feature)
  - Left-click: toggle window visibility
  - Right-click menu: Show, Quit
  - Generate 32×32 countdown pie icon programmatically (updates every second)
  - `update_tray_icon(seconds_remaining)` — refresh the pie chart
- [x] Minimize to tray instead of taskbar
- [x] Tray tooltip shows app name

### Themes
- [x] Dark theme (default, matching a-note's dark theme)
- [x] Light theme
- [x] System preference detection (`prefers-color-scheme`)
- [x] Theme toggle in menu/settings
- [x] Smooth theme transitions (0.2s)

### Search & Filter
- [x] Search bar in toolbar
- [x] Real-time filter as user types
- [x] Match issuer and label fields
- [x] Clear search button
- [x] "No accounts found" empty state

### Keyboard Shortcuts
- [x] `Ctrl+N` — open Add Account dialog
- [x] `Ctrl+F` — focus search bar
- [x] `Ctrl+L` — lock app
- [x] `Escape` — close dialogs, cancel search

### Toast Notifications
- [x] Toast bar at bottom center
- [x] Success (green) and error (red) variants
- [x] Auto-dismiss after 3s
- [x] Messages: "Account added", "Account deleted", "Code copied", "PIN set", "Backup exported"

### Final Polish
- [x] Window close button saves state before closing
- [x] `beforeunload` handler saves config + accounts
- [x] App icon (.ico for Windows, generated from PNG)
- [x] `README.md` with download/setup instructions
- [x] `.gitignore` (node_modules, target, dist, .auth, .crash)

### Verify
- [x] `cargo clippy -- -D warnings` — zero warnings
- [x] `cargo fmt --check` — all code formatted
- [x] `cargo test` — all tests pass
- [x] `cargo tauri build` — produces working .exe
- [x] Portable test: copy .exe + .auth to another folder → run → works
- [x] Network-free: no outbound connections (check with firewall)

---

## Legend

| Phase | Status |
|---|---|
| 🏗️ Phase 1 — Skeleton | ✅ Complete |
| ⏱️ Phase 2 — TOTP Engine | ✅ Complete |
| 💾 Phase 3 — Account Management | ✅ Complete |
| 📷 Phase 4 — QR Scanning | ⏭️ Skipped (intentionally removed for security) |
| 🔒 Phase 5 — Security | ✅ Complete |
| ✨ Phase 6 — Polish | ✅ Complete |

---

*Created: June 12, 2026*
*See: PLAN.md for detailed specs, AGENTS.md for coding conventions*
