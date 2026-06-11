# TODO.md — Development Checklist

> **Tauri Authenticator** — Portable Windows TOTP authenticator (like Google Authenticator, on desktop).
> Check off items as they're implemented. Each phase builds on the previous one.

---

## Phase 1: Project Skeleton 🏗️

### Tauri Init & Config
- [ ] Run `npm init` / create `package.json` with `"type": "module"`
- [ ] Install frontend deps: `npm install @tauri-apps/api jsqr`
- [ ] Install Vite: `npm install -D vite`
- [ ] Create `vite.config.js` (port 1420, `TAURI_` env prefix, esnext target)
- [ ] Create `index.html` (Vite entry point, script type="module")
- [ ] Create `src-tauri/Cargo.toml` with all deps from PLAN.md §7.1
- [ ] Create `src-tauri/tauri.conf.json`:
  - `decorations: false`, `visible: false`
  - `devUrl: "http://localhost:1420"`, `beforeDevCommand: "npm run dev"`
  - `beforeBuildCommand: "npm run build"`
  - CSP: `null` (for inline styles in WebView)
  - Bundle: set `productName`, `identifier`, icon paths
- [ ] Create `src-tauri/build.rs` (calls `tauri_build::build()`)
- [ ] Create `src-tauri/capabilities/default.json`:
  - `"identifier": "default"`
  - `"windows": ["main"]`
  - Permissions: `core:default`, `core:window:allow-close`, `core:window:allow-minimize`, `core:window:allow-outer-size`, `core:window:allow-outer-position`, `core:window:allow-set-position`, `core:window:allow-set-size`, `core:window:allow-set-always-on-top`, `core:window:allow-start-dragging`, `core:window:allow-center`

### Rust Core Modules
- [ ] `src-tauri/src/main.rs` — entry point with `#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]`
- [ ] `src-tauri/src/lib.rs` — `run()` function, `AppState` struct (Mutex<Option<[u8; 32]>> for encryption key)
- [ ] `src-tauri/src/paths.rs` — `exe_stem()`, `exe_dir()`, `auth_path()` (returns `{exe_dir}/{stem}.auth`)
- [ ] `src-tauri/src/diagnostics.rs` — panic hook → `{exe}.crash`, `event()` / `flush_to_log_str()` / `restore_from_log_str()`
- [ ] `src-tauri/src/config.rs` — `Config` struct with serde defaults (width, height, left, top, always_on_top, theme, password fields, lock_timeout)
- [ ] `src-tauri/src/crypto.rs` — skeleton only (structs + stub functions)

### Frontend Skeleton
- [ ] `src/main.js` — `import { invoke } from "@tauri-apps/api/core"`, init sequence, window tracking
- [ ] `src/styles/main.css` — reset, custom titlebar styles, editor area, scrollbar
- [ ] `src/styles/themes.css` — dark + light theme CSS variables
- [ ] Custom frameless titlebar HTML/CSS/JS:
  - `data-tauri-drag-region` on titlebar div
  - Pin button (always-on-top toggle)
  - Minimize button
  - Close button
  - App title (from `get_app_name` command)

### Window Behavior
- [ ] Window hidden on launch (`visible: false`)
- [ ] Rust `setup` hook restores window position/size from `.auth` config
- [ ] `get_app_name` command returns exe stem for titlebar display
- [ ] Track resize/move → debounce 500ms → save to config

### Verify
- [ ] `cargo check` passes
- [ ] `cargo test` — `Config::default()` returns sensible values, JSON roundtrip works
- [ ] `cargo test` — `paths::exe_stem()` non-empty, `auth_path()` ends with `.auth`
- [ ] `cargo test` — `diagnostics::init()` writes startup event, `flush_to_log_str()` returns it
- [ ] `npm run dev` starts Vite
- [ ] `cargo tauri dev` launches window with custom titlebar
- [ ] Window draggable, minimize/close/pin buttons work

---

## Phase 2: TOTP Engine ⏱️

### Rust Backend
- [ ] `src-tauri/src/commands/mod.rs` — register command modules
- [ ] `src-tauri/src/commands/totp.rs`:
  - `generate_code(account_id) → (String, u32)` — uses `totp-rs` to generate current code + seconds_remaining
  - `generate_all_codes() → Vec<(String, String, u32)>` — all codes at once
- [ ] Register TOTP commands in `lib.rs` `invoke_handler`

### Data Model
- [ ] `src-tauri/src/models/mod.rs`
- [ ] `src-tauri/src/models/account.rs`:
  - `Account` struct (id, issuer, label, algorithm, digits, period, secret, sort_order, created_at, updated_at)
  - `AccountSummary` struct (same minus `secret`) — safe for frontend IPC
  - `Algorithm` enum (SHA1, SHA256, SHA512)
- [ ] `src-tauri/src/utils/mod.rs`
- [ ] `src-tauri/src/utils/otpauth.rs` — parse `otpauth://` URIs into `Account` data

### Frontend TOTP Display
- [ ] `src/js/totp.js` — functions for formatting codes, rendering countdown progress bars
- [ ] Account card component: issuer, label, 6/8 digit code (spaced pairs), copy button, countdown bar
- [ ] 1s `setInterval` tick — updates countdown on all cards, calls `generate_all_codes` on cycle
- [ ] Copy-to-clipboard on code click or copy button press

### Verify
- [ ] `cargo test` — TOTP generation tests pass (use hardcoded test `Account` struct, not the add-account flow)
- [ ] Verify codes match phone authenticator for known test secrets (SHA-1, SHA-256, SHA-512, 8-digit)
- [ ] `cargo clippy` on TOTP command module — zero warnings

---

## Phase 3: Account Management 💾

### Storage Layer
- [ ] `src-tauri/src/storage/mod.rs`
- [ ] `src-tauri/src/storage/auth_file.rs`:
  - `AuthData` struct (version, config, accounts encrypted payload, log)
  - `load()` / `try_load()` — read + auto-repair invariants
  - `save()` — serialize + write to `.auth` file
  - `fresh()` — default empty state
  - `AccountsEncrypted` struct (encrypted bool, nonce_hex, ciphertext_hex)
  - `encrypt_accounts(accounts, key)` / `decrypt_accounts(payload, key)`

### Account CRUD Commands
- [ ] `src-tauri/src/commands/accounts.rs`:
  - `add_account(issuer, label, secret, algorithm?, digits?, period?) → Account`
  - `add_account_from_uri(otpauth_uri) → Account` (uses parser from Phase 2)
  - `remove_account(account_id)`
  - `update_account(account_id, issuer?, label?, sort_order?) → Account`
  - `list_accounts(search_query?) → Vec<AccountSummary>` (NO secrets!)

### Frontend Account UI
- [ ] `src/js/accounts.js` — CRUD operations calling Tauri commands
- [ ] Account list rendering — cards sorted by `sort_order`
- [ ] Add account dialog (see PLAN.md §6.2):
  - Manual entry fields: issuer, label, secret, algorithm dropdown, digits dropdown, period dropdown
  - Submit calls `add_account`
- [ ] Edit account (inline or dialog)
- [ ] Delete account with confirmation
- [ ] Drag & drop reorder (updates `sort_order`)

### Verify
- [ ] `cargo test` — storage roundtrip, encrypt/decrypt, CRUD tests pass
- [ ] Add accounts manually → persist across app restart → codes still generate
- [ ] `otpauth://` URI parsing works for real-world URIs
- [ ] Account summaries NEVER expose secrets to frontend

---

## Phase 4: QR Code Scanning 📷

### Camera Access
- [ ] `src/js/qr-scanner.js`:
  - `navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } })`
  - Render video to hidden `<video>` element
  - Canvas extraction every 200ms → feed to `jsqr`
  - On detection: parse URI, call `add_account_from_uri`, close camera
  - Stop media tracks on close/cancel
- [ ] Camera permission request handling
- [ ] Error states: no camera, permission denied, camera in use

### Image Paste Fallback
- [ ] Clipboard paste event listener
- [ ] Detect image data → decode → `jsqr` scan
- [ ] Same flow as camera: parse URI → add account → success/error toast

### UI
- [ ] QR scan button in add-account dialog
- [ ] Camera preview overlay with framing guide
- [ ] "Paste QR image" hint text below scan button
- [ ] Toast notifications for scan success/failure

### Verify
- [ ] Scan real QR codes from Google/Microsoft/GitHub 2FA setup
- [ ] Scan works with camera and image paste
- [ ] Proper cleanup when closing scanner (camera released)
- [ ] Handles non-QR images gracefully (no crash, shows error)

---

## Phase 5: Security 🔒

### App Lock (PIN Protection)
- [ ] `src-tauri/src/commands/auth.rs`:
  - `set_lock(pin) → ()` — generate salt, derive key, encrypt existing accounts, save
  - `unlock(pin) → bool` — derive key from stored salt, attempt decrypt, cache key in AppState
  - `lock() → ()` — clear cached key from AppState
  - `is_locked() → bool`
  - `change_pin(old_pin, new_pin) → ()` — verify old, re-encrypt with new

### Lock Screen UI
- [ ] `src/js/lock.js`:
  - Lock overlay (blurred background, centered PIN input card)
  - Submit on Enter key
  - Error state: "Wrong PIN. Try again."
  - Lock on launch if `password_protected` is true
- [ ] Auto-lock timer (configurable timeout, default 5 min of inactivity)
- [ ] Lock immediately from system tray or keyboard shortcut

### Clipboard Security
- [ ] `src/js/clipboard.js`:
  - Copy code to clipboard
  - Set timeout (configurable, default 30s) to clear clipboard
  - Track last copied code → schedule clear
  - Cancel previous clear on new copy

### Backup / Export
- [ ] `export_backup(path)` — copy `.auth` file to user-chosen destination
- [ ] `import_backup(path)` — validate .auth file, replace current data
- [ ] Confirmation dialogs for import (overwrites current data)

### Verify
- [ ] `cargo test` — set/unlock/lock/change_pin, wrong PIN rejection, auto-repair tests
- [ ] PIN protection toggles correctly (set → lock → unlock → remove)
- [ ] Wrong PIN cannot unlock
- [ ] Clipboard auto-clears after timeout
- [ ] Export → delete .auth → import → accounts restored

---

## Phase 6: Polish ✨

### System Tray
- [ ] `src-tauri/src/tray.rs`:
  - Build tray with `TrayIconBuilder` (tray-icon feature)
  - Left-click: toggle window visibility
  - Right-click menu: Show, Quit
  - Generate 32×32 countdown pie icon programmatically (updates every second)
  - `update_tray_icon(seconds_remaining)` — refresh the pie chart
- [ ] Minimize to tray instead of taskbar
- [ ] Tray tooltip shows app name

### Themes
- [ ] Dark theme (default, matching a-note's dark theme)
- [ ] Light theme
- [ ] System preference detection (`prefers-color-scheme`)
- [ ] Theme toggle in menu/settings
- [ ] Smooth theme transitions (0.2s)

### Search & Filter
- [ ] Search bar in toolbar
- [ ] Real-time filter as user types
- [ ] Match issuer and label fields
- [ ] Clear search button
- [ ] "No accounts found" empty state

### Keyboard Shortcuts
- [ ] `Ctrl+N` — open Add Account dialog
- [ ] `Ctrl+F` — focus search bar
- [ ] `Ctrl+L` — lock app
- [ ] `Escape` — close dialogs, cancel search

### Toast Notifications
- [ ] Toast bar at bottom center
- [ ] Success (green) and error (red) variants
- [ ] Auto-dismiss after 3s
- [ ] Messages: "Account added", "Account deleted", "Code copied", "PIN set", "Backup exported"

### Final Polish
- [ ] Window close button saves state before closing
- [ ] `beforeunload` handler saves config + accounts
- [ ] App icon (.ico for Windows, generated from PNG)
- [ ] `README.md` with download/setup instructions
- [ ] `.gitignore` (node_modules, target, dist, .auth, .crash)

### Verify
- [ ] `cargo clippy -- -D warnings` — zero warnings
- [ ] `cargo fmt --check` — all code formatted
- [ ] `cargo test` — all tests pass
- [ ] `cargo tauri build` — produces working .exe
- [ ] Portable test: copy .exe + .auth to another folder → run → works
- [ ] Network-free: no outbound connections (check with firewall)

---

## Legend

| Phase | Status |
|---|---|
| 🏗️ Phase 1 — Skeleton | ⬜ Not started |
| ⏱️ Phase 2 — TOTP Engine | ⬜ Not started |
| 💾 Phase 3 — Account Management | ⬜ Not started |
| 📷 Phase 4 — QR Scanning | ⬜ Not started |
| 🔒 Phase 5 — Security | ⬜ Not started |
| ✨ Phase 6 — Polish | ⬜ Not started |

---

*Created: June 12, 2026*
*See: PLAN.md for detailed specs, AGENTS.md for coding conventions*
