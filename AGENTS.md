# AGENTS.md — AI Agent Instructions

> Instructions for AI coding assistants (Codebuff, Claude Code, Cursor, etc.) working on this project.

---

## Project Identity

**Tauri Authenticator** — A portable Windows desktop TOTP authenticator app (like Google Authenticator, but on desktop). Built with **Tauri v2 + Rust** backend and a **vanilla JS + Vite** WebView frontend. Fully offline. No installer — runs from anywhere. Data lives alongside the .exe in a `.auth` file with AES-256-GCM encrypted secrets derived via Argon2id.

---

## Tech Stack

| Layer | Technology |
|---|---|
| **Framework** | Tauri v2 |
| **Backend language** | Rust (edition 2021) |
| **Frontend** | Vanilla HTML/CSS/JS + Vite (ES modules, `@tauri-apps/api`) |
| **TOTP engine** | `totp-rs` v5 (RFC 6238) |
| **Secure storage** | Portable `.auth` JSON file + AES-256-GCM (key from **Argon2id**) |
| **System tray** | `tauri` built-in (`tray-icon` feature) |
| **Package manager** | `cargo` for Rust, `npm` for frontend |

---

## Project Structure

```
tauri-authenticator/
├── PLAN.md                     # Full planning & architecture document
├── AGENTS.md                   # This file
├── README.md                   # User-facing docs
├── index.html                  # Vite entry point
├── package.json                # Frontend deps (Vite, @tauri-apps/api)
├── vite.config.js              # Vite configuration
├── src/                        # Frontend (WebView)
│   ├── main.js                 # Entry point, Tauri event listeners, window tracking
│   ├── styles/
│   │   ├── main.css            # Global styles + custom titlebar
│   │   └── themes.css          # Light/dark theme CSS variables
│   └── js/
│       ├── totp.js             # Code display, countdown timers
│       ├── accounts.js         # Account CRUD UI logic
│       ├── clipboard.js        # Copy-to-clipboard with auto-clear
│       ├── dragdrop.js         # Drag-and-drop account reordering
│       ├── lock.js             # Lock screen, PIN entry, unlock
│       └── settings.js         # Settings dialog (PIN, backup, clipboard timeout)
├── src-tauri/                  # Tauri backend (Rust)
│   ├── Cargo.toml
│   ├── tauri.conf.json
│   ├── build.rs
│   ├── capabilities/
│   │   └── default.json
│   ├── icons/
│   └── src/
│       ├── main.rs             # Entry (#![windows_subsystem = "windows"])
│       ├── lib.rs              # App builder, plugin registration, AppState
│       ├── commands/
│       │   ├── mod.rs
│       │   ├── totp.rs
│       │   ├── accounts.rs
│       │   └── auth.rs         # Lock/unlock, backup, .auth file management
│       ├── models/
│       │   ├── mod.rs
│       │   └── account.rs
│       ├── storage/
│       │   ├── mod.rs
│       │   └── auth_file.rs    # .auth file read/write + AES encrypt/decrypt
│       ├── crypto.rs           # Argon2id key derivation + AES-256-GCM
│       ├── paths.rs            # Exe-relative path resolution
│       ├── config.rs           # App settings struct
│       ├── tray.rs             # System tray (icon, menu, left-click toggle)
│       ├── diagnostics.rs      # Crash logging, event log
│       └── utils/
│           ├── mod.rs
│           └── otpauth.rs
└── .gitignore
```

---

## Build & Run Commands

```bash
# Install frontend dependencies
npm install

# Development (hot-reload via Vite)
cargo tauri dev

# Production build
cargo tauri build

# Rust checks only
cargo check

# Rust tests
cargo test

# Rust clippy
cargo clippy -- -D warnings

# Format Rust code
cargo fmt

# Full CI check
cargo fmt --check && cargo clippy -- -D warnings && cargo test
```

---

## Architecture Rules

### TOTP lifecycle (critical path)
1. Secrets arrive via `otpauth://` URI (QR scan) or manual entry
2. Secrets are immediately encrypted with AES-256-GCM → saved to `.auth` JSON file next to the .exe  
   **never held in plaintext in JS**
3. Frontend calls `invoke("generate_code", { account_id })` to get codes
4. Rust reads `.auth` file, decrypts → generates via `totp-rs` → returns code + `seconds_remaining`
5. Frontend handles countdown timer locally; re-fetches from Rust every 30s

### Storage rules (`.auth` file)
- The `.auth` file sits next to the `.exe` with the same basename (e.g. `app.exe` → `app.auth`)
- Runtime path resolved via `std::env::current_exe()` — never hardcoded
- File is a combined JSON: `version`, `config` (window state + password metadata), `accounts` (encrypted payload), `log` (diagnostics)
- Key derived from user PIN via **Argon2id** → AES-256-GCM (matching a-note's proven crypto stack)
- Decrypted accounts held in Rust `AppState` memory only while unlocked; never exposed to frontend
- If `password_protected` is false (no PIN set): accounts stored as plaintext JSON — user prompted to set PIN on first launch
- **DO NOT hide the `.auth` file** — it must remain visible for users to find it for backups/portability
- Export/import is just copying the `.auth` file — no special format needed
- Use `AccountSummary` (no `secret` field) for all frontend-facing responses; `Account` (with `secret`) only for internal storage
- Combined storage auto-repairs config inconsistencies on load (e.g. encrypted accounts force `password_protected: true`)

### Frontend rules
- **Vanilla JS + Vite** — Vite handles HMR in dev and minification in prod; no framework
- Tauri IPC via `import { invoke } from "@tauri-apps/api/core"` (v2 API)
- ES modules (`export`/`import`) — Vite and Tauri v2 WebView2 both support this
- Countdown timers use `setInterval` at 1s granularity
- **Custom frameless titlebar** — window is `decorations: false`, frontend provides drag region (`data-tauri-drag-region`), pin/minimize/close buttons
- Track window resize/move events with debounce (500ms) → persist to config
- Window visibility managed by Rust (hidden initially, shown after state restore)
- All DOM updates happen in `main.js`; individual modules export pure functions

---

## Code Conventions

### Rust
- Follow standard Rust 2021 idioms
- **`#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]`** in `main.rs` to suppress console window on release builds
- App state managed via `tauri::manage()` with `Mutex` for shared mutable state (e.g., encryption key, tray icon)
- Use `thiserror` for error types (add to `Cargo.toml` when implementing)
- Tauri commands return `Result<T, String>` for simple cases, custom error types for complex ones
- Prefer `&str` over `String` in function parameters where ownership isn't needed
- All public types must derive `Debug, Clone, Serialize, Deserialize`
- Follow a-note's module structure: `main.rs` (entry) → `lib.rs` (run fn) → individual modules

### JavaScript
- ES modules (`export`/`import`) — Tauri v2 WebView2 supports this
- No `var` — use `const` by default, `let` when needed
- Functions over classes; prefer pure functions
- DOM queries cached at module init where possible
- CSS uses BEM-like naming: `.account-card`, `.account-card__code`, `.account-card__timer`

### CSS
- Custom properties for all colors (theming via `themes.css`)
- Mobile-first responsive (though desktop-primary, keep flexible)
- Use `system-ui` font stack
- No CSS framework — hand-written, minimal

---

## Key Constraints

- **Portable** — the `.exe` + `.auth` file can be moved anywhere; no installation, no registry entries
- **Fully offline** — no network calls anywhere in the app
- **No plaintext secrets** — secrets touch RAM only inside Rust, never JS
- **Windows primary** — but keep cross-platform in mind (no `winapi`-only code)
- **Binary size matters** — avoid pulling in large dependency trees unnecessarily
- **Tauri v2 APIs** — always check the v2 docs, not v1; plugin APIs changed
- **Frameless window** — `decorations: false`, frontend implements custom titlebar
- **`.auth` file visible** — do NOT hide the `.auth` file; users need to see it for backups
- **Crash logging** — panics written to `{exe}.crash` via `std::panic::set_hook`
- **Combined storage** — config + accounts + log all in one `.auth` file

---

## When Adding Features

1. Read `PLAN.md` first — understand the feature's phase and where it fits
2. Rust logic goes in `src-tauri/src/`; expose via Tauri commands
3. Frontend logic goes in `src/js/`; call Rust commands via `invoke()`
4. New Rust deps: add to `Cargo.toml` under `[dependencies]`
5. New JS deps: add to `package.json`, run `npm install`
6. IPC permissions: update `src-tauri/capabilities/default.json` if needed

---

## When Modifying Code

- Read surrounding code first — match existing patterns, naming, and error handling
- Run `cargo check` after any Rust change
- Run `cargo clippy` before considering a Rust change complete
- When renaming/moving Tauri commands, update both the `#[tauri::command]` function AND all frontend `invoke()` calls in `main.js`
- Test that `.auth` file I/O and encrypt/decrypt still work after any storage-layer changes

---

## Dependencies to Add (when needed)

```toml
# More Tauri plugins as needed
tauri-plugin-dialog = "2"
tauri-plugin-notification = "2"
```

---

*Created: June 12, 2026*
*See also: PLAN.md for full architecture and feature roadmap*
