# oz-auth — Portable Desktop TOTP Authenticator

> A secure, offline TOTP authenticator for Windows. Like Google Authenticator, on your desktop.
> Built with **Tauri v2 + Rust**. No installer — runs from anywhere.

<p align="center">
  <img src="https://img.shields.io/badge/rust-1.80+-orange.svg" alt="Rust 1.80+">
  <img src="https://img.shields.io/badge/tauri-v2-blue.svg" alt="Tauri v2">
  <img src="https://img.shields.io/badge/tests-23%20passing-green.svg" alt="23 tests passing">
  <img src="https://img.shields.io/badge/clippy-clean-brightgreen.svg" alt="Clippy clean">
</p>

---

## Features

- **🔐 TOTP Code Generation** — RFC 6238 compliant, supports SHA-1, SHA-256, SHA-512, 6-digit & 8-digit codes
- **📷 QR Code Scanning** — Camera capture or image paste (Ctrl+V) to add accounts from `otpauth://` URIs
- **🔒 Encrypted Storage** — Portable `.auth` file alongside the `.exe` — AES-256-GCM encryption with Argon2id key derivation
- **🖥️ System Tray** — Real-time countdown pie icon, left-click toggles window, right-click menu
- **🔑 PIN Protection** — App lock/unlock, auto-lock after inactivity, PIN change
- **↕️ Drag & Drop** — Reorder accounts by dragging cards
- **🎨 Dark/Light Theme** — System preference detection or manual toggle
- **📋 Smart Clipboard** — Auto-clears copied codes after 30s
- **⚡ Keyboard Shortcuts** — `Ctrl+N` add, `Ctrl+F` search, `Ctrl+L` lock, `Escape` dismiss
- **🌐 Fully Offline** — No network permissions, no telemetry, no cloud dependency
- **🛡️ Memory Hardened** — Secrets zeroized after use, encryption key `VirtualLock`-ed on Windows

---

## Quick Start

### Prerequisites

- [Rust](https://rustup.rs/) 1.80+
- [Node.js](https://nodejs.org/) 18+
- Windows 10+ (primary target; cross-platform capable)

### Install Dependencies

```bash
# Clone the repository
git clone https://github.com/kardelitaitu/oz-auth.git
cd oz-auth

# Install frontend dependencies
npm install
```

### Development

```bash
# Start with hot-reload (Vite + Tauri)
cargo tauri dev
```

### Production Build

```bash
# One command: build frontend then package .exe
npm run tauri

# Or manually in two steps:
npm run build              # Step 1: Build frontend with Vite
cargo tauri build          # Step 2: Package .exe (requires pre-built dist/)
```

The output is in `src-tauri/target/release/`. Copy `oz-auth.exe` anywhere — it's fully portable.

> **Note:** `beforeBuildCommand` is intentionally omitted from `tauri.conf.json` to avoid a Vite v6 subprocess exit-code issue on Windows. The `npm run tauri` script handles both steps.

---

## Usage

### Adding an Account

1. Click **+** (or `Ctrl+N`) to open the Add Account dialog
2. Enter **Issuer** (e.g. "Google"), **Label** (e.g. "user@gmail.com"), and **Secret Key**
3. Or click **📷 Scan QR Code** to scan from camera or paste an image

### Managing Accounts

| Action | How |
|--------|-----|
| **Copy code** | Click the code on any card |
| **Edit name** | Click ✎ or right-click → Edit |
| **Delete** | Click × or right-click → Delete |
| **Reorder** | Drag any card to a new position |
| **Search** | Type in the search bar (`Ctrl+F`) |

### Setting a PIN

1. Click **⚙** in the toolbar
2. Enter and confirm a PIN → click **Set PIN**
3. Your accounts are now encrypted with AES-256-GCM
4. The app will auto-lock after 5 minutes of inactivity

### Backup & Restore

The `.auth` file lives next to `oz-auth.exe` (same folder, same base name).  
**To backup:** copy the `.auth` file to a safe location.  
**To restore:** replace the `.auth` file next to the `.exe` and restart.

---

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+N` | Add account |
| `Ctrl+F` | Focus search |
| `Ctrl+L` | Lock app |
| `Escape` | Dismiss any dialog |

---

## Security Design

oz-auth is designed with the assumption that your desktop could be compromised.  
Every layer is built to minimize the window where secrets exist in plaintext memory.

### At Rest

- Accounts are stored in a portable `.auth` JSON file next to the `.exe`
- Secrets are encrypted with **AES-256-GCM** using a unique nonce per write
- The encryption key is derived from your PIN via **Argon2id** (memory-hard, GPU-resistant)
- If no PIN is set, accounts are stored as plaintext JSON (prompted to set PIN on first launch)

### In Memory

- The encryption key is wrapped in `Zeroizing<[u8; 32]>` — overwritten on `lock()`
- On Windows, `VirtualLock` prevents the key from being paged to swap
- After every TOTP generation, all decrypted account secrets are zeroized
- After every encrypt/decrypt, all intermediate buffers (JSON, nonce, ciphertext) are zeroized
- Derived keys and salts from PIN operations are zeroized immediately after use
- The frontend never sees raw secrets — only `AccountSummary` (no `secret` field) over IPC
- `SetProcessMitigationPolicy` blocks dynamic code execution, remote image loads

### In Transit (IPC)

- All communication between the WebView frontend and Rust backend uses Tauri's IPC
- Secrets are never passed to the frontend — codes are generated entirely in Rust
- The clipboard auto-clears after 30 seconds

---

## Architecture

```
┌──────────────────────────────────────────┐
│              FRONTEND (WebView)           │
│  Vanilla JS + Vite + @tauri-apps/api     │
│  • Account cards, countdown, drag & drop │
│  • QR scanner (getUserMedia + jsqr)      │
│  • Lock screen, settings, themes         │
└──────────────────┬───────────────────────┘
                   │  invoke() — Tauri IPC
┌──────────────────┴───────────────────────┐
│              BACKEND (Rust)               │
│  • totp-rs — RFC 6238 code generation    │
│  • AES-256-GCM + Argon2id — encryption   │
│  • .auth file — portable JSON storage    │
│  • System tray — pie chart icon          │
│  • Process mitigation — Windows hardening│
└──────────────────────────────────────────┘
```

### Tech Stack

| Layer | Technology |
|-------|-----------|
| Framework | Tauri v2 |
| Backend | Rust (edition 2021) |
| Frontend | Vanilla HTML/CSS/JS + Vite |
| TOTP Engine | `totp-rs` v5 (RFC 6238) |
| Encryption | `aes-gcm` v0.10 + `argon2` v0.5 |
| QR Scanning | `jsqr` v1.4 (frontend) |
| Memory Security | `zeroize` v1.8 |

---

## Project Structure

```
tauri-authenticator/
├── README.md
├── PLAN.md                     # Full architecture & planning doc
├── AGENTS.md                   # AI assistant instructions
├── index.html                  # Vite entry point
├── package.json                # Frontend dependencies
├── vite.config.js              # Vite config
├── src/                        # Frontend (WebView)
│   ├── main.js                 # Orchestrator — imports all modules
│   └── js/
│       ├── totp.js             # TOTP format, countdown, bar updates
│       ├── accounts.js         # Account cards, add/edit dialog
│       ├── clipboard.js        # Copy-to-clipboard with auto-clear
│       ├── lock.js             # Lock overlay, PIN entry, unlock
│       ├── settings.js         # Settings dialog (PIN, backup, clipboard)
│       └── dragdrop.js         # Drag-and-drop account reordering
│   └── styles/
│       ├── main.css            # Global styles, titlebar, cards
│       └── themes.css          # Dark/light theme variables
├── src-tauri/                  # Tauri backend (Rust)
│   ├── Cargo.toml              # Rust dependencies
│   ├── tauri.conf.json         # Tauri window + bundle config
│   ├── build.rs                # Tauri build script
│   ├── capabilities/
│   │   └── default.json        # IPC permissions
│   └── src/
│       ├── main.rs             # Entry, process mitigation
│       ├── lib.rs              # App builder, AppState, IPC registry
│       ├── commands/
│       │   ├── totp.rs         # TOTP code generation (23 tests)
│       │   ├── accounts.rs     # CRUD operations
│       │   └── auth.rs         # Lock/unlock, PIN, backup
│       ├── models/
│       │   └── account.rs      # Account + AccountSummary structs
│       ├── storage/
│       │   └── auth_file.rs    # .auth file read/write + encrypt/decrypt
│       ├── crypto.rs           # Argon2id + AES-256-GCM
│       ├── config.rs           # App settings
│       ├── paths.rs            # Exe-relative path resolution
│       ├── tray.rs             # System tray (pie icon, menu)
│       ├── diagnostics.rs      # Crash logging / event log
│       └── utils/
│           └── otpauth.rs      # otpauth:// URI parser
└── .gitignore
```

---

## Build Commands

```bash
# Rust checks
cargo check                    # Type-check only
cargo test                     # Run tests (23 tests)
cargo clippy -- -D warnings    # Lint with strict mode
cargo fmt --check              # Verify formatting

# Frontend
npm run dev                    # Start Vite dev server (port 1420)
npm run build                  # Production frontend build

# Full app
cargo tauri dev                # Dev mode (frontend + backend with HMR)
npm run tauri                  # Build frontend then package .exe
# or manually:
npm run build && cargo tauri build
```

---

## License

MIT © kardelitaitu

---

*Built with Rust, hardened with zeroize. No network. No telemetry. Just codes.*
