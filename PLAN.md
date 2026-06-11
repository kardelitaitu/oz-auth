# Tauri Authenticator — Planning Document

> **A portable Windows desktop TOTP authenticator app built with Tauri v2 + Rust.**
> Like Google Authenticator, but on the desktop. Runs from anywhere — no installer needed.
> Data lives alongside the .exe in a `.auth` file.

---

## 1. Overview

| Aspect | Choice |
|---|---|
| **Platform** | Windows (primary), cross-platform capable |
| **Framework** | Tauri v2 |
| **Backend** | Rust |
| **Frontend** | Vanilla HTML/CSS/JS + Vite (ES modules, `@tauri-apps/api`) |
| **TOTP Library** | `totp-rs` — RFC 6238 compliant, SHA-1/256/512, `otpauth` URI support |
| **Secure Storage** | Portable `.auth` JSON file alongside the `.exe` — AES-256-GCM encrypted secrets, Argon2id key derivation |
| **System Tray** | `tauri` built-in (`tray-icon` feature) |
| **QR Scanning** | Browser `MediaDevices` API + `jsQR` (or Rust-side `rqrr` crate) |

---

## 2. Feature List

### 2.1 Core Features (MVP)

- [ ] **TOTP Code Generation**
  - RFC 6238 compliant (30-second default time step, 6-digit default code)
  - Support SHA-1, SHA-256, SHA-512 algorithms
  - Real-time countdown timer per code
  - One-click copy to clipboard

- [ ] **Account Management**
  - Add account via **manual secret key entry**
  - Add account via **QR code scan** (camera or image paste)
  - Edit account name/issuer
  - Delete account
  - Reorder accounts (drag & drop)

- [ ] **Portable Encrypted Storage**
  - All data saved to a `.auth` JSON file next to the `.exe` (e.g. `app.exe` → `app.auth`)
  - Secrets encrypted with AES-256-GCM, key derived from user's PIN via Argon2id
  - App is fully portable — copy the `.exe` + `.auth` file anywhere
  - **No network access required**
  - Export/import: just copy the `.auth` file

### 2.2 Security Features

- [ ] **App Lock**
  - PIN or password lock on launch / after inactivity
  - PIN is used to derive the AES encryption key — no separate passphrase needed

- [ ] **Clipboard Auto-Clear**
  - Copied codes auto-clear from clipboard after configurable timeout (default 30s)

- [ ] **No Network**
  - App requires no internet permissions — fully offline

### 2.3 Quality of Life

- [ ] **System Tray**
  - Left-click toggles window visibility (show/hide)
  - Right-click context menu: Show, Quit
  - Tray icon shows a real-time countdown pie chart (TOTP timer)

- [ ] **Dark / Light Theme**
  - Follow system preference or manual toggle

- [ ] **Search / Filter**
  - Quick search accounts by name or issuer

- [ ] **Keyboard Shortcuts**
  - `Ctrl+N` — Add account
  - `Ctrl+F` — Search
  - `Ctrl+C` — Copy focused code

---

## 3. Architecture

### 3.1 Directory Structure

```
tauri-authenticator/
├── PLAN.md                          # This document
├── AGENTS.md                        # AI agent instructions
├── README.md                        # User-facing docs
├── index.html                       # Vite entry point
├── package.json                     # Frontend dependencies (Vite, @tauri-apps/api, jsqr)
├── vite.config.js                   # Vite configuration
├── src/                             # Frontend (WebView)
│   ├── main.js                      # Main app init, Tauri event listeners
│   ├── styles/
│   │   ├── main.css                 # Global styles, custom titlebar
│   │   └── themes.css               # Light/dark theme variables
│   ├── js/
│   │   ├── totp.js                  # TOTP display logic (countdown, refresh)
│   │   ├── accounts.js              # Account CRUD UI operations
│   │   ├── qr-scanner.js            # Camera QR scanner
│   │   ├── clipboard.js             # Clipboard helpers
│   │   └── lock.js                  # App lock screen logic
│   └── assets/
│       ├── icons/                   # App icons
│       └── sounds/                  # Optional: copy/scan sounds
│
├── src-tauri/                       # Tauri backend (Rust)
│   ├── Cargo.toml                   # Rust dependencies
│   ├── tauri.conf.json              # Tauri configuration
│   ├── build.rs                     # Tauri build script
│   ├── capabilities/
│   │   └── default.json             # IPC permissions
│   ├── icons/                       # Platform icons
│   └── src/
│       ├── main.rs                  # Entry point (#![windows_subsystem = "windows"])
│       ├── lib.rs                   # App setup, command registration, AppState
│       ├── commands/
│       │   ├── mod.rs
│       │   ├── totp.rs              # TOTP generate/validate commands
│       │   ├── accounts.rs          # Account CRUD commands
│       │   └── auth.rs              # Lock/unlock, backup, auth file management
│       ├── models/
│       │   ├── mod.rs
│       │   └── account.rs           # Account struct (serde)
│       ├── storage/
│       │   ├── mod.rs
│       │   └── auth_file.rs         # .auth file read/write + AES encrypt/decrypt
│       ├── crypto.rs                # Argon2id key derivation + AES-256-GCM
│       ├── paths.rs                 # Exe-relative path resolution
│       ├── config.rs                # App settings struct
│       ├── tray.rs                  # System tray (icon, menu, left-click toggle)
│       ├── diagnostics.rs           # Crash logging, event log
│       └── utils/
│           ├── mod.rs
│           └── otpauth.rs           # otpauth:// URI parser
│
└── .gitignore
```

### 3.2 Data Flow

```
┌──────────────────────────────────────────────────┐
│                    FRONTEND (WebView)              │
│                                                    │
│  ┌─────────┐  ┌──────────┐  ┌───────────────┐    │
│  │  UI     │  │ Account  │  │  QR Scanner   │    │
│  │ (codes, │  │ List     │  │  (camera/     │    │
│  │ timer)  │  │ Manager  │  │   paste)      │    │
│  └────┬────┘  └────┬─────┘  └───────┬───────┘    │
│       │            │                │             │
│       └────────────┼────────────────┘             │
│                    │ invoke()                      │
└────────────────────┼──────────────────────────────┘
                     │  IPC (Tauri Commands)
┌────────────────────┼──────────────────────────────┐
│              BACKEND (Rust)                        │
│                    │                               │
│  ┌─────────────────┼───────────────────────┐      │
│  │           Commands Layer                │      │
│  │  ┌──────────┐ ┌──────────┐ ┌─────────┐ │      │
│  │  │  totp.rs │ │accounts  │ │ auth.rs │ │      │
│  │  │ generate │ │  .rs     │ │         │ │      │
│  │  └────┬─────┘ └────┬─────┘ └────┬────┘ │      │
│  └───────┼────────────┼────────────┼───────┘      │
│          │            │            │               │
│  ┌───────┼────────────┼────────────┼───────┐      │
│  │       ▼            ▼            ▼        │      │
│  │  ┌────────┐  ┌────────────┐  ┌────────┐ │      │
│  │  │ totp-rs│  │ crypto.rs  │  │otpauth │ │      │
│  │  │ crate  │  │ Argon2id + │  │ parser │ │      │
│  │  │        │  │ AES-256-GCM│  │        │ │      │
│  │  └────────┘  └──────┬─────┘  └────────┘ │      │
│  │                     │                    │      │
│  │                ┌────▼─────┐              │      │
│  │                │ storage/ │              │      │
│  │                │.auth file│              │      │
│  │                └──────────┘              │      │
│  └─────────────────────────────────────────┘      │
│                                                    │
│  Support: paths.rs | config.rs | tray.rs           │
│           diagnostics.rs | util/otpauth.rs         │
└──────────────────────────────────────────────────┘
```

### 3.3 TOTP Code Lifecycle

```
1. Account added (manual or QR scan)
     │
2. Secret key encrypted with AES-256-GCM (Argon2id-derived key) → saved to `.auth` JSON file
     │
3. Frontend requests code via `invoke("generate_totp", { account_id })`
     │
4. Rust backend:
     a. Reads `.auth` file, decrypts accounts with in-memory key from AppState
     b. Finds the account, passes secret to `totp-rs` → generates current 6-digit code
     c. Also returns seconds_remaining
     │
5. Frontend displays code + countdown
     │
6. Every 1s: frontend decrements countdown (also updates tray icon pie)
     │
7. Every 30s (or on new window): fetch new code
```

---

## 4. Data Model

### 4.1 `Account` Struct

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub id: String,            // UUID
    pub issuer: String,        // "Google", "GitHub", etc.
    pub label: String,         // "user@example.com"
    pub algorithm: Algorithm,  // SHA1, SHA256, SHA512
    pub digits: u8,            // 6 or 8
    pub period: u32,           // 30 (seconds), sometimes 60
    pub secret: Vec<u8>,       // Raw secret key bytes — #[serde(skip)] in AccountSummary!
    pub sort_order: u32,       // For user-defined ordering
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Frontend-safe view of an account — no secret field exposed over IPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountSummary {
    pub id: String,
    pub issuer: String,
    pub label: String,
    pub algorithm: Algorithm,
    pub digits: u8,
    pub period: u32,
    pub sort_order: u32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub enum Algorithm {
    SHA1,
    SHA256,
    SHA512,
}
```

### 4.2 Storage Schema (`.auth` file)

The `.auth` file is a combined JSON file stored alongside the `.exe` with the same base name.
Holds config, encrypted accounts, and a diagnostics log — all in one portable file.

```
Location:  <exe_dir>/<exe_name>.auth
Example:   C:/apps/tauri-authenticator.exe
           C:/apps/tauri-authenticator.auth
```

The `.auth` file MUST remain visible (not hidden) — users need to see it for backups.

**File structure:**

```json
{
  "version": 1,
  "config": {
    "password_protected": true,
    "password_salt": "<hex-encoded Argon2 salt>",
    "lock_timeout_minutes": 5,
    "width": 320,
    "height": 480,
    "left": 100,
    "top": 100,
    "always_on_top": false,
    "theme": "dark"
  },
  "accounts": {
    "nonce_hex": "<hex-encoded 12-byte AES-GCM nonce>",
    "ciphertext_hex": "<hex-encoded AES-256-GCM ciphertext>",
    "encrypted": true
  },
  "log": "[1718123456] startup: Application started\n[1718123500] account: added GitHub\n"
}
```

**Encryption flow:**
1. User sets a PIN → **Argon2id** (memory-hard) derives a 256-bit key
2. Accounts JSON (`Vec<Account>`) is serialized, encrypted with AES-256-GCM (unique nonce per write)
3. Salt is stored in `config.password_salt` (hex-encoded); nonce stored in `accounts.nonce_hex`
4. On unlock: PIN → Argon2id → decrypt → hold decrypted accounts in memory (Rust `AppState` only)
5. If no PIN is set (`password_protected: false`): accounts stored as plaintext JSON.
   The user is prompted to set a PIN on first launch to enable encryption.

---

## 5. Tauri Commands (IPC API)

| Command | Input | Output | Description |
|---|---|---|---|
| `add_account` | `issuer`, `label`, `secret`, `algorithm?`, `digits?`, `period?` | `Account` | Add a new account |
| `add_account_from_uri` | `otpauth_uri: String` | `Account` | Parse & add from `otpauth://` URI |
| `remove_account` | `account_id: String` | `()` | Delete account |
| `update_account` | `account_id`, `issuer?`, `label?`, `sort_order?` | `Account` | Edit metadata |
| `list_accounts` | `search_query?` | `Vec<AccountSummary>` | List all (or filtered) accounts — **secrets excluded** |
| `generate_code` | `account_id: String` | `(String, u32)` | Get current code + seconds remaining |
| `generate_all_codes` | — | `Vec<(String, String, u32)>` | All codes (id, code, remaining) |
| `export_backup` | `path: String` | `()` | Copy `.auth` file to destination |
| `import_backup` | `path: String` | `()` | Replace current `.auth` with backup |
| `set_lock` | `pin: String` | `()` | Set/change app lock PIN (re-encrypts accounts with new key) |
| `unlock` | `pin: String` | `bool` | Attempt unlock with PIN |
| `is_locked` | — | `bool` | Check if app is currently locked |
| `get_config` | — | `Config` | Get app settings (window state, theme, lock) |
| `update_config` | `Config` | `()` | Save settings |

---

## 6. Frontend UI Design

### 6.1 Main Window

```
┌─────────────────────────────────────────┐
│  [🔍 Search...]              [+ Add]  ⚙ │  ← Toolbar
├─────────────────────────────────────────┤
│                                          │
│  ┌──────────────────────────────────┐    │
│  │  Google                          │    │
│  │  user@example.com    123 456  [📋]│  │  ← Account card
│  │  ████████████░░░░░░░░  22s       │    │     with progress bar
│  └──────────────────────────────────┘    │
│                                          │
│  ┌──────────────────────────────────┐    │
│  │  GitHub                          │    │
│  │  dev@github.com      789 012  [📋]│  │
│  │  ██████░░░░░░░░░░░░░░  10s       │    │
│  └──────────────────────────────────┘    │
│                                          │
│  ┌──────────────────────────────────┐    │
│  │  AWS                             │    │
│  │  admin@aws          345 678  [📋]│  │
│  │  ████████████████████  28s       │    │
│  └──────────────────────────────────┘    │
│                                          │
└─────────────────────────────────────────┘
```

### 6.2 Add Account Dialog

```
┌─────────────────────────────┐
│  Add Account           ✕    │
├─────────────────────────────┤
│                              │
│  [ 📷 Scan QR Code ]         │  ← Opens camera
│                              │
│  ──────── or ────────        │
│                              │
│  Issuer: [GitHub       ]     │
│  Label:  [user@gh.com  ]     │
│  Secret: [JBSWY3DPE... ]     │  ← Manual entry
│                              │
│  Algorithm: [SHA1  ▾]        │
│  Digits:    [6  ▾]           │
│  Period:    [30 ▾]           │
│                              │
│  [     Add Account     ]     │
└─────────────────────────────┘
```

### 6.3 Lock Screen

```
┌─────────────────────────────┐
│                              │
│         🔒                   │
│                              │
│    Tauri Authenticator       │
│                              │
│    Enter PIN: [····]         │
│                              │
│    [Unlock]                  │
│                              │
└─────────────────────────────┘
```

---

## 7. Dependencies

### 7.1 Rust (`Cargo.toml`)

```toml
[package]
name = "tauri-authenticator"
version = "0.1.0"
edition = "2021"

[lib]
name = "authenticator_lib"
crate-type = ["lib", "cdylib", "staticlib"]

[dependencies]
tauri = { version = "2", features = ["tray-icon"] }
tauri-plugin-clipboard-manager = "2"
tauri-plugin-opener = "2"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
totp-rs = { version = "5", features = ["gen_secret", "otpauth"] }
uuid = { version = "1", features = ["v4"] }
chrono = { version = "0.4", features = ["serde"] }
url = "2"
base32 = "0.5"
aes-gcm = "0.10"
argon2 = "0.5"
hex = "0.4"
rand = "0.8"
image = "0.25"

[build-dependencies]
tauri-build = { version = "2", features = [] }
```

### 7.2 Frontend (`package.json`)

```json
{
  "name": "tauri-authenticator",
  "private": true,
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "@tauri-apps/api": "^2.0.0",
    "jsqr": "^1.4.0"
  },
  "devDependencies": {
    "vite": "^6.3.0"
  }
}
```

---

## 8. Implementation Phases

### Phase 1: Skeleton (current phase)
- [ ] Initialize Tauri v2 project with Vite frontend
- [ ] Set up directory structure (per §3.1)
- [ ] Configure `tauri.conf.json`: `decorations: false`, `visible: false`, `devUrl`, `beforeDevCommand`
- [ ] Configure `vite.config.js`, `package.json`, `Cargo.toml`, `capabilities/default.json`
- [ ] Build "Hello World" window (hidden initially, shown via Rust after state restore)
- [ ] Implement custom frameless titlebar (drag region, pin/minimize/close buttons)
- [ ] Implement `paths.rs` (exe-stem derived `.auth` path)
- [ ] Implement `diagnostics.rs` (crash hook → `{exe}.crash`, in-memory event log)

### Phase 2: TOTP Engine
- [ ] Implement `totp-rs` integration in Rust
- [ ] Create `generate_code` command
- [ ] Build frontend display (code + countdown timer)
- [ ] Support SHA-1, SHA-256, SHA-512

### Phase 3: Account Management
- [ ] Implement `.auth` file read/write + AES-256-GCM encrypt/decrypt
- [ ] CRUD commands (add, edit, delete, list)
- [ ] `otpauth://` URI parser
- [ ] Frontend account list UI

### Phase 4: QR Scanning
- [ ] Camera access via WebView `getUserMedia`
- [ ] QR code detection with `jsqr`
- [ ] Fallback: paste QR image or enter secret manually

### Phase 5: Security
- [ ] App lock with PIN
- [ ] Clipboard auto-clear timer
- [ ] Export/import encrypted backup

### Phase 6: Polish
- [ ] System tray integration
- [ ] Dark/light theme
- [ ] Keyboard shortcuts
- [ ] Search/filter accounts
- [ ] Drag & drop reorder

---

## 9. Key Technical Decisions

| Decision | Rationale |
|---|---|
| **`totp-rs` over `cotp`** | More feature-rich, built-in `otpauth` URI parsing, active maintenance |
| **Portable `.auth` file over Stronghold** | No external dependencies, data lives alongside .exe — trivially portable and backup-friendly |
| **Vanilla JS + Vite over React/Svelte** | Small binary, fast HMR in dev, full ES module support, clean production builds |
| **Frontend QR scanning** | Browser APIs are mature; avoids native camera dependencies |
| **No network permission** | Core to the "offline authenticator" trust model |
| **Argon2id + AES-256-GCM** | Memory-hard key derivation (stronger than PBKDF2), standard AES-GCM encryption; PIN-derived key |
| **Custom frameless window** | `decorations: false` with custom titlebar for a modern, clean look |

---

## 10. Open Questions

1. **Frontend framework**: ✅ Resolved — Vanilla JS + **Vite** (provides HMR in dev, minification in prod, clean ES module support).
2. **Window chrome**: ✅ Resolved — **Custom frameless** (`decorations: false`) with a custom titlebar (`data-tauri-drag-region`), pin/minimize/close buttons. Matches the polished a-note look.
3. **Always-on-top mode**: ✅ Resolved — **Yes**, with a [📌] pin button in the custom titlebar.
4. **Auto-start**: ✅ Resolved — Not applicable. The app is portable, not installed.
5. **`.auth` file naming**: Derive from the .exe name at runtime via `std::env::current_exe()`. Multiple copies each have their own `.auth` file.

---

*Plan created: June 12, 2026*
*Next: Phase 1 — Project initialization*
