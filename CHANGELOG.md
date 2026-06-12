# Changelog

All notable changes to oz-auth will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] - 2026-06-12

### Added

#### TOTP Engine
- RFC 6238 compliant TOTP code generation via `totp-rs` v5
- Support for SHA-1, SHA-256, SHA-512 algorithms
- Support for 6 and 8 digit codes
- Configurable time period (30s default, 60s supported)
- Real-time countdown timer per code
- `otpauth://` URI parsing for easy account import

#### Account Management
- Add accounts via manual entry or `otpauth://` URI paste
- Edit account issuer, label, and sort order
- Delete accounts with confirmation
- Drag-and-drop account reordering
- Real-time search/filter by issuer or label

#### Security
- AES-256-GCM encryption for stored secrets
- Argon2id key derivation from user PIN (memory-hard, GPU-resistant)
- Auto-lock after configurable inactivity timeout (default 5 min)
- Clipboard auto-clear after configurable timeout (default 30s)
- Zeroizing of all secrets and keys after use
- `VirtualLock` on Windows to prevent key paging to swap
- Process mitigation policies (blocks dynamic code injection, remote image loads)
- Core dump prevention on Windows and Linux

#### Storage
- Portable `.auth` JSON file alongside the `.exe`
- Combined config, accounts, and diagnostics in one file
- Auto-repair of inconsistent storage states
- Export/import via simple file copy

#### UI/UX
- Custom frameless titlebar with drag region
- Pin window on top toggle
- Dark and light themes (follows system preference)
- System tray with real-time countdown pie icon
- Left-click tray toggles window visibility
- Keyboard shortcuts: `Ctrl+N` (add), `Ctrl+F` (search), `Ctrl+L` (lock), `Escape` (dismiss)
- Toast notifications for actions (account added, code copied, etc.)
- Responsive design with smooth theme transitions

#### Diagnostics
- Crash logging to `{exe}.crash` file
- In-memory event log with automatic trimming

#### Testing
- 249 tests covering crypto, storage, TOTP generation, account CRUD, auth flows, and more

### Security Notes
- QR code scanning intentionally removed to prevent camera/image processing attack surface
- Secrets never leave the Rust backend — only `AccountSummary` (no secret field) sent to frontend
- No network permissions — fully offline operation
