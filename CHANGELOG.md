# Changelog

All notable changes to oz-auth.

## [0.1.1] — Unreleased

### Added
- **QR Code on right-click** — generate a QR code from any account for easy import on another device
- **Backup all keys** — export all account secrets as `otpauth://` URIs to a `.txt` file from Settings (with ⚠ plaintext warning)
- **Search icon** — magnifying glass inside the search box with focus highlight
- **New pin icon** — replaced outlined pin with a filled thumbtack SVG in the titlebar
- **Titlebar icon animation** — pin, minimize, and close buttons now wiggle on hover (matching toolbar icons)
- **Rounded search box** — softer `8px` border-radius and `"Search . . ."` placeholder

## [0.1.0] — 2026-06-13

Initial release.

### Core
- TOTP code generation — RFC 6238 compliant with SHA-1, SHA-256, and SHA-512
- 6-digit and 8-digit codes, 30s and 60s periods
- Auto-refreshing codes with countdown ring animation
- System tray icon with time-remaining pie indicator

### Security
- AES-256-GCM encryption for account secrets at rest
- Argon2 key derivation for PIN-based encryption
- Memory hardening — secrets and keys zeroized after use, `VirtualLock` on Windows, core dump prevention
- PIN protection with auto-lock on inactivity (configurable timeout)
- Clipboard auto-clear after configurable seconds

### Account Management
- Add accounts manually (issuer, label, secret) or paste `otpauth://` URIs
- Edit issuer/label, delete accounts with confirmation dialog
- Drag & drop reorder via ≡ handle
- Right-click context menu (Edit / Delete)
- Search/filter accounts by issuer or label (Ctrl+F)

### UI
- Frameless custom titlebar with minimize, always-on-top, and close buttons
- Dark/light theme toggle with system preference detection
- Toolbar icon animations (wiggle, bounce, spin)
- Toast notifications for actions and errors
- Keyboard shortcuts: Ctrl+N (add), Ctrl+F (search), Ctrl+L (lock), Escape (close dialogs)

### Backward Compatibility
- Version-aware `.auth` file format (v1 → v2 auto-upgrade)
- `#[serde(default)]` on all optional account fields (algorithm, digits, period, sort_order, timestamps)
- Corrupted or missing `.auth` file gracefully falls back to defaults

### Testing
- 309+ tests across all modules
- RFC 6238 test vectors for all three SHA algorithms
- Property-based testing with proptest
- Full PIN lifecycle, CRUD, crypto, and edge case coverage
