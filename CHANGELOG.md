# Changelog

All notable changes to oz-auth.

## [0.1.6] — 2026-06-14

### Added
- **File locking** — advisory file locking via `fs2` crate: exclusive lock on writes (`atomic_write`), shared lock on reads (`try_load`), prevents TOCTOU races between concurrent instances
- **Windows CI** — `.github/workflows/windows.yml`: clippy + test + fmt + build + npm audit + vitest on `windows-latest`
- **Security documentation** — 8 items marked complete, supported version bumped, threat model updated in `SECURITY.md`
- **Advisory audit** — `CODEBASE_REVIEW.md` with full review across all 7 areas (crypto, models, auth, accounts, bootstrap, frontend, config)

### Changed
- **`try_load()` self-deadlock fix** — file handle (holding `lock_shared`) scoped so shared lock is released before `flush_and_save` acquires exclusive lock; resolves Windows `LockFileEx` deadlock
- **`derive_key()` returns `Zeroizing<[u8; 32]>`** — type-level enforcement prevents accidental key copies; all callers updated
- **`Account.secret` → `Zeroizing<Vec<u8>>`** — automatic zeroization on drop for all secret fields; `AccountSummary`/`Account` separation enforced via serde
- **`Config.password_salt` → `Zeroizing<String>`** — defense-in-depth for salt in memory
- **IPC input length validation** — `validate_length()` on all IPC commands (PIN 4-128, issuer 1-128, label 1-256, URI 1-4096, account_id 1-128, search 0-256, path 1-4096)
- **`paths.rs` hardened** — 4 `.expect()` calls converted to `Result` returns; all callers handle errors gracefully
- **`settings.js` refactored** — replaced all `innerHTML` string templates with pure DOM APIs (`createElement`, `textContent`, `appendChild`); removed `esc()` helper
- **`accounts.js` refactored** — replaced `innerHTML` card builder with DOM APIs including proper SVG namespace (`createElementNS`); empty state uses DOM methods
- **CSS deduplication** — removed duplicate dark theme CSS variables from `main.css`; single source in `themes.css`
- **Startup double-read fixed** — `.auth` file loaded once instead of twice during initialization
- **Version sync** — `tauri.conf.json` → `0.1.6` matching `Cargo.toml` and `package.json`

### Testing
- **589 total tests** — 485 Rust + 104 Vitest, all passing
- Clippy clean (zero warnings)
- New tests: PIN strength indicator, IPC validation, file lock integrity, DOM structure assertions via `textContent` / `children`

## [0.1.5] — 2026-06-14

### Added
- **167 new tests** — total test count reaches 472; 11 bug fixes covering edge cases in PIN lifecycle, QR parsing, CRUD operations
- **Test helper extraction** — shared test utilities extracted for reuse across unit and integration tests
- **Documentation** — expanded README with platform/security/code size badges, animated GIF demo, updated screenshots

### Changed
- **`.auth` file caching** — `AppState` caches `.auth` data with mtime-based staleness detection; avoids redundant disk reads
- **Screenshot/demo assets** — updated PNG screenshots, GIF slider, SVG assets for README
- **Icon handling** — fixed PNG icon RGBA format, `TrueColorAlpha` conversion, Linux icon compilation
- **`zeroize` updated** — 1.8.2 → 1.9.0

### Removed
- **`docs/` directory** — removed obsolete planning documents (`SECURITY_AUDIT_PLAN.md`)

### CI
- Linux system dependencies installed for Tauri build on ubuntu

## [0.1.4] — 2026-06-13

### Added
- **Security audit trail** — append-only signed audit log for all security events (auth, CRUD, config, backup, import, system)
- **Audit trail viewer** — in-app UI showing chronological event log with hash chain verification
- **Audit coverage** — all CRUD operations and config changes now logged; verified via tests

### CI
- `npm audit` job added to security workflow
- Weekly scheduled security scan

### Dependencies
- Vite upgraded to 8.0.16
- `esbuild` added as explicit dependency

## [0.1.3] — 2026-06-13

### Added
- **Rate limiting** — exponential backoff on failed PIN attempts (saturating add, 30s cap)
- **Auto-lock on focus loss** — window blur triggers lock after configurable timeout
- **Frontend lock guards** — defense-in-depth for all PIN handlers (set/change/verify), backup/QR handlers, and import/export
- **Content Security Policy** — `default-src 'self'` with tight restrictions; no eval, no inline scripts in production

### Changed
- **Clipboard clearing** — clipboard auto-clears on lock, preventing secret exposure after session ends
- **XSS hardening** — additional sanitization for user-controlled content

## [0.1.2] — 2026-06-13

### Added
- **Lock guard on `change_pin`** — PIN change requires unlocked state
- **Lock guard on `import_backup`** — import requires unlocked state

### Fixed
- **QR code popup** — `accountId` nulled before use, causing blank popup; fixed ordering in event handler

### Changed
- **`accounts.rs` refactored** — split into `crud.rs` and `qr.rs` sub-modules for maintainability

## [0.1.1] — 2026-06-13

### Added
- **Backup & restore** — export all encrypted keys to `.oz-backup` file, import from file
- **QR code display** — right-click context menu option to show QR code for any account
- **Backup confirmation popup** — modal confirmation before overwriting existing backup

### Changed
- **UI polish** — search icon, PIN icon, rounded corners, titlebar wiggle animation

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
