# Contributing to oz-auth

> First off, thanks for considering contributing! oz-auth is a security-focused project, and every contribution helps keep it robust.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Development Setup](#development-setup)
- [Project Overview](#project-overview)
- [Coding Guidelines](#coding-guidelines)
- [Testing](#testing)
- [Security Practices](#security-practices)
- [Pull Request Process](#pull-request-process)
- [CI/CD](#cicd)

---

## Quick Start

```bash
# Prerequisites: Rust 1.80+, Node.js 18+

git clone https://github.com/kardelitaitu/oz-auth.git
cd oz-auth
npm install

# Start development with hot-reload
cargo tauri dev

# Run all checks before committing
npm run build                         # Frontend build
cd src-tauri && cargo fmt --check     # Rust formatting
cargo clippy -- -D warnings           # Rust linting
cargo test                            # Rust tests (116+)
cargo audit                           # Dependency vulnerability scan
cargo deny check                      # License & duplicate check
```

---

## Development Setup

### Prerequisites

| Tool     | Minimum Version | Install                                 |
|----------|-----------------|-----------------------------------------|
| Rust     | 1.80+           | [rustup.rs](https://rustup.rs/)         |
| Node.js  | 18+             | [nodejs.org](https://nodejs.org/)       |
| npm      | 9+              | Bundled with Node.js                    |

### Optional Tools

```bash
cargo install cargo-audit                  # Vulnerability scanning
cargo install cargo-deny                   # License & duplicate checking
cargo install cargo-fuzz                   # Fuzzing (requires nightly)
```

### Install Dependencies

```bash
npm install              # Frontend deps (Vite, @tauri-apps/api)
```

The Rust dependencies (`cargo build`) are fetched automatically on first build.

### Development Workflow

```bash
# Start the full app with hot-reload
cargo tauri dev

# The Vite dev server runs on http://localhost:1420
# The Tauri window opens automatically with the dev URL
```

### Environment

- **Vite dev server**: port `1420` (configured in `vite.config.js`)
- **Tauri dev URL**: `http://localhost:1420` (configured in `src-tauri/tauri.conf.json`)
- **No `.env` file** needed — the app has no external API keys or secrets to configure

---

## Project Overview

### Architecture

```
┌─────────────────┐     ┌──────────────────────┐     ┌──────────┐
│  WebView (JS)    │ IPC │  Rust Backend         │ I/O │ .auth     │
│  Vanilla JS+Vite │◄───►│  AES-256-GCM + Argon2 │◄───►│ File      │
│  No network      │     │  Zeroize on drop      │     │ (Portable)│
└─────────────────┘     └──────────────────────┘     └──────────┘
```

### Directory Layout

```
tauri-authenticator/
├── src/                        # Frontend (WebView)
│   ├── main.js                 # Entry point, IPC calls
│   ├── js/
│   │   ├── accounts.js         # Account CRUD UI
│   │   ├── totp.js             # TOTP code display, countdown
│   │   ├── lock.js             # Lock screen, PIN entry
│   │   ├── settings.js         # Settings dialog
│   │   ├── clipboard.js        # Auto-clear clipboard
│   │   └── dragdrop.js         # Drag-and-drop reorder
│   └── styles/
│       ├── main.css            # Global styles, titlebar, cards
│       └── themes.css          # Dark/light CSS variables
├── src-tauri/                  # Rust backend
│   ├── src/
│   │   ├── main.rs             # Entry, process mitigation
│   │   ├── lib.rs              # App builder, AppState, IPC registry
│   │   ├── crypto.rs           # Argon2id + AES-256-GCM
│   │   ├── commands/
│   │   │   ├── auth.rs         # Lock/unlock, PIN, backup
│   │   │   ├── accounts.rs     # CRUD operations
│   │   │   └── totp.rs         # TOTP code generation
│   │   ├── storage/
│   │   │   └── auth_file.rs    # .auth file read/write + encrypt
│   │   ├── models/
│   │   │   └── account.rs      # Account + AccountSummary
│   │   ├── config.rs           # App settings
│   │   ├── tray.rs             # System tray
│   │   ├── paths.rs            # Exe-relative path resolution
│   │   ├── diagnostics.rs      # Crash logging
│   │   └── utils/
│   │       └── otpauth.rs      # otpauth:// URI parser
│   ├── fuzz/                   # Cargo-fuzz targets
│   │   └── fuzz_targets/
│   │       ├── parse_uri.rs
│   │       ├── decode_secret.rs
│   │       └── decrypt.rs
│   ├── Cargo.toml
│   ├── deny.toml               # cargo-deny config
│   └── .cargo/
│       └── audit.toml          # cargo-audit config
├── SECURITY.md                 # Threat model & security boundaries
├── WHITEPAPER.md               # Design philosophy & threat analysis
├── SECURITY_AUDIT_PLAN.md      # Audit plan & gap tracking
├── AGENTS.md                   # AI assistant instructions
├── PLAN.md                     # Architecture & feature roadmap
└── build.mjs                   # Vite build script
```

---

## Coding Guidelines

### Rust

- **Edition**: 2021
- **Formatting**: `cargo fmt` (runs in CI)
- **Linting**: `cargo clippy -- -D warnings` (zero warnings required)
- **Idioms**: Follow standard Rust 2021 patterns. Prefer `&str` over `&String`, use `thiserror` for error types, derive `Debug + Clone + Serialize + Deserialize` on all public types.
- **Safety**: The app uses `unsafe` only for `VirtualLock`/`VirtualUnlock` (Windows) and `prctl` (Linux). Any new `unsafe` block must include a `// SAFETY:` comment.
- **Error handling**: Tauri commands return `Result<T, String>` for simple cases. Internal functions use idiomatic Rust error handling (no unwraps in production paths).
- **Ownership**: Tauri app state is managed via `tauri::manage()` with `Mutex` for shared mutable state (encryption key, tray).
- **Naming**: `snake_case` for functions/variables, `CamelCase` for types, `SCREAMING_SNAKE_CASE` for constants.

### JavaScript

- **Modules**: ES modules (`export`/`import`) — no CommonJS.
- **No `var`**: Use `const` by default, `let` when reassignment is needed.
- **Style**: Functions over classes; prefer pure functions with explicit parameters.
- **DOM**: Cache DOM queries at module init where possible.
- **Linting**: ESLint is configured — run via `npx eslint src/` to check.

### CSS

- **Theming**: Use CSS custom properties for all colors (defined in `themes.css`).
- **Naming**: BEM-like conventions (`.account-card`, `.account-card__code`, `.account-card--active`).
- **Stack**: No CSS framework — hand-written, minimal, `system-ui` font stack.
- **Responsive**: Mobile-first (though desktop-primary, keep flexible).

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add account search by issuer
fix: prevent crash on empty otpauth URI
security: zeroize salt buffer after derive_key
docs: add fuzzing setup instructions
refactor: extract TOTP generation into helper
test: add roundtrip property tests for encrypt/decrypt
```

Use the `security:` prefix for security-relevant changes (zeroization, timing fixes, etc.).

---

## Testing

### Rust Tests

```bash
# Run all tests
cd src-tauri && cargo test

# Run library tests (excludes integration tests)
cd src-tauri && cargo test --lib

# Run a specific test
cd src-tauri && cargo test test_name
```

The project has **116+ tests** covering:

- **Cryptography**: AES-256-GCM encrypt/decrypt roundtrips, Argon2id key derivation
- **Authentication**: PIN set/unlock/change flows, backup/restore
- **Account CRUD**: Add, edit, delete accounts with encrypted storage
- **URI parsing**: `otpauth://` URI parsing with various edge cases
- **TOTP generation**: Code generation with SHA-1/256/512, 6/8 digit codes

### Adding Tests

- Every new function added to `commands/` should have unit tests in the same file (`#[cfg(test)] mod tests { ... }`).
- Every new module should have at least a basic smoke test.
- For cryptographic changes, include roundtrip property tests where practical.
- Test file I/O by writing to temporary directories (`tempfile` or manual temp dirs).

### Frontend Testing

The frontend currently has no automated test framework. When adding JS logic:

- Keep functions pure and side-effect-free where possible (DOM updates handled in `main.js`).
- Manual test: verify the feature works end-to-end via `cargo tauri dev`.

### Fuzzing (Optional, Nightly Only)

The project has three cargo-fuzz targets in `src-tauri/fuzz/`:

| Target          | Function Fuzzed                   |
|-----------------|-----------------------------------|
| `parse_uri`     | `utils::otpauth::parse_uri`       |
| `decode_secret` | `commands::accounts::decode_secret`|
| `decrypt`       | `crypto::decrypt`                 |

Requires nightly Rust:
```bash
rustup install nightly
cd src-tauri && cargo +nightly fuzz run parse_uri -- -runs=100000
```

> **Note**: Tauri v2 currently has a trait conflict on nightly that may block compilation. Once resolved, these targets are ready to run.

---

## Security Practices

> ⚠️ **oz-auth is a security-sensitive application.** Every contribution must consider memory safety and attack surface.

### Memory Safety

- **All secrets must be zeroized**: Use `Zeroizing<T>` for any buffer containing PINs, keys, salts, plaintext, or account secrets.
- **No unnecessary copies**: Avoid `.clone()` on secret data. Prefer consuming ownership (e.g., `String::from_utf8(vec)` over `String::from_utf8(vec.clone())`).
- **Release allocations**: After `clear()` on a `Vec` containing secrets, call `shrink_to_fit()` to release the backing memory.
- **Stack secrets**: `Zeroizing<[u8; N]>` for fixed-size arrays. Note that intermediate compiler copies on the stack are not zeroized — this is a known limitation.

### Cryptography

- **Only use**: AES-256-GCM (`aes-gcm` v0.10) for encryption, Argon2id (`argon2` v0.5) for key derivation, OS-provided `OsRng` for randomness.
- **No custom crypto**: Never implement cryptographic primitives from scratch. Use established, audited crates.
- **Constant-time**: PIN validation must use constant-time error paths — all decrypt failures return `Ok(false)`, never distinguishing between "wrong PIN" and "corrupted data".

### Supply Chain

- **Dependency scanning**: `cargo audit` and `cargo deny` must pass before merging.
- **Minimal dependencies**: Avoid pulling in large dependency trees. The app's binary size matters — it's a portable single-file executable.
- **No network deps**: The Rust binary must not include HTTP client libraries. Network access is denied at the capability level.

### Review Checklist for Security-Sensitive Changes

- [ ] Are all secret buffers wrapped in `Zeroizing`?
- [ ] Are there any `.clone()` calls on secret data?
- [ ] Are error messages crafted to avoid leaking information?
- [ ] Are `unsafe` blocks justified with a `// SAFETY:` comment?
- [ ] Do the changes respect the constant-time error path requirement?
- [ ] Have the changes been tested for encrypt/decrypt roundtrip correctness?
- [ ] Does `cargo audit` still pass?
- [ ] Does `cargo deny check` still pass?

---

## Pull Request Process

### Before Submitting

1. **Create an issue** for the change you want to make (unless it's trivial).
2. **Discuss the approach** — security-sensitive changes especially benefit from early feedback.
3. **Implement** — follow the coding guidelines above.
4. **Self-review** — run the full check suite:

```bash
cd src-tauri
cargo fmt --check          # Formatting
cargo clippy -- -D warnings  # Linting (zero warnings)
cargo test                   # Tests (all pass)
cargo audit                  # Vulnerability scan
cargo deny check             # License & duplicate check
cd .. && npx eslint src/     # Frontend linting
```

5. **Write a clear commit message** following Conventional Commits (see above).

### PR Requirements

- **Title**: Brief, descriptive (e.g., "Add account search by issuer field").
- **Description**: What changed, why, and how to verify.
- **Size**: Keep PRs focused on a single concern. Large PRs are harder to review, especially for security.
- **Tests**: New features should include tests. Bug fixes should include a regression test.
- **Documentation**: Update README, AGENTS.md, or SECURITY.md if the change affects user-facing behavior or security posture.

### Review Process

1. A maintainer will review the PR within 2-3 business days.
2. For security-sensitive changes, expect a detailed review with specific questions about the security properties.
3. Address all review comments before the PR is merged.

### What Not to Do

- ❌ Do not introduce new `unsafe` blocks without thorough justification and a `// SAFETY:` comment.
- ❌ Do not add network-accessible code (HTTP clients, DNS resolution, WebSocket support).
- ❌ Do not add dependencies that pull in large transitive trees (check `cargo tree --depth 1`).
- ❌ Do not introduce panicking code in production paths (use `Result` + idiomatic error propagation).
- ❌ Do not store secrets in the `localStorage`, `sessionStorage`, or IndexedDB of the WebView.
- ❌ Do not hide the `.auth` data file or move it to a hidden appdata directory — it must remain visible next to the `.exe` so users can find it for backups and portability.

---

## CI/CD

The project uses **GitHub Actions** (`.github/workflows/security.yml`) running on every push and PR to `main`:

| Step                    | What It Checks                          |
|-------------------------|-----------------------------------------|
| `cargo audit`           | Known vulnerabilities in dependencies   |
| `cargo deny check`      | License compliance, duplicate versions  |
| `cargo clippy`          | Rust linting (deny warnings)            |
| `cargo test`            | All unit and integration tests          |
| `cargo fmt --check`     | Rust formatting                         |
| `cargo build --release` | Full release build (ensures it compiles)|

**All CI checks must pass** before a PR can be merged.

---

## Getting Help

- Open an issue on GitHub for questions about the codebase
- For security vulnerabilities, see [SECURITY.md](./SECURITY.md#vulnerability-reporting) for the private disclosure process
- Check [PLAN.md](./PLAN.md) for the feature roadmap and architecture overview

---

*Thank you for contributing to oz-auth — every contribution helps make desktop 2FA more secure.*
