# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.4   | ✅ Current release |
| 0.1.x   | ✅ Active development — security fixes land in `main` |

---

## Threat Model

oz-auth is a **offline-first, memory-hardened** TOTP authenticator designed to protect
2FA seeds from the most common attack vectors targeting browser-based authenticators.

### In-Scope Protections

| Threat | Mitigation |
|--------|------------|
| **Infostealer malware** harvesting browser extension storage | Secrets live in a native Rust process — never in browser storage, extension APIs, or JavaScript heap accessible to other browser contexts. |
| **Browser extension supply-chain attacks** | The app is a standalone native binary. No extension framework, no auto-updating third-party code, no browser permissions model. |
| **Memory dump / pagefile recovery** | `Zeroizing` overwrites key bytes on drop. `VirtualLock` pins the encryption key in physical RAM (Windows). All intermediate buffers (salt, nonce, ciphertext, plaintext JSON) are explicitly `zeroize()`'d. |
| **Cross-site scripting (XSS) within WebView** | The WebView has no network capability — even with arbitrary JS execution, there is no `fetch()`, `XMLHttpRequest`, or `WebSocket` available. The Rust backend enforces strict IPC typing. |
| **Timing side-channel on PIN verification** | PINs are padded to 128 bytes before Argon2id hashing (constant-time input length). The `unlock()` endpoint returns `Ok(false)` for ALL decryption failures, preventing error-message-based timing leakage. |
| **Clipboard snooping** | TOTP codes copied to clipboard are auto-cleared after `clipboard_clear_seconds` config (default 30s). The clipboard is readable by any process on the same desktop session. |
| **Crash dump exposure** | Windows: `SetErrorMode(SEM_NOGPFAULTERRORBOX)` suppresses crash dialog (note: WER can still write `.dmp` files to `%LOCALAPPDATA%\CrashDumps`). Linux: `prctl(PR_SET_DUMPABLE, 0)` disables core dumps. |
| **Dependency vulnerabilities** | `cargo-audit` and `cargo-deny` run in CI on every push. Dependencies are audited against the RustSec Advisory Database. |
| **Dynamic code injection** | `SetProcessMitigationPolicy(PROCESS_DYNAMIC_CODE_POLICY)` blocks `VirtualAlloc` + `EXECUTE` on Windows. |
| **DLL injection / process hollowing** | `SetProcessMitigationPolicy(PROCESS_SIGNATURE_POLICY)` in audit mode (blocks non-Microsoft-signed DLLs when feasible). `PROCESS_IMAGE_LOAD_POLICY` blocks remote/UNC and low-integrity image loads. |
| **Offline brute-force of .auth file** | Argon2id key derivation is memory-hard (GPU-resistant). Even if an attacker copies the `.auth` file, brute-forcing the PIN is computationally expensive. Salt is unique per PIN. |
| **Screen capture / overlay attacks** | TOTP codes are displayed in the WebView. Malware with screen capture access can read codes. Mitigation: codes auto-refresh every 30s, limiting the window. (See Out-of-Scope for full analysis.) |
| **IPC input length DoS** | Tauri's IPC serialization has implicit buffer limits. The Rust backend validates required fields (non-empty PIN, non-empty secret). Future: explicit max-length checks on all string inputs. |
| **Audit trail tampering** | The audit trail uses a SHA-256 hash chain. Each entry references its predecessor via `SHA256(prev_entry)`. Any modification, removal, or reordering breaks the chain and is detectable via `verify_chain()`. The frontend can only read the audit log — no IPC command clears or modifies it. |

### Out-of-Scope / Accepted Risks

| Limitation | Rationale |
|------------|-----------|
| **Keylogging** — a local keylogger can capture the PIN as it's typed | PINs arrive via Tauri IPC from the WebView. The OS input stack cannot be bypassed by the application. Use OS-level anti-keylogging (e.g., Windows Defender, hardware keyboard). |
| **Debugger attachment** — a debugger (WinDbg, GDB) attached to the process can read all memory | If an attacker has debugger privileges on the machine, all bets are off. Pin-based encryption provides no protection at this privilege level. |
| **Cold-boot / RAM acquisition** — physical memory capture after `lock()` | `Zeroizing` ensures key bytes are overwritten, but residual capacitor charge in RAM chips can survive brief power loss (cold boot attack). Mitigation: use a TPM-backed keystore (future work). |
| **WebView2 compromise** — a zero-day in the WebView2 rendering engine | The WebView has no network access. The Rust backend validates all IPC inputs. A WebView compromise is limited to UI manipulation and IPC calls against validated command handlers. |
| **Side-channel (power analysis, EM, cache timing)** | The app runs on a general-purpose OS where these attacks require physical access and specialized equipment. Not in scope for v0.1. |
| **Supply chain: Tauri framework vulnerabilities** | oz-auth uses Tauri v2 with minimum necessary capabilities. Framework-level vulnerabilities are mitigated by the app's minimal attack surface (no file system access, no shell access, no network). |
| **Screen capture by privileged malware** | Any process with screen capture access (e.g., `PrintWindow`, `BitBlt`) can read TOTP codes while displayed. This is a fundamental limitation of displaying secrets on screen. Mitigation: codes auto-refresh every 30s, limiting the exposure window. Users running untrusted software alongside oz-auth accept this risk. |
| **Supply chain: compromised dependency** | While `cargo-deny` rejects unknown registries and `cargo-audit` scans for known CVEs, a targeted backdoor in a trusted crate could evade detection. Mitigation: minimal dependency tree, lockfile pinning. Future: `cargo-vet` for third-party auditing. |
| **.auth file backup exposure** | Users who copy the `.auth` file to insecure locations (cloud sync, shared drives) expose encrypted secrets. The file is encrypted when a PIN is set, but weak PINs are vulnerable to offline brute-force. Mitigation: user education, future PIN strength guidance. |
| **Clipboard hijacking before auto-clear** | Malware monitoring the clipboard can capture codes during the 30s window before auto-clear. Mitigation: users should verify codes are cleared after use. Future: Windows clipboard encryption (Win10+ `CF_UNICODETEXT` with `CLIPBRD_USE_OLE`). |

---

## Security Architecture

```
┌──────────────────────────────────────────────────────┐
│                   User Machine                        │
│                                                        │
│  ┌─────────────────────┐     ┌──────────────────────┐  │
│  │   WebView (UI)       │     │   Rust Backend        │  │
│  │                      │     │                       │  │
│  │  - Renders HTML/CSS  │ ◄──►│  - IPC command handler│  │
│  │  - No network access │ IPC │  - TOTP code generator│  │
│  │  - No extension API  │     │  - AES-256-GCM crypto │  │
│  │  - No persistent     │     │  - Argon2id KDF       │  │
│  │    storage           │     │  - File I/O (.auth)   │  │
│  └─────────────────────┘     │  - Zeroize on drop    │  │
│                               └──────────────────────┘  │
│                                                        │
│  ┌──────────────────────────────────────────────────┐  │
│  │  Data File (.auth)                               │  │
│  │  - Exe-adjacent JSON file                        │  │
│  │  - Encrypted when PIN is set (AES-256-GCM)       │  │
│  │  - Plaintext when no PIN (fresh install)          │  │
│  └──────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────┘
```

### Key Properties

1. **No network stack** — The Rust binary has zero HTTP client libraries in its dependency graph. Network access is denied at the OS capability level.
2. **Secrets never reach the UI** — The `AccountSummary` type (what the frontend receives) has no `secret` field. The native backend manages all raw secret operations (encrypt, decrypt, TOTP code generation).
3. **Explicit zeroization** — Every buffer containing secret material (plaintext, key, salt, nonce, ciphertext, account secrets) is explicitly `zeroize()`'d after use.
4. **PIN is not stored** — The PIN is never written to disk. Only the Argon2id salt is stored. The PIN is used only to derive the encryption key, then immediately zeroized.
5. **Key-on-lock invariant** — When locked, `AppState.clear_key()` drops the `Zeroizing` wrapper, overwriting the encryption key in memory. The key must be re-derived from the PIN to unlock.
6. **In-memory cache with staleness detection** — Decrypted `AuthData` is cached in `AppState` and validated against file mtime on each access. The cache is invalidated on every save, preventing stale reads. External file modifications (e.g., backup import) are detected via mtime comparison.
7. **.auth file visible by design** — The `.auth` file is intentionally kept visible (not hidden) so users can find it for backups and portability.

---

## Security Boundaries

### What the Rust Backend Controls

- **Encryption/decryption** of the `.auth` file (AES-256-GCM)
- **Key derivation** (Argon2id with salt rotation on PIN change)
- **Memory zeroization** of all secret buffers
- **PIN validation** (constant-time error paths)
- **File I/O** (read/write `.auth` data file)
- **Process mitigation policies** (Windows code-injection prevention, core dump suppression)
- **VirtualLock** to prevent key from being paged to disk
- **Audit trail** (SHA-256 hash chain, append-only, frontend read-only)
- **Rate limiting** (exponential backoff on failed PIN attempts)

### What the Rust Backend Does NOT Yet Control

- **IPC input length validation** — No max-length checks on string parameters (PIN, issuer, label, secret, URI, path). Tauri's IPC has implicit limits, but the Rust side should enforce explicit bounds.
- **PIN strength enforcement** — No minimum length or complexity requirement beyond non-empty.
- **File locking** — No advisory locking on `.auth` file reads/writes (TOCTOU risk with concurrent access).

### What the WebView Controls

- **UI rendering** — display TOTP codes, account list, settings
- **IPC calls** — the frontend invokes Rust commands via `@tauri-apps/api`
- **No raw secrets** — the frontend only receives `AccountSummary` (no `secret` field)
- **No network** — the WebView's `capabilities` manifest denies all network access
- **No persistent storage** — `localStorage`, `sessionStorage`, `IndexedDB` are not used

### What the User Controls

- **The `.auth` data file** — it sits alongside the `.exe` (intentionally visible, not hidden). Users can back it up, copy it to another machine, or encrypt it externally. The `.auth` file is a self-contained JSON with version, config, encrypted accounts, and audit log.
- **The PIN** — users choose the PIN length and complexity. There is no minimum length (beyond non-empty), no complexity requirement, and no lockout.
- **Executable placement** — running from an encrypted volume (BitLocker, VeraCrypt) adds a layer of file-at-rest protection.

---

## Planned Security Improvements

| Priority | Item | Status | Description |
|----------|------|--------|-------------|
| High | IPC input length validation | Planned | Add max-length checks on all string IPC inputs (PIN, issuer, label, secret, URI, path) to prevent memory exhaustion DoS. |
| High | `derive_key()` return type | Planned | Change return type from `[u8; 32]` to `Zeroizing<[u8; 32]>` to prevent accidental key copies on the stack. |
| Medium | `Account.secret` Zeroizing | Planned | Change `secret: Vec<u8>` to `secret: Zeroizing<Vec<u8>>` for automatic zeroization. |
| Medium | `paths.rs` error handling | Planned | Convert 4 `.expect()` calls to `Result` returns to prevent panics on exe path resolution failure. |
| Medium | PIN strength guidance | Planned | Add optional PIN complexity check (min 6 digits, reject common PINs) with user override. |
| Low | `Config.password_salt` Zeroizing | Planned | Wrap salt in `Zeroizing<String>` for defense-in-depth (salt is not secret, but zeroizing reduces exposure window). |
| Low | File locking on .auth | Planned | Use advisory file locking during read/write to prevent TOCTOU race conditions between concurrent access. |
| Future | TPM-backed keystore | Backlog | Use Windows DPAPI or TPM to protect the encryption key, eliminating cold-boot attack vector. |
| Future | Encrypted backup format | Backlog | Export/import with user-supplied passphrase (separate from PIN) for secure backup transfer. |
| Future | `cargo-vet` integration | Backlog | Third-party dependency auditing beyond `cargo-audit`/`cargo-deny`. |

---

## Vulnerability Reporting

If you discover a security vulnerability in oz-auth, please report it privately:

1. **Open a GitHub Security Advisory** at `https://github.com/kardelitaitu/oz-auth/security/advisories/new`
2. Or email the maintainer directly (see commit history for contact)

**Please do not file public issues for security vulnerabilities.**

### Response Timeline

- **Acknowledgement**: Within 48 hours
- **Triage & fix**: Within 7 days for critical vulnerabilities
- **Disclosure**: Coordinated public disclosure after fix is deployed

### Scope

The following are in scope for vulnerability reports:

- The Rust backend (`src-tauri/src/`)
- Cryptographic implementation (`src-tauri/src/crypto.rs`, `src-tauri/src/commands/auth.rs`, `src-tauri/src/storage/auth_file.rs`)
- IPC command handlers (`src-tauri/src/commands/`)
- Data serialization (`src-tauri/src/models/`)
- Build and dependency configuration (`src-tauri/Cargo.toml`, `src-tauri/deny.toml`)

The following are **out of scope**:

- Tauri framework vulnerabilities (report to Tauri team)
- WebView2 engine vulnerabilities (report to Microsoft)
- UI-specific issues (CSS injection, XSS within WebView) without IPC escalation
- Social engineering of the maintainer

---

## Dependencies & Supply Chain

oz-auth uses `cargo-audit` and `cargo-deny` in CI to scan for known vulnerabilities and license compliance on every push.

### Current Advisory Status

| Tool | Status | Notes |
|------|--------|-------|
| `cargo audit` | ✅ Passes | Unmaintained crates (GTK/Wayland/unic — all transitive Linux deps) are suppressed via `.cargo/audit.toml` |
| `cargo deny` | ✅ Passes | Licenses: MIT, Apache-2.0, BSD, ISC, Zlib, Unicode-3.0, CC0-1.0, BSL-1.0, MPL-2.0 |

### Safe Defaults

- `cargo deny` warns on duplicate dependency versions
- `cargo deny` rejects unknown registry/git sources
- Private dependencies (path dependencies) are excluded from license checks

---

## Security-Relevant Bug Fixes (v0.1.1)

| Fix | Severity | Description |
|-----|----------|-------------|
| PIN change key zeroization order | Critical | `change_pin_impl` zeroed the new key before storing it, breaking the app after PIN change. Fixed by reordering: store key first, then zeroize old key. |
| TOTP period=0 division-by-zero | High | `make_totp()` panics when `period=0`. Now validated and rejected before code generation. |
| Silent data loss on lock | High | `set_lock_impl` used `unwrap_or_default()` on malformed JSON, wiping accounts during PIN setup. Now returns an explicit error. |
| Clipboard auto-clear fires immediately | Medium | `setTimeout(..., 0)` wiped the code instantly when timeout was 0. Now only clears when timeout > 0. |
| Settings save race condition | Medium | Shared debounce timer across inputs caused rapid changes to cancel earlier saves. Now uses per-field timers. |
| Account IDs not HTML-escaped | Medium | Raw account IDs injected into HTML `data-id` attributes. Now escaped via `escapeHtml()`. |
| parse_uri accepted hotp URIs | Low | `otpauth://hotp/...` URIs were silently accepted. Now only `totp` type is accepted. |

---

## Testing

- **476 tests** across all Rust modules (unit + property-based) and JS frontend (Vitest)
- Shared test infrastructure in `test_utils.rs` (test_app_state, cleanup_auth_file, with_fs_lock)
- Proptest 1.11 compatibility (generic return types, `prop_assert!` Result handling)
- Coverage: 100% on crypto, config, paths, otpauth, account models; 85-97% on commands; 55% on lib.rs (Tauri command wrappers require WebView2 for full coverage)

---

## Cryptographic Primitives

| Operation | Algorithm | Implementation |
|-----------|-----------|----------------|
| Symmetric encryption | AES-256-GCM | `aes-gcm` crate (v0.10) |
| Key derivation | Argon2id (default params) | `argon2` crate (v0.5) |
| Random number generation | OS-provided CSPRNG | `rand::rngs::OsRng` |
| TOTP code generation | RFC 6238 | `totp-rs` crate (v5) |
| Memory zeroization | `Zeroize` trait | `zeroize` crate (v1.9) |

---

*Questions? Open an issue or start a discussion on GitHub.*
