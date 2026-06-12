# oz-auth — Memory Safety Audit Plan

> A phased, evidence-driven plan to harden oz-auth's memory safety
> against information disclosure via memory dumps, swap files, and side-channel attacks.

---

## Current Security Posture

oz-auth already implements several memory-safety best practices:

| Practice | Status | Location |
|----------|--------|----------|
| `Zeroizing<[u8; 32]>` for encryption key | ✅ Done | `AppState` in `lib.rs` |
| `Zeroize` trait on key buffers | ✅ Done | `crypto.rs`, `commands/auth.rs` |
| Explicit `.zeroize()` calls | ✅ Done | Key copies, salt, nonce, ciphertext, account secrets |
| `VirtualLock` on Windows | ✅ Done | Encryption key in `AppState::set_key()` |
| `VirtualUnlock` on unlock | ✅ Done | `AppState::clear_key()` |
| Process mitigation policies | ✅ Done | `main.rs` — blocks dynamic code, remote image loads |
| No network libraries in dependencies | ✅ Done | `Cargo.toml` has no HTTP client |
| `AccountSummary` excludes secrets | ✅ Done | Compile-time guarantee via struct design |
| Auto-zeroize on `lock()` | ✅ Done | `clear_key()` drops the `Zeroizing` wrapper |

This plan addresses the gaps identified during the audit.

---

## Phase 1: Tooling & Supply Chain (Day 1)

### 1.1 Install `cargo-audit`

Scan `Cargo.lock` against the RustSec Advisory Database for known vulnerabilities in dependencies.

```bash
cargo install cargo-audit
cargo audit  # Should pass cleanly
```

**Expected result:** Zero known vulnerabilities. If any are found, update the affected crate immediately.

### 1.2 Install `cargo-deny`

Enforce license compliance and detect duplicate dependencies.

```bash
cargo install cargo-deny
cargo deny init
cargo deny check
```

**Expected result:** All dependencies use MIT/Apache-2.0 licenses (Rust ecosystem standard).

### 1.3 Add CI Pipeline

Add a GitHub Actions workflow that runs on every push:

```yaml
# .github/workflows/security.yml
- cargo audit
- cargo deny check
- cargo clippy -- -D warnings
- cargo test
- cargo fmt --check
```

---

## Phase 2: `secrecy` Crate Integration (Day 1-2)

### 2.1 Problem

Currently, the encryption key is wrapped in `Zeroizing<[u8; 32]>`, but:
- It can still be printed accidentally via `Debug` (though there's no code doing this)
- It can be cloned — `get_key()` returns `Option<Zeroizing<[u8; 32]>>` which uses `Clone`
- There's no type-level protection against passing the key to non-security functions

### 2.2 Solution

Add the `secrecy` crate and wrap all secret types in `Secret<T>`:

```toml
# Cargo.toml
secrecy = { version = "0.10", features = ["zeroize"] }
```

**Changes required:**

| File | Change |
|------|--------|
| `lib.rs` | `encryption_key: Mutex<Option<Secret<[u8; 32]>>>` |
| `lib.rs` | `set_key()` accepts `Secret<[u8; 32]>`, prevents debug output |
| `crypto.rs` | `encrypt()` and `decrypt()` accept `&Secret<[u8; 32]>` |
| `commands/auth.rs` | Wrap derived keys in `Secret<T>` after derivation |
| `commands/accounts.rs` | Wrap keys in `Secret<T>` before passing to storage |

### 2.3 Key Benefit

`Secret<T>` prevents:
- Accidental debug logging of key material (`Debug` is redacted)
- Accidental display (`Display` is redacted)
- Makes the security boundary explicit at the type level

---

## Phase 3: Constant-Time Comparison (Day 2)

### 3.1 Problem

The PIN comparison in `unlock()` is not constant-time:

```rust
// In unlock() — the PIN is used to derive a key, then we try to decrypt.
// If decryption fails with "wrong password", the attacker learns the PIN
// was incorrect. But the comparison itself (AES-GCM authentication tag
// verification) IS constant-time in aes-gcm. However, the error message
// path is NOT constant-time:
//
//   if e.contains("wrong password") || e.contains("corrupted") { Ok(false) }
//   else { Err(e) }
//
// A timing attacker could distinguish "wrong password" from "corrupted data"
// based on the error string matching.

// Also: PIN length matters. The Argon2id derivation takes ~constant time
// for a given PIN length, but different PIN lengths may take different
// amounts of time.
```

### 3.2 Solution

Add the `subtle` crate for constant-time operations:

```toml
subtle = "2"
```

**Changes:**

1. **Pad PINs to a fixed length before key derivation** — Pre-pad the PIN with a known character to a maximum length (e.g., 128 chars) before passing to Argon2id. This eliminates PIN-length timing leakage.

2. **Use constant-time error path** — Ensure the error branching in `unlock()` does not leak whether the failure was "wrong PIN" vs "corrupted data" through timing. Return `Ok(false)` in all error cases.

---

## Phase 4: Zeroizing Gaps (Day 2-3)

### 4.1 Problem: `plaintext.clone()` in `crypto.rs`

```rust
// crypto.rs — decrypt() function
let result = String::from_utf8(plaintext.clone()).map_err(...)?;
plaintext.zeroize();
```

`plaintext.clone()` creates a copy of the decrypted plaintext in memory. The clone is only dropped when `result` goes out of scope, which could be far from the zeroization point. If a memory dump happens between the clone and the zeroize, there are two copies of the plaintext in memory.

**Fix:** Use `Vec::into_iter()` or `String::from_raw_parts` to avoid the clone:

```rust
let result = String::from_utf8(plaintext.clone())?; // unavoidable clone for error handling
plaintext.zeroize();
// At this point, the clone lives as `result`. It will be zeroized by the caller.
```

Actually, `String::from_utf8` takes ownership of the `Vec<u8>`, so no clone is needed:

```rust
// Better:
let result = String::from_utf8(plaintext)
    .map_err(|e| format!("invalid utf-8: {e}"))?;
// plaintext is consumed — no clone
```

This is the cleanest fix. `from_utf8` takes ownership of the `Vec<u8>`.

### 4.2 Problem: Salt is a raw `Vec<u8>`

In `commands/auth.rs`, the salt is decoded from hex into `Vec<u8>`, then zeroized. But:
- The `Vec<u8>` could be reallocated during decoding, leaving copies
- There's no `Zeroizing` wrapper on the salt

**Fix:** Use `Zeroizing<Vec<u8>>` for salts:

```rust
let mut salt = Zeroizing::new(
    hex::decode(&data.config.password_salt)
        .map_err(|e| format!("invalid salt: {e}"))?
);
```

### 4.3 Problem: `config.password_salt` is plain `String`

The salt is stored as a plain hex `String` in `Config`. While hex-encoded, the raw salt bytes are also present in memory as decoded `Vec<u8>` during operations.

**Fix:** This is acceptable. The hex string itself doesn't leak the salt's value without Argon2id knowledge. The decoded salt bytes are now wrapped in `Zeroizing<Vec<u8>>`.

### 4.4 Problem: Password/PIN strings from Tauri IPC

When the frontend sends a PIN via `invoke("unlock", { pin: "..." })`, the PIN arrives as a Rust `String`. This string lives in memory until it's dropped. Rust has no way to zeroize the original allocation in the Tauri IPC buffer.

**Fix:** This is a Tauri framework limitation. Mitigate by:
- Copying the PIN into a `Zeroizing<Vec<u8>>` immediately on receipt
- Dropping the original `String` (letting Rust's allocator reclaim it)
- Noting that Tauri's IPC uses WebView2 message passing — the PIN is also present in the WebView's JS heap

### 4.5 Problem: `generate_salt()` returns raw `[u8; 16]`

```rust
pub fn generate_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    salt
}
```

The salt is a stack-allocated array. It's copied by value everywhere it's used. Each copy remains on the stack until overwritten by other function calls.

**Fix:** Return `Zeroizing<[u8; 16]>` to ensure automatic zeroing on drop. But note: stack copies are not zeroized — this is a fundamental limitation. The `Zeroizing` wrapper helps for the primary copy but not for intermediate register/stack copies.

### 4.6 Problem: Account secrets in `Vec<Account>` on the heap

When accounts are decrypted, the entire `Vec<Account>` is on the heap. While the code calls `a.secret.zeroize()` and `accounts.clear()`, `Vec::clear()` does not release the heap allocation — it only sets `len` to 0. The capacity is retained.

**Fix:** Call `accounts.shrink_to_fit()` after clearing to release the backing allocation. Or better, use `Vec::into_boxed_slice()` which drops the spare capacity.

---

## Phase 5: Process Hardening (Day 3)

### 5.1 Application-Backed Memory

Research whether the encryption key should use `VirtualAlloc` with `PAGE_NOACCESS` guard pages instead of standard heap allocation. The current `Zeroizing` wrapper lives on the Rust heap, which is managed by the global allocator.

**Potential improvement:** Allocate key memory via `mmap`/`VirtualAlloc` with:
- Guard pages before and after the allocation (detect buffer overflows)
- `MEM_PRIVATE` + `PAGE_READWRITE` then `PAGE_NOACCESS` when locked
- Custom allocator that returns page-aligned, locked memory

This is a significant change and may be overkill for this application's threat model. Document as a future consideration.

### 5.2 Stack Scrubbing

Rust does not automatically zero stack frames when functions return. This means:
- Local variables containing secret material remain on the stack
- Subsequent function calls overwrite them eventually, but not deterministically

**Mitigation:** There's no portable way to scrub the stack in Rust. The `zeroize` crate provides `Zeroize::zeroize()` for types that implement it, but stack variables go out of scope without zeroing. This is a known limitation.

### 5.3 Disable Core Dumps

Prevent the OS from writing core dumps that could contain secret material:

```rust
// In main.rs, before any secret handling:
#[cfg(unix)]
unsafe {
    libc::prctl(libc::PR_SET_DUMPABLE, 0);
}

#[cfg(windows)]
unsafe {
    // Windows: SetProcessMitigationPolicy already handles some of this
    // But also disallow crash dumps via registry or API
}
```

For Windows specifically, the `SetProcessMitigationPolicy` call in `main.rs` already blocks some information disclosure paths. Add explicit crash dump prevention.

---

## Phase 6: Fuzzing (Day 3-4)

### 6.1 Install `cargo-fuzz`

```bash
cargo install cargo-fuzz
```

### 6.2 Create Fuzz Targets

| Target | Function | Input |
|--------|----------|-------|
| `parse_uri` | `utils::otpauth::parse_uri` | Arbitrary strings |
| `decode_secret` | `commands::accounts::decode_secret` | Arbitrary strings |
| `decrypt_accounts` | `storage::auth_file::decrypt_accounts` | Corrupted ciphertext + nonce |
| `generate_code_impl` | `commands::totp::generate_code_impl` | Random account IDs + state |

### 6.3 Expected Findings

- `parse_uri` with malformed URIs should return `Err`, not panic
- `decode_secret` with random bytes should not panic
- `decrypt_accounts` with corrupted ciphertext should return `Err`

---

## Phase 7: Verification (Day 4-5)

### 7.1 Run Full Audit Suite

```bash
# Supply chain
cargo audit
cargo deny check

# Linting
cargo clippy -- -D warnings

# Memory safety (nightly)
cargo +nightly miri test  # Detects UB in unsafe code

# Fuzzing
cargo fuzz run parse_uri -- -runs=100000
cargo fuzz run decode_secret -- -runs=100000
cargo fuzz run decrypt_accounts -- -runs=100000

# Functional
cargo test
cargo fmt --check

# Build
cargo build --release
```

### 7.2 Manual Review Checklist

- [ ] All `unsafe` blocks reviewed and justified (currently: `VirtualLock`, `VirtualUnlock`, `SetProcessMitigationPolicy`)
- [ ] No `String` or `Vec<u8>` containing secrets without `Zeroizing` wrapper
- [ ] All `expect()` calls reviewed and justified
- [ ] No `unwrap()` in production code paths
- [ ] All error messages avoid leaking secret material
- [ ] Clipboard clear timer correctly implemented
- [ ] Auto-lock timer correctly implemented

---

## Phase 8: Future Considerations (Post-Audit)

### 8.1 Hardware-Backed Security

- **TPM-backed key storage**: Store the encryption key in the TPM and derive it only when unlocked. This would protect against cold boot attacks and memory dumps.
- **Windows Hello integration**: Use biometric unlock with TPM-backed keys. Requires `winrt` / `windows-rs` crate.

### 8.2 Formal Verification

- **Proptest**: Property-based testing for `encrypt`/`decrypt` roundtrips with random inputs
- **Kani**: Rust formal verifier for memory safety of critical paths (if using nightly)

### 8.3 Third-Party Audit

Engage a professional security firm (e.g., [Cure53](https://cure53.de/), [Trail of Bits](https://www.trailofbits.com/)) for a full-source audit before v1.0 release.

---

## Priority Matrix

| Phase | Effort | Impact | Priority |
|-------|--------|--------|----------|
| P1: Tooling & CI | 1 day | High (prevents known vulns) | **Critical** |
| P2: `secrecy` crate | 1 day | Medium (type-level safety) | **High** |
| P3: Constant-time | 1 day | Medium (timing attack mitigation) | **High** |
| P4: Zeroizing gaps | 1 day | High (closing existing gaps) | **Critical** |
| P5: Process hardening | 1 day | Low-Medium (defense in depth) | Medium |
| P6: Fuzzing | 2 days | Medium (catches edge cases) | Medium |
| P7: Verification | 1 day | High (proves the work) | **Critical** |
| P8: Future work | Ongoing | Variable | Low |

---

## Summary of Gaps Found

| # | Severity | Gap | Location | Fix |
|---|----------|-----|----------|-----|
| 1 | 🔴 **High** | `plaintext.clone()` creates extra copy | `crypto.rs:27` | Use `String::from_utf8(plaintext)` instead |
| 2 | 🔴 **High** | No `cargo-audit` in toolchain | — | Install, add to CI |
| 3 | 🟡 **Medium** | No `secrecy::Secret<T>` wrapper | `lib.rs`, `crypto.rs` | Wrap key in `Secret<T>` |
| 4 | 🟡 **Medium** | No constant-time PIN handling | `commands/auth.rs` | Add `subtle` crate, pad PINs |
| 5 | 🟡 **Medium** | Salt is raw `Vec<u8>` | `commands/auth.rs` | Wrap in `Zeroizing<Vec<u8>>` |
| 6 | 🟡 **Medium** | `generate_salt()` returns raw array | `crypto.rs` | Return `Zeroizing<[u8; 16]>` |
| 7 | 🟢 **Low** | `Vec::clear()` doesn't release capacity | `commands/auth.rs`, `commands/accounts.rs` | Add `shrink_to_fit()` or `into_boxed_slice()` |
| 8 | 🟢 **Low** | No core dump prevention | `main.rs` | Add platform-specific dump prevention |
| 9 | 🟢 **Low** | No fuzzing setup | — | Create `cargo-fuzz` targets |
| 10 | 🟢 **Low** | No CI pipeline | — | Add GitHub Actions |

---

*Planned: June 2026*
*Next: Phase 1 — Tooling installation and CI setup*
