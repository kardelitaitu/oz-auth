# oz-auth — Whitepaper

> Why a desktop TOTP authenticator? Why no internet? Why now?

---

## 1. The Problem: 2FA Codes in the Browser

Two-factor authentication (2FA) is one of the most effective defenses against account takeover. Every major service — Google, GitHub, Microsoft, AWS, banking portals — supports or requires TOTP-based 2FA. Yet the most common way people manage their 2FA codes is through a **browser extension** or a **phone app**.

Both have fundamental security flaws that undermine the very protection 2FA is supposed to provide.

### 1.1 The Browser: An Inherently Hostile Environment

Modern browsers are extraordinarily complex pieces of software, comprising tens of millions of lines of code across rendering engines (Chromium, WebKit, Gecko), JavaScript virtual machines, networking stacks, GPU pipelines, and thousands of internal APIs. This complexity creates an enormous attack surface.

The browser was designed for a world of connectivity, interactivity, and real-time communication — not for storing cryptographic secrets. Every browser extension you install runs with deep privileges into every page you visit. Extensions can read and modify web page content, intercept network requests, access storage APIs, and communicate with remote servers.

Consider this attack chain:

1. A popular browser extension is acquired by a malicious actor (a growing trend)
2. An update pushes code that exfiltrates all data from authenticator extension storage
3. The user's 2FA seeds — intended to protect their accounts — are now in the hands of an attacker
4. The user has no way to detect this; the extension still works normally

This isn't theoretical. Supply-chain attacks on browser extensions have been documented repeatedly. In 2024 alone, multiple widely-used extensions were compromised through developer account takeovers, pushing malicious updates to millions of users.

### 1.2 The Phone: Closed but Not Secure

Phone-based authenticators (Google Authenticator, Microsoft Authenticator, Authy, etc.) are more secure than browser extensions, but they introduce a different set of problems:

- **Phone theft**: Your phone contains your life — banking apps, email, social media, messaging, and your 2FA codes. If someone gains access to your unlocked phone, they have everything.
- **Cloud backup leakage**: Most phone authenticators back up to iCloud or Google Drive. If your cloud account is compromised (a far more common occurrence than device theft), the encrypted seeds are available for offline brute-force.
- **Sync poisoning**: Some authenticators sync across devices via cloud accounts. If an attacker gains access to your sync account, they can silently add their own device to receive your 2FA codes.
- **Platform dependency**: You're tied to a specific mobile ecosystem. Switching platforms (iOS → Android or vice versa) can be difficult or impossible without resetting all your 2FA seeds.
- **No desktop workflow**: When you're working at a computer, reaching for your phone to type a 2FA code is friction. Workflows like copy-paste, search, and multi-account management are far more natural on a desktop.

---

## 2. The Threat Landscape: Why This Matters Now

### 2.1 Infostealers Are Rampant

Infostealer malware — RedLine, Vidar, Raccoon, AuroraStealer — has become a commodity. These trojans target browser-stored credentials, cookies, and extension storage. In 2023-2024, infostealers compromised tens of millions of devices globally. Their primary target is browser data, precisely because browsers are where secrets live.

When an infostealer runs on a machine, it:
1. Extracts all saved passwords from the browser's credential store
2. Harvests cookies for active sessions (bypassing password login entirely)
3. Dumps storage from authenticator extensions — including TOTP seeds
4. Exfiltrates everything to a command-and-control server

The result: **the attacker has both your password AND your 2FA seed**, completely defeating the purpose of 2FA.

**A desktop app that manages 2FA codes outside the browser eliminates this entire attack vector.** The authenticator seed never touches the browser's storage APIs, extension framework, or JavaScript engine. It lives in a native Rust process that the browser has no access to.

### 2.2 Browser Extensions: A Growing Supply-Chain Risk

The browser extension ecosystem has a fundamental trust problem:

- **Permissions are coarse**: An extension that needs "read and change all your data on all websites" to provide a basic feature (password management, grammar checking, ad blocking) also has access to every page you visit, every form you fill, and every storage API call.
- **Updates are automatic**: When an extension updates, you don't review the diff. You trust the developer, the marketplace, and the supply chain. Each link in that chain can break.
- **Acquisitions are common**: A beloved free extension gets acquired by a larger company. The new owners monetize it. Sometimes benignly. Sometimes not.
- **Developer account takeovers**: A developer's account credentials are leaked, and a malicious update is pushed. Users notice nothing because the extension still functions.

When your 2FA seeds live in a browser extension, you're trusting that every one of these links holds, indefinitely.

### 2.3 The WebView2 Security Boundary

Tauri uses the system's WebView2 runtime (on Windows) to render the user interface. This is the same underlying engine as Edge and Edge WebView — a hardened, sandboxed component that receives security patches through Windows Update.

The critical architectural difference:

| Aspect | Browser Extension | oz-auth (Tauri Desktop) |
|--------|------------------|----------------------|
| Secret storage | Browser extension storage (chrome.storage, localStorage) | Rust native struct with `Zeroizing` wrapper |
| Code execution | In-browser JavaScript, same process space as other extensions | Native Rust binary, separate process |
| Network access | Full network permissions (often required) | **None** — application has `no-network` capability |
| Memory access | Subject to browser-level inspection (devtools, other extensions) | OS-level process isolation; `VirtualLock` prevents paging |
| Supply chain | Auto-updating, coarse permissions | Binary distributed as single .exe; user controls updates |

---

## 3. The Design Philosophy: Offline by Default

### 3.1 No Network, No Telemetry, No Cloud

oz-auth is designed with a single hard constraint: **the application must never make a network request**. Not for updates, not for telemetry, not for analytics, not for crash reporting, not for anything.

This constraint is enforced at two levels:

1. **Capability-based**: Tauri v2's permission system explicitly denies all network access. The `capabilities/default.json` manifest does not include the `core:default` permission set, opting instead for a minimal allow-list of only the IPC commands the app needs.

2. **Architectural**: The Rust backend has no HTTP client libraries, no DNS resolution code, no TLS stack. It literally cannot make network requests even if an attacker found a code path to try.

The result: **even if an attacker achieved arbitrary code execution within the WebView's JavaScript context, there is no network API available to exfiltrate data.**

### 3.2 Portable by Design

oz-auth stores all data in a single `.auth` JSON file alongside the `.exe`. There is no installer, no registry entries, no global configuration, no system-level database. The app runs from any folder, on any drive, from a USB stick, from a network share.

This portability has security implications:

- **No system-level persistence**: The app leaves no trace on the host system. Remove the .exe and the `.auth` file, and the app is gone.
- **User controls the data file**: The `.auth` file is visible, not hidden. Users can back it up, encrypt it with their own tools, store it on a hardware token, or keep it on an encrypted USB drive.
- **No cloud dependency**: There is no "forgot your PIN?" flow, no account recovery, no sync. The data is wherever you put it. This is a feature, not a bug.

### 3.3 Memory Hardening

Secrets exist in memory for the shortest possible time:

- The encryption key is wrapped in `Zeroizing<[u8; 32]>` — a wrapper that overwrites the bytes with zeros when the value goes out of scope. Rust's ownership model guarantees this happens deterministically, unlike garbage-collected languages.
- On Windows, `VirtualLock` pins the encryption key page in physical RAM, preventing the OS from swapping it to disk where it could be recovered from a pagefile.
- After every TOTP generation, all decrypted account secrets are immediately zeroized.
- After every encrypt/decrypt operation, all intermediate buffers (plaintext JSON, nonce, ciphertext) are zeroized.
- Derived keys and salts from PIN operations are zeroized immediately after use.
- The frontend (WebView) never sees raw secrets — only `AccountSummary` objects that lack the `secret` field entirely.

---

## 4. Comparison: oz-auth vs. Alternatives

| Property | oz-auth | Browser Extension | Phone Authenticator | Hardware Token (YubiKey) |
|----------|---------|-------------------|--------------------|---------------------------|
| **Offline** | ✅ Enforced at OS level | ❌ Extension has network access | ✅ Generally offline | ✅ Fully offline |
| **No browser dependency** | ✅ Native app | ❌ Runs inside browser | ✅ Native app | ✅ Hardware |
| **Portable** | ✅ Single .exe + .auth file | ❌ Bound to browser profile | ❌ Bound to phone | ✅ Hardware token |
| **Backup** | ✅ Copy .auth file | ❌ Depends on browser sync | ❌ Cloud backup or lost | ❌ Cannot backup |
| **Memory hardened** | ✅ Zeroizing + VirtualLock | ❌ JavaScript GC | ✅ Platform-dependent | ✅ N/A (no secrets in RAM) |
| **Supply-chain resistant** | ✅ Single binary; user controls updates | ❌ Auto-updating extensions | ❌ App store auto-updates | ✅ Firmware signed |
| **Desktop workflow** | ✅ Copy-paste, search, multi-account | ✅ Same, but insecure | ❌ Pick up phone | ❌ Touch token each time |
| **Cost** | ✅ Free, open source | ✅ Free | ✅ Free | ❌ $25-65 per token |

---

## 5. Limitations and Trade-offs

### 5.1 No QR Code Scanning (Removed)

oz-auth initially included QR code scanning via the browser's `getUserMedia` API and the `jsqr` library. This feature was removed because:

- **Camera access expands the attack surface**: The `getUserMedia` API is a powerful capability. Granting it to a Tauri WebView window introduces additional complexity in the permission model.
- **QR codes are a one-time operation**: The secret key from a QR scan is needed only at account creation time. The ongoing risk of a camera-attached permission outweighs the convenience benefit.
- **Manual entry or file import is safer**: Users can type the secret key, paste it from a screenshot, or use an `otpauth://` URI — all without camera access.

The `otpauth://` URI parser is still present in the codebase for users who obtain the URI via other means (screenshot OCR, QR-to-text tools, etc.).

### 5.2 Windows-Only (Primary Target)

The primary build target is Windows. The codebase is written with cross-platform considerations (no Windows-specific API calls where avoidable), but the binary is tested primarily on Windows 10 and Windows 11. Linux and macOS builds are technically possible with modifications to the tray icon and process mitigation code.

### 5.3 No Biometric Lock

The app uses a numeric PIN for encryption key derivation, rather than Windows Hello or biometric authentication. This is intentional:

- **No platform lock-in**: Biometric APIs differ significantly between Windows, macOS, and Linux. A PIN works identically everywhere.
- **Argon2id requires the PIN directly**: The PIN is the input to the key derivation function. There is no clean way to derive a cryptographic key from a biometric sample without additional platform-specific APIs.

---

## 6. Conclusion

The proliferation of browser-based authenticators has created a dangerous blind spot in the 2FA trust model. Users who diligently enable two-factor authentication on every service they use are unknowingly storing the seeds to those accounts in the same software stack that handles untrusted JavaScript from millions of websites — the browser.

oz-auth takes a different approach: move the 2FA codes out of the browser entirely, into a native desktop application that has no network access, no extension framework, and no cross-origin attack surface. The trade-off is that you must manually add accounts and you cannot sync across devices. But for users who value security over convenience — and for threat models where the adversary has access to the same browser — this trade-off is the right one.

**Your 2FA codes should not live in the same place you browse the web.**

---

*"Just codes. No network."*

MIT © kardelitaitu
