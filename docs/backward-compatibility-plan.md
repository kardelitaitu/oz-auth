# Backward Compatibility Plan — `.auth` File Format

## 1. Current Format (Version 1)

The `.auth` file is a JSON document living alongside the `.exe`. Its structure:

```json
{
  "version": 1,
  "config": {
    "width": 320,
    "height": 480,
    "left": 100,
    "top": 100,
    "always_on_top": false,
    "theme": "dark",
    "password_protected": false,
    "password_salt": "",
    "lock_timeout_minutes": 5,
    "clipboard_clear_seconds": 30
  },
  "accounts": {
    "encrypted": false,
    "nonce_hex": null,
    "ciphertext_hex": null,
    "data_json": "[]"
  },
  "log": ""
}
```

## 2. Threat Model — What Could Change

### Adding new fields (most common)
| Area | Examples |
|------|---------|
| `Config` | `auto_lock`, `theme_accent`, `minimize_to_tray`, `hotkey` |
| `Account` / `AccountSummary` | `notes`, `tags`, `icon`, `counter` (HOTP), `account_type` |
| `AccountsPayload` | encryption algorithm version, key derivation params |
| `AuthData` | new top-level sections like `settings`, `profiles` |

### Changing existing fields
- Renaming a field (e.g. `data_json` → `plaintext`)
- Changing a field type (e.g. `u32` → `u64`, `String` → enum)
- Changing serialization format (JSON → JSON with comments, or CBOR)

### Cryptographic changes
- Switching from AES-256-GCM to a different cipher
- Changing nonce size (currently 12 bytes)
- Changing KDF from Argon2id to something else or tuning params
- Adding key-wrapping or multi-key support

### Structural changes
- Splitting into multiple files
- Adding a header before the JSON payload
- Compressing the accounts payload

## 3. Current Strengths (Already Good)

| Pattern | Where | How it helps |
|---------|-------|-------------|
| `#[serde(default)]` | `encrypted`, `password_protected`, `password_salt`, `clipboard_clear_seconds`, `lock_timeout_minutes` | Missing fields → use Rust's `Default` |
| `#[serde(default = "fn")]` | `theme`, `lock_timeout_minutes`, `clipboard_clear_seconds` | Missing fields → custom default |
| `#[serde(skip_serializing_if)]` | `nonce_hex`, `ciphertext_hex`, `data_json` | Optional fields don't pollute output |
| No `deny_unknown_fields` | all structs | Serde ignores extra fields by default |
| `version: u32` at top level | `AuthData` | Foundation for format migration |
| `reconcile_invariants()` | `auth_file.rs` | Fixes in-memory inconsistencies on load |

## 4. Recommended Strategy

### 4.1 Version-Aware Load Pipeline

Replace the current `try_load()` with a pipeline that always runs through version-based upgrades:

```
try_load()
  ↓
read raw JSON string
  ↓
deserialize into AuthData (serde ignores unknown fields ✅)
  ↓ [NEW] check data.version vs CURRENT_VERSION
  ↓ [NEW] for each intermediate version, run upgrade_vN_to_vN+1(&mut data)
  ↓
run reconcile_invariants(&mut data)  (existing)
  ↓
save if anything changed (version bump, reconcile, etc.)
  ↓
return AuthData (always at CURRENT_VERSION in memory)
```

### 4.2 Upgrade Function Pattern (Serde_json::Value Route)

All upgrades operate on `serde_json::Value` **before** deserializing into the typed struct.
This unlocks the ability to handle field renames, type changes, and structural migrations
that are impossible after serde has deserialized into fixed Rust types.

```rust
/// Upgrade v1 → v2: add 'lock_timeout_minutes' default and bump version.
fn upgrade_v1_to_v2(value: &mut serde_json::Value) -> bool {
    let mut changed = false;

    // Add missing config fields with their canonical defaults
    if let Some(config) = value.get_mut("config") {
        if let Some(obj) = config.as_object_mut() {
            if !obj.contains_key("lock_timeout_minutes") {
                obj.insert("lock_timeout_minutes".into(), serde_json::json!(5));
                changed = true;
            }
            // Future: rename old_field → new_field
            // if let Some(old) = obj.remove("old_field") {
            //     obj.insert("new_field".into(), old);
            //     changed = true;
            // }
        }
    }

    changed
}
```

This pattern also handles **field renames** effortlessly (serde_json::Value is stringly-typed)
and **type migrations** (e.g. `String` → `serde_json::Value` by parsing or transforming).

### 4.3 Write-Format Rule

**Always write at `CURRENT_VERSION`.** Never write an older version. This ensures:
- The file is always self-describing at the latest format
- Old `.exe` versions may not read the file → which is **acceptable** because the plan is only about **new .exe → old .auth file**
- A single migration path (v1 → v2 → v3 → ...)

### 4.4 Serde Field-Addition Checklist

When adding ANY new field to any struct that appears in `.auth`:

| Step | Action |
|------|--------|
| 1 | Add `#[serde(default)]` OR `#[serde(default = "fn_name")]` to the field |
| 2 | If the field has a meaningful default (e.g. `false`, `0`, `""`), just `#[serde(default)]` |
| 3 | If the default requires logic, write a default function and use `#[serde(default = "...")]` |
| 4 | **If the field is security-critical** (e.g. new auth mode), add an invariant check in `reconcile_invariants()` |
| 5 | Write a unit test that deserializes a JSON fixture *without* the new field and verifies the default is applied |
| 6 | Write a unit test that the round-trip preserves both old and new fields |

### 4.5 Field Rename Strategy

**Never remove or rename a field in the same version.** Instead:

1. Add the new field with `#[serde(default)]` and `#[serde(alias = "old_name")]` if you want to accept old JSON
2. Or add an upgrade function that copies the old value:
```rust
fn upgrade_v1_to_v2(data: &mut AuthData) -> bool {
    // data.old_field no longer exists in struct — serde will have deserialized
    // it into the new field if we used #[serde(alias)], OR it gets the default.
    // The old value is lost unless we handle it in the upgrade.
    if data.version == 1 {
        // Option: read raw JSON via serde_json::Value to extract old fields
        // before deserializing into AuthData, then apply migration
        data.version = 2;
        true
    } else {
        false
    }
}
```

**Alternative (more robust):** Read the raw `serde_json::Value` first, check `version`, apply transformations on the `Value`, then deserialize into `AuthData`. This gives full control over migrations.

## 5. Concrete Implementation Steps

### Step 1: Add Two-Phase Load (raw Value → upgrade → typed struct)

In `auth_file.rs`, add:

```rust
/// Two-phase load: deserialize to Value first, apply version upgrades,
/// then convert to AuthData.
pub fn try_load() -> Result<AuthData, String> {
    let path = auth_path();
    if !path.exists() {
        return Ok(fresh());
    }

    let raw = std::fs::read_to_string(&path)
        .map_err(|e| format!("failed to read {}: {e}", path.display()))?;

    // Phase 1: parse raw JSON to detect version
    let mut json_value: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|e| format!("failed to parse {}: {e}", path.display()))?;

    // Phase 2: apply version upgrades (mutates json_value)
    let version = json_value.get("version").and_then(|v| v.as_u64()).unwrap_or(0);
    let upgraded = upgrade_json(&mut json_value, version);

    // Phase 3: deserialize into typed struct
    let mut data: AuthData = serde_json::from_value(json_value)
        .map_err(|e| format!("failed to deserialize {}: {e}", path.display()))?;

    // Phase 4: reconcile invariants (existing)
    if reconcile_invariants(&mut data) || upgraded {
        save(&data)?;
    }

    Ok(data)
}
```

### Step 2: Add Upgrade Orchestrator

```rust
/// Apply all version upgrades sequentially.
/// `version` is the version found in the file (0 if missing).
/// Returns true if any mutation occurred.
fn upgrade_json(value: &mut serde_json::Value, mut version: u64) -> bool {
    let mut changed = false;

    // v0 (no version field) → v1: add default version + ensure fresh defaults
    if version < 1 {
        // Any pre-v1 file would be version 1 format — just set version
        value["version"] = serde_json::json!(1);
        version = 1;
        changed = true;
    }

    // Future: v1 → v2
    // if version < 2 { upgrade_v1_to_v2(value); version = 2; changed = true; }

    // Future: v2 → v3
    // if version < 3 { upgrade_v2_to_v3(value); version = 3; changed = true; }

    value["version"] = serde_json::json!(version);
    changed
}
```

### Step 3: Reinforce Serde Patterns on All Structs

| Struct | Current state | What to add |
|--------|--------------|-------------|
| `Account` | No `#[serde(default)]` on any field | Add `#[serde(default)]` on all non-essential fields: `notes`, `tags`, etc. (no existing fields need it since they're all required today) |
| `AccountSummary` | Same as Account | Mirror whatever Account has |
| `Config` | Good — `#[serde(default)]` or `default_fn` on all fields | ✅ Already done |
| `AccountsPayload` | `#[serde(default)]` on `encrypted`, skip/option on others | ✅ Already good — `Option` types handle missing fields |
| `AuthData` | `version` is required (no default) | Add `#[serde(default = "default_version")]` so missing version → 0 → upgraded to 1 |

### Step 4: Write Compatibility Tests

Each test should:

1. **Old-format deserialization** — hardcode a JSON string matching version N format, deserialize as current AuthData, verify defaults fill gaps
2. **Version upgrade** — write a version N file to disk, load with current code, verify version is bumped and file is rewritten
3. **Round-trip preservation** — create an AuthData with custom values, serialize, deserialize, verify all fields preserved
4. **Unknown field passthrough** — include `"unknown_field": "should be preserved"` in JSON, verify it survives a save-load cycle (or at minimum doesn't crash)
5. **Encrypted payload erosion** — encrypt accounts at version X, verify they decrypt at version Y

```rust
#[test]
fn test_old_v1_file_upgraded_on_load() {
    // Simulate a v1 file without newer fields
    let v1_json = r#"{
        "version": 1,
        "config": { "width": 400, "height": 600, ... },
        "accounts": { "encrypted": false, "data_json": "[]" },
        "log": ""
    }"#;

    std::fs::write(auth_path(), v1_json).unwrap();
    let data = try_load().unwrap();
    assert_eq!(data.version, CURRENT_VERSION); // bumped on load
    // Verify file was rewritten with current version
    let raw = std::fs::read_to_string(auth_path()).unwrap();
    let saved: AuthData = serde_json::from_str(&raw).unwrap();
    assert_eq!(saved.version, CURRENT_VERSION);
}
```

### Step 5: Protect Against Unintentional Schema Changes

Add a **schema snapshot test** that serializes an AuthData with **deterministic values**
(no `Utc::now()`) and compares against a committed JSON fixture:

```rust
#[test]
fn test_auth_data_schema_snapshot() {
    let data = AuthData {
        version: CURRENT_VERSION,
        config: Config {
            width: 400,
            height: 600,
            left: 50,
            top: 100,
            always_on_top: false,
            theme: "dark".into(),
            password_protected: false,
            password_salt: String::new(),
            lock_timeout_minutes: 5,
            clipboard_clear_seconds: 30,
        },
        accounts: AccountsPayload {
            encrypted: false,
            nonce_hex: None,
            ciphertext_hex: None,
            data_json: "[]".into(),
        },
        log: String::new(),
    };
    let json = serde_json::to_string_pretty(&data).unwrap();
    let fixture = include_str!("../fixtures/auth_data_v1_snapshot.json");
    assert_eq!(json, fixture,
        "Schema changed! Update fixtures/auth_data_v1_snapshot.json if intentional.");
}
```

**Important:** Use only deterministic values — no `Utc::now()`, no random bytes.

### Step 6: Commit Pre-Baked Fixture Files for Regression Testing

Add a `src-tauri/tests/fixtures/` directory with actual `.auth` files from each
past version. A regression test loads each one and verifies graceful loading:

```rust
#[test]
fn test_load_v1_fixture() {
    let fixture = include_bytes!("../tests/fixtures/auth_v1_plaintext.auth");
    let path = crate::paths::auth_path();
    std::fs::write(&path, fixture).unwrap();
    let data = try_load().unwrap();
    assert!(data.version >= CURRENT_VERSION); // upgraded
    // Verify accounts are accessible
    let accounts = load_accounts(&data, None).unwrap();
    assert!(!accounts.is_empty());
}
```

Each fixture is committed to git and updated only when the format version changes.

## 6. Cryptographic Compatibility

### Current encryption envelope
```
serialize(accounts) as JSON string
  → AES-256-GCM.encrypt(json_bytes, nonce=12_random_bytes, key=Argon2id(pin, salt))
  → store { encrypted: true, nonce_hex, ciphertext_hex }
```

### Future-proofing rules
1. **Never change the nonce size** (or add a nonce_size field if you must)
2. **Never change the KDF** (Argon2id) — if you must, add `kdf: "Argon2id_v2"` to `AccountsPayload` and support both
3. **Use `#[serde(untagged)]` enum** if you need multiple encryption schemes:

```rust
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum CryptoPayload {
    V1 { encrypted: bool, nonce_hex: Option<String>, ciphertext_hex: Option<String>, data_json: String },
    V2 { algorithm: String, params: serde_json::Value, data: String },
}
```

## 7. Testing Matrix

| Scenario | Test | Expectation |
|----------|------|-------------|
| v1 file → v2 code | Load old file | Works — defaults fill new fields |
| v2 file → v1 code | Load new file | Silent ignore of unknown extra fields |
| Corrupted version field | `"version": "not-a-number"` | Serde fails → `try_load` returns Err |
| Missing version field | No `"version"` key | Defaults to 0 → upgraded to CURRENT_VERSION |
| Future unknown section | `"unknown_section": {...}` | Ignored on load, lost on save (acceptable) |
| Encrypted data erosion | Encrypt at v1, load at v2 | Same cipher → works, different cipher → fails |
| File with version > CURRENT | `"version": 999` | Load, warn/skip upgrade, but DON'T corrupt |

## 8. Error Handling Philosophy

| Situation | Behavior |
|-----------|----------|
| Unknown version (higher than current) | Load raw data, skip upgrades, **do not save** (might downgrade), warn via diagnostics |
| Corrupted JSON | `try_load` returns `Err` → caller uses `load()` which falls back to `fresh()` |
| Missing encryption fields | `decrypt_accounts` returns error → graceful denial |
| Junk in optional fields | Silently ignored by serde |

## 8b. Decision Point: Preserve Unknown Fields on Upgrade

When a version upgrade saves the file, any JSON keys the current `AuthData` struct
doesn't know about will be **silently lost** (serde ignores them on deserialize,
they're absent from the struct, so `serde_json::to_string_pretty` won't output them).

**Option A (simpler, chosen):** Accept this loss. Old `.exe` files had those keys;
new `.exe` reads old files; no old `.exe` needs to read the version-upgraded file.

**Option B (stronger backward compat):** Use a round-trip merge in `try_load`:

```rust
fn try_load() -> Result<AuthData, String> {
    let path = auth_path();

    let raw = std::fs::read_to_string(&path)?;
    let mut extra_keys: serde_json::Value = serde_json::from_str(&raw)?;

    // Apply version upgrades on the Value
    let version = extra_keys.get("version").and_then(|v| v.as_u64()).unwrap_or(0);
    let upgraded = upgrade_json(&mut extra_keys, version);

    // Deserialize into typed struct (unknown keys are lost here)
    let mut data: AuthData = serde_json::from_value(extra_keys.clone())?;

    // After reconcile + upgrade, re-attach unknown top-level keys
    // before serializing, so they survive the save.
    if upgraded || reconcile_invariants(&mut data) {
        // Serialize the typed struct back to Value
        let mut typed_value = serde_json::to_value(&data)?;
        if let Some(obj) = typed_value.as_object_mut() {
            if let Some(extra_obj) = extra_keys.as_object() {
                for (k, v) in extra_obj {
                    if !obj.contains_key(k) {
                        obj.insert(k.clone(), v.clone());
                    }
                }
            }
        }
        // Save the merged value
        let json = serde_json::to_string_pretty(&typed_value)?;
        std::fs::write(&path, &json)?;
    }

    Ok(data)
}
```

This ensures that fields created by other versions of the app (or other tools)
survive a save cycle. The tradeoff is added complexity in the load path.

## 8c. Log Field Handling

The `log` field is persisted as a raw string in `.auth`. Its format is
`[timestamp] category: message\n` lines. Across versions:

- **No version-specific format** → no migration needed
- **Log is capped at ~10 KB** by `flush_to_log_str()` → always safe to store
- **Empty log is valid** → `restore_from_log_str("")` is a no-op
- **Worst case**: truncated log lines from a previous version are harmless — they
display but can't be re-parsed (there's no structured log parsing)

**Recommendation**: No special handling needed for the log field across versions.

## 9. Commit & Rollback Strategy

- Each version bump is a **single commit** with:
  1. The upgrade function
  2. Updated `CURRENT_VERSION`
  3. Updated schema snapshot
  4. New compatibility tests
- If a deployed `.exe` writes a file that crashes on an older `.exe`, **that's acceptable** — the plan is forward-compatibility of new `.exe` reading old files, not backward-compatibility of old `.exe` reading new files.

## 10. Summary Checklist

- [ ] Two-phase load pipeline (raw Value → upgrade → typed struct)
- [ ] `upgrade_json()` orchestrator with per-version functions
- [ ] `#[serde(default)]` on ALL optional/evolvable fields
- [ ] Schema snapshot test to catch unintended format changes
- [ ] Unit tests for each past version upgrade path
- [ ] Unit test for unknown field passthrough
- [ ] Unit test for `version > CURRENT` graceful handling
- [ ] Reconcile invariants + version upgrade → save on disk
- [ ] Documentation for developers on how to add a field
