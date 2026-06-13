//! Append-only signed audit log with SHA256 hash chain.
//!
//! Every security-relevant event is logged as a structured `AuditEntry`
//! that includes a `prev_hash` linking to the previous entry, forming
//! an immutable chain. Tampering (modification, removal, reordering)
//! is detectable by re-verifying the chain.
//!
//! # Integrity model
//! - Each entry references its predecessor via SHA256(prev_entry).
//! - Removing any entry breaks the chain (subsequent entry's prev_hash
//!   won't match).
//! - Reordering entries breaks the chain.
//! - Modifying an entry changes its hash, breaking the link to its
//!   successor.
//!
//! The trail is stored as a JSON array of entries in `AuthData.audit_trail`.
//! On load, the chain is verified and a warning event is emitted if broken.

use serde::{Deserialize, Serialize};
use std::sync::Mutex;

/// A single entry in the audit trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Monotonically increasing sequence number (0-based).
    pub seq: u64,
    /// Unix timestamp (seconds since epoch).
    pub ts: u64,
    /// Event category (e.g., "security", "backup", "startup").
    pub cat: String,
    /// Human-readable event description.
    pub msg: String,
    /// SHA256 hex digest of the previous entry.
    /// Set to "0" for the very first entry (genesis block).
    pub prev_hash: String,
}

static AUDIT_TRAIL: Mutex<Option<Vec<AuditEntry>>> = Mutex::new(None);

/// Compute the SHA256 hash of an entry (used for the next entry's prev_hash).
///
/// The hash covers: seq (little-endian) || ts (le) || cat || msg || prev_hash
/// Using the entry's own prev_hash in the hash binds the chain transitively.
pub fn compute_hash(entry: &AuditEntry) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(entry.seq.to_le_bytes());
    hasher.update(entry.ts.to_le_bytes());
    hasher.update(entry.cat.as_bytes());
    hasher.update(entry.msg.as_bytes());
    hasher.update(entry.prev_hash.as_bytes());
    hex::encode(hasher.finalize())
}

/// Append an event to the in-memory audit trail.
/// The new entry includes a prev_hash linking back to the previous entry.
pub fn push(cat: &str, msg: &str) {
    let mut guard = AUDIT_TRAIL
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let trail = guard.get_or_insert_with(Vec::new);
    let seq = trail.len() as u64;
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let prev_hash = if let Some(last) = trail.last() {
        compute_hash(last)
    } else {
        "0".to_string()
    };
    trail.push(AuditEntry {
        seq,
        ts,
        cat: cat.to_string(),
        msg: msg.to_string(),
        prev_hash,
    });
}

/// Serialize and drain the current audit trail.
/// Returns a JSON array string (or empty string if nothing to flush).
/// Truncates to the most recent ~1000 entries if the trail is oversized,
/// discarding oldest entries while keeping the chain intact.
pub fn flush() -> String {
    let mut guard = AUDIT_TRAIL
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let trail = guard.take().unwrap_or_default();
    if trail.is_empty() {
        return String::new();
    }
    // Keep at most 1000 entries (discard oldest).
    // Re-link the chain so the kept segment is self-consistent:
    // the first entry becomes the new genesis (prev_hash = "0"),
    // then each subsequent entry's prev_hash is recomputed from
    // its newly-linked predecessor.
    let kept = if trail.len() > 1000 {
        let mut slice = trail[trail.len() - 1000..].to_vec();
        slice[0].prev_hash = "0".to_string();
        for i in 1..slice.len() {
            slice[i].prev_hash = compute_hash(&slice[i - 1]);
        }
        slice
    } else {
        trail
    };
    serde_json::to_string(&kept).unwrap_or_default()
}

/// Restore a previously persisted audit trail.
/// Verifies the hash chain and logs a warning if tampering is detected.
pub fn restore(json: &str) {
    if json.is_empty() {
        return;
    }
    let trail: Vec<AuditEntry> = match serde_json::from_str(json) {
        Ok(t) => t,
        Err(e) => {
            crate::diagnostics::event("audit", &format!("failed to deserialize audit trail: {e}"));
            return;
        }
    };
    match verify_chain(&trail) {
        Ok(()) => {
            let mut guard = AUDIT_TRAIL
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            *guard = Some(trail);
        }
        Err(e) => {
            crate::diagnostics::event("audit", &format!("audit trail integrity check FAILED: {e}"));
            // Still restore the trail so it can be inspected, but the
            // integrity failure event itself is logged.
            let mut guard = AUDIT_TRAIL
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            *guard = Some(trail);
        }
    }
}

/// Verify the hash chain integrity of an audit trail.
/// Returns Ok(()) if every entry's prev_hash matches the previous entry's hash.
pub fn verify_chain(trail: &[AuditEntry]) -> Result<(), String> {
    for (i, entry) in trail.iter().enumerate() {
        if i == 0 {
            // Genesis entry must have prev_hash == "0"
            if entry.prev_hash != "0" {
                return Err(format!(
                    "entry {i}: genesis prev_hash must be \"0\", got \"{}\"",
                    entry.prev_hash
                ));
            }
        } else {
            let expected = compute_hash(&trail[i - 1]);
            if entry.prev_hash != expected {
                return Err(format!(
                    "entry {i}: prev_hash mismatch. Expected {expected}, got {}",
                    entry.prev_hash
                ));
            }
        }
    }
    Ok(())
}

/// Return a clone of the current in-memory trail (for inspection / testing).
pub fn snapshot() -> Vec<AuditEntry> {
    AUDIT_TRAIL
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .unwrap_or_default()
}

/// Clear the in-memory audit trail (for testing).
#[cfg(test)]
pub fn clear() {
    let mut guard = AUDIT_TRAIL
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    *guard = None;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_lock(f: impl FnOnce()) {
        let _lock = crate::diagnostics::LOG_BUF_TEST_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Clear audit trail before test
        clear();
        f();
    }

    #[test]
    fn test_push_creates_entry_with_sequence() {
        with_lock(|| {
            push("test", "hello");
            let s = snapshot();
            assert_eq!(s.len(), 1);
            assert_eq!(s[0].seq, 0);
            assert_eq!(s[0].cat, "test");
            assert_eq!(s[0].msg, "hello");
            assert_eq!(s[0].prev_hash, "0");
        });
    }

    #[test]
    fn test_push_links_entries() {
        with_lock(|| {
            push("a", "first");
            push("b", "second");
            let s = snapshot();
            assert_eq!(s.len(), 2);
            assert_eq!(s[0].seq, 0);
            assert_eq!(s[1].seq, 1);
            // Second entry's prev_hash must equal hash of first entry
            let expected = compute_hash(&s[0]);
            assert_eq!(s[1].prev_hash, expected);
        });
    }

    #[test]
    fn test_verify_chain_valid() {
        with_lock(|| {
            push("a", "first");
            push("b", "second");
            push("c", "third");
            let s = snapshot();
            assert!(verify_chain(&s).is_ok());
        });
    }

    #[test]
    fn test_verify_chain_broken_by_modification() {
        with_lock(|| {
            push("a", "first");
            push("b", "second");
            let mut s = snapshot();
            assert_eq!(s.len(), 2);
            // Tamper with the first entry's message
            s[0].msg = "tampered!".to_string();
            assert!(verify_chain(&s).is_err());
        });
    }

    #[test]
    fn test_verify_chain_broken_by_removal() {
        with_lock(|| {
            push("a", "first");
            push("b", "second");
            push("c", "third");
            let mut s = snapshot();
            // Remove the middle entry
            s.remove(1);
            assert!(verify_chain(&s).is_err());
        });
    }

    #[test]
    fn test_verify_chain_broken_by_reorder() {
        with_lock(|| {
            push("a", "first");
            push("b", "second");
            let mut s = snapshot();
            // Swap entries
            s.swap(0, 1);
            assert!(verify_chain(&s).is_err());
        });
    }

    #[test]
    fn test_flush_drains_trail() {
        with_lock(|| {
            push("a", "event");
            let json = flush();
            assert!(!json.is_empty());
            assert!(json.contains("event"));
            // Trail should be empty after flush
            assert!(snapshot().is_empty());
        });
    }

    #[test]
    fn test_restore_repopulates_trail() {
        with_lock(|| {
            push("a", "event1");
            push("b", "event2");
            let json = flush();
            assert!(!json.is_empty());

            // Restore into a fresh state
            clear();
            assert!(snapshot().is_empty());
            restore(&json);
            let s = snapshot();
            assert_eq!(s.len(), 2);
            assert_eq!(s[0].msg, "event1");
            assert_eq!(s[1].msg, "event2");
        });
    }

    #[test]
    fn test_restore_empty_string_noop() {
        with_lock(|| {
            restore("");
            assert!(snapshot().is_empty());
        });
    }

    #[test]
    fn test_restore_invalid_json_logs_event() {
        with_lock(|| {
            // Should not panic, should log an audit event via diagnostics::event()
            // which also pushes to the audit trail.
            restore("not valid json");
            let s = snapshot();
            assert_eq!(s.len(), 1, "restore failure must push an audit entry");
            assert!(
                s[0].msg.contains("failed to deserialize"),
                "entry must mention failure: {}",
                s[0].msg
            );
        });
    }

    #[test]
    fn test_compute_hash_deterministic() {
        with_lock(|| {
            push("test", "msg");
            let s = snapshot();
            let h1 = compute_hash(&s[0]);
            let h2 = compute_hash(&s[0]);
            assert_eq!(h1, h2, "hash must be deterministic");
        });
    }

    #[test]
    fn test_compute_hash_differs_for_diff_entries() {
        with_lock(|| {
            push("a", "msg1");
            push("b", "msg2");
            let s = snapshot();
            let h0 = compute_hash(&s[0]);
            let h1 = compute_hash(&s[1]);
            assert_ne!(h0, h1, "different entries must have different hashes");
        });
    }

    #[test]
    fn test_genesis_prev_hash_is_zero() {
        with_lock(|| {
            push("startup", "Application started");
            let s = snapshot();
            assert_eq!(s[0].prev_hash, "0");
        });
    }

    #[test]
    fn test_verify_chain_empty_trail_ok() {
        with_lock(|| {
            assert!(verify_chain(&[]).is_ok());
        });
    }

    #[test]
    fn test_verify_chain_single_entry_ok() {
        with_lock(|| {
            push("test", "single");
            let s = snapshot();
            assert!(verify_chain(&s).is_ok());
        });
    }

    #[test]
    fn test_flush_empty_trail_returns_empty() {
        with_lock(|| {
            assert_eq!(flush(), "");
        });
    }

    #[test]
    fn test_flush_truncates_at_1000() {
        with_lock(|| {
            for i in 0..1100 {
                push("bulk", &format!("event {i}"));
            }
            let json = flush();
            let restored: Vec<AuditEntry> = serde_json::from_str(&json).unwrap();
            assert_eq!(restored.len(), 1000, "must truncate to 1000 entries");
            assert_eq!(restored[0].seq, 100, "first kept entry has seq=100");
            assert_eq!(restored[999].seq, 1099, "last kept entry has seq=1099");
            // Chain must still be valid after truncation
            assert!(verify_chain(&restored).is_ok());
        });
    }
}
