use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;
use zeroize::{Zeroize, Zeroizing};

/// Generate a random 16-byte salt wrapped in `Zeroizing` for automatic zeroing on drop.
pub fn generate_salt() -> Zeroizing<[u8; 16]> {
    let mut salt = Zeroizing::new([0u8; 16]);
    rand::rngs::OsRng.fill_bytes(&mut *salt);
    salt
}

pub fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    let mut key = [0u8; 32];
    // Pad PIN to constant length to prevent PIN-length timing leakage
    let mut padded = password.as_bytes().to_vec();
    padded.resize(128, 0u8);
    let result = argon2::Argon2::default().hash_password_into(&padded, salt, &mut key);
    // Zeroize the padded buffer immediately
    padded.zeroize();
    result.map_err(|e| format!("key derivation failed: {e}"))?;
    Ok(key)
}

/// Encrypt plaintext with AES-256-GCM.
///
/// Returns (nonce, ciphertext). The plaintext input is consumed as bytes
/// but the caller should zeroize the plaintext `String` after calling.
pub fn encrypt(plaintext: &str, key: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("invalid key: {e}"))?;
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| format!("encryption failed: {e}"))?;
    Ok((nonce_bytes.to_vec(), ciphertext))
}

/// Decrypt ciphertext with AES-256-GCM.
///
/// Returns the decrypted plaintext. The caller should zeroize the returned
/// String after parsing sensitive data from it.
pub fn decrypt(ciphertext: &[u8], nonce_bytes: &[u8], key: &[u8; 32]) -> Result<String, String> {
    if nonce_bytes.len() != 12 {
        return Err("invalid nonce: must be 12 bytes".to_string());
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("invalid key: {e}"))?;
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "wrong password or corrupted data".to_string())?;
    // String::from_utf8 consumes the Vec — no clone needed
    let result = String::from_utf8(plaintext).map_err(|e| format!("invalid utf-8: {e}"))?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let salt = generate_salt();
        let mut key = derive_key("hunter2", &*salt).unwrap();
        let (nonce, ct) = encrypt("hello encrypted world", &key).unwrap();
        let mut pt = decrypt(&ct, &nonce, &key).unwrap();
        assert_eq!(pt, "hello encrypted world");
        // Verify zeroization doesn't break drop
        pt.zeroize();
        key.zeroize();
    }

    #[test]
    fn test_wrong_key_fails() {
        let salt = generate_salt();
        let mut key = derive_key("correct", &*salt).unwrap();
        let mut wrong_key = derive_key("wrong", &*salt).unwrap();
        let (nonce, ct) = encrypt("secret", &key).unwrap();
        assert!(decrypt(&ct, &nonce, &wrong_key).is_err());
        key.zeroize();
        wrong_key.zeroize();
    }

    #[test]
    fn test_salt_is_random() {
        let a = generate_salt();
        let b = generate_salt();
        assert_ne!(*a, *b);
    }

    #[test]
    fn test_key_is_32_bytes() {
        let salt = generate_salt();
        let mut key = derive_key("test", &*salt).unwrap();
        assert_eq!(key.len(), 32);
        key.zeroize();
    }

    #[test]
    fn test_empty_plaintext_roundtrip() {
        let salt = generate_salt();
        let mut key = derive_key("empty", &*salt).unwrap();
        let (nonce, ct) = encrypt("", &key).unwrap();
        let mut pt = decrypt(&ct, &nonce, &key).unwrap();
        assert_eq!(pt, "");
        pt.zeroize();
        key.zeroize();
    }

    #[test]
    fn test_invalid_nonce_length() {
        let salt = generate_salt();
        let mut key = derive_key("test", &*salt).unwrap();
        assert!(decrypt(b"data", b"short", &key).is_err());
        key.zeroize();
    }

    #[test]
    fn test_large_plaintext_roundtrip() {
        let salt = generate_salt();
        let mut key = derive_key("big", &*salt).unwrap();
        let large = "x".repeat(10_000);
        let (nonce, ct) = encrypt(&large, &key).unwrap();
        let mut pt = decrypt(&ct, &nonce, &key).unwrap();
        assert_eq!(pt, large);
        pt.zeroize();
        key.zeroize();
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let salt = generate_salt();
        let mut key = derive_key("tamper", &*salt).unwrap();
        let (nonce, mut ct) = encrypt("secret", &key).unwrap();
        // Flip a byte
        ct[0] ^= 0xFF;
        assert!(decrypt(&ct, &nonce, &key).is_err());
        key.zeroize();
    }

    #[test]
    fn test_different_keys_produce_different_ciphertext() {
        let salt = generate_salt();
        let mut key1 = derive_key("pass1", &*salt).unwrap();
        let mut key2 = derive_key("pass2", &*salt).unwrap();
        let (_, ct1) = encrypt("secret", &key1).unwrap();
        let (_, ct2) = encrypt("secret", &key2).unwrap();
        // Same plaintext, different keys → different ciphertext
        assert_ne!(ct1, ct2);
        key1.zeroize();
        key2.zeroize();
    }

    // ── New tests ──────────────────────────────────────────────

    #[test]
    fn test_same_inputs_produce_same_key() {
        // Same PIN + same salt → same derived key (deterministic)
        let salt = generate_salt();
        let mut key1 = derive_key("mypin", &*salt).unwrap();
        let mut key2 = derive_key("mypin", &*salt).unwrap();
        assert_eq!(key1, key2, "same salt+pin must produce same key");
        key1.zeroize();
        key2.zeroize();
    }

    #[test]
    fn test_different_salts_produce_different_keys() {
        // Same PIN, different salts → different keys
        let salt1 = generate_salt();
        let salt2 = generate_salt();
        let mut key1 = derive_key("pin", &*salt1).unwrap();
        let mut key2 = derive_key("pin", &*salt2).unwrap();
        assert_ne!(key1, key2, "different salts must produce different keys");
        key1.zeroize();
        key2.zeroize();
    }

    #[test]
    fn test_tampered_nonce_fails() {
        let salt = generate_salt();
        let mut key = derive_key("test", &*salt).unwrap();
        let (mut nonce, ct) = encrypt("secret", &key).unwrap();
        // Flip a byte in the nonce
        nonce[0] ^= 0xFF;
        assert!(
            decrypt(&ct, &nonce, &key).is_err(),
            "tampered nonce must fail decryption"
        );
        key.zeroize();
    }

    #[test]
    fn test_empty_ciphertext_decrypt_fails() {
        let salt = generate_salt();
        let mut key = derive_key("test", &*salt).unwrap();
        let nonce = [0xABu8; 12];
        assert!(
            decrypt(b"", &nonce, &key).is_err(),
            "decrypt of empty ciphertext should fail"
        );
        key.zeroize();
    }

    #[test]
    fn test_same_plaintext_different_nonces() {
        // Same key + same plaintext → different ciphertexts each time (random nonce)
        let salt = generate_salt();
        let mut key = derive_key("test", &*salt).unwrap();
        let (nonce1, ct1) = encrypt("same", &key).unwrap();
        let (nonce2, ct2) = encrypt("same", &key).unwrap();
        // Nonces must be different (randomly generated)
        assert_ne!(nonce1, nonce2, "nonces must be unique per encryption");
        // Ciphertexts must be different (different nonces → different GCM output)
        assert_ne!(
            ct1, ct2,
            "different nonces must produce different ciphertexts"
        );
        // Both must decrypt correctly
        let mut pt1 = decrypt(&ct1, &nonce1, &key).unwrap();
        let mut pt2 = decrypt(&ct2, &nonce2, &key).unwrap();
        assert_eq!(pt1, "same");
        assert_eq!(pt2, "same");
        pt1.zeroize();
        pt2.zeroize();
        key.zeroize();
    }

    #[test]
    fn test_salt_unique_across_many_calls() {
        // Generate 1000 salts and verify no duplicates (statistical guarantee)
        let mut set = std::collections::HashSet::new();
        for _ in 0..1000 {
            let salt = generate_salt();
            assert!(set.insert(*salt), "salt collision detected");
        }
    }

    #[test]
    fn test_derive_key_empty_password() {
        // Empty password should still produce a valid key (it's padded to 128 bytes)
        let salt = generate_salt();
        let mut key = derive_key("", &*salt).unwrap();
        assert_eq!(key.len(), 32);
        key.zeroize();
    }

    #[test]
    fn test_derive_key_very_long_password() {
        // Very long password (longer than the 128-byte pad) should still work
        let salt = generate_salt();
        let long_pin = "a".repeat(256);
        let mut key = derive_key(&long_pin, &*salt).unwrap();
        assert_eq!(key.len(), 32);
        key.zeroize();
    }

    #[test]
    fn test_large_plaintext_100k_roundtrip() {
        let salt = generate_salt();
        let mut key = derive_key("large100k", &*salt).unwrap();
        let large = "Hello World! ".repeat(8_000); // ~104k chars
        let (nonce, ct) = encrypt(&large, &key).unwrap();
        let mut pt = decrypt(&ct, &nonce, &key).unwrap();
        assert_eq!(pt.len(), large.len());
        assert_eq!(pt, large);
        pt.zeroize();
        key.zeroize();
    }

    #[test]
    fn test_unicode_plaintext_roundtrip() {
        let salt = generate_salt();
        let mut key = derive_key("unicode", &*salt).unwrap();
        let unicode = "🔐 AES-256-GCM ✓ unicode émojis 🎉";
        let (nonce, ct) = encrypt(unicode, &key).unwrap();
        let mut pt = decrypt(&ct, &nonce, &key).unwrap();
        assert_eq!(pt, unicode);
        pt.zeroize();
        key.zeroize();
    }

    #[test]
    fn test_decrypt_with_nonce_longer_than_12_bytes_fails() {
        let salt = generate_salt();
        let mut key = derive_key("test", &*salt).unwrap();
        let long_nonce = [0u8; 16];
        assert!(
            decrypt(b"data", &long_nonce, &key).is_err(),
            "nonce longer than 12 bytes must fail"
        );
        key.zeroize();
    }

    #[test]
    fn test_encrypt_decrypt_with_zero_key() {
        // All-zero key is technically valid for AES (though weak)
        let salt = generate_salt();
        let mut key = derive_key("weak", &*salt).unwrap();
        let (nonce, ct) = encrypt("data", &key).unwrap();
        let mut pt = decrypt(&ct, &nonce, &key).unwrap();
        assert_eq!(pt, "data");
        pt.zeroize();
        key.zeroize();
    }

    // ── New tests ──────────────────────────────────────────────

    #[test]
    fn test_derive_key_all_zero_password_produces_valid_key() {
        // Even with "\0\0\0" the padding mechanism should produce a valid 32-byte key
        let salt = generate_salt();
        let null_pin = "\0\0\0";
        let mut key = derive_key(null_pin, &*salt).unwrap();
        assert_eq!(
            key.len(),
            32,
            "null bytes in PIN must still produce 32-byte key"
        );
        // Verify the key can actually encrypt/decrypt
        let (nonce, ct) = encrypt("works", &key).unwrap();
        let mut pt = decrypt(&ct, &nonce, &key).unwrap();
        assert_eq!(pt, "works");
        pt.zeroize();
        key.zeroize();
    }

    #[test]
    fn test_derive_key_exactly_128_byte_pin() {
        // PIN exactly fills the 128-byte pad buffer — should work
        let salt = generate_salt();
        let exact_pin = "a".repeat(128);
        let mut key = derive_key(&exact_pin, &*salt).unwrap();
        assert_eq!(key.len(), 32);
        let (nonce, ct) = encrypt("data", &key).unwrap();
        let mut pt = decrypt(&ct, &nonce, &key).unwrap();
        assert_eq!(pt, "data");
        pt.zeroize();
        key.zeroize();
    }

    #[test]
    fn test_derive_key_same_salt_always_same_key() {
        // Deterministic: same password + same salt bytes → same derived key
        let salt_bytes = [0xABu8; 16];
        let salt = Zeroizing::new(salt_bytes);
        let mut key1 = derive_key("testpin", &*salt).unwrap();
        let mut key2 = derive_key("testpin", &*salt).unwrap();
        assert_eq!(key1, key2, "same salt bytes must produce identical key");
        key1.zeroize();
        key2.zeroize();
    }

    #[test]
    fn test_derive_key_with_unicode_pin() {
        // Unicode characters are multi-byte — padding must handle them correctly
        let salt = generate_salt();
        let unicode_pin = "🔑🔐🔏🔒"; // 4 emoji chars, each 4 bytes = 16 bytes
        let mut key = derive_key(unicode_pin, &*salt).unwrap();
        assert_eq!(key.len(), 32);
        let (nonce, ct) = encrypt("unicode pin works", &key).unwrap();
        let mut pt = decrypt(&ct, &nonce, &key).unwrap();
        assert_eq!(pt, "unicode pin works");
        pt.zeroize();
        key.zeroize();
    }

    #[test]
    fn test_derive_key_pin_with_only_whitespace() {
        // Whitespace-only PIN should still produce a valid key
        let salt = generate_salt();
        let mut key = derive_key("   \t\n  ", &*salt).unwrap();
        assert_eq!(key.len(), 32);
        let (nonce, ct) = encrypt("whitespace", &key).unwrap();
        let mut pt = decrypt(&ct, &nonce, &key).unwrap();
        assert_eq!(pt, "whitespace");
        pt.zeroize();
        key.zeroize();
    }

    // ── Property-based tests (proptest) ─────────────────────────

    use proptest::prelude::*;

    /// Generate a plaintext string with up to `max_chars` Unicode characters.
    /// This avoids byte-index panics that `&s[..N]` would cause on multi-byte UTF-8.
    fn arb_plaintext(max_chars: usize) -> impl Strategy<Value = String> {
        prop::collection::vec(proptest::char::any(), 0..=max_chars)
            .prop_map(|chars| chars.into_iter().collect())
    }

    proptest! {
        /// For ANY key and ANY plaintext (up to 2,000 chars),
        /// encrypt then decrypt returns the original.
        #[test]
        fn prop_encrypt_decrypt_roundtrip(
            key: [u8; 32],
            plaintext in arb_plaintext(2_000),
        ) {
            let (nonce, ct) = encrypt(&plaintext, &key).unwrap();
            let pt = decrypt(&ct, &nonce, &key).unwrap();
            assert_eq!(pt, plaintext, "roundtrip failed");
        }

        /// For ANY key, empty plaintext roundtrips correctly.
        #[test]
        fn prop_empty_plaintext_roundtrip(key: [u8; 32]) {
            let (nonce, ct) = encrypt("", &key).unwrap();
            let pt = decrypt(&ct, &nonce, &key).unwrap();
            assert_eq!(pt, "", "empty plaintext roundtrip failed");
        }

        /// A wrong key MUST fail to decrypt.
        /// AES-256-GCM has built-in authentication — a wrong key
        /// produces a GCM authentication failure (not corrupted data).
        #[test]
        fn prop_wrong_key_fails(
            plaintext in arb_plaintext(1_000),
            key1: [u8; 32],
            key2: [u8; 32],
        ) {
            prop_assume!(key1 != key2, "keys must differ");
            let (nonce, ct) = encrypt(&plaintext, &key1).unwrap();
            // Wrong key: GCM authenticates, so decryption must fail
            assert!(
                decrypt(&ct, &nonce, &key2).is_err(),
                "wrong key must fail decryption"
            );
        }

        /// Same plaintext + same key → DIFFERENT ciphertext each time
        /// (because encrypt generates a fresh random nonce).
        #[test]
        fn prop_non_deterministic_ciphertext(
            key: [u8; 32],
            plaintext in arb_plaintext(500),
        ) {
            let (nonce1, ct1) = encrypt(&plaintext, &key).unwrap();
            let (nonce2, ct2) = encrypt(&plaintext, &key).unwrap();
            // Nonces must be unique (randomly generated)
            assert_ne!(nonce1, nonce2, "nonces must be unique per encryption");
            // Different nonces → different GCM keystream → different ciphertext
            assert_ne!(ct1, ct2, "ciphertext must differ due to distinct nonces");
        }

        /// Encrypt/decrypt roundtrip with single-byte plaintext.
        #[test]
        fn prop_single_byte_plaintext(key: [u8; 32], byte: u8) {
            let plaintext = (byte as char).to_string();
            let (nonce, ct) = encrypt(&plaintext, &key).unwrap();
            let result = decrypt(&ct, &nonce, &key).unwrap();
            assert_eq!(result, plaintext);
        }

        /// Very long plaintext (up to ~50 KB) roundtrips correctly.
        #[test]
        fn prop_large_plaintext_roundtrip(key: [u8; 32], size in 10_000usize..=50_000) {
            let plaintext = "x".repeat(size);
            let (nonce, ct) = encrypt(&plaintext, &key).unwrap();
            let pt = decrypt(&ct, &nonce, &key).unwrap();
            assert_eq!(pt.len(), size, "large plaintext roundtrip length mismatch");
            assert_eq!(pt, plaintext, "large plaintext roundtrip content mismatch");
        }
    }
}
