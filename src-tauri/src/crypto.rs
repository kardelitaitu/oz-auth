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
    let result = argon2::Argon2::default()
        .hash_password_into(&padded, salt, &mut key);
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
    let result = String::from_utf8(plaintext)
        .map_err(|e| format!("invalid utf-8: {e}"))?;
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
}
