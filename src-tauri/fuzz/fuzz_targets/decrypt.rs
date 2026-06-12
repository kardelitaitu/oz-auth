#![no_main]

use libfuzzer_sys::fuzz_target;

/// Fixed key for fuzzing — decryption should never panic,
/// only return Err for corrupted inputs.
const FUZZ_KEY: [u8; 32] = [0xAB; 32];

fuzz_target!(|data: &[u8]| {
    // First 12 bytes = nonce, rest = ciphertext
    if data.len() >= 12 {
        let nonce = &data[..12];
        let ciphertext = &data[12..];

        // Must not panic for any input — only Err(String)
        let _ = oz_auth_lib::crypto::decrypt(ciphertext, nonce, &FUZZ_KEY);
    }
});
