#![no_main]

use libfuzzer_sys::fuzz_target;

// decode_secret is pub in commands::accounts, accessible from the fuzz crate.

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // decode_secret tries base32 first, then hex on decode failure
        let _ = oz_auth_lib::commands::accounts::decode_secret(s);
    }
});
