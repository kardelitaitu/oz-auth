#![no_main]

use libfuzzer_sys::fuzz_target;

// decode_secret is pub(crate) in commands::accounts
// We expose it through a thin public wrapper or call it directly
// when compiled with the fuzz target's access to the crate.

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // decode_secret tries base32 first, then hex — panics on neither
        let _ = oz_auth_lib::commands::accounts::decode_secret(s);
    }
});
