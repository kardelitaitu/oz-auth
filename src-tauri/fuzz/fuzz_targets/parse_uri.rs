#![no_main]

use libfuzzer_sys::fuzz_target;
use oz_auth_lib::utils::otpauth::parse_uri;

fuzz_target!(|data: &[u8]| {
    // Convert arbitrary bytes to a string (UTF-8 lossy for resilience)
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = parse_uri(s);
    }
});
