#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // Harden the process against code injection on Windows.
    // Must happen before any library loading.
    #[cfg(windows)]
    apply_process_mitigations();
    oz_auth_lib::run()
}

/// Apply Windows process mitigation policies to harden against
/// DLL injection, code injection, and other attack vectors.
///
/// These are defense-in-depth: if any policy fails, the app continues.
/// Not enabling MicrosoftSignedOnly since the app loads Tauri/WebView2 DLLs.
#[cfg(windows)]
fn apply_process_mitigations() {
    use std::mem;

    // PROCESS_MITIGATION_POLICY types from Windows SDK
    const PROCESS_SIGNATURE_POLICY: u32 = 8;
    const PROCESS_DYNAMIC_CODE_POLICY: u32 = 2;
    const PROCESS_IMAGE_LOAD_POLICY: u32 = 10;

    extern "system" {
        fn SetProcessMitigationPolicy(
            mitigation_policy: u32,
            lp_buffer: *const std::ffi::c_void,
            dw_length: u32,
        ) -> i32;
    }

    unsafe {
        // 1. Block non-Microsoft-signed DLLs from loading.
        //    Set to 0 (audit mode) since Tauri/WebView2 DLLs aren't MSFT-signed.
        #[repr(C)]
        struct SignaturePolicy {
            microsoft_signed_only: u32,
        }
        let sig = SignaturePolicy {
            microsoft_signed_only: 0,
        };
        let _ = SetProcessMitigationPolicy(
            PROCESS_SIGNATURE_POLICY,
            &sig as *const _ as *const std::ffi::c_void,
            mem::size_of::<SignaturePolicy>() as u32,
        );

        // 2. Block dynamic code generation (VirtualAlloc + execute)
        #[repr(C)]
        struct DynamicCodePolicy {
            prohibit_dynamic_code: u32,
        }
        let dyn_code = DynamicCodePolicy {
            prohibit_dynamic_code: 1,
        };
        let _ = SetProcessMitigationPolicy(
            PROCESS_DYNAMIC_CODE_POLICY,
            &dyn_code as *const _ as *const std::ffi::c_void,
            mem::size_of::<DynamicCodePolicy>() as u32,
        );

        // 3. Block loading images from remote/UNC paths and low-integrity locations
        #[repr(C)]
        struct ImageLoadPolicy {
            no_remote_images: u32,
            no_low_label_images: u32,
            prefer_system32_images: u32,
            _audit: u32,
        }
        let img = ImageLoadPolicy {
            no_remote_images: 1,
            no_low_label_images: 1,
            prefer_system32_images: 1,
            _audit: 0,
        };
        let _ = SetProcessMitigationPolicy(
            PROCESS_IMAGE_LOAD_POLICY,
            &img as *const _ as *const std::ffi::c_void,
            mem::size_of::<ImageLoadPolicy>() as u32,
        );
    }
}
