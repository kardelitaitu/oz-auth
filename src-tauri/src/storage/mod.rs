pub mod auth_file;

// Re-export key functions for convenience
pub use auth_file::{decrypt_accounts, encrypt_accounts, exists, load, load_accounts, save, try_load, AuthData};
