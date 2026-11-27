//! Core `AppLock` rules, configuration persistence, authentication, and lockout logic.

pub mod activity;
pub mod auth;
pub mod config;
pub mod lockout;
pub mod rules;

use applock_ipc::PROTOCOL_VERSION;
use applock_sys::{current_process_id, WinError};
use thiserror::Error;

/// Errors returned by `applock-core` operations.
#[derive(Debug, Error)]
pub enum CoreError {
    /// Underlying Windows API failure.
    #[error("system operation failed: {0}")]
    Sys(#[from] WinError),
    /// Password or PIN hashing failed.
    #[error("credential hashing failed")]
    Crypto,
    /// Configuration file is missing, corrupt, or has an unsupported version.
    #[error("configuration is invalid or corrupt")]
    CorruptConfig,
    /// Filesystem I/O failure.
    #[error("storage I/O failed")]
    Io(#[from] std::io::Error),
}

/// Returns a basic runtime identity summary for diagnostics.
#[must_use]
pub fn runtime_summary() -> (u16, u32) {
    (PROTOCOL_VERSION, current_process_id())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_summary_returns_expected_protocol() {
        let (proto, pid) = runtime_summary();
        assert_eq!(proto, 1);
        assert!(pid > 0);
    }
}
