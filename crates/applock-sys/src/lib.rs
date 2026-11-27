//! Thin safe wrappers over Windows APIs for `AppLock`.
//!
//! All `unsafe` code in the workspace (outside v2 shell extensions) lives in this crate.

pub mod apps;
pub mod crypto;
pub mod etw;
pub mod lock_dialog;
pub mod pipe;
pub mod process;
pub mod security;
pub mod window;
pub mod winevent;

/// Error returned by a Windows API wrapper.
#[derive(Debug, Clone)]
pub struct WinError {
    /// Win32 error code or `NTSTATUS`.
    pub code: u32,
    /// Short operation name (no secrets or user paths).
    pub context: &'static str,
}

impl std::fmt::Display for WinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} failed (code 0x{:08X})", self.context, self.code)
    }
}

impl std::error::Error for WinError {}

/// Returns the current process identifier.
#[must_use]
pub fn current_process_id() -> u32 {
    std::process::id()
}

pub(crate) fn to_wide_null(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_pid_is_nonzero() {
        assert!(current_process_id() > 0);
    }
}
