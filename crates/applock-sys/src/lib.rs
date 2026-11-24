//! Thin safe wrappers over Windows APIs for `AppLock`.
//!
//! All `unsafe` code in the workspace (outside v2 shell extensions) lives in this crate.

/// Returns the current process identifier.
#[must_use]
pub fn current_process_id() -> u32 {
    std::process::id()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_pid_is_nonzero() {
        assert!(current_process_id() > 0);
    }
}

