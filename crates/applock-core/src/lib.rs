//! Core AppLock rules, configuration types, and security state machines.

use applock_ipc::PROTOCOL_VERSION;
use applock_sys::current_process_id;

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
