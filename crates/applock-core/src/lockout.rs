//! Escalating wrong-attempt lockout state machine (`FR-AUTH-04`).

/// Persistent lockout state owned exclusively by `applock-service`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LockoutState {
    /// Consecutive failed attempts since the last successful unlock.
    pub failed_count: u32,
    /// Unix timestamp (seconds) until which authentication is blocked.
    pub locked_until_unix_secs: Option<u64>,
}

impl LockoutState {
    /// Returns remaining lockout seconds at `now_unix_secs` (`0` if not locked out).
    #[must_use]
    pub fn remaining_secs(&self, now_unix_secs: u64) -> u64 {
        self.locked_until_unix_secs
            .map_or(0, |until| until.saturating_sub(now_unix_secs))
    }

    /// Returns `true` if authentication attempts are currently blocked.
    #[must_use]
    pub fn is_locked_out(&self, now_unix_secs: u64) -> bool {
        self.remaining_secs(now_unix_secs) > 0
    }

    /// Records a failed credential attempt and applies escalating delays (30s, 1m, 5m, 30m).
    pub fn record_failure(&mut self, now_unix_secs: u64) {
        self.failed_count = self.failed_count.saturating_add(1);
        let wait_secs = match self.failed_count {
            0..=2 => 0,
            3 => 30,
            4 => 60,
            5 => 300,
            _ => 1800,
        };
        if wait_secs > 0 {
            self.locked_until_unix_secs = Some(now_unix_secs.saturating_add(wait_secs));
        }
    }

    /// Resets the lockout counter after a valid credential is presented.
    pub fn record_success(&mut self) {
        self.failed_count = 0;
        self.locked_until_unix_secs = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escalating_lockout_schedule_matches_prd() {
        let mut st = LockoutState::default();
        st.record_failure(1000);
        st.record_failure(1001);
        assert_eq!(st.remaining_secs(1001), 0);

        st.record_failure(1002); // 3rd -> 30s
        assert_eq!(st.remaining_secs(1002), 30);
        assert!(st.is_locked_out(1020));
        assert!(!st.is_locked_out(1032));

        st.record_failure(1033); // 4th -> 60s
        assert_eq!(st.remaining_secs(1033), 60);

        st.record_failure(1100); // 5th -> 300s
        assert_eq!(st.remaining_secs(1100), 300);

        st.record_failure(1500); // 6th -> 1800s
        assert_eq!(st.remaining_secs(1500), 1800);

        st.record_success();
        assert_eq!(st.failed_count, 0);
        assert_eq!(st.remaining_secs(1500), 0);
    }
}

