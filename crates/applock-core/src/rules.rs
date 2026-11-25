//! Per-app locking rules and grace-period evaluation (`FR-APP-05`).

use std::collections::HashMap;

/// Locking behavior for a protected app.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockMode {
    /// Prompt on every launch or foreground switch.
    Always,
    /// Allow re-use for `seconds` after a successful unlock.
    Grace {
        /// Grace window duration in seconds.
        seconds: u64,
    },
}

/// Configured protected app entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockedApp {
    /// Normalized executable name/path or UWP Package Family Name (lowercase).
    pub app_id: String,
    /// Locking mode for this app.
    pub mode: LockMode,
}

/// In-memory rules evaluator used on the hot decision path (zero disk/network I/O).
#[derive(Debug, Default)]
pub struct RuleEngine {
    rules: HashMap<String, LockMode>,
    last_unlocked: HashMap<String, u64>,
}

impl RuleEngine {
    /// Builds a `RuleEngine` from configured locked apps.
    #[must_use]
    pub fn from_apps(apps: &[LockedApp]) -> Self {
        let mut rules = HashMap::with_capacity(apps.len());
        for app in apps {
            rules.insert(app.app_id.to_ascii_lowercase(), app.mode);
        }
        Self {
            rules,
            last_unlocked: HashMap::new(),
        }
    }

    /// Returns `true` if `app_id` must be locked at `now_unix_secs`.
    #[must_use]
    pub fn should_lock(&self, app_id: &str, now_unix_secs: u64) -> bool {
        let key = app_id.to_ascii_lowercase();
        let Some(&mode) = self.rules.get(&key) else {
            return false;
        };
        match mode {
            LockMode::Always => true,
            LockMode::Grace { seconds } => match self.last_unlocked.get(&key) {
                Some(&ts) => now_unix_secs.saturating_sub(ts) >= seconds,
                None => true,
            },
        }
    }

    /// Records a successful unlock timestamp for `app_id`.
    pub fn record_unlock(&mut self, app_id: &str, now_unix_secs: u64) {
        self.last_unlocked
            .insert(app_id.to_ascii_lowercase(), now_unix_secs);
    }

    /// Clears all active grace periods (e.g., on Windows lock, sleep, or pause end).
    pub fn invalidate_all(&mut self) {
        self.last_unlocked.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn always_and_grace_modes_work_with_injected_clock() {
        let apps = vec![
            LockedApp {
                app_id: "notepad.exe".to_string(),
                mode: LockMode::Always,
            },
            LockedApp {
                app_id: "msedge.exe".to_string(),
                mode: LockMode::Grace { seconds: 300 },
            },
        ];
        let mut engine = RuleEngine::from_apps(&apps);

        assert!(!engine.should_lock("calc.exe", 1000));
        assert!(engine.should_lock("Notepad.exe", 1000));
        assert!(engine.should_lock("msedge.exe", 1000));

        engine.record_unlock("notepad.exe", 1000);
        engine.record_unlock("msedge.exe", 1000);

        // Always mode never skips lock.
        assert!(engine.should_lock("notepad.exe", 1001));
        // Grace mode skips lock within 300s, re-locks at >= 300s.
        assert!(!engine.should_lock("msedge.exe", 1299));
        assert!(engine.should_lock("msedge.exe", 1300));

        engine.record_unlock("msedge.exe", 1300);
        assert!(!engine.should_lock("msedge.exe", 1350));
        engine.invalidate_all();
        assert!(engine.should_lock("msedge.exe", 1350));
    }
}
