//! Localization loader and RTL helpers for `AppLock` (`locales/en.toml`, `locales/ur.toml`).

use std::collections::HashMap;

const EN_TOML: &str = include_str!("../../../locales/en.toml");
const UR_TOML: &str = include_str!("../../../locales/ur.toml");

/// Supported UI languages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    /// English (LTR).
    En,
    /// Urdu (RTL).
    Ur,
}

impl Language {
    /// Returns `true` for right-to-left languages (Urdu).
    #[must_use]
    pub const fn is_rtl(self) -> bool {
        matches!(self, Self::Ur)
    }
}

/// Externalized UI strings for the lock screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockStrings {
    /// Window title.
    pub lock_title: String,
    /// Instruction line shown above the input field.
    pub prompt_instruction: String,
    /// Placeholder for the PIN/password field.
    pub pin_placeholder: String,
    /// Primary unlock button label.
    pub unlock_button: String,
    /// Cancel and terminate button label.
    pub cancel_button: String,
    /// Status shown if verification takes longer than 300 ms.
    pub checking_status: String,
    /// Error shown on wrong credential.
    pub wrong_credential: String,
    /// Prefix for escalating lockout countdown.
    pub lockout_prefix: String,
    /// Seconds suffix for lockout countdown.
    pub seconds_suffix: String,
    /// Error shown when the service pipe is unavailable.
    pub service_offline: String,
}

impl LockStrings {
    /// Loads all lock screen strings for `lang` from embedded locale TOML files.
    #[must_use]
    pub fn load(lang: Language) -> Self {
        let raw = match lang {
            Language::En => EN_TOML,
            Language::Ur => UR_TOML,
        };
        let map = parse_simple_toml(raw);
        let get = |k: &str, fallback: &str| {
            map.get(k)
                .cloned()
                .unwrap_or_else(|| fallback.to_string())
        };
        Self {
            lock_title: get("lock_title", "AppLock"),
            prompt_instruction: get("prompt_instruction", "Enter your PIN or password to open"),
            pin_placeholder: get("pin_placeholder", "PIN or password"),
            unlock_button: get("unlock_button", "Unlock"),
            cancel_button: get("cancel_button", "Cancel and close app"),
            checking_status: get("checking_status", "Checking..."),
            wrong_credential: get("wrong_credential", "The PIN or password is wrong."),
            lockout_prefix: get("lockout_prefix", "Too many attempts. Try again in"),
            seconds_suffix: get("seconds_suffix", "s."),
            service_offline: get("service_offline", "AppLock service is not running."),
        }
    }
}

fn parse_simple_toml(input: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in input.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = trimmed.split_once('=') {
            let key = k.trim().to_string();
            let val = v.trim().trim_matches('"').to_string();
            map.insert(key, val);
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn english_and_urdu_have_matching_keys() {
        let en = parse_simple_toml(EN_TOML);
        let ur = parse_simple_toml(UR_TOML);
        assert_eq!(en.len(), ur.len());
        for key in en.keys() {
            assert!(ur.contains_key(key), "missing key in ur.toml: {key}");
        }
        assert!(!Language::En.is_rtl());
        assert!(Language::Ur.is_rtl());
    }
}
