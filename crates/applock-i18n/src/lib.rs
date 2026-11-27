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
        let get =
            |k: &str, fallback: &str| map.get(k).cloned().unwrap_or_else(|| fallback.to_string());
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

/// Externalized UI strings for the Manager window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagerStrings {
    /// Window title.
    pub title: String,
    /// Unlock gate prompt.
    pub unlock_prompt: String,
    /// Apps navigation tab.
    pub tab_apps: String,
    /// Security navigation tab.
    pub tab_security: String,
    /// Honest limits navigation tab.
    pub tab_limits: String,
    /// Search input placeholder.
    pub search_placeholder: String,
    /// Add executable input placeholder.
    pub add_placeholder: String,
    /// Add/lock app button label.
    pub add_button: String,
    /// Secondary Browse `.exe` button label.
    pub browse_button: String,
    /// Status text while scanning installed apps.
    pub loading_apps: String,
    /// Empty state message when no apps match.
    pub empty_apps: String,
    /// Locked badge text.
    pub locked_label: String,
    /// Unlocked badge text.
    pub unlocked_label: String,
    /// Action label to unlock/remove an app.
    pub remove_label: String,
    /// Current PIN field label.
    pub current_pin: String,
    /// New PIN field label.
    pub new_pin: String,
    /// Confirm PIN field label.
    pub confirm_pin: String,
    /// Save PIN button label.
    pub save_pin: String,
    /// Error when new PINs do not match.
    pub pin_mismatch: String,
    /// Error when new PIN is too short.
    pub pin_too_short: String,
    /// Confirmation when PIN is saved.
    pub pin_saved: String,
    /// Language toggle label.
    pub lang_label: String,
    /// Dark theme toggle label.
    pub theme_label: String,
    /// Honest limits intro sentence.
    pub limits_intro: String,
    /// Honest limit: admin account.
    pub limits_admin: String,
    /// Honest limit: safe mode.
    pub limits_safemode: String,
    /// Honest limit: disk without `BitLocker`.
    pub limits_disk: String,
}

impl ManagerStrings {
    /// Loads all Manager strings for `lang` from embedded locale TOML files.
    #[must_use]
    pub fn load(lang: Language) -> Self {
        let raw = match lang {
            Language::En => EN_TOML,
            Language::Ur => UR_TOML,
        };
        let map = parse_simple_toml(raw);
        let get =
            |k: &str, fallback: &str| map.get(k).cloned().unwrap_or_else(|| fallback.to_string());
        Self {
            title: get("mgr_title", "AppLock Manager"),
            unlock_prompt: get(
                "mgr_unlock_prompt",
                "Enter your PIN or password to open AppLock Manager.",
            ),
            tab_apps: get("mgr_tab_apps", "Apps"),
            tab_security: get("mgr_tab_security", "Security"),
            tab_limits: get("mgr_tab_limits", "Honest limits"),
            search_placeholder: get("mgr_search_placeholder", "Search apps"),
            add_placeholder: get(
                "mgr_add_placeholder",
                "Add executable (for example: whatsapp.exe)",
            ),
            add_button: get("mgr_add_button", "Lock app"),
            browse_button: get("mgr_browse_button", "Browse .exe"),
            loading_apps: get("mgr_loading_apps", "Scanning installed apps..."),
            empty_apps: get("mgr_empty_apps", "No matching apps found."),
            locked_label: get("mgr_locked_label", "Locked"),
            unlocked_label: get("mgr_unlocked_label", "Unlocked"),
            remove_label: get("mgr_remove_label", "Unlock"),
            current_pin: get("mgr_current_pin", "Current PIN or password"),
            new_pin: get("mgr_new_pin", "New PIN or password (at least 4 characters)"),
            confirm_pin: get("mgr_confirm_pin", "Confirm new PIN or password"),
            save_pin: get("mgr_save_pin", "Save new PIN"),
            pin_mismatch: get("mgr_pin_mismatch", "The new PIN entries do not match."),
            pin_too_short: get("mgr_pin_too_short", "The new PIN must be at least 4 characters."),
            pin_saved: get("mgr_pin_saved", "The new PIN is saved."),
            lang_label: get("mgr_lang_label", "Language"),
            theme_label: get("mgr_theme_label", "Dark theme"),
            limits_intro: get(
                "mgr_limits_intro",
                "AppLock blocks normal app launches in your Windows account. It cannot protect against:",
            ),
            limits_admin: get(
                "mgr_limits_admin",
                "Anyone with a Windows Administrator account on this PC.",
            ),
            limits_safemode: get(
                "mgr_limits_safemode",
                "Booting Windows into Safe Mode or another operating system.",
            ),
            limits_disk: get(
                "mgr_limits_disk",
                "Reading files directly from the drive if BitLocker is turned off.",
            ),
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
