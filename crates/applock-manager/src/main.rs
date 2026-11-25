//! Software-rendered Slint Manager UI for `AppLock`.

#![deny(unsafe_code)]
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::cell::{Cell, RefCell};
use std::process::ExitCode;
use std::rc::Rc;

use applock_i18n::{Language, LockStrings, ManagerStrings};
use applock_ipc::{Request, Response};
use applock_sys::crypto::fill_random;
use applock_sys::pipe::{PipeClient, PIPE_NAME};
use slint::{ComponentHandle, ModelRc, VecModel};

#[allow(
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    missing_docs
)]
mod slint_generated {
    slint::include_modules!();
}

use slint_generated::{AppEntry, ManagerWindow, Tokens};

#[derive(Debug, Clone, PartialEq, Eq)]
struct CliArgs {
    lang: Language,
    dark: bool,
}

fn parse_args<I>(iter: I) -> CliArgs
where
    I: IntoIterator<Item = String>,
{
    let mut lang = Language::En;
    let mut dark = false;
    let mut it = iter.into_iter();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--lang" => {
                if let Some(val) = it.next() {
                    if val.eq_ignore_ascii_case("ur") {
                        lang = Language::Ur;
                    } else {
                        lang = Language::En;
                    }
                }
            }
            "--dark" => dark = true,
            _ => {}
        }
    }
    CliArgs { lang, dark }
}

fn send_ipc(req: &Request) -> Option<Response> {
    let bytes = req.encode().ok()?;
    let client = PipeClient::connect(PIPE_NAME, 1000).ok()?;
    client.write_frame(&bytes).ok()?;
    let resp_bytes = client.read_frame().ok()?;
    Response::decode(&resp_bytes).ok()
}

fn filter_apps(all: &[String], query: &str) -> Vec<AppEntry> {
    let q = query.trim().to_ascii_lowercase();
    all.iter()
        .filter(|name| q.is_empty() || name.to_ascii_lowercase().contains(&q))
        .map(|name| AppEntry {
            name: name.as_str().into(),
            locked: true,
        })
        .collect()
}

fn apply_strings(window: &ManagerWindow, lang: Language) {
    let lock_s = LockStrings::load(lang);
    let mgr_s = ManagerStrings::load(lang);
    window.global::<Tokens>().set_rtl(lang.is_rtl());
    window.set_window_title(mgr_s.title.into());
    window.set_gate_prompt(mgr_s.unlock_prompt.into());
    window.set_pin_placeholder(lock_s.pin_placeholder.into());
    window.set_unlock_label(lock_s.unlock_button.into());
    window.set_tab_apps_label(mgr_s.tab_apps.into());
    window.set_tab_security_label(mgr_s.tab_security.into());
    window.set_tab_limits_label(mgr_s.tab_limits.into());
    window.set_search_placeholder(mgr_s.search_placeholder.into());
    window.set_add_placeholder(mgr_s.add_placeholder.into());
    window.set_add_button_label(mgr_s.add_button.into());
    window.set_empty_apps_label(mgr_s.empty_apps.into());
    window.set_locked_label(mgr_s.locked_label.into());
    window.set_unlocked_label(mgr_s.unlocked_label.into());
    window.set_current_pin_label(mgr_s.current_pin.into());
    window.set_new_pin_label(mgr_s.new_pin.into());
    window.set_confirm_pin_label(mgr_s.confirm_pin.into());
    window.set_save_pin_label(mgr_s.save_pin.into());
    window.set_lang_label(mgr_s.lang_label.into());
    window.set_theme_label(mgr_s.theme_label.into());
    window.set_limits_intro(mgr_s.limits_intro.into());
    window.set_limits_admin(mgr_s.limits_admin.into());
    window.set_limits_safemode(mgr_s.limits_safemode.into());
    window.set_limits_disk(mgr_s.limits_disk.into());
}

fn fetch_locked_apps() -> Vec<String> {
    let mut nonce = [0_u8; 16];
    if fill_random(&mut nonce).is_err() {
        return Vec::new();
    }
    match send_ipc(&Request::ListLockedApps { nonce }) {
        Some(Response::LockedApps {
            nonce: r_nonce,
            apps,
        }) if r_nonce == nonce => apps,
        _ => Vec::new(),
    }
}

fn refresh_app_model(window: &ManagerWindow, cached: &Rc<RefCell<Vec<String>>>, query: &str) {
    let list = fetch_locked_apps();
    let entries = filter_apps(&list, query);
    *cached.borrow_mut() = list;
    window.set_apps(ModelRc::new(VecModel::from(entries)));
}

fn wire_gate_callbacks(
    window: &ManagerWindow,
    current_lang: &Rc<Cell<Language>>,
    cached_apps: &Rc<RefCell<Vec<String>>>,
) {
    let weak = window.as_weak();
    let lang_cell = Rc::clone(current_lang);
    let apps_cache = Rc::clone(cached_apps);
    window.on_gate_submitted(move |secret| {
        let Some(w) = weak.upgrade() else {
            return;
        };
        let lock_s = LockStrings::load(lang_cell.get());
        if secret.is_empty() {
            w.set_gate_error(lock_s.wrong_credential.into());
            return;
        }
        let mut nonce = [0_u8; 16];
        if fill_random(&mut nonce).is_err() {
            w.set_gate_error(lock_s.service_offline.into());
            return;
        }
        let req = Request::VerifyCredential {
            nonce,
            target_pid: 0,
            secret: secret.as_bytes().to_vec(),
        };
        w.set_gate_pin("".into());
        match send_ipc(&req) {
            Some(Response::CredentialResult {
                nonce: r_nonce,
                allowed: true,
                ..
            }) if r_nonce == nonce => {
                w.set_gate_error("".into());
                w.set_unlocked(true);
                refresh_app_model(&w, &apps_cache, w.get_search_query().as_str());
            }
            Some(Response::CredentialResult {
                nonce: r_nonce,
                allowed: false,
                lockout_remaining_secs,
            }) if r_nonce == nonce => {
                if lockout_remaining_secs > 0 {
                    let msg = format!(
                        "{} {}{}",
                        lock_s.lockout_prefix, lockout_remaining_secs, lock_s.seconds_suffix
                    );
                    w.set_gate_error(msg.into());
                } else {
                    w.set_gate_error(lock_s.wrong_credential.into());
                }
            }
            _ => w.set_gate_error(lock_s.service_offline.into()),
        }
    });
}

fn wire_apps_callbacks(window: &ManagerWindow, cached_apps: &Rc<RefCell<Vec<String>>>) {
    let weak = window.as_weak();
    let apps_cache = Rc::clone(cached_apps);
    window.on_search_changed(move |query| {
        let Some(w) = weak.upgrade() else {
            return;
        };
        let entries = filter_apps(&apps_cache.borrow(), query.as_str());
        w.set_apps(ModelRc::new(VecModel::from(entries)));
    });

    let weak = window.as_weak();
    let apps_cache = Rc::clone(cached_apps);
    window.on_add_app_submitted(move |raw_name| {
        let Some(w) = weak.upgrade() else {
            return;
        };
        let trimmed = raw_name.trim();
        if trimmed.is_empty() {
            return;
        }
        let mut nonce = [0_u8; 16];
        if fill_random(&mut nonce).is_err() {
            return;
        }
        let req = Request::SetAppLocked {
            nonce,
            app_id: trimmed.to_string(),
            locked: true,
        };
        if matches!(
            send_ipc(&req),
            Some(Response::Ack {
                nonce: r_nonce,
                ok: true
            }) if r_nonce == nonce
        ) {
            w.set_add_input("".into());
            refresh_app_model(&w, &apps_cache, w.get_search_query().as_str());
        }
    });

    let weak = window.as_weak();
    let apps_cache = Rc::clone(cached_apps);
    window.on_toggle_app(move |name, locked| {
        let Some(w) = weak.upgrade() else {
            return;
        };
        let mut nonce = [0_u8; 16];
        if fill_random(&mut nonce).is_err() {
            return;
        }
        let req = Request::SetAppLocked {
            nonce,
            app_id: name.to_string(),
            locked,
        };
        if matches!(
            send_ipc(&req),
            Some(Response::Ack {
                nonce: r_nonce,
                ok: true
            }) if r_nonce == nonce
        ) {
            refresh_app_model(&w, &apps_cache, w.get_search_query().as_str());
        }
    });
}

fn wire_security_callbacks(
    window: &ManagerWindow,
    current_lang: &Rc<Cell<Language>>,
    dark_mode: &Rc<Cell<bool>>,
) {
    let weak = window.as_weak();
    let lang_cell = Rc::clone(current_lang);
    window.on_change_pin_submitted(move |curr, new_p, conf| {
        let Some(w) = weak.upgrade() else {
            return;
        };
        let lock_s = LockStrings::load(lang_cell.get());
        let mgr_s = ManagerStrings::load(lang_cell.get());
        if new_p.len() < 4 {
            w.set_security_is_error(true);
            w.set_security_status(mgr_s.pin_too_short.into());
            return;
        }
        if new_p != conf {
            w.set_security_is_error(true);
            w.set_security_status(mgr_s.pin_mismatch.into());
            return;
        }
        let mut nonce = [0_u8; 16];
        if fill_random(&mut nonce).is_err() {
            w.set_security_is_error(true);
            w.set_security_status(lock_s.service_offline.into());
            return;
        }
        let req = Request::ChangePin {
            nonce,
            current_secret: curr.as_bytes().to_vec(),
            new_secret: new_p.as_bytes().to_vec(),
        };
        w.set_current_pin_input("".into());
        w.set_new_pin_input("".into());
        w.set_confirm_pin_input("".into());
        match send_ipc(&req) {
            Some(Response::CredentialResult {
                nonce: r_nonce,
                allowed: true,
                ..
            }) if r_nonce == nonce => {
                w.set_security_is_error(false);
                w.set_security_status(mgr_s.pin_saved.into());
            }
            Some(Response::CredentialResult {
                nonce: r_nonce,
                allowed: false,
                ..
            }) if r_nonce == nonce => {
                w.set_security_is_error(true);
                w.set_security_status(lock_s.wrong_credential.into());
            }
            _ => {
                w.set_security_is_error(true);
                w.set_security_status(lock_s.service_offline.into());
            }
        }
    });

    let weak = window.as_weak();
    let lang_cell = Rc::clone(current_lang);
    window.on_toggle_language(move || {
        let Some(w) = weak.upgrade() else {
            return;
        };
        let next = match lang_cell.get() {
            Language::En => Language::Ur,
            Language::Ur => Language::En,
        };
        lang_cell.set(next);
        apply_strings(&w, next);
    });

    let weak = window.as_weak();
    let theme_cell = Rc::clone(dark_mode);
    window.on_toggle_theme(move || {
        let Some(w) = weak.upgrade() else {
            return;
        };
        let next = !theme_cell.get();
        theme_cell.set(next);
        w.global::<Tokens>().set_dark_mode(next);
    });
}

fn main() -> ExitCode {
    let args = parse_args(std::env::args().skip(1));
    let Ok(window) = ManagerWindow::new() else {
        return ExitCode::FAILURE;
    };

    let current_lang = Rc::new(Cell::new(args.lang));
    let dark_mode = Rc::new(Cell::new(args.dark));
    let cached_apps = Rc::new(RefCell::new(Vec::<String>::new()));

    window.global::<Tokens>().set_dark_mode(args.dark);
    apply_strings(&window, args.lang);

    wire_gate_callbacks(&window, &current_lang, &cached_apps);
    wire_apps_callbacks(&window, &cached_apps);
    wire_security_callbacks(&window, &current_lang, &dark_mode);

    if window.run().is_err() {
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_apps_matches_case_insensitive_substring() {
        let list = vec!["notepad.exe".to_string(), "WhatsApp.exe".to_string()];
        let all = filter_apps(&list, "");
        assert_eq!(all.len(), 2);
        let filtered = filter_apps(&list, "whats");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name.as_str(), "WhatsApp.exe");
    }

    #[test]
    fn parse_args_handles_lang_and_dark() {
        let parsed = parse_args(["--lang".to_string(), "ur".to_string(), "--dark".to_string()]);
        assert_eq!(parsed.lang, Language::Ur);
        assert!(parsed.dark);
    }
}
