//! Software-rendered Slint Manager UI for `AppLock`.

#![deny(unsafe_code)]
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::process::ExitCode;
use std::rc::Rc;
use std::thread;

use applock_i18n::{Language, LockStrings, ManagerStrings};
use applock_ipc::{Request, Response};
use applock_sys::apps::{
    browse_exe_dialog, enumerate_installed_apps, extract_icon_rgba, DiscoveredApp,
};
use applock_sys::crypto::fill_random;
use applock_sys::pipe::{PipeClient, PIPE_NAME};
use slint::{ComponentHandle, Image, ModelRc, Rgba8Pixel, SharedPixelBuffer, VecModel};

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

#[derive(Clone)]
struct AppRowState {
    id: String,
    name: String,
    path: String,
    icon: Option<Image>,
}

thread_local! {
    static DISCOVERED_APPS: RefCell<Vec<AppRowState>> = const { RefCell::new(Vec::new()) };
}

fn rgba_to_slint_image(rgba: Option<(u32, u32, Vec<u8>)>) -> Option<Image> {
    let (w, h, pixels) = rgba?;
    let expected = usize::try_from(w.saturating_mul(h).saturating_mul(4)).ok()?;
    if pixels.len() != expected || w == 0 || h == 0 {
        return None;
    }
    let buf = SharedPixelBuffer::<Rgba8Pixel>::clone_from_slice(&pixels, w, h);
    Some(Image::from_rgba8(buf))
}

fn format_mode_label(grace_seconds: u64) -> &'static str {
    match grace_seconds {
        0 => "Ask",
        60 => "1m",
        300 => "5m",
        900 => "15m",
        1800 => "30m",
        _ => "Grace",
    }
}

fn next_grace_seconds(current: i32) -> u64 {
    match current {
        0 => 60,
        60 => 300,
        300 => 900,
        900 => 1800,
        _ => 0,
    }
}

fn build_app_entries(
    discovered: &[AppRowState],
    locked_modes: &HashMap<String, u64>,
    query: &str,
) -> Vec<AppEntry> {
    let q = query.trim().to_ascii_lowercase();
    let mut seen = HashSet::with_capacity(discovered.len());
    let mut entries = Vec::with_capacity(discovered.len() + locked_modes.len());

    for row in discovered {
        seen.insert(row.id.clone());
        let matches = q.is_empty()
            || row.name.to_ascii_lowercase().contains(&q)
            || row.id.to_ascii_lowercase().contains(&q)
            || row.path.to_ascii_lowercase().contains(&q);
        if matches {
            let grace = locked_modes.get(&row.id).copied();
            let secs = grace.unwrap_or(0);
            entries.push(AppEntry {
                id: row.id.as_str().into(),
                name: row.name.as_str().into(),
                path: row.path.as_str().into(),
                icon: row.icon.clone().unwrap_or_default(),
                has_icon: row.icon.is_some(),
                locked: grace.is_some(),
                grace_seconds: i32::try_from(secs).unwrap_or(0),
                mode_label: format_mode_label(secs).into(),
            });
        }
    }

    let mut custom_locked: Vec<(&String, &u64)> = locked_modes
        .iter()
        .filter(|(id, _)| !seen.contains(*id))
        .collect();
    custom_locked.sort_by(|a, b| a.0.cmp(b.0));
    for (id, &secs) in custom_locked {
        if q.is_empty() || id.to_ascii_lowercase().contains(&q) {
            entries.push(AppEntry {
                id: id.as_str().into(),
                name: id.as_str().into(),
                path: id.as_str().into(),
                icon: Image::default(),
                has_icon: false,
                locked: true,
                grace_seconds: i32::try_from(secs).unwrap_or(0),
                mode_label: format_mode_label(secs).into(),
            });
        }
    }

    entries
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
    window.set_browse_button_label(mgr_s.browse_button.into());
    window.set_loading_apps_label(mgr_s.loading_apps.into());
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

fn fetch_locked_apps() -> HashMap<String, u64> {
    let mut nonce = [0_u8; 16];
    if fill_random(&mut nonce).is_err() {
        return HashMap::new();
    }
    match send_ipc(&Request::ListAppModes { nonce }) {
        Some(Response::AppModes {
            nonce: r_nonce,
            apps,
        }) if r_nonce == nonce => apps
            .into_iter()
            .map(|(id, secs)| (id.to_ascii_lowercase(), secs))
            .collect(),
        _ => HashMap::new(),
    }
}

fn refresh_app_model(
    window: &ManagerWindow,
    locked_cache: &Rc<RefCell<HashMap<String, u64>>>,
    query: &str,
) {
    let locked = fetch_locked_apps();
    (*locked_cache.borrow_mut()).clone_from(&locked);
    let entries = DISCOVERED_APPS.with(|cell| build_app_entries(&cell.borrow(), &locked, query));
    window.set_apps(ModelRc::new(VecModel::from(entries)));
}

fn start_async_discovery(window: &ManagerWindow, locked_cache: &Rc<RefCell<HashMap<String, u64>>>) {
    window.set_loading_apps(true);
    let weak_bg = window.as_weak();
    let _ = locked_cache;

    thread::spawn(move || {
        let raw_apps: Vec<DiscoveredApp> = enumerate_installed_apps();
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(w) = weak_bg.upgrade() {
                let rows: Vec<AppRowState> = raw_apps
                    .into_iter()
                    .map(|a| AppRowState {
                        id: a.app_id,
                        name: a.display_name,
                        path: a.exe_path,
                        icon: rgba_to_slint_image(a.icon_rgba),
                    })
                    .collect();
                DISCOVERED_APPS.with(|cell| {
                    *cell.borrow_mut() = rows;
                });
                w.set_loading_apps(false);
                let locked = fetch_locked_apps();
                let entries = DISCOVERED_APPS.with(|cell| {
                    build_app_entries(&cell.borrow(), &locked, w.get_search_query().as_str())
                });
                w.set_apps(ModelRc::new(VecModel::from(entries)));
            }
        });
    });
}

fn wire_gate_callbacks(
    window: &ManagerWindow,
    current_lang: &Rc<Cell<Language>>,
    locked_cache: &Rc<RefCell<HashMap<String, u64>>>,
) {
    let weak = window.as_weak();
    let lang_cell = Rc::clone(current_lang);
    let lock_ref = Rc::clone(locked_cache);
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
                refresh_app_model(&w, &lock_ref, w.get_search_query().as_str());
                start_async_discovery(&w, &lock_ref);
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

fn wire_apps_callbacks(window: &ManagerWindow, locked_cache: &Rc<RefCell<HashMap<String, u64>>>) {
    let weak = window.as_weak();
    let lock_ref = Rc::clone(locked_cache);
    window.on_search_changed(move |query| {
        let Some(w) = weak.upgrade() else {
            return;
        };
        let entries = DISCOVERED_APPS
            .with(|cell| build_app_entries(&cell.borrow(), &lock_ref.borrow(), query.as_str()));
        w.set_apps(ModelRc::new(VecModel::from(entries)));
    });

    let weak = window.as_weak();
    let lock_ref = Rc::clone(locked_cache);
    window.on_browse_exe_clicked(move || {
        let Some(w) = weak.upgrade() else {
            return;
        };
        let Some(exe_path) = browse_exe_dialog() else {
            return;
        };
        let Some(app_id) = Path::new(&exe_path)
            .file_name()
            .and_then(|s| s.to_str())
            .map(str::to_ascii_lowercase)
        else {
            return;
        };
        if send_set_app_locked(&app_id, true) {
            DISCOVERED_APPS.with(|cell| {
                let mut rows = cell.borrow_mut();
                if !rows.iter().any(|r| r.id == app_id) {
                    let name = app_id.strip_suffix(".exe").unwrap_or(&app_id).to_string();
                    let icon = rgba_to_slint_image(extract_icon_rgba(&exe_path));
                    rows.push(AppRowState {
                        id: app_id,
                        name,
                        path: exe_path,
                        icon,
                    });
                }
            });
            refresh_app_model(&w, &lock_ref, w.get_search_query().as_str());
        }
    });

    let weak = window.as_weak();
    let lock_ref = Rc::clone(locked_cache);
    window.on_toggle_app(move |app_id, locked| {
        let Some(w) = weak.upgrade() else {
            return;
        };
        let normalized = app_id.to_ascii_lowercase();
        if send_set_app_locked(&normalized, locked) {
            refresh_app_model(&w, &lock_ref, w.get_search_query().as_str());
        }
    });

    let weak = window.as_weak();
    let lock_ref = Rc::clone(locked_cache);
    window.on_cycle_app_mode(move |app_id, current_secs| {
        let Some(w) = weak.upgrade() else {
            return;
        };
        let normalized = app_id.to_ascii_lowercase();
        let next_secs = next_grace_seconds(current_secs);
        if send_set_app_mode(&normalized, next_secs) {
            refresh_app_model(&w, &lock_ref, w.get_search_query().as_str());
        }
    });
}

fn send_set_app_mode(app_id: &str, grace_seconds: u64) -> bool {
    let mut nonce = [0_u8; 16];
    if fill_random(&mut nonce).is_err() {
        return false;
    }
    let req = Request::SetAppMode {
        nonce,
        app_id: app_id.to_string(),
        grace_seconds,
    };
    matches!(
        send_ipc(&req),
        Some(Response::Ack {
            nonce: r_nonce,
            ok: true
        }) if r_nonce == nonce
    )
}

fn send_set_app_locked(app_id: &str, locked: bool) -> bool {
    let mut nonce = [0_u8; 16];
    if fill_random(&mut nonce).is_err() {
        return false;
    }
    let req = Request::SetAppLocked {
        nonce,
        app_id: app_id.to_string(),
        locked,
    };
    matches!(
        send_ipc(&req),
        Some(Response::Ack {
            nonce: r_nonce,
            ok: true
        }) if r_nonce == nonce
    )
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
    let locked_cache = Rc::new(RefCell::new(HashMap::<String, u64>::new()));

    window.global::<Tokens>().set_dark_mode(args.dark);
    apply_strings(&window, args.lang);

    wire_gate_callbacks(&window, &current_lang, &locked_cache);
    wire_apps_callbacks(&window, &locked_cache);
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
        let list = vec![
            AppRowState {
                id: "notepad.exe".to_string(),
                name: "Notepad".to_string(),
                path: r"C:\Windows\System32\notepad.exe".to_string(),
                icon: None,
            },
            AppRowState {
                id: "whatsapp.exe".to_string(),
                name: "WhatsApp".to_string(),
                path: r"C:\Users\Test\AppData\Local\WhatsApp\WhatsApp.exe".to_string(),
                icon: None,
            },
        ];
        let locked = HashMap::from([("whatsapp.exe".to_string(), 300)]);
        let all = build_app_entries(&list, &locked, "");
        assert_eq!(all.len(), 2);
        let filtered = build_app_entries(&list, &locked, "whats");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name.as_str(), "WhatsApp");
        assert!(filtered[0].locked);
        assert_eq!(filtered[0].grace_seconds, 300);
        assert_eq!(filtered[0].mode_label.as_str(), "5m");
    }

    #[test]
    fn parse_args_handles_lang_and_dark() {
        let parsed = parse_args(["--lang".to_string(), "ur".to_string(), "--dark".to_string()]);
        assert_eq!(parsed.lang, Language::Ur);
        assert!(parsed.dark);
    }
}
