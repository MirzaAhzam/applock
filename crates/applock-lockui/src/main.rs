//! Software-rendered Slint lock screen UI for `AppLock`.

// Slint's generated `ItemTreeVTable_static!` macro emits `#[allow(unsafe_code)]`,
// which triggers E0453 under `#![forbid(unsafe_code)]`. All hand-written code
// in this crate contains zero `unsafe`.
#![deny(unsafe_code)]
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::cell::Cell;
use std::process::ExitCode;
use std::rc::Rc;

use applock_i18n::{Language, LockStrings};
use applock_ipc::{Request, Response};
use applock_sys::crypto::fill_random;
use applock_sys::pipe::{PipeClient, PIPE_NAME};

#[allow(clippy::all, clippy::pedantic, missing_docs)]
mod slint_generated {
    slint::include_modules!();
}

use slint_generated::{ComponentHandle, LockWindow, Tokens};

#[derive(Debug, Clone, PartialEq, Eq)]
struct CliArgs {
    app_name: String,
    pid: u32,
    lang: Language,
    dark: bool,
}

impl Default for CliArgs {
    fn default() -> Self {
        Self {
            app_name: "App".to_string(),
            pid: 0,
            lang: Language::En,
            dark: false,
        }
    }
}

fn parse_args<I>(iter: I) -> CliArgs
where
    I: IntoIterator<Item = String>,
{
    let mut args = CliArgs::default();
    let mut it = iter.into_iter();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--app" => {
                if let Some(val) = it.next() {
                    if !val.trim().is_empty() {
                        args.app_name = val;
                    }
                }
            }
            "--pid" => {
                if let Some(val) = it.next() {
                    if let Ok(parsed) = val.parse::<u32>() {
                        args.pid = parsed;
                    }
                }
            }
            "--lang" => {
                if let Some(val) = it.next() {
                    if val.eq_ignore_ascii_case("ur") {
                        args.lang = Language::Ur;
                    } else {
                        args.lang = Language::En;
                    }
                }
            }
            "--dark" => {
                args.dark = true;
            }
            _ => {}
        }
    }
    args
}

enum VerifyOutcome {
    Allowed,
    Denied { lockout_remaining_secs: u64 },
    ServiceUnavailable,
}

fn verify_with_service(target_pid: u32, secret: &str) -> VerifyOutcome {
    let mut nonce = [0_u8; 16];
    if fill_random(&mut nonce).is_err() {
        return VerifyOutcome::ServiceUnavailable;
    }

    let req = Request::VerifyCredential {
        nonce,
        target_pid,
        secret: secret.as_bytes().to_vec(),
    };
    let Ok(bytes) = req.encode() else {
        return VerifyOutcome::ServiceUnavailable;
    };

    let Ok(client) = PipeClient::connect(PIPE_NAME, 1000) else {
        return VerifyOutcome::ServiceUnavailable;
    };
    if client.write_frame(&bytes).is_err() {
        return VerifyOutcome::ServiceUnavailable;
    }
    let Ok(resp_bytes) = client.read_frame() else {
        return VerifyOutcome::ServiceUnavailable;
    };
    let Ok(resp) = Response::decode(&resp_bytes) else {
        return VerifyOutcome::ServiceUnavailable;
    };

    match resp {
        Response::CredentialResult {
            nonce: resp_nonce,
            allowed,
            lockout_remaining_secs,
        } if resp_nonce == nonce => {
            if allowed {
                VerifyOutcome::Allowed
            } else {
                VerifyOutcome::Denied {
                    lockout_remaining_secs,
                }
            }
        }
        _ => VerifyOutcome::ServiceUnavailable,
    }
}

fn main() -> ExitCode {
    let args = parse_args(std::env::args().skip(1));
    let strings = LockStrings::load(args.lang);

    let Ok(window) = LockWindow::new() else {
        return ExitCode::FAILURE;
    };

    let tokens = window.global::<Tokens>();
    tokens.set_dark_mode(args.dark);
    tokens.set_rtl(args.lang.is_rtl());

    window.set_app_name(args.app_name.clone().into());
    window.set_prompt_instruction(strings.prompt_instruction.clone().into());
    window.set_pin_placeholder(strings.pin_placeholder.clone().into());
    window.set_unlock_label(strings.unlock_button.clone().into());
    window.set_cancel_label(strings.cancel_button.clone().into());

    let unlocked = Rc::new(Cell::new(false));
    let weak = window.as_weak();
    let unlocked_cb = Rc::clone(&unlocked);
    let strings_cb = strings.clone();
    let target_pid = args.pid;

    window.on_unlock_submitted(move |secret| {
        let Some(w) = weak.upgrade() else {
            return;
        };
        if secret.is_empty() {
            w.set_error_text(strings_cb.wrong_credential.clone().into());
            return;
        }

        w.set_busy(true);
        w.set_error_text("".into());

        let outcome = verify_with_service(target_pid, secret.as_str());
        w.set_busy(false);
        w.set_secret_input("".into());

        match outcome {
            VerifyOutcome::Allowed => {
                unlocked_cb.set(true);
                let _ = slint::quit_event_loop();
            }
            VerifyOutcome::Denied {
                lockout_remaining_secs,
            } => {
                if lockout_remaining_secs > 0 {
                    w.set_is_locked_out(true);
                    let msg = format!(
                        "{} {}{}",
                        strings_cb.lockout_prefix,
                        lockout_remaining_secs,
                        strings_cb.seconds_suffix
                    );
                    w.set_error_text(msg.into());
                } else {
                    w.set_is_locked_out(false);
                    w.set_error_text(strings_cb.wrong_credential.clone().into());
                }
            }
            VerifyOutcome::ServiceUnavailable => {
                w.set_is_locked_out(false);
                w.set_error_text(strings_cb.service_offline.clone().into());
            }
        }
    });

    window.on_cancelled(move || {
        let _ = slint::quit_event_loop();
    });

    if window.run().is_err() {
        return ExitCode::FAILURE;
    }

    if unlocked.get() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cli_args_defaults_and_overrides() {
        let parsed = parse_args([
            "--app".to_string(),
            "WhatsApp".to_string(),
            "--pid".to_string(),
            "4242".to_string(),
            "--lang".to_string(),
            "ur".to_string(),
            "--dark".to_string(),
        ]);
        assert_eq!(parsed.app_name, "WhatsApp");
        assert_eq!(parsed.pid, 4242);
        assert_eq!(parsed.lang, Language::Ur);
        assert!(parsed.dark);
    }

    #[test]
    fn parse_cli_args_ignores_invalid_values() {
        let parsed = parse_args([
            "--app".to_string(),
            "   ".to_string(),
            "--pid".to_string(),
            "not-a-number".to_string(),
        ]);
        assert_eq!(parsed.app_name, "App");
        assert_eq!(parsed.pid, 0);
        assert_eq!(parsed.lang, Language::En);
        assert!(!parsed.dark);
    }
}
