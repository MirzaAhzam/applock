//! Software-rendered Slint lock screen UI for `AppLock`.

// Slint's generated `ItemTreeVTable_static!` macro emits `#[allow(unsafe_code)]`,
// which triggers E0453 under `#![forbid(unsafe_code)]`. All hand-written code
// in this crate contains zero `unsafe`.
#![deny(unsafe_code)]
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::cell::Cell;
use std::process::ExitCode;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use applock_i18n::{Language, LockStrings};
use applock_ipc::{OverlayUpdate, Request, Response, WindowVisibility};
use applock_sys::crypto::fill_random;
use applock_sys::pipe::{PipeClient, PipeServer, PIPE_NAME};
use applock_sys::window::{configure_lock_overlay_hwnd, find_own_window_hwnd, WindowBounds};

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

use slint::ComponentHandle;
use slint_generated::{LockWindow, Tokens};

#[derive(Debug, Clone, PartialEq, Eq)]
struct CliArgs {
    app_name: String,
    pid: u32,
    lang: Language,
    dark: bool,
    bounds: Option<WindowBounds>,
    overlay_pipe: Option<String>,
}

impl Default for CliArgs {
    fn default() -> Self {
        Self {
            app_name: "App".to_string(),
            pid: 0,
            lang: Language::En,
            dark: true,
            bounds: None,
            overlay_pipe: None,
        }
    }
}

fn parse_args<I>(iter: I) -> CliArgs
where
    I: IntoIterator<Item = String>,
{
    let mut args = CliArgs::default();
    let mut x: Option<i32> = None;
    let mut y: Option<i32> = None;
    let mut width: Option<i32> = None;
    let mut height: Option<i32> = None;
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
            "--light" => {
                args.dark = false;
            }
            "--x" => {
                if let Some(val) = it.next() {
                    x = val.parse::<i32>().ok();
                }
            }
            "--y" => {
                if let Some(val) = it.next() {
                    y = val.parse::<i32>().ok();
                }
            }
            "--width" => {
                if let Some(val) = it.next() {
                    width = val.parse::<i32>().ok();
                }
            }
            "--height" => {
                if let Some(val) = it.next() {
                    height = val.parse::<i32>().ok();
                }
            }
            "--overlay-pipe" => {
                if let Some(val) = it.next() {
                    if !val.trim().is_empty() {
                        args.overlay_pipe = Some(val);
                    }
                }
            }
            _ => {}
        }
    }
    if let (Some(left), Some(top), Some(w), Some(h)) = (x, y, width, height) {
        if w > 0 && h > 0 {
            args.bounds = Some(WindowBounds {
                left,
                top,
                width: w,
                height: h,
            });
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

    if let Some(b) = args.bounds {
        window
            .window()
            .set_position(slint::PhysicalPosition::new(b.left, b.top));
        window.window().set_size(slint::PhysicalSize::new(
            u32::try_from(b.width).unwrap_or(420),
            u32::try_from(b.height).unwrap_or(290),
        ));
    }

    let current_bounds = Arc::new(Mutex::new(args.bounds.unwrap_or(WindowBounds {
        left: 100,
        top: 100,
        width: 420,
        height: 290,
    })));

    if let Some(b) = args.bounds {
        slint::Timer::single_shot(Duration::from_millis(15), move || {
            if let Some(hwnd) = find_own_window_hwnd() {
                configure_lock_overlay_hwnd(hwnd, b, true);
            }
        });
    }

    if let Some(pipe_name) = args.overlay_pipe.clone() {
        let weak_win = window.as_weak();
        let bounds_state = Arc::clone(&current_bounds);
        thread::spawn(move || {
            let Ok(server) = PipeServer::create(&pipe_name) else {
                return;
            };
            loop {
                if server.accept().is_err() {
                    continue;
                }
                if let Ok(frame) = server.read_frame() {
                    if let Ok(update) = OverlayUpdate::decode(&frame) {
                        let visible = update.visibility == WindowVisibility::Visible;
                        let new_bounds = WindowBounds {
                            left: update.rect.x,
                            top: update.rect.y,
                            width: update.rect.width,
                            height: update.rect.height,
                        };
                        if visible && new_bounds.width > 0 && new_bounds.height > 0 {
                            if let Ok(mut g) = bounds_state.lock() {
                                *g = new_bounds;
                            }
                        }
                        let effective_bounds = bounds_state
                            .lock()
                            .map(|g| *g)
                            .unwrap_or(new_bounds);
                        let weak_ui = weak_win.clone();
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(w) = weak_ui.upgrade() {
                                if visible && effective_bounds.width > 0 && effective_bounds.height > 0 {
                                    w.window().set_position(slint::PhysicalPosition::new(
                                        effective_bounds.left,
                                        effective_bounds.top,
                                    ));
                                    w.window().set_size(slint::PhysicalSize::new(
                                        u32::try_from(effective_bounds.width).unwrap_or(420),
                                        u32::try_from(effective_bounds.height).unwrap_or(290),
                                    ));
                                }
                                if let Some(hwnd) = find_own_window_hwnd() {
                                    configure_lock_overlay_hwnd(hwnd, effective_bounds, visible);
                                }
                            }
                        });
                    }
                }
                server.disconnect();
            }
        });
    }

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
            "--x".to_string(),
            "120".to_string(),
            "--y".to_string(),
            "80".to_string(),
            "--width".to_string(),
            "900".to_string(),
            "--height".to_string(),
            "600".to_string(),
            "--overlay-pipe".to_string(),
            r"\\.\pipe\AppLockOverlay_1".to_string(),
        ]);
        assert_eq!(parsed.app_name, "WhatsApp");
        assert_eq!(parsed.pid, 4242);
        assert_eq!(parsed.lang, Language::Ur);
        assert!(parsed.dark);
        assert_eq!(
            parsed.bounds,
            Some(WindowBounds {
                left: 120,
                top: 80,
                width: 900,
                height: 600,
            })
        );
        assert_eq!(
            parsed.overlay_pipe.as_deref(),
            Some(r"\\.\pipe\AppLockOverlay_1")
        );
    }

    #[test]
    fn parse_cli_args_ignores_invalid_values() {
        let parsed = parse_args([
            "--app".to_string(),
            "   ".to_string(),
            "--pid".to_string(),
            "not-a-number".to_string(),
            "--light".to_string(),
            "--width".to_string(),
            "-10".to_string(),
        ]);
        assert_eq!(parsed.app_name, "App");
        assert_eq!(parsed.pid, 0);
        assert_eq!(parsed.lang, Language::En);
        assert!(!parsed.dark);
        assert!(parsed.bounds.is_none());
    }
}
