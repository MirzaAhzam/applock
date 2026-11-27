//! `AppLock` Windows service binary: ETW launch interception, named-pipe IPC, Argon2id auth, and DPAPI config.

use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use applock_core::auth::{hash_secret, verify_secret};
use applock_core::config::{
    append_tamper_event, load_with_marker, save_atomic, AppConfig, ConfigLoadOutcome,
};
use applock_core::rules::{LockMode, LockedApp, RuleEngine};
use applock_ipc::{Request, Response};
use applock_sys::etw::EtwSession;
use applock_sys::lock_dialog::{show_m0_lock_prompt, LockPromptOutcome};
use applock_sys::pipe::{PipeServer, PIPE_NAME};
use applock_sys::process::{
    current_cpu_time_100ns, current_private_memory_bytes, hide_process_windows,
    launch_hidden_command, resume_process, show_process_windows, suspend_process,
    terminate_process, wait_process_exit,
};
use applock_sys::scm::{run_as_windows_service, ScmOutcome};
use applock_sys::security::{
    clear_install_marker, has_install_marker, set_install_marker, verify_and_repair_dir_acl,
};

const DEFAULT_PIN: &str = "1234";
const DEFAULT_WATCH_APPS: &[&str] = &[
    "notepad.exe",
    "calculatorapp.exe",
    "msedge.exe",
    "chrome.exe",
    "firefox.exe",
];

struct ServiceState {
    config_path: PathBuf,
    config: AppConfig,
    rules: RuleEngine,
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.iter().any(|a| a == "--bench-m0") {
        return run_bench_m0();
    }
    if args.iter().any(|a| a == "--reset-tamper") {
        return run_reset_tamper();
    }
    let service_args = args.clone();
    match run_as_windows_service("AppLockService", move || {
        let _ = run_service(&service_args);
    }) {
        Ok(ScmOutcome::ServiceCompleted) => ExitCode::SUCCESS,
        Ok(ScmOutcome::NotStartedByScm) => run_service(&args),
        Err(e) => {
            eprintln!("SCM dispatcher failed: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run_reset_tamper() -> ExitCode {
    let config_path = default_config_path();
    let log_path = tamper_log_path(&config_path);
    if let Err(e) = clear_install_marker() {
        eprintln!("Failed to clear install marker (run as Administrator): {e}");
        return ExitCode::FAILURE;
    }
    let _ = std::fs::remove_file(&config_path);
    let _ = std::fs::remove_file(config_path.with_extension("bin.bak"));
    let _ = std::fs::remove_file(config_path.with_extension("bin.tmp"));
    append_tamper_event(
        &log_path,
        now_unix_secs(),
        "Admin-elevated reset completed (--reset-tamper); ready for fresh credential setup",
    );
    println!("AppLock tamper state reset. Restart AppLockService and set a new credential.");
    ExitCode::SUCCESS
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn default_config_path() -> PathBuf {
    if let Ok(program_data) = env::var("ProgramData") {
        return PathBuf::from(program_data)
            .join("AppLock")
            .join("config.bin");
    }
    PathBuf::from("config.bin")
}

fn tamper_log_path(config_path: &Path) -> PathBuf {
    config_path.with_file_name("tamper.log")
}

fn default_locked_apps(apps_override: &[String]) -> Vec<LockedApp> {
    let app_list: Vec<String> = if apps_override.is_empty() {
        DEFAULT_WATCH_APPS
            .iter()
            .map(|s| (*s).to_string())
            .collect()
    } else {
        apps_override.to_vec()
    };
    app_list
        .into_iter()
        .map(|app_id| LockedApp {
            app_id,
            mode: LockMode::Always,
        })
        .collect()
}

fn load_or_init_config(path: &Path, apps_override: &[String]) -> AppConfig {
    let log_path = tamper_log_path(path);
    let now = now_unix_secs();

    // Machine-scope DPAPI detects corruption only; %ProgramData%\AppLock ACL is the real tamper barrier.
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(dir);
            match verify_and_repair_dir_acl(dir) {
                Ok(true) => append_tamper_event(
                    &log_path,
                    now,
                    "Permissive ACL detected on config directory and repaired",
                ),
                Ok(false) => {}
                Err(e) => append_tamper_event(
                    &log_path,
                    now,
                    &format!("Config directory ACL verification failed: {e}"),
                ),
            }
        }
    }

    let marker_present = match has_install_marker() {
        Ok(present) => present,
        Err(e) => {
            append_tamper_event(
                &log_path,
                now,
                &format!("Install marker check failed (failing closed): {e}"),
            );
            true
        }
    };

    match load_with_marker(path, marker_present) {
        Ok(ConfigLoadOutcome::Loaded(cfg)) => cfg,
        Ok(ConfigLoadOutcome::RecoveredFromBackup(cfg)) => {
            append_tamper_event(
                &log_path,
                now,
                "Primary config.bin was corrupt or tampered; restored last-known-good backup",
            );
            cfg
        }
        Ok(ConfigLoadOutcome::FreshInstall) => {
            let pin_hash = hash_secret(DEFAULT_PIN.as_bytes()).ok();
            let cfg = AppConfig {
                pin_hash,
                locked_apps: default_locked_apps(apps_override),
                ..AppConfig::default()
            };
            if save_atomic(path, &cfg).is_ok() {
                if let Err(e) = set_install_marker() {
                    append_tamper_event(
                        &log_path,
                        now,
                        &format!("Failed to write HKLM install marker: {e}"),
                    );
                }
            }
            cfg
        }
        Err(_) => {
            // Fail closed: do NOT create a fresh unlocked config when install marker exists.
            append_tamper_event(
                &log_path,
                now,
                "Config and backup missing or corrupt with install marker present; failing closed",
            );
            AppConfig {
                pin_hash: None,
                password_hash: None,
                locked_apps: default_locked_apps(apps_override),
                ..AppConfig::default()
            }
        }
    }
}

fn verify_and_update(
    state: &Arc<Mutex<ServiceState>>,
    attempt: &[u8],
    app_id: Option<&str>,
) -> (bool, u64) {
    let now = now_unix_secs();
    let Ok(mut guard) = state.lock() else {
        return (false, 30);
    };
    let rem = guard.config.lockout.remaining_secs(now);
    if rem > 0 {
        return (false, rem);
    }

    let ok_pw = guard
        .config
        .password_hash
        .as_deref()
        .is_some_and(|h| verify_secret(h, attempt));
    let ok_pin = guard
        .config
        .pin_hash
        .as_deref()
        .is_some_and(|h| verify_secret(h, attempt));

    if ok_pw || ok_pin {
        guard.config.lockout.record_success();
        if let Some(id) = app_id {
            guard.rules.record_unlock(id, now);
        }
        let cfg_clone = guard.config.clone();
        let path_clone = guard.config_path.clone();
        let _ = save_atomic(&path_clone, &cfg_clone);
        (true, 0)
    } else {
        guard.config.lockout.record_failure(now);
        let new_rem = guard.config.lockout.remaining_secs(now);
        let cfg_clone = guard.config.clone();
        let path_clone = guard.config_path.clone();
        let _ = save_atomic(&path_clone, &cfg_clone);
        (false, new_rem)
    }
}

fn spawn_pipe_server(state: Arc<Mutex<ServiceState>>) {
    thread::spawn(move || {
        let Ok(server) = PipeServer::create(PIPE_NAME) else {
            eprintln!("Warning: could not bind named pipe {PIPE_NAME}");
            return;
        };
        loop {
            if server.accept().is_err() {
                continue;
            }
            if let Ok(frame) = server.read_frame() {
                let resp = handle_ipc_frame(&state, &frame);
                if let Ok(bytes) = resp.encode() {
                    let _ = server.write_frame(&bytes);
                }
            }
            server.disconnect();
        }
    });
}

fn handle_set_app_locked(state: &Arc<Mutex<ServiceState>>, app_id: &str, locked: bool) -> bool {
    let normalized = app_id.trim().to_ascii_lowercase();
    if normalized.is_empty() || normalized.starts_with("applock-") {
        return false;
    }
    let Ok(mut guard) = state.lock() else {
        return false;
    };
    if locked {
        if !guard
            .config
            .locked_apps
            .iter()
            .any(|a| a.app_id.eq_ignore_ascii_case(&normalized))
        {
            guard.config.locked_apps.push(LockedApp {
                app_id: normalized,
                mode: LockMode::Always,
            });
        }
    } else {
        guard
            .config
            .locked_apps
            .retain(|a| !a.app_id.eq_ignore_ascii_case(&normalized));
    }
    guard.rules = RuleEngine::from_apps(&guard.config.locked_apps);
    let cfg_clone = guard.config.clone();
    let path_clone = guard.config_path.clone();
    save_atomic(&path_clone, &cfg_clone).is_ok()
}

fn handle_change_pin(
    state: &Arc<Mutex<ServiceState>>,
    current_secret: &[u8],
    new_secret: &[u8],
) -> (bool, u64) {
    let (allowed, rem) = verify_and_update(state, current_secret, None);
    if !allowed || new_secret.len() < 4 {
        return (false, rem);
    }
    let Ok(new_hash) = hash_secret(new_secret) else {
        return (false, 0);
    };
    let Ok(mut guard) = state.lock() else {
        return (false, 0);
    };
    guard.config.pin_hash = Some(new_hash);
    let cfg_clone = guard.config.clone();
    let path_clone = guard.config_path.clone();
    (save_atomic(&path_clone, &cfg_clone).is_ok(), 0)
}

fn handle_ipc_frame(state: &Arc<Mutex<ServiceState>>, frame: &[u8]) -> Response {
    match Request::decode(frame) {
        Ok(Request::Ping { nonce }) => Response::Pong { nonce },
        Ok(Request::QueryAppLocked { nonce, app_id }) => {
            let locked = state
                .lock()
                .map_or(true, |g| g.rules.should_lock(&app_id, now_unix_secs()));
            Response::AppLockStatus { nonce, locked }
        }
        Ok(Request::VerifyCredential {
            nonce,
            target_pid,
            secret,
        }) => {
            let (allowed, lockout_remaining_secs) = verify_and_update(state, &secret, None);
            if allowed && target_pid != 0 {
                let _ = resume_process(target_pid);
            }
            Response::CredentialResult {
                nonce,
                allowed,
                lockout_remaining_secs,
            }
        }
        Ok(Request::ListLockedApps { nonce }) => {
            let mut apps: Vec<String> = state
                .lock()
                .map(|g| {
                    g.config
                        .locked_apps
                        .iter()
                        .map(|a| a.app_id.clone())
                        .collect()
                })
                .unwrap_or_default();
            apps.sort();
            Response::LockedApps { nonce, apps }
        }
        Ok(Request::SetAppLocked {
            nonce,
            app_id,
            locked,
        }) => Response::Ack {
            nonce,
            ok: handle_set_app_locked(state, &app_id, locked),
        },
        Ok(Request::ChangePin {
            nonce,
            current_secret,
            new_secret,
        }) => {
            let (allowed, lockout_remaining_secs) =
                handle_change_pin(state, &current_secret, &new_secret);
            Response::CredentialResult {
                nonce,
                allowed,
                lockout_remaining_secs,
            }
        }
        Err(_) => Response::Error {
            nonce: [0_u8; 16],
            code: 400,
        },
    }
}

fn run_service(args: &[String]) -> ExitCode {
    let config_path = default_config_path();
    let apps_override: Vec<String> = args.iter().map(|s| s.to_ascii_lowercase()).collect();
    let config = load_or_init_config(&config_path, &apps_override);
    let rules = RuleEngine::from_apps(&config.locked_apps);

    println!("AppLock Service running (ETW + DPAPI config + Argon2id + Named Pipe).");
    println!("Config: {}", config_path.display());
    println!("Default M0 PIN (if new config): {DEFAULT_PIN}");

    let state = Arc::new(Mutex::new(ServiceState {
        config_path,
        config,
        rules,
    }));

    spawn_pipe_server(Arc::clone(&state));

    let (tx, rx) = std::sync::mpsc::channel::<(u32, String)>();
    let state_etw = Arc::clone(&state);

    let _session = match EtwSession::start(move |pid, path| {
        let exe_name = Path::new(path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if exe_name.is_empty() {
            return;
        }
        let should_lock = state_etw
            .lock()
            .map_or(true, |g| g.rules.should_lock(&exe_name, now_unix_secs()));
        if should_lock && suspend_process(pid).is_ok() {
            let _ = tx.send((pid, exe_name));
        }
    }) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to start ETW session (run as Administrator): {e}");
            return ExitCode::FAILURE;
        }
    };

    for (pid, exe_name) in rx {
        let hidden = hide_process_windows(pid);
        println!("Frozen {exe_name} (pid {pid}); verifying via Argon2id...");
        let outcome = show_m0_lock_prompt(&exe_name);
        match outcome {
            LockPromptOutcome::Attempt(pin) => {
                let (allowed, rem) = verify_and_update(&state, pin.as_bytes(), Some(&exe_name));
                if allowed {
                    println!("Unlocked {exe_name} (pid {pid})");
                    let _ = resume_process(pid);
                    show_process_windows(&hidden);
                } else {
                    println!("Rejected (lockout {rem}s) -> terminating {exe_name} (pid {pid})");
                    let _ = terminate_process(pid);
                }
            }
            LockPromptOutcome::Cancelled => {
                println!("Cancelled -> terminating {exe_name} (pid {pid})");
                let _ = terminate_process(pid);
            }
        }
    }

    ExitCode::SUCCESS
}

fn run_bench_m0() -> ExitCode {
    let pending: Arc<Mutex<HashMap<u32, Instant>>> = Arc::new(Mutex::new(HashMap::new()));
    let latencies_us: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));

    let pending_cb = Arc::clone(&pending);
    let lat_cb = Arc::clone(&latencies_us);

    let mut session = match EtwSession::start(move |pid, _path| {
        let launch_time = match pending_cb.lock() {
            Ok(mut guard) => guard.remove(&pid),
            Err(_) => None,
        };
        if let Some(t0) = launch_time {
            let _ = suspend_process(pid);
            let elapsed_us = u64::try_from(t0.elapsed().as_micros()).unwrap_or(u64::MAX);
            let _ = resume_process(pid);
            if let Ok(mut lats) = lat_cb.lock() {
                lats.push(elapsed_us);
            }
        }
    }) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ETW start failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    thread::sleep(Duration::from_millis(200));

    let total_runs = 60_usize;
    for _ in 0..total_runs {
        let t0 = Instant::now();
        match launch_hidden_command("cmd.exe /c exit 0") {
            Ok(pid) => {
                if let Ok(mut guard) = pending.lock() {
                    guard.insert(pid, t0);
                }
                thread::sleep(Duration::from_millis(35));
                wait_process_exit(pid, 100);
            }
            Err(e) => {
                eprintln!("launch_hidden_command failed: {e}");
            }
        }
    }

    thread::sleep(Duration::from_millis(150));

    let ram_bytes = current_private_memory_bytes().unwrap_or(0);
    let cpu_before = current_cpu_time_100ns().unwrap_or(0);
    let wall_before = Instant::now();
    thread::sleep(Duration::from_secs(1));
    let cpu_after = current_cpu_time_100ns().unwrap_or(cpu_before);
    let wall_100ns = u64::try_from(wall_before.elapsed().as_nanos() / 100).unwrap_or(10_000_000);
    let cpu_delta = cpu_after.saturating_sub(cpu_before);
    let idle_cpu_pct = (f64::from(u32::try_from(cpu_delta).unwrap_or(u32::MAX))
        / f64::from(u32::try_from(wall_100ns.max(1)).unwrap_or(u32::MAX)))
        * 100.0;

    session.stop();

    let mut samples = match latencies_us.lock() {
        Ok(guard) => guard.clone(),
        Err(_) => Vec::new(),
    };
    samples.sort_unstable();

    if samples.is_empty() {
        eprintln!("No ETW ProcessStart events captured for launched child processes.");
        return ExitCode::FAILURE;
    }

    let median_micros = percentile(&samples, 50);
    let tail_micros = percentile(&samples, 95);
    let p50_ms = f64::from(u32::try_from(median_micros).unwrap_or(u32::MAX)) / 1000.0;
    let p95_ms = f64::from(u32::try_from(tail_micros).unwrap_or(u32::MAX)) / 1000.0;
    let ram_mb = f64::from(u32::try_from(ram_bytes).unwrap_or(u32::MAX)) / (1024.0 * 1024.0);

    println!("M0 Service Benchmark Results:");
    println!("  captured_runs: {}/{total_runs}", samples.len());
    println!("  detect_to_frozen_p50_ms: {p50_ms:.2}");
    println!("  detect_to_frozen_p95_ms: {p95_ms:.2}");
    println!("  service_idle_ram_bytes: {ram_bytes} ({ram_mb:.2} MiB)");
    println!("  service_idle_cpu_pct: {idle_cpu_pct:.3}%");

    ExitCode::SUCCESS
}

fn percentile(sorted: &[u64], pct: usize) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = (sorted.len().saturating_sub(1) * pct) / 100;
    sorted.get(idx).copied().unwrap_or(0)
}
