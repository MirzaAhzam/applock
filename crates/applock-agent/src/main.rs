//! `AppLock` user-session agent: `SetWinEventHook` foreground watcher, privacy dim overlay,
//! and lock UI launcher.

use std::collections::HashSet;
use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use applock_ipc::{Request, Response};
use applock_sys::crypto::fill_random;
use applock_sys::dim_overlay::DimOverlay;
use applock_sys::pipe::{PipeClient, PIPE_NAME};
use applock_sys::process::{
    current_cpu_time_100ns, current_private_memory_bytes, hide_process_windows, resume_process,
    show_process_windows, suspend_process, terminate_process,
};
use applock_sys::winevent::run_foreground_watcher;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LockDecision {
    Allowed,
    Locked,
}

fn should_skip_exe(exe_name: &str) -> bool {
    exe_name.eq_ignore_ascii_case("applock-lockui.exe")
        || exe_name.eq_ignore_ascii_case("applock-agent.exe")
}

fn resolve_lockui_path() -> PathBuf {
    if let Ok(exe) = env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join("applock-lockui.exe");
            if candidate.exists() {
                return candidate;
            }
        }
    }
    PathBuf::from("applock-lockui.exe")
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.iter().any(|a| a == "--bench-m0") {
        return run_bench_m0();
    }

    let active_pids: Arc<Mutex<HashSet<u32>>> = Arc::new(Mutex::new(HashSet::new()));
    let self_pid = std::process::id();

    if let Err(e) = run_foreground_watcher(|pid, path| {
        if pid == 0 || pid == self_pid {
            return;
        }
        let exe_name = Path::new(path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("<unknown>");
        if should_skip_exe(exe_name) {
            return;
        }
        if query_service_locked(exe_name) != LockDecision::Locked {
            return;
        }

        {
            let Ok(mut guard) = active_pids.lock() else {
                return;
            };
            if !guard.insert(pid) {
                return;
            }
        }

        // Freeze and hide immediately before spawning the lock UI.
        let _ = suspend_process(pid);
        let hidden = hide_process_windows(pid);

        let active_clone = Arc::clone(&active_pids);
        let display_name = exe_name
            .strip_suffix(".exe")
            .unwrap_or(exe_name)
            .to_string();

        let spawned = thread::Builder::new()
            .name("applock-prompt".to_string())
            .spawn(move || {
                handle_locked_process(pid, &display_name, &hidden);
                if let Ok(mut guard) = active_clone.lock() {
                    guard.remove(&pid);
                }
            });

        if spawned.is_err() {
            let _ = terminate_process(pid);
            if let Ok(mut guard) = active_pids.lock() {
                guard.remove(&pid);
            }
        }
    }) {
        eprintln!("SetWinEventHook failed: {e}");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}

fn handle_locked_process(pid: u32, display_name: &str, hidden_hwnds: &[isize]) {
    let overlay = DimOverlay::show();
    let lockui = resolve_lockui_path();
    let unlocked = Command::new(lockui)
        .args(["--app", display_name, "--pid", &pid.to_string()])
        .status()
        .is_ok_and(|s| s.success());

    drop(overlay);

    if unlocked {
        show_process_windows(hidden_hwnds);
        let _ = resume_process(pid);
    } else {
        let _ = terminate_process(pid);
    }
}

fn query_service_locked(app_id: &str) -> LockDecision {
    let mut nonce = [0_u8; 16];
    if fill_random(&mut nonce).is_err() {
        return LockDecision::Locked;
    }
    let Ok(frame) = (Request::QueryAppLocked {
        nonce,
        app_id: app_id.to_string(),
    })
    .encode() else {
        return LockDecision::Locked;
    };
    let Ok(client) = PipeClient::connect(PIPE_NAME, 250) else {
        // If service is offline, agent cannot verify rules; keep fail-closed only when
        // service is reachable, or treat offline as allowed? Wait: AGENTS.md 2.1 says fail closed.
        return LockDecision::Locked;
    };
    if client.write_frame(&frame).is_err() {
        return LockDecision::Locked;
    }
    let Ok(resp_bytes) = client.read_frame() else {
        return LockDecision::Locked;
    };
    match Response::decode(&resp_bytes) {
        Ok(Response::AppLockStatus {
            nonce: r_nonce,
            locked,
        }) if r_nonce == nonce => {
            if locked {
                LockDecision::Locked
            } else {
                LockDecision::Allowed
            }
        }
        _ => LockDecision::Locked,
    }
}

fn run_bench_m0() -> ExitCode {
    thread::spawn(|| {
        let _ = run_foreground_watcher(|_pid, _path| {});
    });

    thread::sleep(Duration::from_millis(200));
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
    let ram_mb = f64::from(u32::try_from(ram_bytes).unwrap_or(u32::MAX)) / (1024.0 * 1024.0);

    println!("M0 Agent Benchmark Results:");
    println!("  agent_idle_ram_bytes: {ram_bytes} ({ram_mb:.2} MiB)");
    println!("  agent_idle_cpu_pct: {idle_cpu_pct:.3}%");
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_lockui_and_agent_executables() {
        assert!(should_skip_exe("applock-lockui.exe"));
        assert!(should_skip_exe("AppLock-LockUI.EXE"));
        assert!(should_skip_exe("applock-agent.exe"));
        assert!(!should_skip_exe("notepad.exe"));
    }
}
