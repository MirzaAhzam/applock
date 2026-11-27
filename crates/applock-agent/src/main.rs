//! `AppLock` user-session agent: `SetWinEventHook` window watcher and window-scoped lock UI launcher.

use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use applock_ipc::{OverlayUpdate, Request, Response, WindowRect, WindowVisibility};
use applock_sys::crypto::fill_random;
use applock_sys::pipe::{PipeClient, PIPE_NAME};
use applock_sys::process::{
    current_cpu_time_100ns, current_private_memory_bytes, resume_process, suspend_process,
    terminate_process,
};
use applock_sys::window::{get_window_bounds, WindowBounds};
use applock_sys::winevent::{run_window_watcher, WindowEventKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LockDecision {
    Allowed,
    Locked,
}

#[derive(Debug, Clone)]
struct ActiveOverlay {
    pid: u32,
    pipe_name: String,
    last_rect: WindowRect,
}

fn should_skip_exe(exe_name: &str) -> bool {
    exe_name.eq_ignore_ascii_case("applock-lockui.exe")
        || exe_name.eq_ignore_ascii_case("applock-agent.exe")
        || exe_name.eq_ignore_ascii_case("explorer.exe")
        || exe_name.eq_ignore_ascii_case("shellexperiencehost.exe")
        || exe_name.eq_ignore_ascii_case("startmenuexperiencehost.exe")
        || exe_name.eq_ignore_ascii_case("searchhost.exe")
        || exe_name.eq_ignore_ascii_case("lockapp.exe")
        || exe_name.eq_ignore_ascii_case("dwm.exe")
        || exe_name.eq_ignore_ascii_case("csrss.exe")
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

fn to_window_rect(b: WindowBounds) -> WindowRect {
    WindowRect {
        x: b.left,
        y: b.top,
        width: b.width,
        height: b.height,
    }
}

fn make_overlay_pipe_name(pid: u32) -> String {
    let mut rnd = [0_u8; 4];
    let _ = fill_random(&mut rnd);
    let token = u32::from_le_bytes(rnd);
    format!(r"\\.\pipe\AppLockOverlay_{pid}_{token:08x}")
}

fn send_overlay_update(pipe_name: &str, rect: WindowRect, visibility: WindowVisibility) {
    let mut nonce = [0_u8; 16];
    if fill_random(&mut nonce).is_err() {
        return;
    }
    let Ok(frame) = (OverlayUpdate {
        nonce,
        rect,
        visibility,
    })
    .encode() else {
        return;
    };
    if let Ok(client) = PipeClient::connect(pipe_name, 100) {
        let _ = client.write_frame(&frame);
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.iter().any(|a| a == "--bench-m0") {
        return run_bench_m0();
    }

    let active_overlays: Arc<Mutex<HashMap<isize, ActiveOverlay>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let self_pid = std::process::id();

    if let Err(e) = run_window_watcher(move |ev| {
        handle_window_event(&active_overlays, self_pid, &ev);
    }) {
        eprintln!("SetWinEventHook failed: {e}");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}

fn handle_window_event(
    active_overlays: &Arc<Mutex<HashMap<isize, ActiveOverlay>>>,
    self_pid: u32,
    ev: &applock_sys::winevent::WindowEvent,
) {
    if ev.pid == 0 || ev.pid == self_pid {
        return;
    }
    let exe_name = Path::new(&ev.image_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("<unknown>");

    match ev.kind {
        WindowEventKind::LocationChanged => {
            let maybe_update = active_overlays.lock().ok().and_then(|mut map| {
                let entry = map.get_mut(&ev.hwnd)?;
                let bounds = ev.bounds.or_else(|| get_window_bounds(ev.hwnd))?;
                let rect = to_window_rect(bounds);
                entry.last_rect = rect;
                Some((entry.pipe_name.clone(), rect))
            });
            if let Some((pipe_name, rect)) = maybe_update {
                send_overlay_update(&pipe_name, rect, WindowVisibility::Visible);
            }
        }
        WindowEventKind::Minimized | WindowEventKind::Hidden => {
            let vis = if ev.kind == WindowEventKind::Minimized {
                WindowVisibility::Minimized
            } else {
                WindowVisibility::Hidden
            };
            let maybe_pipe = active_overlays.lock().ok().and_then(|map| {
                map.get(&ev.hwnd)
                    .map(|e| (e.pipe_name.clone(), e.last_rect))
            });
            if let Some((pipe_name, rect)) = maybe_pipe {
                send_overlay_update(&pipe_name, rect, vis);
            }
        }
        WindowEventKind::Foreground => {
            handle_foreground_event(active_overlays, ev, exe_name);
        }
    }
}

fn handle_foreground_event(
    active_overlays: &Arc<Mutex<HashMap<isize, ActiveOverlay>>>,
    ev: &applock_sys::winevent::WindowEvent,
    exe_name: &str,
) {
    if !exe_name.eq_ignore_ascii_case("applock-lockui.exe") {
        let unfocused: Vec<(String, WindowRect)> = active_overlays
            .lock()
            .map(|map| {
                map.iter()
                    .filter(|(&h, _)| h != ev.hwnd)
                    .map(|(_, e)| (e.pipe_name.clone(), e.last_rect))
                    .collect()
            })
            .unwrap_or_default();
        for (pipe_name, rect) in unfocused {
            send_overlay_update(&pipe_name, rect, WindowVisibility::Unfocused);
        }
    }

    let existing = active_overlays.lock().ok().and_then(|mut map| {
        let entry = map.get_mut(&ev.hwnd)?;
        if let Some(bounds) = ev.bounds.or_else(|| get_window_bounds(ev.hwnd)) {
            entry.last_rect = to_window_rect(bounds);
        }
        Some((entry.pipe_name.clone(), entry.last_rect))
    });
    if let Some((pipe_name, rect)) = existing {
        send_overlay_update(&pipe_name, rect, WindowVisibility::Visible);
        return;
    }

    if should_skip_exe(exe_name) || query_service_locked(exe_name) != LockDecision::Locked {
        return;
    }

    let bounds = ev
        .bounds
        .or_else(|| get_window_bounds(ev.hwnd))
        .unwrap_or(WindowBounds {
            left: 100,
            top: 100,
            width: 480,
            height: 360,
        });
    let rect = to_window_rect(bounds);
    let pipe_name = make_overlay_pipe_name(ev.pid);

    {
        let Ok(mut guard) = active_overlays.lock() else {
            return;
        };
        if guard.values().any(|o| o.pid == ev.pid) {
            return;
        }
        guard.insert(
            ev.hwnd,
            ActiveOverlay {
                pid: ev.pid,
                pipe_name: pipe_name.clone(),
                last_rect: rect,
            },
        );
    }

    let _ = suspend_process(ev.pid);

    let overlays_clone = Arc::clone(active_overlays);
    let display_name = exe_name
        .strip_suffix(".exe")
        .unwrap_or(exe_name)
        .to_string();
    let hwnd = ev.hwnd;
    let pid = ev.pid;

    let spawned = thread::Builder::new()
        .name("applock-prompt".to_string())
        .spawn(move || {
            handle_locked_process(pid, &display_name, rect, &pipe_name);
            if let Ok(mut guard) = overlays_clone.lock() {
                guard.remove(&hwnd);
            }
        });

    if spawned.is_err() {
        let _ = terminate_process(pid);
        if let Ok(mut guard) = active_overlays.lock() {
            guard.remove(&hwnd);
        }
    }
}

fn handle_locked_process(pid: u32, display_name: &str, rect: WindowRect, pipe_name: &str) {
    let lockui = resolve_lockui_path();
    let unlocked = Command::new(lockui)
        .args([
            "--app",
            display_name,
            "--pid",
            &pid.to_string(),
            "--x",
            &rect.x.to_string(),
            "--y",
            &rect.y.to_string(),
            "--width",
            &rect.width.to_string(),
            "--height",
            &rect.height.to_string(),
            "--overlay-pipe",
            pipe_name,
        ])
        .status()
        .is_ok_and(|s| s.success());

    if unlocked {
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
            nonce: resp_nonce,
            locked,
        }) if resp_nonce == nonce => {
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
