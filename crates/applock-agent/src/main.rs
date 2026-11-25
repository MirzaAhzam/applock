//! `AppLock` user-session agent: `SetWinEventHook` foreground watcher querying service via IPC.

use std::env;
use std::path::Path;
use std::process::ExitCode;
use std::thread;
use std::time::{Duration, Instant};

use applock_ipc::{Request, Response};
use applock_sys::crypto::fill_random;
use applock_sys::pipe::{PIPE_NAME, PipeClient};
use applock_sys::process::{current_cpu_time_100ns, current_private_memory_bytes};
use applock_sys::winevent::run_foreground_watcher;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.iter().any(|a| a == "--bench-m0") {
        return run_bench_m0();
    }

    println!("AppLock Agent running (`SetWinEventHook` + Named Pipe IPC).");
    println!("Switch between apps to see live lock status from applock-service.");

    if let Err(e) = run_foreground_watcher(|pid, path| {
        let exe_name = Path::new(path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("<unknown>");
        let status = query_service_locked(exe_name);
        println!("Foreground: {exe_name} (pid {pid}) -> {status}");
    }) {
        eprintln!("SetWinEventHook failed: {e}");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}

fn query_service_locked(app_id: &str) -> &'static str {
    let mut nonce = [0_u8; 16];
    if fill_random(&mut nonce).is_err() {
        return "UNKNOWN (fail-closed)";
    }
    let Ok(frame) = (Request::QueryAppLocked {
        nonce,
        app_id: app_id.to_string(),
    })
    .encode() else {
        return "ERROR";
    };
    let Ok(client) = PipeClient::connect(PIPE_NAME, 250) else {
        return "SERVICE_OFFLINE";
    };
    if client.write_frame(&frame).is_err() {
        return "IPC_WRITE_ERR";
    }
    let Ok(resp_bytes) = client.read_frame() else {
        return "IPC_READ_ERR";
    };
    match Response::decode(&resp_bytes) {
        Ok(Response::AppLockStatus {
            nonce: r_nonce,
            locked,
        }) if r_nonce == nonce => {
            if locked {
                "LOCKED"
            } else {
                "ALLOWED"
            }
        }
        _ => "LOCKED (fail-closed)",
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
