//! `AppLock` M0 proof-of-concept service (ETW launch detection, freeze, prompt, resume/kill).

use std::collections::HashMap;
use std::env;
use std::path::Path;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use applock_sys::etw::EtwSession;
use applock_sys::lock_dialog::{show_m0_lock_prompt, LockPromptOutcome};
use applock_sys::process::{
    current_cpu_time_100ns, current_private_memory_bytes, launch_hidden_command, resume_process,
    suspend_process, terminate_process, wait_process_exit,
};

const M0_TEST_PIN: &str = "1234";
const DEFAULT_WATCH_APPS: &[&str] = &[
    "notepad.exe",
    "calculatorapp.exe",
    "msedge.exe",
    "chrome.exe",
    "firefox.exe",
];

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.iter().any(|a| a == "--bench-m0") {
        return run_bench_m0();
    }
    run_interactive_m0(&args)
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

    // Warm up ETW delivery briefly before timed runs.
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

    // Measure idle RAM and idle CPU% over 1 second with ETW session open and no launches.
    let ram_bytes = current_private_memory_bytes().unwrap_or(0);
    let cpu_before = current_cpu_time_100ns().unwrap_or(0);
    let wall_before = Instant::now();
    thread::sleep(Duration::from_secs(1));
    let cpu_after = current_cpu_time_100ns().unwrap_or(cpu_before);
    let wall_100ns = u64::try_from(wall_before.elapsed().as_nanos() / 100).unwrap_or(10_000_000);
    let cpu_delta = cpu_after.saturating_sub(cpu_before);
    let idle_cpu_pct = (cpu_delta as f64 / wall_100ns.max(1) as f64) * 100.0;

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

    let p50_us = percentile(&samples, 50);
    let p95_us = percentile(&samples, 95);
    let p50_ms = p50_us as f64 / 1000.0;
    let p95_ms = p95_us as f64 / 1000.0;
    let ram_mb = ram_bytes as f64 / (1024.0 * 1024.0);

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

fn run_interactive_m0(args: &[String]) -> ExitCode {
    let watch_list: Vec<String> = if args.is_empty() {
        DEFAULT_WATCH_APPS
            .iter()
            .map(|s| (*s).to_string())
            .collect()
    } else {
        args.iter().map(|s| s.to_ascii_lowercase()).collect()
    };

    println!("AppLock M0 Service Spike running (Administrator required for ETW).");
    println!("Watching launches for: {}", watch_list.join(", "));
    println!("Test PIN: {M0_TEST_PIN} | Press Ctrl+C in this window to stop.");

    let (tx, rx) = std::sync::mpsc::channel::<(u32, String)>();
    let watch_clone = watch_list;

    let _session = match EtwSession::start(move |pid, path| {
        let exe_name = Path::new(path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if !exe_name.is_empty() && watch_clone.iter().any(|w| w == &exe_name) {
            if suspend_process(pid).is_ok() {
                let _ = tx.send((pid, exe_name));
            }
        }
    }) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to start ETW session (run as Administrator): {e}");
            return ExitCode::FAILURE;
        }
    };

    for (pid, exe_name) in rx {
        println!("Frozen {exe_name} (pid {pid}); showing lock prompt...");
        let outcome = show_m0_lock_prompt(&exe_name);
        match outcome {
            LockPromptOutcome::Attempt(pin) if pin == M0_TEST_PIN => {
                println!("Correct PIN -> resuming {exe_name} (pid {pid})");
                let _ = resume_process(pid);
            }
            LockPromptOutcome::Attempt(_) => {
                println!("Wrong PIN -> terminating {exe_name} (pid {pid})");
                let _ = terminate_process(pid);
            }
            LockPromptOutcome::Cancelled => {
                println!("Cancelled -> terminating {exe_name} (pid {pid})");
                let _ = terminate_process(pid);
            }
        }
    }

    ExitCode::SUCCESS
}
