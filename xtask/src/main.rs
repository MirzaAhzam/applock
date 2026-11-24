//! Build, budget verification, and packaging helpers for `AppLock`.

use std::env;
use std::fs;
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("check-budgets") => check_budgets(),
        Some("package") => package_stub(),
        Some(other) => {
            eprintln!("unknown xtask command: {other}");
            print_usage();
            ExitCode::FAILURE
        }
        None => {
            print_usage();
            ExitCode::FAILURE
        }
    }
}

fn print_usage() {
    eprintln!("usage: cargo xtask <check-budgets | package>");
}

fn check_budgets() -> ExitCode {
    let budgets_path = Path::new("tests/perf/budgets.toml");
    if !budgets_path.exists() {
        eprintln!("missing budget file: {}", budgets_path.display());
        return ExitCode::FAILURE;
    }

    let targets = [
        ("target/release/applock-service.exe", 2_621_440_u64),
        ("target/release/applock-agent.exe", 1_048_576_u64),
    ];

    let mut failed = false;
    for (path_str, limit) in targets {
        let path = Path::new(path_str);
        match fs::metadata(path) {
            Ok(meta) => {
                let size = meta.len();
                let status = if size <= limit { "PASS" } else { "FAIL" };
                println!("{path_str}: {size} bytes (limit {limit} bytes) [{status}]");
                if size > limit {
                    failed = true;
                }
            }
            Err(_) => {
                println!("{path_str}: not built yet (stub skip)");
            }
        }
    }

    println!("RAM and latency budgets: stub (measured in M0)");
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn package_stub() -> ExitCode {
    eprintln!("xtask package: stub — installer packaging is not implemented yet");
    ExitCode::FAILURE
}
