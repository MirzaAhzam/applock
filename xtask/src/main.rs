//! Build, budget verification, and packaging helpers for `AppLock`.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

const INSTALLER_MAX_BYTES: u64 = 10_485_760;

#[derive(Debug, Clone, PartialEq, Eq)]
struct PackageArgs {
    target: Option<String>,
    version: String,
}

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("check-budgets") => check_budgets("target/release"),
        Some("package") => {
            let parsed = parse_package_args(args);
            package_release(&parsed)
        }
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
    eprintln!("usage: cargo xtask <check-budgets | package [--target <triple>] [--version <ver>]>");
}

fn parse_package_args<I>(iter: I) -> PackageArgs
where
    I: IntoIterator<Item = String>,
{
    let mut target = None;
    let mut version = env!("CARGO_PKG_VERSION").to_string();
    let mut it = iter.into_iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--target" => {
                if let Some(val) = it.next() {
                    if !val.trim().is_empty() {
                        target = Some(val);
                    }
                }
            }
            "--version" => {
                if let Some(val) = it.next() {
                    if !val.trim().is_empty() {
                        version = val;
                    }
                }
            }
            _ => {}
        }
    }
    PackageArgs { target, version }
}

fn arch_from_target(target: Option<&str>) -> &'static str {
    match target {
        Some(t) if t.starts_with("aarch64") => "arm64",
        _ => "x64",
    }
}

fn check_budgets(bin_dir: &str) -> ExitCode {
    let budgets_path = Path::new("tests/perf/budgets.toml");
    if !budgets_path.exists() {
        eprintln!("missing budget file: {}", budgets_path.display());
        return ExitCode::FAILURE;
    }

    let targets = [
        ("applock-service.exe", 2_621_440_u64),
        ("applock-agent.exe", 1_048_576_u64),
        ("applock-lockui.exe", 6_291_456_u64),
        ("applock-manager.exe", 8_388_608_u64),
    ];

    let mut failed = false;
    for (bin, limit) in targets {
        let path = Path::new(bin_dir).join(bin);
        match fs::metadata(&path) {
            Ok(meta) => {
                let size = meta.len();
                let status = if size <= limit { "PASS" } else { "FAIL" };
                println!("{}: {size} bytes (limit {limit} bytes) [{status}]", path.display());
                if size > limit {
                    failed = true;
                }
            }
            Err(_) => {
                println!("{}: not built yet (stub skip)", path.display());
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

fn find_iscc() -> Option<PathBuf> {
    let candidates = [
        r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
        r"C:\Program Files\Inno Setup 6\ISCC.exe",
    ];
    for c in candidates {
        let p = PathBuf::from(c);
        if p.exists() {
            return Some(p);
        }
    }
    Some(PathBuf::from("iscc.exe"))
}

fn package_release(args: &PackageArgs) -> ExitCode {
    let mut build_cmd = Command::new("cargo");
    build_cmd.args(["build", "--release", "--workspace", "--locked"]);
    if let Some(ref t) = args.target {
        build_cmd.args(["--target", t]);
    }
    let Ok(status) = build_cmd.status() else {
        eprintln!("failed to invoke cargo build");
        return ExitCode::FAILURE;
    };
    if !status.success() {
        return ExitCode::FAILURE;
    }

    let bin_dir = match &args.target {
        Some(t) => format!("target/{t}/release"),
        None => "target/release".to_string(),
    };
    if check_budgets(&bin_dir) != ExitCode::SUCCESS {
        return ExitCode::FAILURE;
    }

    let dist_dir = Path::new("dist");
    if fs::create_dir_all(dist_dir).is_err() {
        eprintln!("failed to create dist directory");
        return ExitCode::FAILURE;
    }

    let arch = arch_from_target(args.target.as_deref());
    let zip_name = format!("applock-{}-{arch}-portable.zip", args.version);
    let zip_path = dist_dir.join(&zip_name);
    let ps_zip = format!(
        "Compress-Archive -Path '{bin_dir}\\applock-service.exe','{bin_dir}\\applock-agent.exe','{bin_dir}\\applock-lockui.exe','{bin_dir}\\applock-manager.exe' -DestinationPath '{}' -Force",
        zip_path.display()
    );
    let zip_ok = Command::new("pwsh")
        .args(["-NoProfile", "-Command", &ps_zip])
        .status()
        .is_ok_and(|s| s.success());
    if !zip_ok {
        eprintln!("failed to create portable zip");
        return ExitCode::FAILURE;
    }

    let Some(iscc) = find_iscc() else {
        eprintln!("Inno Setup ISCC.exe not found");
        return ExitCode::FAILURE;
    };
    let setup_name = format!("applock-{}-{arch}-setup.exe", args.version);
    let setup_path = dist_dir.join(&setup_name);

    let iss_ok = Command::new(iscc)
        .args([
            "/Qp",
            &format!("/DAppVersion={}", args.version),
            &format!("/DAppArch={arch}"),
            &format!("/DBinDir=..\\{bin_dir}"),
            "/DOutDir=..\\dist",
            "installer/applock.iss",
        ])
        .status()
        .is_ok_and(|s| s.success());
    if !iss_ok {
        eprintln!("Inno Setup build failed");
        return ExitCode::FAILURE;
    }

    match fs::metadata(&setup_path) {
        Ok(meta) => {
            let size = meta.len();
            let pass = size <= INSTALLER_MAX_BYTES;
            println!(
                "{}: {size} bytes (limit {INSTALLER_MAX_BYTES} bytes) [{}]",
                setup_path.display(),
                if pass { "PASS" } else { "FAIL" }
            );
            if !pass {
                return ExitCode::FAILURE;
            }
        }
        Err(_) => {
            eprintln!("installer output missing: {}", setup_path.display());
            return ExitCode::FAILURE;
        }
    }

    let sum_path = dist_dir.join(format!("SHA256SUMS-{arch}.txt"));
    let ps_sum = format!(
        "Get-ChildItem dist -File | Where-Object {{ $_.Name -ne '{}' }} | ForEach-Object {{ $h = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant(); \"$h  $($_.Name)\" }} | Set-Content -Encoding ascii '{}'",
        sum_path.file_name().and_then(|n| n.to_str()).unwrap_or(""),
        sum_path.display()
    );
    let sum_ok = Command::new("pwsh")
        .args(["-NoProfile", "-Command", &ps_sum])
        .status()
        .is_ok_and(|s| s.success());
    if !sum_ok {
        eprintln!("failed to write SHA256SUMS");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_package_args_and_arch() {
        let parsed = parse_package_args([
            "--target".to_string(),
            "aarch64-pc-windows-msvc".to_string(),
            "--version".to_string(),
            "0.2.0".to_string(),
        ]);
        assert_eq!(parsed.target.as_deref(), Some("aarch64-pc-windows-msvc"));
        assert_eq!(parsed.version, "0.2.0");
        assert_eq!(arch_from_target(parsed.target.as_deref()), "arm64");
        assert_eq!(arch_from_target(Some("x86_64-pc-windows-msvc")), "x64");
    }
}
