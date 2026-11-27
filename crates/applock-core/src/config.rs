//! Atomic DPAPI-encrypted configuration storage with last-known-good fallback (`FR-TAMP-04`).
//!
//! Security note: machine-scope DPAPI detects corruption or truncation only; the real
//! protection against tampering by standard users is the `SYSTEM`/`Administrators`-only
//! ACL on `%ProgramData%\AppLock` and `HKLM\SOFTWARE\AppLock`.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;

use applock_sys::crypto::{dpapi_protect_machine, dpapi_unprotect_machine};

use crate::lockout::LockoutState;
use crate::rules::{LockMode, LockedApp};
use crate::CoreError;

const CONFIG_MAGIC: &[u8; 4] = b"APCF";
const CONFIG_VERSION: u16 = 1;
const MAX_TAMPER_LOG_BYTES: u64 = 256 * 1024;

/// Result of loading configuration with install-marker awareness (`FR-TAMP-04`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigLoadOutcome {
    /// Primary `config.bin` loaded and passed DPAPI + structural validation.
    Loaded(AppConfig),
    /// Primary `config.bin` was missing or corrupt; valid `.bak` was restored over primary.
    RecoveredFromBackup(AppConfig),
    /// Neither `config.bin` nor `.bak` exists and no install marker is present.
    FreshInstall,
}

/// Persistent `AppLock` configuration stored encrypted with machine-scope DPAPI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppConfig {
    /// Config format version.
    pub version: u16,
    /// Argon2id PHC hash for the master password.
    pub password_hash: Option<String>,
    /// Argon2id PHC hash for the numeric PIN.
    pub pin_hash: Option<String>,
    /// Persistent escalating lockout state.
    pub lockout: LockoutState,
    /// Protected applications and their lock modes.
    pub locked_apps: Vec<LockedApp>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            version: CONFIG_VERSION,
            password_hash: None,
            pin_hash: None,
            lockout: LockoutState::default(),
            locked_apps: Vec::new(),
        }
    }
}

impl AppConfig {
    /// Serializes this configuration into a versioned binary blob.
    ///
    /// # Errors
    /// Returns `CoreError::CorruptConfig` if a string exceeds `u16::MAX` bytes.
    pub fn encode(&self) -> Result<Vec<u8>, CoreError> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(CONFIG_MAGIC);
        out.extend_from_slice(&self.version.to_le_bytes());
        write_opt_str(&mut out, self.password_hash.as_deref())?;
        write_opt_str(&mut out, self.pin_hash.as_deref())?;
        out.extend_from_slice(&self.lockout.failed_count.to_le_bytes());
        match self.lockout.locked_until_unix_secs {
            Some(ts) => {
                out.push(1);
                out.extend_from_slice(&ts.to_le_bytes());
            }
            None => out.push(0),
        }
        let app_count =
            u32::try_from(self.locked_apps.len()).map_err(|_| CoreError::CorruptConfig)?;
        out.extend_from_slice(&app_count.to_le_bytes());
        for app in &self.locked_apps {
            write_str(&mut out, &app.app_id)?;
            match app.mode {
                LockMode::Always => out.push(0),
                LockMode::Grace { seconds } => {
                    out.push(1);
                    out.extend_from_slice(&seconds.to_le_bytes());
                }
            }
        }
        Ok(out)
    }

    /// Deserializes a configuration blob with strict version and bounds checks.
    ///
    /// # Errors
    /// Returns `CoreError::CorruptConfig` if magic, version, or payload is invalid.
    pub fn decode(bytes: &[u8]) -> Result<Self, CoreError> {
        if bytes.len() < 6 || &bytes[..4] != CONFIG_MAGIC {
            return Err(CoreError::CorruptConfig);
        }
        let version = u16::from_le_bytes([bytes[4], bytes[5]]);
        if version != CONFIG_VERSION {
            return Err(CoreError::CorruptConfig);
        }
        let mut cur = &bytes[6..];
        let password_hash = read_opt_str(&mut cur)?;
        let pin_hash = read_opt_str(&mut cur)?;
        if cur.len() < 5 {
            return Err(CoreError::CorruptConfig);
        }
        let failed_count = u32::from_le_bytes([cur[0], cur[1], cur[2], cur[3]]);
        let has_until = cur[4];
        cur = &cur[5..];
        let locked_until_unix_secs = match has_until {
            0 => None,
            1 => {
                if cur.len() < 8 {
                    return Err(CoreError::CorruptConfig);
                }
                let ts = u64::from_le_bytes([
                    cur[0], cur[1], cur[2], cur[3], cur[4], cur[5], cur[6], cur[7],
                ]);
                cur = &cur[8..];
                Some(ts)
            }
            _ => return Err(CoreError::CorruptConfig),
        };
        if cur.len() < 4 {
            return Err(CoreError::CorruptConfig);
        }
        let app_count =
            usize::try_from(u32::from_le_bytes([cur[0], cur[1], cur[2], cur[3]])).unwrap_or(0);
        cur = &cur[4..];
        let mut locked_apps = Vec::with_capacity(app_count.min(4096));
        for _ in 0..app_count {
            let app_id = read_str(&mut cur)?;
            if cur.is_empty() {
                return Err(CoreError::CorruptConfig);
            }
            let mode_tag = cur[0];
            cur = &cur[1..];
            let mode = match mode_tag {
                0 => LockMode::Always,
                1 => {
                    if cur.len() < 8 {
                        return Err(CoreError::CorruptConfig);
                    }
                    let secs = u64::from_le_bytes([
                        cur[0], cur[1], cur[2], cur[3], cur[4], cur[5], cur[6], cur[7],
                    ]);
                    cur = &cur[8..];
                    LockMode::Grace { seconds: secs }
                }
                _ => return Err(CoreError::CorruptConfig),
            };
            locked_apps.push(LockedApp { app_id, mode });
        }
        if !cur.is_empty() {
            return Err(CoreError::CorruptConfig);
        }
        Ok(Self {
            version,
            password_hash,
            pin_hash,
            lockout: LockoutState {
                failed_count,
                locked_until_unix_secs,
            },
            locked_apps,
        })
    }
}

/// Encrypts `cfg` with DPAPI and writes it atomically, preserving a validated `.bak` copy.
///
/// A corrupt primary `config.bin` is never copied into `.bak`.
///
/// # Errors
/// Returns `CoreError` on encoding, DPAPI encryption, or filesystem error.
pub fn save_atomic(path: &Path, cfg: &AppConfig) -> Result<(), CoreError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let plain = cfg.encode()?;
    let sealed = dpapi_protect_machine(&plain)?;

    let tmp_path = path.with_extension("bin.tmp");
    let bak_path = path.with_extension("bin.bak");
    write_synced(&tmp_path, &sealed)?;

    // Only back up the existing primary file if it passes full validation.
    if path.exists() && load_single(path).is_ok() {
        let _ = fs::copy(path, &bak_path);
    }
    fs::rename(&tmp_path, path)?;
    Ok(())
}

/// Loads `AppConfig` using `install_marker_present` to distinguish fresh installs from tampering.
///
/// If primary `config.bin` is corrupt/missing and `.bak` is valid, restores `.bak` over `config.bin`
/// and returns `ConfigLoadOutcome::RecoveredFromBackup`. If `install_marker_present` is `true`
/// and both files are missing or corrupt, returns `Err(CoreError::CorruptConfig)` (fail closed).
///
/// # Errors
/// Returns `CoreError::CorruptConfig` if configuration is tampered/missing on an installed system.
pub fn load_with_marker(
    path: &Path,
    install_marker_present: bool,
) -> Result<ConfigLoadOutcome, CoreError> {
    if let Ok(cfg) = load_single(path) {
        return Ok(ConfigLoadOutcome::Loaded(cfg));
    }

    let bak_path = path.with_extension("bin.bak");
    if let Ok(cfg) = load_single(&bak_path) {
        if let Ok(sealed) = fs::read(&bak_path) {
            let tmp_path = path.with_extension("bin.tmp");
            if write_synced(&tmp_path, &sealed).is_ok() {
                let _ = fs::rename(&tmp_path, path);
            }
        }
        return Ok(ConfigLoadOutcome::RecoveredFromBackup(cfg));
    }

    if !install_marker_present && !path.exists() && !bak_path.exists() {
        return Ok(ConfigLoadOutcome::FreshInstall);
    }

    Err(CoreError::CorruptConfig)
}

/// Loads and decrypts `AppConfig`, falling back to `.bak` if the primary file is corrupt.
///
/// # Errors
/// Returns `CoreError` if both primary and backup files are missing or corrupt.
pub fn load_fail_closed(path: &Path) -> Result<AppConfig, CoreError> {
    match load_with_marker(path, true)? {
        ConfigLoadOutcome::Loaded(cfg) | ConfigLoadOutcome::RecoveredFromBackup(cfg) => Ok(cfg),
        ConfigLoadOutcome::FreshInstall => Err(CoreError::CorruptConfig),
    }
}

/// Appends a timestamped tamper event (no secrets) to a size-capped append-only log file.
///
/// Temporary until `FR-GEN-03` (activity log) is implemented, at which point tamper events
/// will be routed into the unified activity log.
pub fn append_tamper_event(log_path: &Path, now_unix_secs: u64, event: &str) {
    if let Some(parent) = log_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(meta) = fs::metadata(log_path) {
        if meta.len() >= MAX_TAMPER_LOG_BYTES {
            let rotated = log_path.with_extension("log.1");
            let _ = fs::rename(log_path, rotated);
        }
    }
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(log_path) {
        let _ = writeln!(file, "[{now_unix_secs}] TAMPER: {event}");
    }
}

fn write_synced(path: &Path, bytes: &[u8]) -> Result<(), CoreError> {
    let mut file = File::create(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn load_single(path: &Path) -> Result<AppConfig, CoreError> {
    let sealed = fs::read(path)?;
    let plain = dpapi_unprotect_machine(&sealed)?;
    AppConfig::decode(&plain)
}

fn write_opt_str(out: &mut Vec<u8>, s: Option<&str>) -> Result<(), CoreError> {
    match s {
        Some(val) => {
            out.push(1);
            write_str(out, val)?;
        }
        None => out.push(0),
    }
    Ok(())
}

fn write_str(out: &mut Vec<u8>, s: &str) -> Result<(), CoreError> {
    let len = u16::try_from(s.len()).map_err(|_| CoreError::CorruptConfig)?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(s.as_bytes());
    Ok(())
}

fn read_opt_str(cur: &mut &[u8]) -> Result<Option<String>, CoreError> {
    if cur.is_empty() {
        return Err(CoreError::CorruptConfig);
    }
    let tag = cur[0];
    *cur = &cur[1..];
    match tag {
        0 => Ok(None),
        1 => Ok(Some(read_str(cur)?)),
        _ => Err(CoreError::CorruptConfig),
    }
}

fn read_str(cur: &mut &[u8]) -> Result<String, CoreError> {
    if cur.len() < 2 {
        return Err(CoreError::CorruptConfig);
    }
    let len = usize::from(u16::from_le_bytes([cur[0], cur[1]]));
    let body = &cur[2..];
    if body.len() < len {
        return Err(CoreError::CorruptConfig);
    }
    let s = std::str::from_utf8(&body[..len])
        .map_err(|_| CoreError::CorruptConfig)?
        .to_string();
    *cur = &body[len..];
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpapi_atomic_save_and_backup_recovery_work() -> Result<(), CoreError> {
        let dir = std::env::temp_dir().join(format!("applock_cfg_test_{}", std::process::id()));
        let cfg_path = dir.join("config.bin");

        let cfg = AppConfig {
            version: CONFIG_VERSION,
            password_hash: Some("$argon2id$test".to_string()),
            pin_hash: Some("$argon2id$pin".to_string()),
            lockout: LockoutState {
                failed_count: 2,
                locked_until_unix_secs: None,
            },
            locked_apps: vec![LockedApp {
                app_id: "notepad.exe".to_string(),
                mode: LockMode::Grace { seconds: 60 },
            }],
        };

        save_atomic(&cfg_path, &cfg)?;
        save_atomic(&cfg_path, &cfg)?;

        let loaded = load_fail_closed(&cfg_path)?;
        assert_eq!(loaded, cfg);

        // Tamper primary config; fail-closed loader recovers last-known-good .bak and restores primary.
        fs::write(&cfg_path, b"tampered-bytes")?;
        let outcome = load_with_marker(&cfg_path, true)?;
        assert_eq!(outcome, ConfigLoadOutcome::RecoveredFromBackup(cfg.clone()));
        assert_eq!(
            load_with_marker(&cfg_path, true)?,
            ConfigLoadOutcome::Loaded(cfg)
        );

        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[test]
    fn corrupt_primary_does_not_overwrite_valid_backup() -> Result<(), CoreError> {
        let dir = std::env::temp_dir().join(format!("applock_bak_guard_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let cfg_path = dir.join("config.bin");
        let bak_path = cfg_path.with_extension("bin.bak");

        let cfg1 = AppConfig {
            pin_hash: Some("$argon2id$pin1".to_string()),
            ..AppConfig::default()
        };
        let cfg2 = AppConfig {
            pin_hash: Some("$argon2id$pin2".to_string()),
            ..AppConfig::default()
        };
        let cfg3 = AppConfig {
            pin_hash: Some("$argon2id$pin3".to_string()),
            ..AppConfig::default()
        };

        save_atomic(&cfg_path, &cfg1)?;
        save_atomic(&cfg_path, &cfg2)?;
        assert_eq!(load_single(&bak_path)?, cfg1);

        // Corrupt primary before saving cfg3: .bak must keep cfg1, not the corrupt primary.
        fs::write(&cfg_path, b"corrupt-primary")?;
        save_atomic(&cfg_path, &cfg3)?;
        assert_eq!(load_single(&bak_path)?, cfg1);
        assert_eq!(load_single(&cfg_path)?, cfg3);

        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[test]
    fn install_marker_with_deleted_configs_fails_closed() {
        let dir = std::env::temp_dir().join(format!("applock_deleted_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let cfg_path = dir.join("config.bin");

        // Fresh install (no marker, no files) -> FreshInstall.
        let fresh = load_with_marker(&cfg_path, false);
        assert!(matches!(fresh, Ok(ConfigLoadOutcome::FreshInstall)));

        // Marker present, both files deleted -> must fail closed, never FreshInstall.
        let tampered = load_with_marker(&cfg_path, true);
        assert!(matches!(tampered, Err(CoreError::CorruptConfig)));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn append_tamper_event_writes_without_secrets() -> Result<(), CoreError> {
        let dir = std::env::temp_dir().join(format!("applock_tlog_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let log_path = dir.join("tamper.log");

        append_tamper_event(&log_path, 12345, "Primary config tampered; restored backup");
        let content = fs::read_to_string(&log_path)?;
        assert!(content.contains("[12345] TAMPER: Primary config tampered; restored backup"));

        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }
}
