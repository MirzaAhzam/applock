//! Atomic DPAPI-encrypted configuration storage with last-known-good fallback (`FR-TAMP-04`).

use std::fs;
use std::path::Path;

use applock_sys::crypto::{dpapi_protect_machine, dpapi_unprotect_machine};

use crate::lockout::LockoutState;
use crate::rules::{LockMode, LockedApp};
use crate::CoreError;

const CONFIG_MAGIC: &[u8; 4] = b"APCF";
const CONFIG_VERSION: u16 = 1;

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

/// Encrypts `cfg` with DPAPI and writes it atomically, preserving a `.bak` copy.
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
    fs::write(&tmp_path, &sealed)?;
    if path.exists() {
        let _ = fs::copy(path, &bak_path);
    }
    fs::rename(&tmp_path, path)?;
    Ok(())
}

/// Loads and decrypts `AppConfig`, falling back to `.bak` if the primary file is corrupt.
///
/// # Errors
/// Returns `CoreError` if both primary and backup files are missing or corrupt.
pub fn load_fail_closed(path: &Path) -> Result<AppConfig, CoreError> {
    if let Ok(cfg) = load_single(path) {
        return Ok(cfg);
    }
    let bak_path = path.with_extension("bin.bak");
    load_single(&bak_path)
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
    fn dpapi_atomic_save_and_backup_recovery_work() {
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

        save_atomic(&cfg_path, &cfg).expect("save 1");
        save_atomic(&cfg_path, &cfg).expect("save 2 creates .bak");

        let loaded = load_fail_closed(&cfg_path).expect("load");
        assert_eq!(loaded, cfg);

        // Tamper primary config; fail-closed loader recovers last-known-good .bak.
        fs::write(&cfg_path, b"tampered-bytes").expect("tamper");
        let recovered = load_fail_closed(&cfg_path).expect("recover from .bak");
        assert_eq!(recovered, cfg);

        let _ = fs::remove_dir_all(&dir);
    }
}
