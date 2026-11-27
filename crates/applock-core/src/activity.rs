//! Local rotated activity log (`FR-GEN-03`) with zero secrets.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::CoreError;

const DEFAULT_MAX_LOG_BYTES: u64 = 256 * 1024;

/// Single local activity log record (never contains secrets).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivityEntry {
    /// Unix timestamp in seconds.
    pub timestamp_unix_secs: u64,
    /// Event category (`unlock`, `config`, `tamper`, `auth`).
    pub kind: String,
    /// Target app or subsystem name.
    pub target: String,
    /// Outcome (`allowed`, `denied`, `locked`, `unlocked`, `repaired`, etc.).
    pub result: String,
}

/// Size-capped, rotated append-only activity log stored under `%ProgramData%\AppLock\logs\`.
#[derive(Debug, Clone)]
pub struct ActivityLog {
    path: PathBuf,
    max_bytes: u64,
}

impl ActivityLog {
    /// Creates an `ActivityLog` handle at `path` with the default 256 KiB cap.
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            max_bytes: DEFAULT_MAX_LOG_BYTES,
        }
    }

    /// Creates an `ActivityLog` handle with a custom byte limit (for tests).
    #[must_use]
    pub fn with_max_bytes(path: PathBuf, max_bytes: u64) -> Self {
        Self {
            path,
            max_bytes: max_bytes.max(128),
        }
    }

    /// Appends a sanitized activity entry, rotating to `.1` when `max_bytes` is reached.
    pub fn append(&self, entry: &ActivityEntry) {
        if let Some(parent) = self.path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Ok(meta) = fs::metadata(&self.path) {
            if meta.len() >= self.max_bytes {
                let rotated = rotated_path(&self.path);
                let _ = fs::remove_file(&rotated);
                let _ = fs::rename(&self.path, rotated);
            }
        }
        let line = format!(
            "{}\t{}\t{}\t{}\n",
            entry.timestamp_unix_secs,
            sanitize_field(&entry.kind),
            sanitize_field(&entry.target),
            sanitize_field(&entry.result)
        );
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            let _ = file.write_all(line.as_bytes());
        }
    }

    /// Reads up to `limit` most recent entries (newest first).
    #[must_use]
    pub fn read_recent(&self, limit: usize) -> Vec<ActivityEntry> {
        let mut all = Vec::new();
        let rotated = rotated_path(&self.path);
        read_file_entries(&rotated, &mut all);
        read_file_entries(&self.path, &mut all);
        all.reverse();
        all.truncate(limit);
        all
    }

    /// Deletes active and rotated log files.
    ///
    /// # Errors
    /// Returns `CoreError::Io` if an existing log file cannot be removed.
    pub fn clear(&self) -> Result<(), CoreError> {
        if self.path.exists() {
            fs::remove_file(&self.path)?;
        }
        let rotated = rotated_path(&self.path);
        if rotated.exists() {
            fs::remove_file(rotated)?;
        }
        Ok(())
    }
}

fn rotated_path(path: &Path) -> PathBuf {
    path.with_extension("log.1")
}

fn sanitize_field(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '\t' | '\r' | '\n' => ' ',
            other => other,
        })
        .take(120)
        .collect()
}

fn read_file_entries(path: &Path, out: &mut Vec<ActivityEntry>) {
    let Ok(content) = fs::read_to_string(path) else {
        return;
    };
    for line in content.lines() {
        let mut parts = line.splitn(4, '\t');
        let (Some(ts_s), Some(kind), Some(target), Some(result)) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        if let Ok(ts) = ts_s.parse::<u64>() {
            out.push(ActivityEntry {
                timestamp_unix_secs: ts,
                kind: kind.to_string(),
                target: target.to_string(),
                result: result.to_string(),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activity_log_appends_rotates_reads_and_clears() -> Result<(), CoreError> {
        let dir = std::env::temp_dir().join(format!("applock_act_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let log_path = dir.join("logs").join("activity.log");
        let log = ActivityLog::with_max_bytes(log_path.clone(), 128);

        for i in 1..=8_u64 {
            log.append(&ActivityEntry {
                timestamp_unix_secs: 1000 + i,
                kind: "unlock".to_string(),
                target: format!("app_{i}.exe"),
                result: "allowed".to_string(),
            });
        }

        assert!(rotated_path(&log_path).exists());
        let recent = log.read_recent(5);
        assert_eq!(recent.len(), 5);
        assert_eq!(recent[0].timestamp_unix_secs, 1008);
        assert_eq!(recent[0].target, "app_8.exe");

        log.clear()?;
        assert!(log.read_recent(10).is_empty());

        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }
}
