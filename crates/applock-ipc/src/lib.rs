//! Pure IPC message definitions, framing, and strict validation for `AppLock`.

use std::fmt;

/// Current IPC protocol version.
pub const PROTOCOL_VERSION: u16 = 1;

/// Maximum allowed serialized IPC message size in bytes (16 KiB).
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024;

const MAGIC: &[u8; 4] = b"APLK";
const HEADER_LEN: usize = 4 + 2 + 1 + 16; // magic + version + kind + nonce

/// Error returned when encoding or decoding an IPC frame fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcError {
    /// Frame exceeds `MAX_MESSAGE_BYTES` or is shorter than the header.
    InvalidLength,
    /// Frame header magic bytes did not match `APLK`.
    InvalidMagic,
    /// Protocol version is not supported.
    UnsupportedVersion(u16),
    /// Unknown message kind tag.
    UnknownKind(u8),
    /// Trailing unread bytes after a valid payload.
    TrailingBytes,
    /// Malformed payload field (e.g., invalid UTF-8 or truncated string).
    MalformedPayload,
}

impl fmt::Display for IpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength => write!(f, "invalid IPC frame length"),
            Self::InvalidMagic => write!(f, "invalid IPC magic"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported IPC version {v}"),
            Self::UnknownKind(k) => write!(f, "unknown IPC message kind {k}"),
            Self::TrailingBytes => write!(f, "unexpected trailing bytes in IPC frame"),
            Self::MalformedPayload => write!(f, "malformed IPC payload"),
        }
    }
}

impl std::error::Error for IpcError {}

/// Physical screen bounding rectangle of a target application window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowRect {
    /// Left coordinate in physical screen pixels.
    pub x: i32,
    /// Top coordinate in physical screen pixels.
    pub y: i32,
    /// Width in physical screen pixels.
    pub width: i32,
    /// Height in physical screen pixels.
    pub height: i32,
}

/// Visibility state of the tracked target application window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowVisibility {
    /// Target window is visible and in the foreground.
    Visible,
    /// Target window was minimized.
    Minimized,
    /// Target window was hidden or closed.
    Hidden,
    /// Another window took foreground focus.
    Unfocused,
}

/// Dynamic window-bounds and visibility update sent from `applock-agent` to `applock-lockui`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OverlayUpdate {
    /// Per-message random nonce.
    pub nonce: [u8; 16],
    /// Current target window bounding rectangle.
    pub rect: WindowRect,
    /// Current target window visibility state.
    pub visibility: WindowVisibility,
}

impl OverlayUpdate {
    /// Encodes this overlay update into a bounded binary frame.
    ///
    /// # Errors
    /// Returns `IpcError::InvalidLength` if the encoded frame exceeds `MAX_MESSAGE_BYTES`.
    pub fn encode(&self) -> Result<Vec<u8>, IpcError> {
        let mut out = Vec::with_capacity(HEADER_LEN + 17);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
        out.push(10);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.rect.x.to_le_bytes());
        out.extend_from_slice(&self.rect.y.to_le_bytes());
        out.extend_from_slice(&self.rect.width.to_le_bytes());
        out.extend_from_slice(&self.rect.height.to_le_bytes());
        let vis_tag = match self.visibility {
            WindowVisibility::Visible => 0_u8,
            WindowVisibility::Minimized => 1_u8,
            WindowVisibility::Hidden => 2_u8,
            WindowVisibility::Unfocused => 3_u8,
        };
        out.push(vis_tag);
        if out.len() > MAX_MESSAGE_BYTES {
            return Err(IpcError::InvalidLength);
        }
        Ok(out)
    }

    /// Decodes an `OverlayUpdate` with strict header, payload length, and trailing-byte checks.
    ///
    /// # Errors
    /// Returns `IpcError` if the frame is malformed, oversized, or has an unknown kind/tag.
    pub fn decode(bytes: &[u8]) -> Result<Self, IpcError> {
        let (kind, nonce, rest) = parse_header(bytes)?;
        if kind != 10 {
            return Err(IpcError::UnknownKind(kind));
        }
        if rest.len() != 17 {
            return Err(if rest.len() > 17 {
                IpcError::TrailingBytes
            } else {
                IpcError::MalformedPayload
            });
        }
        let x = i32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]);
        let y = i32::from_le_bytes([rest[4], rest[5], rest[6], rest[7]]);
        let width = i32::from_le_bytes([rest[8], rest[9], rest[10], rest[11]]);
        let height = i32::from_le_bytes([rest[12], rest[13], rest[14], rest[15]]);
        let visibility = match rest[16] {
            0 => WindowVisibility::Visible,
            1 => WindowVisibility::Minimized,
            2 => WindowVisibility::Hidden,
            3 => WindowVisibility::Unfocused,
            _ => return Err(IpcError::MalformedPayload),
        };
        Ok(Self {
            nonce,
            rect: WindowRect {
                x,
                y,
                width,
                height,
            },
            visibility,
        })
    }
}

/// Request sent from `applock-agent`, `applock-lockui`, or `applock-manager` to `applock-service`.
#[derive(Clone, PartialEq, Eq)]
pub enum Request {
    /// Health check ping.
    Ping {
        /// Per-request random nonce.
        nonce: [u8; 16],
    },
    /// Ask the service whether an executable path is currently locked.
    QueryAppLocked {
        /// Per-request random nonce.
        nonce: [u8; 16],
        /// Normalized executable path or package family name.
        app_id: String,
    },
    /// Submit a credential attempt for verification by the service.
    VerifyCredential {
        /// Per-request random nonce.
        nonce: [u8; 16],
        /// Target frozen process ID (0 if verifying for Manager access).
        target_pid: u32,
        /// Plaintext attempt bytes (redacted in `Debug` output).
        secret: Vec<u8>,
    },
    /// List currently locked app IDs (Manager UI).
    ListLockedApps {
        /// Per-request random nonce.
        nonce: [u8; 16],
    },
    /// Enable or disable lock for a specific app ID (Manager UI).
    SetAppLocked {
        /// Per-request random nonce.
        nonce: [u8; 16],
        /// Normalized executable name (e.g. `notepad.exe`).
        app_id: String,
        /// `true` to lock, `false` to unlock.
        locked: bool,
    },
    /// Change the master PIN/password after verifying the current one.
    ChangePin {
        /// Per-request random nonce.
        nonce: [u8; 16],
        /// Current PIN/password bytes (redacted in `Debug` output).
        current_secret: Vec<u8>,
        /// New PIN/password bytes (redacted in `Debug` output).
        new_secret: Vec<u8>,
    },
    /// Set per-app locking mode (`grace_seconds == 0` for Always, `> 0` for Grace).
    SetAppMode {
        /// Per-request random nonce.
        nonce: [u8; 16],
        /// Normalized app identifier.
        app_id: String,
        /// Grace window in seconds (`0` = always ask).
        grace_seconds: u64,
    },
    /// List locked apps along with their configured grace seconds.
    ListAppModes {
        /// Per-request random nonce.
        nonce: [u8; 16],
    },
    /// Fetch recent local activity log entries.
    ListActivityLog {
        /// Per-request random nonce.
        nonce: [u8; 16],
        /// Maximum number of entries to return.
        limit: u16,
    },
    /// Clear the local activity log.
    ClearActivityLog {
        /// Per-request random nonce.
        nonce: [u8; 16],
    },
}

impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ping { nonce } => f.debug_struct("Ping").field("nonce", nonce).finish(),
            Self::QueryAppLocked { nonce, app_id } => f
                .debug_struct("QueryAppLocked")
                .field("nonce", nonce)
                .field("app_id", app_id)
                .finish(),
            Self::VerifyCredential {
                nonce, target_pid, ..
            } => f
                .debug_struct("VerifyCredential")
                .field("nonce", nonce)
                .field("target_pid", target_pid)
                .field("secret", &"[REDACTED]")
                .finish(),
            Self::ListLockedApps { nonce } => f
                .debug_struct("ListLockedApps")
                .field("nonce", nonce)
                .finish(),
            Self::SetAppLocked {
                nonce,
                app_id,
                locked,
            } => f
                .debug_struct("SetAppLocked")
                .field("nonce", nonce)
                .field("app_id", app_id)
                .field("locked", locked)
                .finish(),
            Self::ChangePin { nonce, .. } => f
                .debug_struct("ChangePin")
                .field("nonce", nonce)
                .field("current_secret", &"[REDACTED]")
                .field("new_secret", &"[REDACTED]")
                .finish(),
            Self::SetAppMode {
                nonce,
                app_id,
                grace_seconds,
            } => f
                .debug_struct("SetAppMode")
                .field("nonce", nonce)
                .field("app_id", app_id)
                .field("grace_seconds", grace_seconds)
                .finish(),
            Self::ListAppModes { nonce } => f
                .debug_struct("ListAppModes")
                .field("nonce", nonce)
                .finish(),
            Self::ListActivityLog { nonce, limit } => f
                .debug_struct("ListActivityLog")
                .field("nonce", nonce)
                .field("limit", limit)
                .finish(),
            Self::ClearActivityLog { nonce } => f
                .debug_struct("ClearActivityLog")
                .field("nonce", nonce)
                .finish(),
        }
    }
}

/// Response sent from `applock-service` back to the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    /// Reply to `Ping`.
    Pong {
        /// Matching request nonce.
        nonce: [u8; 16],
    },
    /// Reply to `QueryAppLocked`.
    AppLockStatus {
        /// Matching request nonce.
        nonce: [u8; 16],
        /// `true` if the app must be locked right now.
        locked: bool,
    },
    /// Reply to `VerifyCredential` and `ChangePin`.
    CredentialResult {
        /// Matching request nonce.
        nonce: [u8; 16],
        /// `true` if the credential was accepted.
        allowed: bool,
        /// Remaining lockout wait in seconds (`0` if not locked out).
        lockout_remaining_secs: u64,
    },
    /// Reply to `ListLockedApps`.
    LockedApps {
        /// Matching request nonce.
        nonce: [u8; 16],
        /// Currently locked app IDs.
        apps: Vec<String>,
    },
    /// Reply to `ListAppModes`.
    AppModes {
        /// Matching request nonce.
        nonce: [u8; 16],
        /// Pairs of `(app_id, grace_seconds)`.
        apps: Vec<(String, u64)>,
    },
    /// Reply to `ListActivityLog`.
    ActivityLogEntries {
        /// Matching request nonce.
        nonce: [u8; 16],
        /// Tuples of `(timestamp_unix_secs, kind, target, result)`.
        entries: Vec<(u64, String, String, String)>,
    },
    /// Generic acknowledgement (`SetAppLocked`).
    Ack {
        /// Matching request nonce.
        nonce: [u8; 16],
        /// `true` if the operation succeeded.
        ok: bool,
    },
    /// Generic protocol/validation error (never reveals internals).
    Error {
        /// Matching request nonce (or zeroes if unparseable).
        nonce: [u8; 16],
        /// Stable numeric error code.
        code: u16,
    },
}

impl Request {
    /// Encodes this request into a bounded binary frame.
    ///
    /// # Errors
    /// Returns `IpcError::InvalidLength` if the encoded frame would exceed `MAX_MESSAGE_BYTES`.
    pub fn encode(&self) -> Result<Vec<u8>, IpcError> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
        match self {
            Self::Ping { nonce } => {
                out.push(1);
                out.extend_from_slice(nonce);
            }
            Self::QueryAppLocked { nonce, app_id } => {
                out.push(2);
                out.extend_from_slice(nonce);
                write_bytes(&mut out, app_id.as_bytes())?;
            }
            Self::VerifyCredential {
                nonce,
                target_pid,
                secret,
            } => {
                out.push(3);
                out.extend_from_slice(nonce);
                out.extend_from_slice(&target_pid.to_le_bytes());
                write_bytes(&mut out, secret)?;
            }
            Self::ListLockedApps { nonce } => {
                out.push(4);
                out.extend_from_slice(nonce);
            }
            Self::SetAppLocked {
                nonce,
                app_id,
                locked,
            } => {
                out.push(5);
                out.extend_from_slice(nonce);
                write_bytes(&mut out, app_id.as_bytes())?;
                out.push(u8::from(*locked));
            }
            Self::ChangePin {
                nonce,
                current_secret,
                new_secret,
            } => {
                out.push(6);
                out.extend_from_slice(nonce);
                write_bytes(&mut out, current_secret)?;
                write_bytes(&mut out, new_secret)?;
            }
            Self::SetAppMode {
                nonce,
                app_id,
                grace_seconds,
            } => {
                out.push(7);
                out.extend_from_slice(nonce);
                write_bytes(&mut out, app_id.as_bytes())?;
                out.extend_from_slice(&grace_seconds.to_le_bytes());
            }
            Self::ListAppModes { nonce } => {
                out.push(8);
                out.extend_from_slice(nonce);
            }
            Self::ListActivityLog { nonce, limit } => {
                out.push(9);
                out.extend_from_slice(nonce);
                out.extend_from_slice(&limit.to_le_bytes());
            }
            Self::ClearActivityLog { nonce } => {
                out.push(10);
                out.extend_from_slice(nonce);
            }
        }
        if out.len() > MAX_MESSAGE_BYTES {
            return Err(IpcError::InvalidLength);
        }
        Ok(out)
    }

    /// Decodes a `Request` from raw bytes with strict length, version, and trailing-byte checks.
    ///
    /// # Errors
    /// Returns an `IpcError` if the frame is malformed, oversized, or has an unknown version/kind.
    pub fn decode(bytes: &[u8]) -> Result<Self, IpcError> {
        let (kind, nonce, rest) = parse_header(bytes)?;
        match kind {
            1 => {
                if !rest.is_empty() {
                    return Err(IpcError::TrailingBytes);
                }
                Ok(Self::Ping { nonce })
            }
            2 => {
                let (raw, tail) = read_bytes(rest)?;
                if !tail.is_empty() {
                    return Err(IpcError::TrailingBytes);
                }
                let app_id = std::str::from_utf8(raw)
                    .map_err(|_| IpcError::MalformedPayload)?
                    .to_string();
                Ok(Self::QueryAppLocked { nonce, app_id })
            }
            3 => {
                if rest.len() < 4 {
                    return Err(IpcError::MalformedPayload);
                }
                let target_pid = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]);
                let (secret_slice, tail) = read_bytes(&rest[4..])?;
                if !tail.is_empty() {
                    return Err(IpcError::TrailingBytes);
                }
                Ok(Self::VerifyCredential {
                    nonce,
                    target_pid,
                    secret: secret_slice.to_vec(),
                })
            }
            4 => {
                if !rest.is_empty() {
                    return Err(IpcError::TrailingBytes);
                }
                Ok(Self::ListLockedApps { nonce })
            }
            5 => {
                let (raw_id, tail) = read_bytes(rest)?;
                if tail.len() != 1 || tail[0] > 1 {
                    return Err(IpcError::MalformedPayload);
                }
                let app_id = std::str::from_utf8(raw_id)
                    .map_err(|_| IpcError::MalformedPayload)?
                    .to_string();
                Ok(Self::SetAppLocked {
                    nonce,
                    app_id,
                    locked: tail[0] == 1,
                })
            }
            6 => {
                let (curr, tail) = read_bytes(rest)?;
                let (new_s, end) = read_bytes(tail)?;
                if !end.is_empty() {
                    return Err(IpcError::TrailingBytes);
                }
                Ok(Self::ChangePin {
                    nonce,
                    current_secret: curr.to_vec(),
                    new_secret: new_s.to_vec(),
                })
            }
            7 => decode_set_app_mode(nonce, rest),
            8 => {
                if !rest.is_empty() {
                    return Err(IpcError::TrailingBytes);
                }
                Ok(Self::ListAppModes { nonce })
            }
            9 => {
                if rest.len() != 2 {
                    return Err(IpcError::MalformedPayload);
                }
                let limit = u16::from_le_bytes([rest[0], rest[1]]);
                Ok(Self::ListActivityLog { nonce, limit })
            }
            10 => {
                if !rest.is_empty() {
                    return Err(IpcError::TrailingBytes);
                }
                Ok(Self::ClearActivityLog { nonce })
            }
            other => Err(IpcError::UnknownKind(other)),
        }
    }
}

impl Response {
    /// Encodes this response into a bounded binary frame.
    ///
    /// # Errors
    /// Returns `IpcError::InvalidLength` if the encoded frame would exceed `MAX_MESSAGE_BYTES`.
    pub fn encode(&self) -> Result<Vec<u8>, IpcError> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
        match self {
            Self::Pong { nonce } => {
                out.push(101);
                out.extend_from_slice(nonce);
            }
            Self::AppLockStatus { nonce, locked } => {
                out.push(102);
                out.extend_from_slice(nonce);
                out.push(u8::from(*locked));
            }
            Self::CredentialResult {
                nonce,
                allowed,
                lockout_remaining_secs,
            } => {
                out.push(103);
                out.extend_from_slice(nonce);
                out.push(u8::from(*allowed));
                out.extend_from_slice(&lockout_remaining_secs.to_le_bytes());
            }
            Self::LockedApps { nonce, apps } => {
                out.push(104);
                out.extend_from_slice(nonce);
                let count = u16::try_from(apps.len()).map_err(|_| IpcError::InvalidLength)?;
                out.extend_from_slice(&count.to_le_bytes());
                for app in apps {
                    write_bytes(&mut out, app.as_bytes())?;
                }
            }
            Self::AppModes { nonce, apps } => {
                out.push(106);
                out.extend_from_slice(nonce);
                let count = u16::try_from(apps.len()).map_err(|_| IpcError::InvalidLength)?;
                out.extend_from_slice(&count.to_le_bytes());
                for (app, secs) in apps {
                    write_bytes(&mut out, app.as_bytes())?;
                    out.extend_from_slice(&secs.to_le_bytes());
                }
            }
            Self::ActivityLogEntries { nonce, entries } => {
                out.push(107);
                out.extend_from_slice(nonce);
                let count = u16::try_from(entries.len()).map_err(|_| IpcError::InvalidLength)?;
                out.extend_from_slice(&count.to_le_bytes());
                for (ts, kind, target, result) in entries {
                    out.extend_from_slice(&ts.to_le_bytes());
                    write_bytes(&mut out, kind.as_bytes())?;
                    write_bytes(&mut out, target.as_bytes())?;
                    write_bytes(&mut out, result.as_bytes())?;
                }
            }
            Self::Ack { nonce, ok } => {
                out.push(105);
                out.extend_from_slice(nonce);
                out.push(u8::from(*ok));
            }
            Self::Error { nonce, code } => {
                out.push(255);
                out.extend_from_slice(nonce);
                out.extend_from_slice(&code.to_le_bytes());
            }
        }
        if out.len() > MAX_MESSAGE_BYTES {
            return Err(IpcError::InvalidLength);
        }
        Ok(out)
    }

    /// Decodes a `Response` from raw bytes with strict validation.
    ///
    /// # Errors
    /// Returns an `IpcError` if the frame is malformed, oversized, or has an unknown version/kind.
    pub fn decode(bytes: &[u8]) -> Result<Self, IpcError> {
        let (kind, nonce, rest) = parse_header(bytes)?;
        match kind {
            101 => {
                if !rest.is_empty() {
                    return Err(IpcError::TrailingBytes);
                }
                Ok(Self::Pong { nonce })
            }
            102 => {
                if rest.len() != 1 || rest[0] > 1 {
                    return Err(IpcError::MalformedPayload);
                }
                Ok(Self::AppLockStatus {
                    nonce,
                    locked: rest[0] == 1,
                })
            }
            103 => {
                if rest.len() != 9 || rest[0] > 1 {
                    return Err(IpcError::MalformedPayload);
                }
                let secs = u64::from_le_bytes([
                    rest[1], rest[2], rest[3], rest[4], rest[5], rest[6], rest[7], rest[8],
                ]);
                Ok(Self::CredentialResult {
                    nonce,
                    allowed: rest[0] == 1,
                    lockout_remaining_secs: secs,
                })
            }
            104 => {
                if rest.len() < 2 {
                    return Err(IpcError::MalformedPayload);
                }
                let count = usize::from(u16::from_le_bytes([rest[0], rest[1]]));
                let mut cursor = &rest[2..];
                let mut apps = Vec::with_capacity(count.min(256));
                for _ in 0..count {
                    let (raw, next) = read_bytes(cursor)?;
                    let app = std::str::from_utf8(raw)
                        .map_err(|_| IpcError::MalformedPayload)?
                        .to_string();
                    apps.push(app);
                    cursor = next;
                }
                if !cursor.is_empty() {
                    return Err(IpcError::TrailingBytes);
                }
                Ok(Self::LockedApps { nonce, apps })
            }
            105 => {
                if rest.len() != 1 || rest[0] > 1 {
                    return Err(IpcError::MalformedPayload);
                }
                Ok(Self::Ack {
                    nonce,
                    ok: rest[0] == 1,
                })
            }
            106 => decode_app_modes(nonce, rest),
            107 => decode_activity_entries(nonce, rest),
            255 => {
                if rest.len() != 2 {
                    return Err(IpcError::MalformedPayload);
                }
                let code = u16::from_le_bytes([rest[0], rest[1]]);
                Ok(Self::Error { nonce, code })
            }
            other => Err(IpcError::UnknownKind(other)),
        }
    }
}

fn decode_set_app_mode(nonce: [u8; 16], rest: &[u8]) -> Result<Request, IpcError> {
    let (raw_id, tail) = read_bytes(rest)?;
    if tail.len() != 8 {
        return Err(IpcError::MalformedPayload);
    }
    let app_id = std::str::from_utf8(raw_id)
        .map_err(|_| IpcError::MalformedPayload)?
        .to_string();
    let grace_seconds = u64::from_le_bytes([
        tail[0], tail[1], tail[2], tail[3], tail[4], tail[5], tail[6], tail[7],
    ]);
    Ok(Request::SetAppMode {
        nonce,
        app_id,
        grace_seconds,
    })
}

fn decode_app_modes(nonce: [u8; 16], rest: &[u8]) -> Result<Response, IpcError> {
    if rest.len() < 2 {
        return Err(IpcError::MalformedPayload);
    }
    let count = usize::from(u16::from_le_bytes([rest[0], rest[1]]));
    let mut cursor = &rest[2..];
    let mut apps = Vec::with_capacity(count.min(256));
    for _ in 0..count {
        let (raw, next) = read_bytes(cursor)?;
        if next.len() < 8 {
            return Err(IpcError::MalformedPayload);
        }
        let app = std::str::from_utf8(raw)
            .map_err(|_| IpcError::MalformedPayload)?
            .to_string();
        let secs = u64::from_le_bytes([
            next[0], next[1], next[2], next[3], next[4], next[5], next[6], next[7],
        ]);
        apps.push((app, secs));
        cursor = &next[8..];
    }
    if !cursor.is_empty() {
        return Err(IpcError::TrailingBytes);
    }
    Ok(Response::AppModes { nonce, apps })
}

fn decode_activity_entries(nonce: [u8; 16], rest: &[u8]) -> Result<Response, IpcError> {
    if rest.len() < 2 {
        return Err(IpcError::MalformedPayload);
    }
    let count = usize::from(u16::from_le_bytes([rest[0], rest[1]]));
    let mut cursor = &rest[2..];
    let mut entries = Vec::with_capacity(count.min(256));
    for _ in 0..count {
        if cursor.len() < 8 {
            return Err(IpcError::MalformedPayload);
        }
        let ts = u64::from_le_bytes([
            cursor[0], cursor[1], cursor[2], cursor[3], cursor[4], cursor[5], cursor[6], cursor[7],
        ]);
        let (k_b, c1) = read_bytes(&cursor[8..])?;
        let (t_b, c2) = read_bytes(c1)?;
        let (r_b, c3) = read_bytes(c2)?;
        let kind = std::str::from_utf8(k_b)
            .map_err(|_| IpcError::MalformedPayload)?
            .to_string();
        let target = std::str::from_utf8(t_b)
            .map_err(|_| IpcError::MalformedPayload)?
            .to_string();
        let result = std::str::from_utf8(r_b)
            .map_err(|_| IpcError::MalformedPayload)?
            .to_string();
        entries.push((ts, kind, target, result));
        cursor = c3;
    }
    if !cursor.is_empty() {
        return Err(IpcError::TrailingBytes);
    }
    Ok(Response::ActivityLogEntries { nonce, entries })
}

fn parse_header(bytes: &[u8]) -> Result<(u8, [u8; 16], &[u8]), IpcError> {
    if bytes.len() < HEADER_LEN || bytes.len() > MAX_MESSAGE_BYTES {
        return Err(IpcError::InvalidLength);
    }
    if &bytes[..4] != MAGIC {
        return Err(IpcError::InvalidMagic);
    }
    let version = u16::from_le_bytes([bytes[4], bytes[5]]);
    if version != PROTOCOL_VERSION {
        return Err(IpcError::UnsupportedVersion(version));
    }
    let kind = bytes[6];
    let mut nonce = [0_u8; 16];
    nonce.copy_from_slice(&bytes[7..23]);
    Ok((kind, nonce, &bytes[23..]))
}

fn write_bytes(out: &mut Vec<u8>, data: &[u8]) -> Result<(), IpcError> {
    let len = u16::try_from(data.len()).map_err(|_| IpcError::InvalidLength)?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(data);
    Ok(())
}

fn read_bytes(input: &[u8]) -> Result<(&[u8], &[u8]), IpcError> {
    if input.len() < 2 {
        return Err(IpcError::MalformedPayload);
    }
    let len = usize::from(u16::from_le_bytes([input[0], input[1]]));
    let body = &input[2..];
    if body.len() < len {
        return Err(IpcError::MalformedPayload);
    }
    Ok((&body[..len], &body[len..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_requests_and_responses() -> Result<(), IpcError> {
        let nonce = [7_u8; 16];
        let req = Request::VerifyCredential {
            nonce,
            target_pid: 4242,
            secret: b"1234".to_vec(),
        };
        let encoded = req.encode()?;
        let decoded = Request::decode(&encoded)?;
        assert_eq!(req, decoded);

        let resp = Response::CredentialResult {
            nonce,
            allowed: false,
            lockout_remaining_secs: 30,
        };
        let r_enc = resp.encode()?;
        let r_dec = Response::decode(&r_enc)?;
        assert_eq!(resp, r_dec);
        Ok(())
    }

    #[test]
    fn rejects_debug_secret_leak() {
        let req = Request::VerifyCredential {
            nonce: [1_u8; 16],
            target_pid: 10,
            secret: b"supersecretpin".to_vec(),
        };
        let dbg_str = format!("{req:?}");
        assert!(!dbg_str.contains("supersecretpin"));
        assert!(dbg_str.contains("[REDACTED]"));

        let cp = Request::ChangePin {
            nonce: [2_u8; 16],
            current_secret: b"oldsecret99".to_vec(),
            new_secret: b"newsecret88".to_vec(),
        };
        let cp_dbg = format!("{cp:?}");
        assert!(!cp_dbg.contains("oldsecret99"));
        assert!(!cp_dbg.contains("newsecret88"));
        assert!(cp_dbg.contains("[REDACTED]"));
    }

    #[test]
    fn round_trip_manager_messages() -> Result<(), IpcError> {
        let nonce = [9_u8; 16];
        let msgs = [
            Request::ListLockedApps { nonce },
            Request::SetAppLocked {
                nonce,
                app_id: "whatsapp.exe".to_string(),
                locked: true,
            },
            Request::ChangePin {
                nonce,
                current_secret: b"1234".to_vec(),
                new_secret: b"5678".to_vec(),
            },
        ];
        for req in msgs {
            let enc = req.encode()?;
            assert_eq!(Request::decode(&enc)?, req);
        }
        let resp = Response::LockedApps {
            nonce,
            apps: vec!["notepad.exe".to_string(), "whatsapp.exe".to_string()],
        };
        assert_eq!(Response::decode(&resp.encode()?)?, resp);
        let ack = Response::Ack { nonce, ok: true };
        assert_eq!(Response::decode(&ack.encode()?)?, ack);
        let set_mode = Request::SetAppMode {
            nonce,
            app_id: "msedge.exe".to_string(),
            grace_seconds: 300,
        };
        assert_eq!(Request::decode(&set_mode.encode()?)?, set_mode);
        let list_modes = Request::ListAppModes { nonce };
        assert_eq!(Request::decode(&list_modes.encode()?)?, list_modes);
        let modes_resp = Response::AppModes {
            nonce,
            apps: vec![("msedge.exe".to_string(), 300)],
        };
        assert_eq!(Response::decode(&modes_resp.encode()?)?, modes_resp);
        let list_act = Request::ListActivityLog { nonce, limit: 50 };
        assert_eq!(Request::decode(&list_act.encode()?)?, list_act);
        let clear_act = Request::ClearActivityLog { nonce };
        assert_eq!(Request::decode(&clear_act.encode()?)?, clear_act);
        let act_resp = Response::ActivityLogEntries {
            nonce,
            entries: vec![(
                1_700_000_000,
                "unlock".to_string(),
                "notepad.exe".to_string(),
                "allowed".to_string(),
            )],
        };
        assert_eq!(Response::decode(&act_resp.encode()?)?, act_resp);
        Ok(())
    }

    #[test]
    fn rejects_invalid_frames_and_trailing_bytes() -> Result<(), IpcError> {
        assert_eq!(Request::decode(&[]), Err(IpcError::InvalidLength));
        let mut frame = Request::Ping { nonce: [0_u8; 16] }.encode()?;
        frame.push(0xAA);
        assert_eq!(Request::decode(&frame), Err(IpcError::TrailingBytes));

        frame.pop();
        frame[4] = 99; // bad version
        assert!(matches!(
            Request::decode(&frame),
            Err(IpcError::UnsupportedVersion(_))
        ));

        let oversized = vec![0_u8; MAX_MESSAGE_BYTES + 1];
        assert_eq!(Request::decode(&oversized), Err(IpcError::InvalidLength));
        Ok(())
    }

    #[test]
    fn round_trip_overlay_update_and_reject_invalid() -> Result<(), IpcError> {
        let nonce = [5_u8; 16];
        for vis in [
            WindowVisibility::Visible,
            WindowVisibility::Minimized,
            WindowVisibility::Hidden,
            WindowVisibility::Unfocused,
        ] {
            let msg = OverlayUpdate {
                nonce,
                rect: WindowRect {
                    x: -100,
                    y: 250,
                    width: 1280,
                    height: 720,
                },
                visibility: vis,
            };
            let enc = msg.encode()?;
            assert_eq!(OverlayUpdate::decode(&enc)?, msg);
        }

        let mut bad = OverlayUpdate {
            nonce,
            rect: WindowRect {
                x: 0,
                y: 0,
                width: 400,
                height: 300,
            },
            visibility: WindowVisibility::Visible,
        }
        .encode()?;
        if let Some(last) = bad.last_mut() {
            *last = 99;
        }
        assert_eq!(OverlayUpdate::decode(&bad), Err(IpcError::MalformedPayload));
        Ok(())
    }
}
