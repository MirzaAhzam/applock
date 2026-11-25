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
    /// Reply to `VerifyCredential`.
    CredentialResult {
        /// Matching request nonce.
        nonce: [u8; 16],
        /// `true` if the credential was accepted.
        allowed: bool,
        /// Remaining lockout wait in seconds (`0` if not locked out).
        lockout_remaining_secs: u64,
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
    fn round_trip_requests_and_responses() {
        let nonce = [7_u8; 16];
        let req = Request::VerifyCredential {
            nonce,
            target_pid: 4242,
            secret: b"1234".to_vec(),
        };
        let encoded = req.encode().expect("encode");
        let decoded = Request::decode(&encoded).expect("decode");
        assert_eq!(req, decoded);

        let resp = Response::CredentialResult {
            nonce,
            allowed: false,
            lockout_remaining_secs: 30,
        };
        let r_enc = resp.encode().expect("encode");
        let r_dec = Response::decode(&r_enc).expect("decode");
        assert_eq!(resp, r_dec);
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
    }

    #[test]
    fn rejects_invalid_frames_and_trailing_bytes() {
        assert_eq!(Request::decode(&[]), Err(IpcError::InvalidLength));
        let mut frame = Request::Ping { nonce: [0_u8; 16] }
            .encode()
            .expect("encode");
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
    }
}
