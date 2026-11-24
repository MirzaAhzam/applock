//! Pure IPC message definitions and protocol constants for `AppLock`.

/// Current IPC protocol version.
pub const PROTOCOL_VERSION: u16 = 1;

/// Maximum allowed serialized IPC message size in bytes.
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_constants_are_valid() {
        assert_eq!(PROTOCOL_VERSION, 1);
        assert_eq!(MAX_MESSAGE_BYTES, 16 * 1024);
    }
}

