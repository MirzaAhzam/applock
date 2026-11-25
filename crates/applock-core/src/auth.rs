//! Argon2id password/PIN hashing and constant-time secret comparison.

use applock_sys::crypto::fill_random;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::CoreError;

const ARGON2_MEMORY_KIB: u32 = 32 * 1024;
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 1;

/// Hashes `secret` using Argon2id with a fresh 16-byte OS CSPRNG salt.
///
/// # Errors
/// Returns `CoreError` if OS CSPRNG or Argon2id hashing fails.
pub fn hash_secret(secret: &[u8]) -> Result<String, CoreError> {
    let mut salt_bytes = Zeroizing::new([0_u8; 16]);
    fill_random(&mut *salt_bytes)?;
    let salt = SaltString::encode_b64(&*salt_bytes).map_err(|_| CoreError::Crypto)?;
    let params = Params::new(ARGON2_MEMORY_KIB, ARGON2_ITERATIONS, ARGON2_PARALLELISM, None)
        .map_err(|_| CoreError::Crypto)?;
    let hasher = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let hash = hasher
        .hash_password(secret, &salt)
        .map_err(|_| CoreError::Crypto)?;
    Ok(hash.to_string())
}

/// Verifies `attempt` against a stored PHC Argon2id hash string (fail-closed).
#[must_use]
pub fn verify_secret(hash_phc: &str, attempt: &[u8]) -> bool {
    let Ok(parsed) = PasswordHash::new(hash_phc) else {
        return false;
    };
    Argon2::default().verify_password(attempt, &parsed).is_ok()
}

/// Compares two byte slices in constant time.
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    bool::from(a.ct_eq(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon2id_hash_and_verify_round_trip() {
        let pin = Zeroizing::new(b"482910".to_vec());
        let phc = hash_secret(&pin).expect("hash");
        assert!(phc.starts_with("$argon2id$"));
        assert!(verify_secret(&phc, &pin));
        assert!(!verify_secret(&phc, b"000000"));
        assert!(!verify_secret("corrupt-hash", &pin));
    }

    #[test]
    fn constant_time_comparison_works() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }
}
