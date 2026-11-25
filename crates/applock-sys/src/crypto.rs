//! OS CSPRNG (`BCryptGenRandom`) and Windows DPAPI (`CryptProtectData` / `CryptUnprotectData`).

use std::ptr;

use windows_sys::Win32::Foundation::{GetLastError, LocalFree, HLOCAL};
use windows_sys::Win32::Security::Cryptography::{
    BCryptGenRandom, CryptProtectData, CryptUnprotectData, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
    CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
};

use crate::WinError;

/// Fills `buf` with cryptographically secure random bytes from the OS CSPRNG.
///
/// # Errors
/// Returns `WinError` if `BCryptGenRandom` fails.
pub fn fill_random(buf: &mut [u8]) -> Result<(), WinError> {
    if buf.is_empty() {
        return Ok(());
    }
    let len = u32::try_from(buf.len()).map_err(|_| WinError {
        code: 87,
        context: "fill_random(length)",
    })?;
    // SAFETY: `buf` is a valid mutable slice of `len` bytes.
    let status = unsafe {
        BCryptGenRandom(
            ptr::null_mut(),
            buf.as_mut_ptr(),
            len,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status < 0 {
        return Err(WinError {
            code: u32::from_ne_bytes(status.to_ne_bytes()),
            context: "BCryptGenRandom",
        });
    }
    Ok(())
}

/// Encrypts `plaintext` with Windows DPAPI (machine scope).
///
/// # Errors
/// Returns `WinError` if `CryptProtectData` fails.
pub fn dpapi_protect_machine(plaintext: &[u8]) -> Result<Vec<u8>, WinError> {
    let len = u32::try_from(plaintext.len()).map_err(|_| WinError {
        code: 87,
        context: "dpapi_protect(length)",
    })?;
    let mut in_blob = CRYPT_INTEGER_BLOB {
        cbData: len,
        pbData: plaintext.as_ptr().cast_mut(),
    };
    let mut out_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };
    // SAFETY: `in_blob` points to `plaintext`; `out_blob.pbData` is freed via `LocalFree`.
    unsafe {
        let ok = CryptProtectData(
            &raw mut in_blob,
            ptr::null(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null(),
            CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
            &raw mut out_blob,
        );
        if ok == 0 {
            return Err(WinError {
                code: GetLastError(),
                context: "CryptProtectData",
            });
        }
        let slice = std::slice::from_raw_parts(
            out_blob.pbData,
            usize::try_from(out_blob.cbData).unwrap_or(0),
        );
        let result = slice.to_vec();
        LocalFree(out_blob.pbData as HLOCAL);
        Ok(result)
    }
}

/// Decrypts `ciphertext` encrypted with [`dpapi_protect_machine`].
///
/// # Errors
/// Returns `WinError` if `CryptUnprotectData` fails.
pub fn dpapi_unprotect_machine(ciphertext: &[u8]) -> Result<Vec<u8>, WinError> {
    let len = u32::try_from(ciphertext.len()).map_err(|_| WinError {
        code: 87,
        context: "dpapi_unprotect(length)",
    })?;
    let mut in_blob = CRYPT_INTEGER_BLOB {
        cbData: len,
        pbData: ciphertext.as_ptr().cast_mut(),
    };
    let mut out_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };
    // SAFETY: `in_blob` points to `ciphertext`; `out_blob.pbData` is freed via `LocalFree`.
    unsafe {
        let ok = CryptUnprotectData(
            &raw mut in_blob,
            ptr::null_mut(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &raw mut out_blob,
        );
        if ok == 0 {
            return Err(WinError {
                code: GetLastError(),
                context: "CryptUnprotectData",
            });
        }
        let slice = std::slice::from_raw_parts(
            out_blob.pbData,
            usize::try_from(out_blob.cbData).unwrap_or(0),
        );
        let result = slice.to_vec();
        LocalFree(out_blob.pbData as HLOCAL);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_and_dpapi_round_trip() -> Result<(), WinError> {
        let mut buf = [0_u8; 32];
        fill_random(&mut buf)?;
        assert!(buf.iter().any(|&b| b != 0));

        let plain = b"applock-dpapi-test-payload";
        let sealed = dpapi_protect_machine(plain)?;
        assert_ne!(sealed.as_slice(), plain);
        let opened = dpapi_unprotect_machine(&sealed)?;
        assert_eq!(opened.as_slice(), plain);
        Ok(())
    }
}
