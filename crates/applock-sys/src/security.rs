//! Windows ACL verification/repair and privileged install-marker helpers (`FR-TAMP-04`).
//!
//! Machine-scope DPAPI detects corruption or truncation only; the real protection
//! against tampering by standard users is the SYSTEM/Administrators-only ACL on
//! `%ProgramData%\AppLock` and `HKLM\SOFTWARE\AppLock`.

use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::{
    GetLastError, LocalFree, ERROR_FILE_NOT_FOUND, ERROR_SUCCESS, HLOCAL,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW,
    SetNamedSecurityInfoW, SE_FILE_OBJECT, SE_REGISTRY_KEY,
};
use windows_sys::Win32::Security::{
    AclSizeInformation, CreateWellKnownSid, EqualSid, GetAce, GetAclInformation,
    GetSecurityDescriptorControl, GetSecurityDescriptorDacl, WinBuiltinAdministratorsSid,
    WinLocalSystemSid, ACCESS_ALLOWED_ACE, ACCESS_ALLOWED_ACE_TYPE, ACL, ACL_SIZE_INFORMATION,
    DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR_CONTROL, SE_DACL_PROTECTED,
};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY,
    HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE, REG_DWORD, REG_OPTION_NON_VOLATILE,
};

use crate::{to_wide_null, WinError};

/// Protected DACL granting Full Control only to `SYSTEM` (`SY`) and `Administrators` (`BA`).
const SDDL_DIR_SYSTEM_ADMIN_ONLY: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
/// Protected DACL granting Full Key Access only to `SYSTEM` (`SY`) and `Administrators` (`BA`).
const SDDL_REG_SYSTEM_ADMIN_ONLY: &str = "D:P(A;OICI;KA;;;SY)(A;OICI;KA;;;BA)";

const INSTALL_MARKER_SUBKEY: &str = r"SOFTWARE\AppLock";
const INSTALL_MARKER_VALUE: &str = "Installed";
const INSTALL_MARKER_NAMED_OBJ: &str = r"MACHINE\SOFTWARE\AppLock";

/// Verifies that `dir` has a protected DACL allowing only `SYSTEM` and `Administrators`.
///
/// If the DACL is missing, unprotected, or contains any ACE for another principal (such as
/// `Users`, `Authenticated Users`, or `Everyone`), it repairs the ACL in place and returns
/// `Ok(true)`. Returns `Ok(false)` when the ACL was already compliant.
///
/// # Errors
/// Returns `WinError` if querying or repairing the directory security descriptor fails.
pub fn verify_and_repair_dir_acl(dir: &Path) -> Result<bool, WinError> {
    let dir_str = dir.to_string_lossy();
    let dir_wide = to_wide_null(&dir_str);

    if is_dir_dacl_compliant(&dir_wide)? {
        return Ok(false);
    }

    apply_protected_sddl(&dir_wide, SE_FILE_OBJECT, SDDL_DIR_SYSTEM_ADMIN_ONLY)?;
    Ok(true)
}

/// Returns `true` if the `HKLM\SOFTWARE\AppLock\Installed` marker exists and equals `1`.
///
/// # Errors
/// Returns `WinError` on unexpected registry errors (callers should fail closed).
pub fn has_install_marker() -> Result<bool, WinError> {
    let subkey_wide = to_wide_null(INSTALL_MARKER_SUBKEY);
    let value_wide = to_wide_null(INSTALL_MARKER_VALUE);
    let mut hkey: HKEY = ptr::null_mut();

    // SAFETY: `subkey_wide` is null-terminated; `hkey` receives the opened key handle on success.
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            subkey_wide.as_ptr(),
            0,
            KEY_READ,
            &raw mut hkey,
        )
    };
    if status == ERROR_FILE_NOT_FOUND {
        return Ok(false);
    }
    if status != ERROR_SUCCESS {
        return Err(WinError {
            code: status,
            context: "RegOpenKeyExW",
        });
    }

    let mut data: u32 = 0;
    let mut data_size: u32 = u32::try_from(std::mem::size_of::<u32>()).unwrap_or(4);
    let mut reg_type: u32 = 0;

    // SAFETY: `hkey` is valid; `data` and `data_size` point to initialized stack storage.
    let q_status = unsafe {
        let res = RegQueryValueExW(
            hkey,
            value_wide.as_ptr(),
            ptr::null(),
            &raw mut reg_type,
            (&raw mut data).cast::<u8>(),
            &raw mut data_size,
        );
        RegCloseKey(hkey);
        res
    };

    if q_status == ERROR_FILE_NOT_FOUND {
        return Ok(false);
    }
    if q_status != ERROR_SUCCESS {
        return Err(WinError {
            code: q_status,
            context: "RegQueryValueExW",
        });
    }
    Ok(reg_type == REG_DWORD && data == 1)
}

/// Creates/updates `HKLM\SOFTWARE\AppLock\Installed = 1` with a `SYSTEM`/`Administrators`-only ACL.
///
/// # Errors
/// Returns `WinError` if creating the registry key, setting its ACL, or writing the value fails.
pub fn set_install_marker() -> Result<(), WinError> {
    let subkey_wide = to_wide_null(INSTALL_MARKER_SUBKEY);
    let value_wide = to_wide_null(INSTALL_MARKER_VALUE);
    let sddl_wide = to_wide_null(SDDL_REG_SYSTEM_ADMIN_ONLY);
    let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();

    // SAFETY: `sddl_wide` is null-terminated; `sd` is freed with `LocalFree` after `RegCreateKeyExW`.
    unsafe {
        let ok_sd = ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl_wide.as_ptr(),
            1,
            &raw mut sd,
            ptr::null_mut(),
        );
        if ok_sd == 0 {
            return Err(WinError {
                code: GetLastError(),
                context: "ConvertStringSecurityDescriptorToSecurityDescriptorW",
            });
        }

        let mut sa = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
            lpSecurityDescriptor: sd,
            bInheritHandle: 0,
        };
        let mut hkey: HKEY = ptr::null_mut();
        let status = RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            subkey_wide.as_ptr(),
            0,
            ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            &raw mut sa,
            &raw mut hkey,
            ptr::null_mut(),
        );
        LocalFree(sd as HLOCAL);

        if status != ERROR_SUCCESS {
            return Err(WinError {
                code: status,
                context: "RegCreateKeyExW",
            });
        }

        let val: u32 = 1;
        let val_size = u32::try_from(std::mem::size_of::<u32>()).unwrap_or(4);
        let set_status = RegSetValueExW(
            hkey,
            value_wide.as_ptr(),
            0,
            REG_DWORD,
            (&raw const val).cast::<u8>(),
            val_size,
        );
        RegCloseKey(hkey);

        if set_status != ERROR_SUCCESS {
            return Err(WinError {
                code: set_status,
                context: "RegSetValueExW",
            });
        }
    }

    // Re-apply protected DACL in case the key already existed with inherited permissions.
    let named_obj = to_wide_null(INSTALL_MARKER_NAMED_OBJ);
    apply_protected_sddl(&named_obj, SE_REGISTRY_KEY, SDDL_REG_SYSTEM_ADMIN_ONLY)
}

fn is_dir_dacl_compliant(dir_wide: &[u16]) -> Result<bool, WinError> {
    let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
    let mut dacl: *mut ACL = ptr::null_mut();

    // SAFETY: `dir_wide` is null-terminated; `sd` is freed via `LocalFree` before returning.
    unsafe {
        let status = GetNamedSecurityInfoW(
            dir_wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &raw mut dacl,
            ptr::null_mut(),
            &raw mut sd,
        );
        if status != ERROR_SUCCESS {
            return Err(WinError {
                code: status,
                context: "GetNamedSecurityInfoW",
            });
        }

        let compliant = check_sd_dacl_system_admin_only(sd, dacl);
        LocalFree(sd as HLOCAL);
        compliant
    }
}

unsafe fn check_sd_dacl_system_admin_only(
    sd: PSECURITY_DESCRIPTOR,
    dacl: *const ACL,
) -> Result<bool, WinError> {
    if dacl.is_null() {
        return Ok(false);
    }

    let mut control: SECURITY_DESCRIPTOR_CONTROL = 0;
    let mut revision: u32 = 0;
    if GetSecurityDescriptorControl(sd, &raw mut control, &raw mut revision) == 0 {
        return Err(WinError {
            code: GetLastError(),
            context: "GetSecurityDescriptorControl",
        });
    }
    if (u32::from(control) & SE_DACL_PROTECTED) == 0 {
        return Ok(false);
    }

    let mut size_info = ACL_SIZE_INFORMATION {
        AceCount: 0,
        AclBytesInUse: 0,
        AclBytesFree: 0,
    };
    let info_len = u32::try_from(std::mem::size_of::<ACL_SIZE_INFORMATION>()).unwrap_or(0);
    if GetAclInformation(
        dacl,
        (&raw mut size_info).cast(),
        info_len,
        AclSizeInformation,
    ) == 0
    {
        return Err(WinError {
            code: GetLastError(),
            context: "GetAclInformation",
        });
    }
    if size_info.AceCount == 0 {
        return Ok(false);
    }

    let system_sid = well_known_sid(WinLocalSystemSid)?;
    let admin_sid = well_known_sid(WinBuiltinAdministratorsSid)?;

    for idx in 0..size_info.AceCount {
        let mut ace_ptr: *mut std::ffi::c_void = ptr::null_mut();
        if GetAce(dacl, idx, &raw mut ace_ptr) == 0 || ace_ptr.is_null() {
            return Ok(false);
        }
        let ace = &*(ace_ptr.cast::<ACCESS_ALLOWED_ACE>());
        if u32::from(ace.Header.AceType) != ACCESS_ALLOWED_ACE_TYPE {
            return Ok(false);
        }
        let sid_ptr = (&raw const ace.SidStart).cast::<std::ffi::c_void>();
        let is_sys = EqualSid(sid_ptr, system_sid.as_ptr().cast()) != 0;
        let is_adm = EqualSid(sid_ptr, admin_sid.as_ptr().cast()) != 0;
        if !is_sys && !is_adm {
            return Ok(false);
        }
    }

    Ok(true)
}

fn well_known_sid(sid_type: i32) -> Result<Vec<u8>, WinError> {
    let mut size: u32 = 68;
    let mut buf = vec![0_u8; usize::try_from(size).unwrap_or(68)];
    // SAFETY: `buf` is at least `SECURITY_MAX_SID_SIZE` (68 bytes) and `size` matches its length.
    let ok = unsafe {
        CreateWellKnownSid(
            sid_type,
            ptr::null_mut(),
            buf.as_mut_ptr().cast(),
            &raw mut size,
        )
    };
    if ok == 0 {
        return Err(WinError {
            code: unsafe { GetLastError() },
            context: "CreateWellKnownSid",
        });
    }
    Ok(buf)
}

fn apply_protected_sddl(object_wide: &[u16], object_type: i32, sddl: &str) -> Result<(), WinError> {
    let sddl_wide = to_wide_null(sddl);
    let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();

    // SAFETY: `sddl_wide` is null-terminated; `sd` is freed with `LocalFree` after `SetNamedSecurityInfoW`.
    unsafe {
        let ok_sd = ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl_wide.as_ptr(),
            1,
            &raw mut sd,
            ptr::null_mut(),
        );
        if ok_sd == 0 {
            return Err(WinError {
                code: GetLastError(),
                context: "ConvertStringSecurityDescriptorToSecurityDescriptorW",
            });
        }

        let mut dacl_present: i32 = 0;
        let mut dacl: *mut ACL = ptr::null_mut();
        let mut dacl_defaulted: i32 = 0;
        let ok_dacl = GetSecurityDescriptorDacl(
            sd,
            &raw mut dacl_present,
            &raw mut dacl,
            &raw mut dacl_defaulted,
        );
        if ok_dacl == 0 || dacl_present == 0 || dacl.is_null() {
            let err = GetLastError();
            LocalFree(sd as HLOCAL);
            return Err(WinError {
                code: err,
                context: "GetSecurityDescriptorDacl",
            });
        }

        let status = SetNamedSecurityInfoW(
            object_wide.as_ptr().cast_mut(),
            object_type,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            dacl,
            ptr::null_mut(),
        );
        LocalFree(sd as HLOCAL);

        if status != ERROR_SUCCESS {
            return Err(WinError {
                code: status,
                context: "SetNamedSecurityInfoW",
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn dir_acl_check_and_repair_detects_permissive_acl() -> Result<(), Box<dyn std::error::Error>> {
        let dir = std::env::temp_dir().join(format!("applock_acl_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir)?;

        // Fresh temp dir inherits user/permissive ACLs -> first call must repair it.
        let first = verify_and_repair_dir_acl(&dir)?;
        assert!(first, "fresh temp dir should require ACL repair");

        // Second call must see it as already compliant.
        let second = verify_and_repair_dir_acl(&dir)?;
        assert!(!second, "repaired dir should already be compliant");

        // Granting Users (BU) read access must be detected and repaired again.
        let dir_wide = to_wide_null(&dir.to_string_lossy());
        apply_protected_sddl(
            &dir_wide,
            SE_FILE_OBJECT,
            "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;BU)",
        )?;
        let third = verify_and_repair_dir_acl(&dir)?;
        assert!(third, "permissive Users ACE must trigger repair");

        let fourth = verify_and_repair_dir_acl(&dir)?;
        assert!(!fourth);

        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }
}

