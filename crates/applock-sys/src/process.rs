//! Process control and inspection wrappers (suspend, resume, terminate, memory, CPU).

use std::mem::{size_of, zeroed};
use std::ptr;

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, FILETIME, HANDLE, NTSTATUS};
use windows_sys::Win32::System::ProcessStatus::{
    GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS, PROCESS_MEMORY_COUNTERS_EX,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessW, GetCurrentProcess, GetProcessTimes, OpenProcess, QueryFullProcessImageNameW,
    TerminateProcess, WaitForSingleObject, CREATE_NO_WINDOW, PROCESS_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SUSPEND_RESUME, PROCESS_TERMINATE, STARTUPINFOW,
};

use crate::{to_wide_null, WinError};

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtSuspendProcess(process_handle: HANDLE) -> NTSTATUS;
    fn NtResumeProcess(process_handle: HANDLE) -> NTSTATUS;
}

/// Suspends all threads of the target process (`NtSuspendProcess`).
///
/// # Errors
/// Returns `WinError` if opening the process or suspending it fails.
pub fn suspend_process(pid: u32) -> Result<(), WinError> {
    // SAFETY: `OpenProcess` returns either a valid handle or null; `NtSuspendProcess`
    // takes a valid `PROCESS_SUSPEND_RESUME` handle; `CloseHandle` closes it once.
    unsafe {
        let handle = OpenProcess(PROCESS_SUSPEND_RESUME, 0, pid);
        if handle.is_null() {
            return Err(WinError {
                code: GetLastError(),
                context: "OpenProcess(SUSPEND_RESUME)",
            });
        }
        let status = NtSuspendProcess(handle);
        CloseHandle(handle);
        if status < 0 {
            return Err(WinError {
                code: status.cast_unsigned(),
                context: "NtSuspendProcess",
            });
        }
    }
    Ok(())
}

/// Resumes all threads of the target process (`NtResumeProcess`).
///
/// # Errors
/// Returns `WinError` if opening the process or resuming it fails.
pub fn resume_process(pid: u32) -> Result<(), WinError> {
    // SAFETY: `OpenProcess` returns either a valid handle or null; `NtResumeProcess`
    // takes a valid `PROCESS_SUSPEND_RESUME` handle; `CloseHandle` closes it once.
    unsafe {
        let handle = OpenProcess(PROCESS_SUSPEND_RESUME, 0, pid);
        if handle.is_null() {
            return Err(WinError {
                code: GetLastError(),
                context: "OpenProcess(SUSPEND_RESUME)",
            });
        }
        let status = NtResumeProcess(handle);
        CloseHandle(handle);
        if status < 0 {
            return Err(WinError {
                code: status.cast_unsigned(),
                context: "NtResumeProcess",
            });
        }
    }
    Ok(())
}

/// Terminates the target process (`TerminateProcess`).
///
/// # Errors
/// Returns `WinError` if opening or terminating the process fails.
pub fn terminate_process(pid: u32) -> Result<(), WinError> {
    // SAFETY: `OpenProcess` returns a valid `PROCESS_TERMINATE` handle or null,
    // and `CloseHandle` releases it after `TerminateProcess`.
    unsafe {
        let handle = OpenProcess(PROCESS_TERMINATE, 0, pid);
        if handle.is_null() {
            return Err(WinError {
                code: GetLastError(),
                context: "OpenProcess(TERMINATE)",
            });
        }
        let ok = TerminateProcess(handle, 1);
        let err = GetLastError();
        CloseHandle(handle);
        if ok == 0 {
            return Err(WinError {
                code: err,
                context: "TerminateProcess",
            });
        }
    }
    Ok(())
}

/// Queries the full executable path for a running process ID.
///
/// # Errors
/// Returns `WinError` if the process cannot be opened or queried.
pub fn query_image_path(pid: u32) -> Result<String, WinError> {
    // SAFETY: `buf` is a stack-allocated UTF-16 buffer of `len` elements;
    // `QueryFullProcessImageNameW` writes at most `len` code units and updates `len`.
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return Err(WinError {
                code: GetLastError(),
                context: "OpenProcess(QUERY_LIMITED)",
            });
        }
        let mut buf = [0_u16; 1024];
        let mut len = u32::try_from(buf.len()).unwrap_or(1024);
        let ok = QueryFullProcessImageNameW(handle, 0, buf.as_mut_ptr(), &mut len);
        let err = GetLastError();
        CloseHandle(handle);
        if ok == 0 {
            return Err(WinError {
                code: err,
                context: "QueryFullProcessImageNameW",
            });
        }
        Ok(String::from_utf16_lossy(&buf[..len as usize]))
    }
}

/// Returns current process private memory usage in bytes (`PrivateUsage`).
#[must_use]
pub fn current_private_memory_bytes() -> Option<u64> {
    // SAFETY: `PROCESS_MEMORY_COUNTERS_EX` is a C POD struct whose first fields match
    // `PROCESS_MEMORY_COUNTERS`; `cb` is set to `size_of::<PROCESS_MEMORY_COUNTERS_EX>()`.
    unsafe {
        let mut pmc: PROCESS_MEMORY_COUNTERS_EX = zeroed();
        let cb = u32::try_from(size_of::<PROCESS_MEMORY_COUNTERS_EX>()).ok()?;
        pmc.cb = cb;
        let ptr = (&raw mut pmc).cast::<PROCESS_MEMORY_COUNTERS>();
        if GetProcessMemoryInfo(GetCurrentProcess(), ptr, cb) == 0 {
            return None;
        }
        Some(pmc.PrivateUsage as u64)
    }
}

/// Returns cumulative kernel + user CPU time of the current process in 100-ns units.
#[must_use]
pub fn current_cpu_time_100ns() -> Option<u64> {
    fn ft_to_u64(ft: FILETIME) -> u64 {
        (u64::from(ft.dwHighDateTime) << 32) | u64::from(ft.dwLowDateTime)
    }
    // SAFETY: All four `FILETIME` pointers are valid stack locals.
    unsafe {
        let mut creation: FILETIME = zeroed();
        let mut exit: FILETIME = zeroed();
        let mut kernel: FILETIME = zeroed();
        let mut user: FILETIME = zeroed();
        if GetProcessTimes(
            GetCurrentProcess(),
            &raw mut creation,
            &raw mut exit,
            &raw mut kernel,
            &raw mut user,
        ) == 0
        {
            return None;
        }
        Some(ft_to_u64(kernel).saturating_add(ft_to_u64(user)))
    }
}

/// Launches a hidden child process for headless CI latency benchmarks and returns `(pid, handle)`.
///
/// # Errors
/// Returns `WinError` if `CreateProcessW` fails.
pub fn launch_hidden_command(command_line: &str) -> Result<u32, WinError> {
    let mut cmd = to_wide_null(command_line);
    // SAFETY: `STARTUPINFOW` and `PROCESS_INFORMATION` are zero-initialized POD structs;
    // `cmd` is a mutable null-terminated UTF-16 buffer as required by `CreateProcessW`.
    unsafe {
        let mut si: STARTUPINFOW = zeroed();
        si.cb = u32::try_from(size_of::<STARTUPINFOW>()).unwrap_or(0);
        let mut pi: PROCESS_INFORMATION = zeroed();
        let ok = CreateProcessW(
            ptr::null(),
            cmd.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            0,
            CREATE_NO_WINDOW,
            ptr::null(),
            ptr::null(),
            &raw const si,
            &raw mut pi,
        );
        if ok == 0 {
            return Err(WinError {
                code: GetLastError(),
                context: "CreateProcessW",
            });
        }
        let pid = pi.dwProcessId;
        // Wait briefly? No, return immediately so ETW benchmark measures real launch.
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        Ok(pid)
    }
}

/// Waits up to `timeout_ms` for a process to exit (used by tests/benchmarks).
pub fn wait_process_exit(pid: u32, timeout_ms: u32) {
    // SAFETY: Opens process with `SYNCHRONIZE` (0x0010_0000) and waits up to `timeout_ms`.
    unsafe {
        let handle = OpenProcess(0x0010_0000, 0, pid);
        if !handle.is_null() {
            WaitForSingleObject(handle, timeout_ms);
            CloseHandle(handle);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_and_cpu_queries_succeed() {
        assert!(current_private_memory_bytes().unwrap_or(0) > 0);
        assert!(current_cpu_time_100ns().is_some());
    }
}
