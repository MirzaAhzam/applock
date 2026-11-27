//! Windows Service Control Manager (SCM) dispatcher wrapper (`FR-TAMP-01`).

use std::ffi::c_void;
use std::ptr;
use std::sync::atomic::{AtomicIsize, Ordering};
use std::sync::Mutex;

use windows_sys::Win32::Foundation::{
    GetLastError, ERROR_FAILED_SERVICE_CONTROLLER_CONNECT, ERROR_SUCCESS, NO_ERROR,
};
use windows_sys::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SetServiceStatus, StartServiceCtrlDispatcherW,
    SERVICE_ACCEPT_SHUTDOWN, SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_SHUTDOWN,
    SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_HANDLE, SERVICE_STOPPED,
    SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
};

use crate::{to_wide_null, WinError};

/// Outcome of attempting to attach to the Windows Service Control Manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScmOutcome {
    /// Service ran under SCM and exited cleanly.
    ServiceCompleted,
    /// Process was not launched by SCM (e.g., interactive console or test runner).
    NotStartedByScm,
}

type ServiceEntry = Box<dyn FnOnce() + Send + 'static>;

static SERVICE_ENTRY: Mutex<Option<ServiceEntry>> = Mutex::new(None);
static SERVICE_NAME: Mutex<String> = Mutex::new(String::new());
static STATUS_HANDLE: AtomicIsize = AtomicIsize::new(0);

/// Connects the current process to Windows SCM and runs `entry` inside `ServiceMain`.
///
/// Returns `Ok(ScmOutcome::NotStartedByScm)` if launched interactively from a terminal
/// (`ERROR_FAILED_SERVICE_CONTROLLER_CONNECT`).
///
/// # Errors
/// Returns `WinError` if `StartServiceCtrlDispatcherW` fails with an unexpected error.
pub fn run_as_windows_service<F>(service_name: &str, entry: F) -> Result<ScmOutcome, WinError>
where
    F: FnOnce() + Send + 'static,
{
    if let Ok(mut name_guard) = SERVICE_NAME.lock() {
        (*name_guard).clone_from(&service_name.to_string());
    }
    if let Ok(mut entry_guard) = SERVICE_ENTRY.lock() {
        *entry_guard = Some(Box::new(entry));
    }

    let mut wide_name = to_wide_null(service_name);
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: wide_name.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: ptr::null_mut(),
            lpServiceProc: None,
        },
    ];

    // SAFETY: `table` is null-terminated with `SERVICE_TABLE_ENTRYW { null, None }` and
    // `wide_name` remains alive for the duration of `StartServiceCtrlDispatcherW`.
    let ok = unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) };
    if ok != 0 {
        return Ok(ScmOutcome::ServiceCompleted);
    }

    // Clear unused entry if SCM did not invoke `service_main`.
    if let Ok(mut entry_guard) = SERVICE_ENTRY.lock() {
        *entry_guard = None;
    }

    // SAFETY: `GetLastError` reads the calling thread's last Win32 error code.
    let err = unsafe { GetLastError() };
    if err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT {
        return Ok(ScmOutcome::NotStartedByScm);
    }

    Err(WinError {
        code: err,
        context: "StartServiceCtrlDispatcherW",
    })
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
    let svc_name = SERVICE_NAME
        .lock()
        .map(|g| g.clone())
        .unwrap_or_else(|_| "AppLockService".to_string());
    let name_w = to_wide_null(&svc_name);

    let handle: SERVICE_STATUS_HANDLE =
        RegisterServiceCtrlHandlerExW(name_w.as_ptr(), Some(ctrl_handler), ptr::null_mut());
    if handle.is_null() {
        return;
    }
    STATUS_HANDLE.store(handle as isize, Ordering::SeqCst);

    report_status(handle, SERVICE_START_PENDING, 0, 1, 2000);
    // Never advertise SERVICE_ACCEPT_STOP so standard users cannot stop the service.
    report_status(handle, SERVICE_RUNNING, SERVICE_ACCEPT_SHUTDOWN, 0, 0);

    let entry = SERVICE_ENTRY.lock().ok().and_then(|mut g| g.take());
    if let Some(run) = entry {
        run();
    }

    report_status(handle, SERVICE_STOPPED, 0, 0, 0);
}

unsafe extern "system" fn ctrl_handler(
    control: u32,
    _event_type: u32,
    _event_data: *mut c_void,
    _context: *mut c_void,
) -> u32 {
    let handle = STATUS_HANDLE.load(Ordering::SeqCst) as SERVICE_STATUS_HANDLE;
    match control {
        SERVICE_CONTROL_SHUTDOWN => {
            if !handle.is_null() {
                report_status(handle, SERVICE_STOPPED, 0, 0, 0);
            }
            NO_ERROR
        }
        SERVICE_CONTROL_INTERROGATE => {
            if !handle.is_null() {
                report_status(handle, SERVICE_RUNNING, SERVICE_ACCEPT_SHUTDOWN, 0, 0);
            }
            NO_ERROR
        }
        _ => ERROR_SUCCESS,
    }
}

unsafe fn report_status(
    handle: SERVICE_STATUS_HANDLE,
    current_state: u32,
    controls_accepted: u32,
    check_point: u32,
    wait_hint: u32,
) {
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: current_state,
        dwControlsAccepted: controls_accepted,
        dwWin32ExitCode: NO_ERROR,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: check_point,
        dwWaitHint: wait_hint,
    };
    let _ = SetServiceStatus(handle, &raw const status);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_service_dispatcher_returns_not_started_by_scm_in_console() -> Result<(), WinError> {
        let outcome = run_as_windows_service("AppLockServiceTest", || {})?;
        assert_eq!(outcome, ScmOutcome::NotStartedByScm);
        Ok(())
    }
}
