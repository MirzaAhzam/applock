//! Event-driven ETW process-start listener using `Microsoft-Windows-Kernel-Process`.

use std::mem::{size_of, zeroed};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, ERROR_SUCCESS};
use windows_sys::Win32::System::Diagnostics::Etw::{
    CloseTrace, ControlTraceW, EnableTraceEx2, OpenTraceW, ProcessTrace, StartTraceW,
    CONTROLTRACE_HANDLE, ENABLE_TRACE_PARAMETERS, EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_RECORD,
    EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES,
    EVENT_TRACE_REAL_TIME_MODE, PROCESSTRACE_HANDLE, PROCESS_TRACE_MODE_EVENT_RECORD,
    PROCESS_TRACE_MODE_REAL_TIME, TRACE_LEVEL_INFORMATION, WNODE_FLAG_TRACED_GUID,
};

use crate::{process::query_image_path, to_wide_null, WinError};

const SESSION_NAME: &str = "AppLockM0Trace";
static KERNEL_PROCESS_GUID: GUID = GUID {
    data1: 0x22FB_2CD6,
    data2: 0x0E7B,
    data3: 0x422B,
    data4: [0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16],
};
const WINEVENT_KEYWORD_PROCESS: u64 = 0x10;
const PROCESS_START_EVENT_ID: u16 = 1;
const INVALID_TRACE_HANDLE: PROCESSTRACE_HANDLE = PROCESSTRACE_HANDLE { Value: u64::MAX };

type ProcessStartCallback = Arc<dyn Fn(u32, &str) + Send + Sync>;

struct CallbackContext {
    callback: ProcessStartCallback,
    running: Arc<AtomicBool>,
}

/// Active real-time ETW process-start trace session.
pub struct EtwSession {
    session_handle: CONTROLTRACE_HANDLE,
    trace_handle: PROCESSTRACE_HANDLE,
    running: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl EtwSession {
    /// Starts the real-time ETW session and spawns a blocking consumer thread.
    ///
    /// # Errors
    /// Returns `WinError` if starting or opening the ETW trace fails (e.g. missing elevation).
    pub fn start<F>(on_process_start: F) -> Result<Self, WinError>
    where
        F: Fn(u32, &str) + Send + Sync + 'static,
    {
        let session_wide = to_wide_null(SESSION_NAME);
        let props_buf_len = size_of::<EVENT_TRACE_PROPERTIES>() + session_wide.len() * 2;
        let mut props_buf = vec![0_u8; props_buf_len];

        // SAFETY: `props_buf` is zeroed and large enough for `EVENT_TRACE_PROPERTIES` followed
        // by the UTF-16 session name. `StartTraceW` initializes the session handle.
        let session_handle = unsafe {
            let props = props_buf.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>();
            (*props).Wnode.BufferSize = u32::try_from(props_buf_len).unwrap_or(0);
            (*props).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            (*props).Wnode.ClientContext = 1;
            (*props).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
            (*props).LoggerNameOffset =
                u32::try_from(size_of::<EVENT_TRACE_PROPERTIES>()).unwrap_or(0);

            let mut handle = CONTROLTRACE_HANDLE { Value: 0 };
            let mut status = StartTraceW(&raw mut handle, session_wide.as_ptr(), props);
            if status == ERROR_ALREADY_EXISTS {
                let mut stop_buf = vec![0_u8; props_buf_len];
                let stop_props = stop_buf.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>();
                (*stop_props).Wnode.BufferSize = u32::try_from(props_buf_len).unwrap_or(0);
                (*stop_props).LoggerNameOffset =
                    u32::try_from(size_of::<EVENT_TRACE_PROPERTIES>()).unwrap_or(0);
                let _ = ControlTraceW(
                    CONTROLTRACE_HANDLE { Value: 0 },
                    session_wide.as_ptr(),
                    stop_props,
                    EVENT_TRACE_CONTROL_STOP,
                );
                handle = CONTROLTRACE_HANDLE { Value: 0 };
                status = StartTraceW(&raw mut handle, session_wide.as_ptr(), props);
            }
            if status != ERROR_SUCCESS {
                return Err(WinError {
                    code: status,
                    context: "StartTraceW",
                });
            }

            let enable_params: ENABLE_TRACE_PARAMETERS = zeroed();
            let enable_status = EnableTraceEx2(
                handle,
                &raw const KERNEL_PROCESS_GUID,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                u8::try_from(TRACE_LEVEL_INFORMATION).unwrap_or(4),
                WINEVENT_KEYWORD_PROCESS,
                0,
                0,
                &raw const enable_params,
            );
            if enable_status != ERROR_SUCCESS {
                let _ = ControlTraceW(handle, ptr::null(), props, EVENT_TRACE_CONTROL_STOP);
                return Err(WinError {
                    code: enable_status,
                    context: "EnableTraceEx2",
                });
            }
            handle
        };

        let running = Arc::new(AtomicBool::new(true));
        let ctx = Box::new(CallbackContext {
            callback: Arc::new(on_process_start),
            running: Arc::clone(&running),
        });
        let ctx_ptr = Box::into_raw(ctx);

        let mut logger_name = to_wide_null(SESSION_NAME);
        // SAFETY: `logfile` references `logger_name` only during `OpenTraceW`, and `ctx_ptr`
        // remains valid until after `worker.join()` in `Drop`.
        let trace_handle = unsafe {
            let mut logfile: EVENT_TRACE_LOGFILEW = zeroed();
            logfile.LoggerName = logger_name.as_mut_ptr();
            logfile.Anonymous1.ProcessTraceMode =
                PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
            logfile.Anonymous2.EventRecordCallback = Some(event_record_callback);
            logfile.Context = ctx_ptr.cast();
            OpenTraceW(&raw mut logfile)
        };

        if trace_handle.Value == INVALID_TRACE_HANDLE.Value {
            // SAFETY: `OpenTraceW` failed so no worker thread will ever read `ctx_ptr`.
            unsafe {
                drop(Box::from_raw(ctx_ptr));
                stop_trace_by_handle(session_handle);
            }
            return Err(WinError {
                code: 1,
                context: "OpenTraceW",
            });
        }

        let worker_handle_val = trace_handle.Value;
        let ctx_addr = ctx_ptr as usize;
        let worker = thread::spawn(move || {
            let h = PROCESSTRACE_HANDLE {
                Value: worker_handle_val,
            };
            // SAFETY: `h` is a valid open trace handle and `ctx_addr` points to a
            // uniquely-owned `CallbackContext` that stays alive until `ProcessTrace` returns.
            unsafe {
                let _ = ProcessTrace(&raw const h, 1, ptr::null(), ptr::null());
                drop(Box::from_raw(ctx_addr as *mut CallbackContext));
            }
        });

        Ok(Self {
            session_handle,
            trace_handle,
            running,
            worker: Some(worker),
        })
    }

    /// Stops the ETW session and waits for the consumer thread to exit.
    pub fn stop(&mut self) {
        if !self.running.swap(false, Ordering::SeqCst) {
            return;
        }
        // SAFETY: Stopping the trace session and closing `trace_handle` unblocks `ProcessTrace`.
        unsafe {
            stop_trace_by_handle(self.session_handle);
            let _ = CloseTrace(self.trace_handle);
        }
        if let Some(handle) = self.worker.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for EtwSession {
    fn drop(&mut self) {
        self.stop();
    }
}

unsafe fn stop_trace_by_handle(session_handle: CONTROLTRACE_HANDLE) {
    let props_buf_len = size_of::<EVENT_TRACE_PROPERTIES>() + 256;
    let mut props_buf = vec![0_u8; props_buf_len];
    let props = props_buf.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>();
    (*props).Wnode.BufferSize = u32::try_from(props_buf_len).unwrap_or(0);
    let _ = ControlTraceW(session_handle, ptr::null(), props, EVENT_TRACE_CONTROL_STOP);
}

unsafe extern "system" fn event_record_callback(event_record: *mut EVENT_RECORD) {
    if event_record.is_null() {
        return;
    }
    let record = &*event_record;
    if record.UserContext.is_null() {
        return;
    }
    let ctx = &*record.UserContext.cast::<CallbackContext>();
    if !ctx.running.load(Ordering::Relaxed) {
        return;
    }
    if record.EventHeader.EventDescriptor.Id != PROCESS_START_EVENT_ID {
        return;
    }
    if record.UserData.is_null() || record.UserDataLength < 4 {
        return;
    }
    let pid_bytes = std::slice::from_raw_parts(record.UserData.cast::<u8>(), 4);
    let pid = u32::from_le_bytes([pid_bytes[0], pid_bytes[1], pid_bytes[2], pid_bytes[3]]);
    if pid == 0 {
        return;
    }
    let path = query_image_path(pid).unwrap_or_default();
    (ctx.callback)(pid, &path);
}
