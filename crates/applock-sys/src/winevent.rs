//! Event-driven foreground window watcher using `SetWinEventHook`.

use std::cell::RefCell;

use windows_sys::Win32::Foundation::{BOOL, HWND, LPARAM};
use windows_sys::Win32::UI::Accessibility::{HWINEVENTHOOK, SetWinEventHook, UnhookWinEvent};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    DispatchMessageW, EVENT_SYSTEM_FOREGROUND, EnumChildWindows, GetMessageW,
    GetWindowThreadProcessId, MSG, TranslateMessage, WINEVENT_OUTOFCONTEXT,
    WINEVENT_SKIPOWNPROCESS,
};

use crate::{WinError, process::query_image_path};

type ForegroundHandler = Box<dyn FnMut(u32, &str)>;

thread_local! {
    static HOOK_HANDLER: RefCell<Option<ForegroundHandler>> = const { RefCell::new(None) };
}

/// Runs an event-driven `SetWinEventHook` loop on the current thread for foreground changes.
///
/// # Errors
/// Returns `WinError` if `SetWinEventHook` fails.
pub fn run_foreground_watcher<F>(handler: F) -> Result<(), WinError>
where
    F: FnMut(u32, &str) + 'static,
{
    HOOK_HANDLER.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(handler));
    });

    // SAFETY: `SetWinEventHook` with `WINEVENT_OUTOFCONTEXT` delivers events to `win_event_proc`
    // on this thread's message loop; `UnhookWinEvent` removes the hook before returning.
    unsafe {
        let hook: HWINEVENTHOOK = SetWinEventHook(
            EVENT_SYSTEM_FOREGROUND,
            EVENT_SYSTEM_FOREGROUND,
            std::ptr::null_mut(),
            Some(win_event_proc),
            0,
            0,
            WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS,
        );
        if hook.is_null() {
            HOOK_HANDLER.with(|slot| *slot.borrow_mut() = None);
            return Err(WinError {
                code: 1,
                context: "SetWinEventHook",
            });
        }

        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&raw mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            TranslateMessage(&raw const msg);
            DispatchMessageW(&raw const msg);
        }

        let _ = UnhookWinEvent(hook);
    }

    HOOK_HANDLER.with(|slot| *slot.borrow_mut() = None);
    Ok(())
}

unsafe extern "system" fn win_event_proc(
    _hook: HWINEVENTHOOK,
    _event: u32,
    hwnd: HWND,
    _id_object: i32,
    _id_child: i32,
    _id_event_thread: u32,
    _event_time: u32,
) {
    if hwnd.is_null() {
        return;
    }
    let Some((pid, path)) = resolve_window_owner(hwnd) else {
        return;
    };
    HOOK_HANDLER.with(|slot| {
        if let Ok(mut guard) = slot.try_borrow_mut() {
            if let Some(cb) = guard.as_mut() {
                cb(pid, &path);
            }
        }
    });
}

fn resolve_window_owner(hwnd: HWND) -> Option<(u32, String)> {
    let mut pid: u32 = 0;
    // SAFETY: `hwnd` is a non-null window handle from `win_event_proc`.
    unsafe {
        GetWindowThreadProcessId(hwnd, &raw mut pid);
    }
    if pid == 0 {
        return None;
    }
    let path = query_image_path(pid).unwrap_or_default();
    if path.to_ascii_lowercase().ends_with("applicationframehost.exe") {
        let mut child_state = UwpSearch {
            host_pid: pid,
            found: None,
        };
        // SAFETY: `child_state` lives on the stack for the synchronous `EnumChildWindows` call.
        unsafe {
            EnumChildWindows(
                hwnd,
                Some(enum_child_proc),
                (&raw mut child_state).cast::<isize>() as LPARAM,
            );
        }
        if let Some(found) = child_state.found {
            return Some(found);
        }
    }
    Some((pid, path))
}

struct UwpSearch {
    host_pid: u32,
    found: Option<(u32, String)>,
}

unsafe extern "system" fn enum_child_proc(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let state = &mut *(lparam as *mut UwpSearch);
    let mut pid: u32 = 0;
    GetWindowThreadProcessId(hwnd, &raw mut pid);
    if pid != 0 && pid != state.host_pid {
        if let Ok(path) = query_image_path(pid) {
            state.found = Some((pid, path));
            return 0;
        }
    }
    1
}
