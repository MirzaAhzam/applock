//! Event-driven window watcher using `SetWinEventHook`.

use std::cell::RefCell;

use windows_sys::core::BOOL;
use windows_sys::Win32::Foundation::{HWND, LPARAM};
use windows_sys::Win32::UI::Accessibility::{SetWinEventHook, UnhookWinEvent, HWINEVENTHOOK};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    DispatchMessageW, EnumChildWindows, GetMessageW, GetWindowThreadProcessId, TranslateMessage,
    EVENT_OBJECT_HIDE, EVENT_OBJECT_LOCATIONCHANGE, EVENT_SYSTEM_FOREGROUND,
    EVENT_SYSTEM_MINIMIZESTART, MSG, WINEVENT_OUTOFCONTEXT, WINEVENT_SKIPOWNPROCESS,
};

use crate::window::{get_window_bounds, WindowBounds};
use crate::{process::query_image_path, WinError};

/// Window lifecycle events observed by `applock-agent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowEventKind {
    /// Foreground window changed.
    Foreground,
    /// Window moved or resized.
    LocationChanged,
    /// Window was hidden or closed.
    Hidden,
    /// Window started minimizing.
    Minimized,
}

/// Event payload delivered from `SetWinEventHook` to `applock-agent`.
#[derive(Debug, Clone)]
pub struct WindowEvent {
    /// Event kind.
    pub kind: WindowEventKind,
    /// Raw target `HWND`.
    pub hwnd: isize,
    /// Resolved owning process ID.
    pub pid: u32,
    /// Full executable path of the owning process.
    pub image_path: String,
    /// Current physical screen bounds of `hwnd` (if available).
    pub bounds: Option<WindowBounds>,
}

type WindowEventHandler = Box<dyn FnMut(WindowEvent)>;

thread_local! {
    static HOOK_HANDLER: RefCell<Option<WindowEventHandler>> = const { RefCell::new(None) };
}

/// Runs an event-driven `SetWinEventHook` loop on the current thread for foreground changes.
///
/// # Errors
/// Returns `WinError` if `SetWinEventHook` fails.
pub fn run_foreground_watcher<F>(mut handler: F) -> Result<(), WinError>
where
    F: FnMut(u32, &str) + 'static,
{
    run_window_watcher(move |ev| {
        if ev.kind == WindowEventKind::Foreground {
            handler(ev.pid, &ev.image_path);
        }
    })
}

/// Runs an event-driven `SetWinEventHook` loop listening for foreground, location-change,
/// hide, and minimize events.
///
/// # Errors
/// Returns `WinError` if `SetWinEventHook` fails.
pub fn run_window_watcher<F>(handler: F) -> Result<(), WinError>
where
    F: FnMut(WindowEvent) + 'static,
{
    HOOK_HANDLER.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(handler));
    });

    let event_ranges = [
        (EVENT_SYSTEM_FOREGROUND, EVENT_SYSTEM_FOREGROUND),
        (EVENT_SYSTEM_MINIMIZESTART, EVENT_SYSTEM_MINIMIZESTART),
        (EVENT_OBJECT_HIDE, EVENT_OBJECT_HIDE),
        (EVENT_OBJECT_LOCATIONCHANGE, EVENT_OBJECT_LOCATIONCHANGE),
    ];

    let mut hooks: Vec<HWINEVENTHOOK> = Vec::with_capacity(event_ranges.len());

    // SAFETY: `SetWinEventHook` with `WINEVENT_OUTOFCONTEXT` delivers events to `win_event_proc`
    // on this thread's message loop; every hook is removed via `UnhookWinEvent` before returning.
    unsafe {
        for (min_ev, max_ev) in event_ranges {
            let hook: HWINEVENTHOOK = SetWinEventHook(
                min_ev,
                max_ev,
                std::ptr::null_mut(),
                Some(win_event_proc),
                0,
                0,
                WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS,
            );
            if hook.is_null() {
                for installed in hooks {
                    let _ = UnhookWinEvent(installed);
                }
                HOOK_HANDLER.with(|slot| *slot.borrow_mut() = None);
                return Err(WinError {
                    code: 1,
                    context: "SetWinEventHook",
                });
            }
            hooks.push(hook);
        }

        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&raw mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            TranslateMessage(&raw const msg);
            DispatchMessageW(&raw const msg);
        }

        for installed in hooks {
            let _ = UnhookWinEvent(installed);
        }
    }

    HOOK_HANDLER.with(|slot| *slot.borrow_mut() = None);
    Ok(())
}

unsafe extern "system" fn win_event_proc(
    _hook: HWINEVENTHOOK,
    event: u32,
    hwnd: HWND,
    id_object: i32,
    id_child: i32,
    _id_event_thread: u32,
    _event_time: u32,
) {
    if hwnd.is_null() {
        return;
    }
    // Filter out child-control and caret location/hide noise.
    if (event == EVENT_OBJECT_LOCATIONCHANGE || event == EVENT_OBJECT_HIDE)
        && (id_object != 0 || id_child != 0)
    {
        return;
    }

    let kind = match event {
        EVENT_SYSTEM_FOREGROUND => WindowEventKind::Foreground,
        EVENT_OBJECT_LOCATIONCHANGE => WindowEventKind::LocationChanged,
        EVENT_OBJECT_HIDE => WindowEventKind::Hidden,
        EVENT_SYSTEM_MINIMIZESTART => WindowEventKind::Minimized,
        _ => return,
    };

    let Some((pid, image_path)) = resolve_window_owner(hwnd) else {
        return;
    };
    let raw_hwnd = hwnd as isize;
    let bounds = if kind == WindowEventKind::Hidden || kind == WindowEventKind::Minimized {
        None
    } else {
        get_window_bounds(raw_hwnd)
    };

    let ev = WindowEvent {
        kind,
        hwnd: raw_hwnd,
        pid,
        image_path,
        bounds,
    };

    HOOK_HANDLER.with(|slot| {
        if let Ok(mut guard) = slot.try_borrow_mut() {
            if let Some(cb) = guard.as_mut() {
                cb(ev);
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
    if path
        .to_ascii_lowercase()
        .ends_with("applicationframehost.exe")
    {
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
    let mut child_pid: u32 = 0;
    GetWindowThreadProcessId(hwnd, &raw mut child_pid);
    if child_pid != 0 && child_pid != state.host_pid {
        if let Some(path) = query_image_path(child_pid) {
            state.found = Some((child_pid, path));
            return 0;
        }
    }
    1
}
