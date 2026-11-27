//! Safe Win32/DWM window bounds and topmost overlay positioning helpers.

use std::mem::zeroed;
use std::ptr;

use windows_sys::core::BOOL;
use windows_sys::Win32::Foundation::{HWND, LPARAM, RECT};
use windows_sys::Win32::Graphics::Dwm::{DwmGetWindowAttribute, DWMWA_EXTENDED_FRAME_BOUNDS};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetWindowLongPtrW, GetWindowRect, GetWindowThreadProcessId, IsWindowVisible,
    SetWindowLongPtrW, SetWindowPos, ShowWindow, GWL_EXSTYLE, HWND_TOPMOST, SWP_FRAMECHANGED,
    SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOSIZE, SWP_NOZORDER, SWP_SHOWWINDOW, SW_HIDE, SW_SHOW,
    WS_EX_TOOLWINDOW, WS_EX_TOPMOST,
};

/// Physical screen bounding rectangle of a window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowBounds {
    /// Left coordinate in physical screen pixels.
    pub left: i32,
    /// Top coordinate in physical screen pixels.
    pub top: i32,
    /// Width in physical screen pixels.
    pub width: i32,
    /// Height in physical screen pixels.
    pub height: i32,
}

/// Extracts physical screen coordinates for `hwnd` using `DWMWA_EXTENDED_FRAME_BOUNDS`,
/// falling back to `GetWindowRect` if DWM attributes are unavailable.
#[must_use]
pub fn get_window_bounds(hwnd: isize) -> Option<WindowBounds> {
    if hwnd == 0 {
        return None;
    }
    let raw_hwnd = hwnd as HWND;
    let mut rect: RECT = unsafe { zeroed() };
    let rect_size = u32::try_from(std::mem::size_of::<RECT>()).unwrap_or(16);

    // SAFETY: `raw_hwnd` is non-zero and `rect` is valid stack storage of `size_of::<RECT>()`.
    let dwm_ok = unsafe {
        DwmGetWindowAttribute(
            raw_hwnd,
            u32::try_from(DWMWA_EXTENDED_FRAME_BOUNDS).unwrap_or(9),
            (&raw mut rect).cast(),
            rect_size,
        )
    };

    if dwm_ok != 0 {
        // SAFETY: `raw_hwnd` is non-zero and `rect` is valid stack storage.
        let rect_ok = unsafe { GetWindowRect(raw_hwnd, &raw mut rect) };
        if rect_ok == 0 {
            return None;
        }
    }

    bounds_from_rect(rect.left, rect.top, rect.right, rect.bottom)
}

#[must_use]
fn bounds_from_rect(left: i32, top: i32, right: i32, bottom: i32) -> Option<WindowBounds> {
    let width = right.saturating_sub(left);
    let height = bottom.saturating_sub(top);
    if width <= 0 || height <= 0 {
        return None;
    }
    Some(WindowBounds {
        left,
        top,
        width,
        height,
    })
}

/// Finds the first visible top-level window belonging to the current process.
#[must_use]
pub fn find_own_window_hwnd() -> Option<isize> {
    struct SearchState {
        pid: u32,
        found: isize,
    }

    unsafe extern "system" fn enum_proc(hwnd: HWND, lparam: LPARAM) -> BOOL {
        let state = &mut *(lparam as *mut SearchState);
        let mut win_pid: u32 = 0;
        GetWindowThreadProcessId(hwnd, &raw mut win_pid);
        if win_pid == state.pid && IsWindowVisible(hwnd) != 0 {
            state.found = hwnd as isize;
            return 0;
        }
        1
    }

    let mut state = SearchState {
        pid: std::process::id(),
        found: 0,
    };
    // SAFETY: `state` lives on the stack for the synchronous `EnumWindows` call.
    unsafe {
        let _ = EnumWindows(Some(enum_proc), (&raw mut state) as LPARAM);
    }
    if state.found != 0 {
        Some(state.found)
    } else {
        None
    }
}

/// Configures `hwnd` as a topmost tool window (`WS_EX_TOPMOST | WS_EX_TOOLWINDOW`) and
/// positions it to `bounds` (or hides it when `visible` is `false`).
pub fn configure_lock_overlay_hwnd(hwnd: isize, bounds: WindowBounds, visible: bool) {
    if hwnd == 0 || bounds.width <= 0 || bounds.height <= 0 {
        return;
    }
    let raw_hwnd = hwnd as HWND;

    // SAFETY: `raw_hwnd` is non-zero; `GetWindowLongPtrW`/`SetWindowLongPtrW` and
    // `SetWindowPos`/`ShowWindow` are standard Win32 window-positioning calls.
    unsafe {
        let ex_style = GetWindowLongPtrW(raw_hwnd, GWL_EXSTYLE);
        let desired = ex_style
            | isize::try_from(WS_EX_TOPMOST).unwrap_or(0)
            | isize::try_from(WS_EX_TOOLWINDOW).unwrap_or(0);
        if desired != ex_style {
            SetWindowLongPtrW(raw_hwnd, GWL_EXSTYLE, desired);
            let _ = SetWindowPos(
                raw_hwnd,
                ptr::null_mut(),
                0,
                0,
                0,
                0,
                SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED,
            );
        }

        if visible {
            let _ = SetWindowPos(
                raw_hwnd,
                HWND_TOPMOST,
                bounds.left,
                bounds.top,
                bounds.width,
                bounds.height,
                SWP_SHOWWINDOW,
            );
            let _ = ShowWindow(raw_hwnd, SW_SHOW);
        } else {
            let _ = ShowWindow(raw_hwnd, SW_HIDE);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_bounds_rejects_null_and_empty_rects() {
        assert!(get_window_bounds(0).is_none());
        assert!(bounds_from_rect(100, 100, 100, 200).is_none());
        assert!(bounds_from_rect(100, 100, 50, 200).is_none());
        assert_eq!(
            bounds_from_rect(10, 20, 410, 320),
            Some(WindowBounds {
                left: 10,
                top: 20,
                width: 400,
                height: 300,
            })
        );
    }
}
