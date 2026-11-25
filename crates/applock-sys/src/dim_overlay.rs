//! Full-screen 55% black privacy dim overlay for locked applications.

use std::mem::zeroed;
use std::ptr;
use std::sync::mpsc;
use std::thread::{self, JoinHandle};

use windows_sys::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{GetStockObject, BLACK_BRUSH};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW,
    GetSystemMetrics, PostMessageW, PostQuitMessage, RegisterClassW, SetLayeredWindowAttributes,
    ShowWindow, TranslateMessage, LWA_ALPHA, MSG, SM_CXSCREEN, SM_CXVIRTUALSCREEN, SM_CYSCREEN,
    SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN, SW_SHOWNOACTIVATE, WM_CLOSE,
    WM_DESTROY, WNDCLASSW, WS_DISABLED, WS_EX_LAYERED, WS_EX_NOACTIVATE, WS_EX_TOOLWINDOW,
    WS_EX_TOPMOST, WS_POPUP,
};

use crate::to_wide_null;

const DIM_ALPHA_55_PCT: u8 = 140;

/// RAII guard for a topmost 55% black virtual-screen dim overlay.
///
/// Dropping the guard closes the overlay window and stops its message thread.
pub struct DimOverlay {
    hwnd: isize,
    thread: Option<JoinHandle<()>>,
}

impl DimOverlay {
    /// Creates and displays the 55% black dim overlay across the virtual desktop.
    ///
    /// Returns `None` if window creation fails (callers continue fail-closed without panicking).
    #[must_use]
    pub fn show() -> Option<Self> {
        let (tx, rx) = mpsc::sync_channel::<isize>(1);
        let handle = thread::Builder::new()
            .name("applock-dim-overlay".to_string())
            .spawn(move || run_overlay_thread(&tx))
            .ok()?;

        match rx.recv() {
            Ok(hwnd) if hwnd != 0 => Some(Self {
                hwnd,
                thread: Some(handle),
            }),
            _ => {
                let _ = handle.join();
                None
            }
        }
    }
}

impl Drop for DimOverlay {
    fn drop(&mut self) {
        if self.hwnd != 0 {
            // SAFETY: `self.hwnd` is a valid top-level overlay window created on the overlay
            // thread; `PostMessageW(WM_CLOSE)` triggers `DestroyWindow` and `PostQuitMessage`.
            unsafe {
                let _ = PostMessageW(self.hwnd as HWND, WM_CLOSE, 0, 0);
            }
        }
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }
}

fn run_overlay_thread(tx: &mpsc::SyncSender<isize>) {
    let class_name = to_wide_null("AppLockDimOverlay");
    let title = to_wide_null("AppLock Overlay");

    // SAFETY: Standard Win32 window class registration, layered window creation, and
    // modal message loop confined to this thread.
    unsafe {
        let hinst: HINSTANCE = GetModuleHandleW(ptr::null());
        let wc = WNDCLASSW {
            lpfnWndProc: Some(overlay_wnd_proc),
            hInstance: hinst,
            lpszClassName: class_name.as_ptr(),
            hbrBackground: GetStockObject(BLACK_BRUSH),
            ..zeroed()
        };
        let _ = RegisterClassW(&raw const wc);

        let vx = GetSystemMetrics(SM_XVIRTUALSCREEN);
        let vy = GetSystemMetrics(SM_YVIRTUALSCREEN);
        let vw = GetSystemMetrics(SM_CXVIRTUALSCREEN);
        let vh = GetSystemMetrics(SM_CYVIRTUALSCREEN);
        let (x, y, w, h) = if vw > 0 && vh > 0 {
            (vx, vy, vw, vh)
        } else {
            (
                0,
                0,
                GetSystemMetrics(SM_CXSCREEN).max(1),
                GetSystemMetrics(SM_CYSCREEN).max(1),
            )
        };

        let hwnd = CreateWindowExW(
            WS_EX_LAYERED | WS_EX_TOOLWINDOW | WS_EX_TOPMOST | WS_EX_NOACTIVATE,
            class_name.as_ptr(),
            title.as_ptr(),
            WS_POPUP | WS_DISABLED,
            x,
            y,
            w,
            h,
            ptr::null_mut(),
            ptr::null_mut(),
            hinst,
            ptr::null(),
        );

        if hwnd.is_null() {
            let _ = tx.send(0);
            return;
        }

        let _ = SetLayeredWindowAttributes(hwnd, 0, DIM_ALPHA_55_PCT, LWA_ALPHA);
        let _ = ShowWindow(hwnd, SW_SHOWNOACTIVATE);

        let _ = tx.send(hwnd as isize);

        let mut msg: MSG = zeroed();
        while GetMessageW(&raw mut msg, ptr::null_mut(), 0, 0) > 0 {
            TranslateMessage(&raw const msg);
            DispatchMessageW(&raw const msg);
        }
    }
}

unsafe extern "system" fn overlay_wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_CLOSE => {
            let _ = DestroyWindow(hwnd);
            0
        }
        WM_DESTROY => {
            PostQuitMessage(0);
            0
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dim_overlay_show_and_drop_does_not_panic() {
        let overlay = DimOverlay::show();
        drop(overlay);
    }
}
