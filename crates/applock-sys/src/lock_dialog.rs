//! Minimal native Win32 lock prompt used only for the M0 proof-of-concept spike.

use std::mem::zeroed;
use std::ptr;

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{GetStockObject, COLOR_WINDOW, DEFAULT_GUI_FONT};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW,
    GetWindowLongPtrW, GetWindowTextW, PostQuitMessage, RegisterClassW, SetFocus,
    SetForegroundWindow, SetWindowLongPtrW, ShowWindow, TranslateMessage, BS_DEFPUSHBUTTON,
    BS_PUSHBUTTON, ES_PASSWORD, GWLP_USERDATA, IDOK, MSG, SW_SHOW, WM_COMMAND, WM_CREATE,
    WM_DESTROY, WM_SETFONT, WNDCLASSW, WS_BORDER, WS_CAPTION, WS_CHILD, WS_EX_TOPMOST, WS_SYSMENU,
    WS_TABSTOP, WS_VISIBLE,
};

use crate::to_wide_null;

const ID_EDIT: i32 = 101;
const ID_UNLOCK: i32 = 102;
const ID_CANCEL: i32 = 103;

/// Result of the minimal M0 lock prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockPromptOutcome {
    /// User entered a credential and clicked Unlock (or pressed Enter).
    Attempt(String),
    /// User cancelled or closed the window.
    Cancelled,
}

struct PromptState {
    edit_hwnd: HWND,
    outcome: LockPromptOutcome,
}

/// Shows a minimal topmost Win32 lock window for `app_name` and blocks until submitted or cancelled.
#[must_use]
pub fn show_m0_lock_prompt(app_name: &str) -> LockPromptOutcome {
    let class_name = to_wide_null("AppLockM0Prompt");
    let title = to_wide_null(&format!("AppLock M0 - Locked: {app_name}"));
    let edit_class = to_wide_null("EDIT");
    let button_class = to_wide_null("BUTTON");
    let static_class = to_wide_null("STATIC");
    let label_text = to_wide_null(&format!("Enter PIN (M0 test: 1234) to open {app_name}:"));
    let unlock_text = to_wide_null("Unlock");
    let cancel_text = to_wide_null("Cancel and close app");

    let mut state = PromptState {
        edit_hwnd: ptr::null_mut(),
        outcome: LockPromptOutcome::Cancelled,
    };

    // SAFETY: Standard Win32 window registration and modal message loop on the calling thread;
    // `state` outlives `DestroyWindow` and `GWLP_USERDATA` is only read while `state` is alive.
    unsafe {
        let hinstance = GetModuleHandleW(ptr::null());
        let wc = WNDCLASSW {
            style: 0,
            lpfnWndProc: Some(prompt_wnd_proc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: hinstance,
            hIcon: ptr::null_mut(),
            hCursor: ptr::null_mut(),
            hbrBackground: (COLOR_WINDOW + 1) as _,
            lpszMenuName: ptr::null(),
            lpszClassName: class_name.as_ptr(),
        };
        RegisterClassW(&raw const wc);

        let hwnd = CreateWindowExW(
            WS_EX_TOPMOST,
            class_name.as_ptr(),
            title.as_ptr(),
            WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
            300,
            240,
            400,
            190,
            ptr::null_mut(),
            ptr::null_mut(),
            hinstance,
            (&raw mut state).cast(),
        );
        if hwnd.is_null() {
            return LockPromptOutcome::Cancelled;
        }

        let font = GetStockObject(DEFAULT_GUI_FONT);
        let lbl = CreateWindowExW(
            0,
            static_class.as_ptr(),
            label_text.as_ptr(),
            WS_CHILD | WS_VISIBLE,
            16,
            16,
            352,
            24,
            hwnd,
            ptr::null_mut(),
            hinstance,
            ptr::null(),
        );
        let edit = CreateWindowExW(
            0,
            edit_class.as_ptr(),
            ptr::null(),
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_PASSWORD as u32,
            16,
            48,
            352,
            28,
            hwnd,
            ID_EDIT as _,
            hinstance,
            ptr::null(),
        );
        let btn_ok = CreateWindowExW(
            0,
            button_class.as_ptr(),
            unlock_text.as_ptr(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON as u32,
            16,
            92,
            110,
            32,
            hwnd,
            ID_UNLOCK as _,
            hinstance,
            ptr::null(),
        );
        let btn_cancel = CreateWindowExW(
            0,
            button_class.as_ptr(),
            cancel_text.as_ptr(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON as u32,
            140,
            92,
            228,
            32,
            hwnd,
            ID_CANCEL as _,
            hinstance,
            ptr::null(),
        );

        for child in [lbl, edit, btn_ok, btn_cancel] {
            if !child.is_null() {
                windows_sys::Win32::UI::WindowsAndMessaging::SendMessageW(
                    child,
                    WM_SETFONT,
                    font as WPARAM,
                    1,
                );
            }
        }
        state.edit_hwnd = edit;
        ShowWindow(hwnd, SW_SHOW);
        SetForegroundWindow(hwnd);
        SetFocus(edit);

        let mut msg: MSG = zeroed();
        while GetMessageW(&raw mut msg, ptr::null_mut(), 0, 0) > 0 {
            if !windows_sys::Win32::UI::WindowsAndMessaging::IsDialogMessageW(hwnd, &raw mut msg)
                != 0
            {
                TranslateMessage(&raw const msg);
                DispatchMessageW(&raw const msg);
            }
        }
    }

    state.outcome
}

unsafe extern "system" fn prompt_wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_CREATE => {
            let cs = lparam as *const windows_sys::Win32::UI::WindowsAndMessaging::CREATESTRUCTW;
            if !cs.is_null() {
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, (*cs).lpCreateParams as isize);
            }
            0
        }
        WM_COMMAND => {
            let id = i32::from((wparam & 0xFFFF) as u16);
            let state_ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut PromptState;
            if !state_ptr.is_null() && (id == ID_UNLOCK || id == IDOK) {
                let state = &mut *state_ptr;
                let mut buf = [0_u16; 128];
                let len = GetWindowTextW(state.edit_hwnd, buf.as_mut_ptr(), 128);
                let text = if len > 0 {
                    String::from_utf16_lossy(&buf[..len as usize])
                } else {
                    String::new()
                };
                state.outcome = LockPromptOutcome::Attempt(text);
                DestroyWindow(hwnd);
                return 0;
            }
            if !state_ptr.is_null() && id == ID_CANCEL {
                (*state_ptr).outcome = LockPromptOutcome::Cancelled;
                DestroyWindow(hwnd);
                return 0;
            }
            DefWindowProcW(hwnd, msg, wparam, lparam)
        }
        WM_DESTROY => {
            PostQuitMessage(0);
            0
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}
