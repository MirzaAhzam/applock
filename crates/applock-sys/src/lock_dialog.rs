//! Minimal native Win32 lock prompt with 55% black full-screen dim overlay for M0/M2.

use std::mem::zeroed;
use std::ptr;

use windows_sys::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{
    GetStockObject, BLACK_BRUSH, COLOR_WINDOW, DEFAULT_GUI_FONT,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::SetFocus;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW,
    GetSystemMetrics, GetWindowLongPtrW, GetWindowTextW, IsDialogMessageW, PostQuitMessage,
    RegisterClassW, SendMessageW, SetForegroundWindow, SetLayeredWindowAttributes,
    SetWindowLongPtrW, ShowWindow, TranslateMessage, BS_DEFPUSHBUTTON, BS_PUSHBUTTON,
    CREATESTRUCTW, ES_PASSWORD, GWLP_USERDATA, IDOK, LWA_ALPHA, MSG, SM_CXSCREEN,
    SM_CXVIRTUALSCREEN, SM_CYSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN,
    SW_SHOW, WM_COMMAND, WM_CREATE, WM_DESTROY, WM_SETFONT, WNDCLASSW, WS_BORDER, WS_CAPTION,
    WS_CHILD, WS_DISABLED, WS_EX_LAYERED, WS_EX_TOOLWINDOW, WS_EX_TOPMOST, WS_POPUP, WS_SYSMENU,
    WS_TABSTOP, WS_VISIBLE,
};

use crate::to_wide_null;

const ID_EDIT: i32 = 101;
const ID_UNLOCK: i32 = 102;
const ID_CANCEL: i32 = 103;
const DIM_ALPHA_55_PCT: u8 = 140;
const PROMPT_W: i32 = 400;
const PROMPT_H: i32 = 190;

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

/// Shows a 55% black full-screen dim overlay and a centered topmost lock prompt for `app_name`.
#[must_use]
pub fn show_m0_lock_prompt(app_name: &str) -> LockPromptOutcome {
    let class_name = to_wide_null("AppLockM0Prompt");
    let title = to_wide_null(&format!("AppLock M0 - Locked: {app_name}"));
    let label_text = to_wide_null(&format!("Enter PIN (M0 test: 1234) to open {app_name}:"));

    let mut state = PromptState {
        edit_hwnd: ptr::null_mut(),
        outcome: LockPromptOutcome::Cancelled,
    };

    // SAFETY: Standard Win32 window registration and modal message loop on the calling thread;
    // `state` outlives `DestroyWindow` and `dim_hwnd` is destroyed before returning.
    unsafe {
        let hinstance = GetModuleHandleW(ptr::null());
        let dim_hwnd = create_dim_overlay(hinstance);

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

        let x = (GetSystemMetrics(SM_CXSCREEN) - PROMPT_W) / 2;
        let y = (GetSystemMetrics(SM_CYSCREEN) - PROMPT_H) / 2;
        let hwnd = CreateWindowExW(
            WS_EX_TOPMOST,
            class_name.as_ptr(),
            title.as_ptr(),
            WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
            x.max(0),
            y.max(0),
            PROMPT_W,
            PROMPT_H,
            dim_hwnd,
            ptr::null_mut(),
            hinstance,
            (&raw mut state).cast(),
        );
        if hwnd.is_null() {
            if !dim_hwnd.is_null() {
                DestroyWindow(dim_hwnd);
            }
            return LockPromptOutcome::Cancelled;
        }

        let edit = create_prompt_children(hwnd, hinstance, &label_text);
        state.edit_hwnd = edit;
        ShowWindow(hwnd, SW_SHOW);
        SetForegroundWindow(hwnd);
        SetFocus(edit);

        let mut msg: MSG = zeroed();
        while GetMessageW(&raw mut msg, ptr::null_mut(), 0, 0) > 0 {
            if IsDialogMessageW(hwnd, &raw mut msg) == 0 {
                TranslateMessage(&raw const msg);
                DispatchMessageW(&raw const msg);
            }
        }

        if !dim_hwnd.is_null() {
            DestroyWindow(dim_hwnd);
        }
    }

    state.outcome
}

unsafe fn create_dim_overlay(hinstance: HINSTANCE) -> HWND {
    let dim_class = to_wide_null("AppLockM0Dim");
    let wc = WNDCLASSW {
        style: 0,
        lpfnWndProc: Some(DefWindowProcW),
        cbClsExtra: 0,
        cbWndExtra: 0,
        hInstance: hinstance,
        hIcon: ptr::null_mut(),
        hCursor: ptr::null_mut(),
        hbrBackground: GetStockObject(BLACK_BRUSH),
        lpszMenuName: ptr::null(),
        lpszClassName: dim_class.as_ptr(),
    };
    RegisterClassW(&raw const wc);

    let vx = GetSystemMetrics(SM_XVIRTUALSCREEN);
    let vy = GetSystemMetrics(SM_YVIRTUALSCREEN);
    let vw = GetSystemMetrics(SM_CXVIRTUALSCREEN).max(1920);
    let vh = GetSystemMetrics(SM_CYVIRTUALSCREEN).max(1080);

    let dim_hwnd = CreateWindowExW(
        WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_LAYERED,
        dim_class.as_ptr(),
        ptr::null(),
        WS_POPUP | WS_DISABLED | WS_VISIBLE,
        vx,
        vy,
        vw,
        vh,
        ptr::null_mut(),
        ptr::null_mut(),
        hinstance,
        ptr::null(),
    );
    if !dim_hwnd.is_null() {
        let _ = SetLayeredWindowAttributes(dim_hwnd, 0, DIM_ALPHA_55_PCT, LWA_ALPHA);
        ShowWindow(dim_hwnd, SW_SHOW);
    }
    dim_hwnd
}

unsafe fn create_prompt_children(hwnd: HWND, hinstance: HINSTANCE, label_text: &[u16]) -> HWND {
    let edit_class = to_wide_null("EDIT");
    let button_class = to_wide_null("BUTTON");
    let static_class = to_wide_null("STATIC");
    let unlock_text = to_wide_null("Unlock");
    let cancel_text = to_wide_null("Cancel and close app");

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
        WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | u32::try_from(ES_PASSWORD).unwrap_or(0),
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
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | u32::try_from(BS_DEFPUSHBUTTON).unwrap_or(0),
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
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | u32::try_from(BS_PUSHBUTTON).unwrap_or(0),
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
            SendMessageW(child, WM_SETFONT, font as WPARAM, 1);
        }
    }
    edit
}

unsafe extern "system" fn prompt_wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_CREATE => {
            let cs = lparam as *const CREATESTRUCTW;
            if !cs.is_null() {
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, (*cs).lpCreateParams as isize);
            }
            0
        }
        WM_COMMAND => {
            let id = i32::try_from(wparam & 0xFFFF).unwrap_or(-1);
            let state_ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut PromptState;
            if !state_ptr.is_null() && (id == ID_UNLOCK || id == IDOK) {
                let state = &mut *state_ptr;
                let mut buf = [0_u16; 128];
                let raw_len = GetWindowTextW(state.edit_hwnd, buf.as_mut_ptr(), 128);
                let len = usize::try_from(raw_len).unwrap_or(0).min(buf.len());
                state.outcome = LockPromptOutcome::Attempt(String::from_utf16_lossy(&buf[..len]));
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
