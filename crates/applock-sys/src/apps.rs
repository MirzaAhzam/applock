//! Installed Windows application discovery, icon extraction, and `.exe` file picker (`FR-APP-01`).

use std::collections::HashMap;
use std::env;
use std::fs;
use std::mem::{size_of, zeroed};
use std::path::{Path, PathBuf};
use std::ptr;

use windows_sys::Win32::Foundation::{ERROR_NO_MORE_ITEMS, ERROR_SUCCESS, HGDIOBJ, MAX_PATH};
use windows_sys::Win32::Graphics::Gdi::{
    CreateCompatibleDC, DeleteDC, DeleteObject, GetDIBits, GetObjectW, BITMAP, BITMAPINFO,
    BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS,
};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_CURRENT_USER,
    HKEY_LOCAL_MACHINE, KEY_READ, REG_DWORD, REG_EXPAND_SZ, REG_SZ,
};
use windows_sys::Win32::UI::Controls::Dialogs::{
    GetOpenFileNameW, OFN_FILEMUSTEXIST, OFN_NOCHANGEDIR, OFN_PATHMUSTEXIST, OPENFILENAMEW,
};
use windows_sys::Win32::UI::Shell::{SHGetFileInfoW, SHFILEINFOW, SHGFI_ICON, SHGFI_LARGEICON};
use windows_sys::Win32::UI::WindowsAndMessaging::{DestroyIcon, GetIconInfo, HICON, ICONINFO};

use crate::to_wide_null;

/// An installed Windows application discovered on the machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredApp {
    /// Human-readable display name.
    pub display_name: String,
    /// Normalized identifier for `applock-service` (lowercase `.exe` name or UWP package family).
    pub app_id: String,
    /// Resolved executable path or `shell:AppsFolder` target.
    pub exe_path: String,
    /// Optional 32x32 (or native) RGBA8 icon buffer: `(width, height, pixels)`.
    pub icon_rgba: Option<(u32, u32, Vec<u8>)>,
}

/// Discovers user-facing installed applications from Registry Uninstall keys,
/// Start Menu shortcuts, and registered Store/UWP packages.
#[must_use]
pub fn enumerate_installed_apps() -> Vec<DiscoveredApp> {
    let mut by_id: HashMap<String, DiscoveredApp> = HashMap::new();

    scan_uninstall_key(
        HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        &mut by_id,
    );
    scan_uninstall_key(
        HKEY_LOCAL_MACHINE,
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        &mut by_id,
    );
    scan_uninstall_key(
        HKEY_CURRENT_USER,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        &mut by_id,
    );

    if let Ok(program_data) = env::var("ProgramData") {
        let dir = PathBuf::from(program_data).join(r"Microsoft\Windows\Start Menu\Programs");
        scan_start_menu_dir(&dir, &mut by_id);
    }
    if let Ok(app_data) = env::var("APPDATA") {
        let dir = PathBuf::from(app_data).join(r"Microsoft\Windows\Start Menu\Programs");
        scan_start_menu_dir(&dir, &mut by_id);
    }

    scan_uwp_packages(&mut by_id);

    let mut apps: Vec<DiscoveredApp> = by_id.into_values().collect();
    for app in &mut apps {
        if app.icon_rgba.is_none() && !app.exe_path.starts_with("shell:") {
            app.icon_rgba = extract_icon_rgba(&app.exe_path);
        }
    }
    apps.sort_by(|a, b| {
        a.display_name
            .to_ascii_lowercase()
            .cmp(&b.display_name.to_ascii_lowercase())
    });
    apps
}

/// Opens a native Windows file picker for `.exe` files and returns the selected path.
#[must_use]
pub fn browse_exe_dialog() -> Option<String> {
    let mut file_buf = vec![0_u16; MAX_PATH as usize * 2];
    let filter = to_wide_null("Applications (*.exe)\0*.exe\0All Files (*.*)\0*.*\0");
    let title = to_wide_null("Choose an application (.exe)");

    // SAFETY: `OPENFILENAMEW` is zero-initialized with `lStructSize` set; `lpstrFile` points
    // to `file_buf` with `nMaxFile` matching its capacity.
    unsafe {
        let mut ofn: OPENFILENAMEW = zeroed();
        ofn.lStructSize = u32::try_from(size_of::<OPENFILENAMEW>()).unwrap_or(0);
        ofn.lpstrFilter = filter.as_ptr();
        ofn.lpstrFile = file_buf.as_mut_ptr();
        ofn.nMaxFile = u32::try_from(file_buf.len()).unwrap_or(260);
        ofn.lpstrTitle = title.as_ptr();
        ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;

        if GetOpenFileNameW(&raw mut ofn) == 0 {
            return None;
        }
    }

    let end = file_buf
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(file_buf.len());
    let path = String::from_utf16_lossy(&file_buf[..end])
        .trim()
        .to_string();
    if path.is_empty() {
        None
    } else {
        Some(path)
    }
}

fn is_filtered_entry(name: &str, exe_or_id: &str) -> bool {
    let n = name.trim().to_ascii_lowercase();
    let e = exe_or_id.trim().to_ascii_lowercase();
    if n.is_empty() || e.is_empty() {
        return true;
    }
    let blocked_names = [
        "visual c++",
        "redistributable",
        ".net runtime",
        "windows sdk",
        "update for",
        "security update",
        "uninstall",
        "applock",
    ];
    if blocked_names.iter().any(|b| n.contains(b)) {
        return true;
    }
    let exe_file = Path::new(&e)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(&e);
    exe_file.starts_with("unins")
        || exe_file.contains("uninstall")
        || exe_file.starts_with("applock-")
}

fn upsert_app(map: &mut HashMap<String, DiscoveredApp>, candidate: DiscoveredApp) {
    if is_filtered_entry(&candidate.display_name, &candidate.app_id) {
        return;
    }
    let key = candidate.app_id.to_ascii_lowercase();
    match map.get_mut(&key) {
        Some(existing) => {
            if existing.exe_path.starts_with("shell:") && !candidate.exe_path.starts_with("shell:")
            {
                existing.exe_path = candidate.exe_path;
            }
            if existing.icon_rgba.is_none() && candidate.icon_rgba.is_some() {
                existing.icon_rgba = candidate.icon_rgba;
            }
        }
        None => {
            map.insert(key, candidate);
        }
    }
}

fn scan_uninstall_key(root: HKEY, subkey: &str, out: &mut HashMap<String, DiscoveredApp>) {
    let subkey_w = to_wide_null(subkey);
    let mut hkey: HKEY = ptr::null_mut();

    // SAFETY: `subkey_w` is null-terminated; `hkey` is closed before returning.
    let status = unsafe { RegOpenKeyExW(root, subkey_w.as_ptr(), 0, KEY_READ, &raw mut hkey) };
    if status != ERROR_SUCCESS {
        return;
    }

    let mut idx: u32 = 0;
    loop {
        let mut name_buf = [0_u16; 256];
        let mut name_len = u32::try_from(name_buf.len()).unwrap_or(256);
        // SAFETY: `hkey` is open; `name_buf` is valid stack storage.
        let enum_status = unsafe {
            RegEnumKeyExW(
                hkey,
                idx,
                name_buf.as_mut_ptr(),
                &raw mut name_len,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if enum_status == ERROR_NO_MORE_ITEMS || enum_status != ERROR_SUCCESS {
            break;
        }
        idx = idx.saturating_add(1);

        let child_name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
        let child_path = format!(r"{subkey}\{child_name}");
        if let Some(app) = read_uninstall_entry(root, &child_path) {
            upsert_app(out, app);
        }
    }

    // SAFETY: `hkey` is valid.
    unsafe {
        let _ = RegCloseKey(hkey);
    }
}

fn read_uninstall_entry(root: HKEY, subkey: &str) -> Option<DiscoveredApp> {
    let subkey_w = to_wide_null(subkey);
    let mut hkey: HKEY = ptr::null_mut();
    // SAFETY: `subkey_w` is null-terminated; `hkey` is closed before returning.
    if unsafe { RegOpenKeyExW(root, subkey_w.as_ptr(), 0, KEY_READ, &raw mut hkey) }
        != ERROR_SUCCESS
    {
        return None;
    }

    let sys_comp = query_reg_dword(hkey, "SystemComponent").unwrap_or(0);
    let display_name = query_reg_string(hkey, "DisplayName");
    let display_icon = query_reg_string(hkey, "DisplayIcon");
    let install_loc = query_reg_string(hkey, "InstallLocation");

    // SAFETY: `hkey` is valid.
    unsafe {
        let _ = RegCloseKey(hkey);
    }

    if sys_comp == 1 {
        return None;
    }
    let name = display_name?;
    let exe_path = resolve_exe_from_uninstall(display_icon.as_deref(), install_loc.as_deref())?;
    let app_id = Path::new(&exe_path)
        .file_name()
        .and_then(|s| s.to_str())?
        .to_ascii_lowercase();

    Some(DiscoveredApp {
        display_name: name,
        app_id,
        exe_path,
        icon_rgba: None,
    })
}

fn resolve_exe_from_uninstall(
    display_icon: Option<&str>,
    install_loc: Option<&str>,
) -> Option<String> {
    if let Some(raw_icon) = display_icon {
        let cleaned = raw_icon
            .trim()
            .trim_matches('"')
            .split(',')
            .next()
            .unwrap_or("")
            .trim()
            .trim_matches('"');
        if cleaned.to_ascii_lowercase().ends_with(".exe") && Path::new(cleaned).exists() {
            return Some(cleaned.to_string());
        }
    }
    if let Some(loc) = install_loc {
        let dir = Path::new(loc.trim().trim_matches('"'));
        if dir.is_dir() {
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.extension()
                        .and_then(|e| e.to_str())
                        .is_some_and(|e| e.eq_ignore_ascii_case("exe"))
                    {
                        let fname = p
                            .file_name()
                            .and_then(|s| s.to_str())
                            .unwrap_or("")
                            .to_ascii_lowercase();
                        if !fname.starts_with("unins") && !fname.contains("setup") {
                            return Some(p.to_string_lossy().into_owned());
                        }
                    }
                }
            }
        }
    }
    None
}

fn scan_start_menu_dir(dir: &Path, out: &mut HashMap<String, DiscoveredApp>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            scan_start_menu_dir(&path, out);
            continue;
        }
        if !path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("lnk"))
        {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        if let Some(target_exe) = extract_lnk_exe_target(&path) {
            let app_id = Path::new(&target_exe)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            let icon = extract_icon_rgba(&path.to_string_lossy())
                .or_else(|| extract_icon_rgba(&target_exe));
            upsert_app(
                out,
                DiscoveredApp {
                    display_name: stem.to_string(),
                    app_id,
                    exe_path: target_exe,
                    icon_rgba: icon,
                },
            );
        }
    }
}

/// Extracts an `.exe` path from a Windows `.lnk` binary file (`MS-SHLLINK`) if present.
fn extract_lnk_exe_target(lnk_path: &Path) -> Option<String> {
    let bytes = fs::read(lnk_path).ok()?;
    if bytes.len() < 76 || bytes[0..4] != [0x4C, 0x00, 0x00, 0x00] {
        return None;
    }
    // Scan ASCII and UTF-16LE strings inside the shortcut payload for an existing `.exe` path.
    let ascii = String::from_utf8_lossy(&bytes);
    for token in ascii.split('\0') {
        if let Some(candidate) = find_exe_path_in_text(token) {
            return Some(candidate);
        }
    }
    let u16_words: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let utf16 = String::from_utf16_lossy(&u16_words);
    for token in utf16.split('\0') {
        if let Some(candidate) = find_exe_path_in_text(token) {
            return Some(candidate);
        }
    }
    None
}

fn find_exe_path_in_text(text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    let end = lower.find(".exe")? + 4;
    let prefix = &text[..end];
    let start = prefix.rfind(":\\").map(|i| i.saturating_sub(1))?;
    let candidate = prefix.get(start..)?.trim();
    if Path::new(candidate).exists() {
        Some(candidate.to_string())
    } else {
        None
    }
}

fn scan_uwp_packages(out: &mut HashMap<String, DiscoveredApp>) {
    let subkey = r"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages";
    let subkey_w = to_wide_null(subkey);
    let mut hkey: HKEY = ptr::null_mut();
    // SAFETY: `subkey_w` is null-terminated; `hkey` is closed before returning.
    if unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            subkey_w.as_ptr(),
            0,
            KEY_READ,
            &raw mut hkey,
        )
    } != ERROR_SUCCESS
    {
        return;
    }

    let mut idx: u32 = 0;
    loop {
        let mut name_buf = [0_u16; 256];
        let mut name_len = u32::try_from(name_buf.len()).unwrap_or(256);
        // SAFETY: `hkey` is open; `name_buf` is valid stack storage.
        let enum_status = unsafe {
            RegEnumKeyExW(
                hkey,
                idx,
                name_buf.as_mut_ptr(),
                &raw mut name_len,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if enum_status == ERROR_NO_MORE_ITEMS || enum_status != ERROR_SUCCESS {
            break;
        }
        idx = idx.saturating_add(1);

        let pkg_full = String::from_utf16_lossy(&name_buf[..name_len as usize]);
        let child_subkey = format!(r"{subkey}\{pkg_full}");
        let child_w = to_wide_null(&child_subkey);
        let mut child_key: HKEY = ptr::null_mut();
        // SAFETY: `child_w` is null-terminated; `child_key` is closed right after querying.
        if unsafe {
            RegOpenKeyExW(
                HKEY_CURRENT_USER,
                child_w.as_ptr(),
                0,
                KEY_READ,
                &raw mut child_key,
            )
        } == ERROR_SUCCESS
        {
            let disp = query_reg_string(child_key, "DisplayName");
            let pfn = query_reg_string(child_key, "PackageID");
            unsafe {
                let _ = RegCloseKey(child_key);
            }
            if let (Some(name), Some(id)) = (disp, pfn) {
                if !name.starts_with("ms-resource:") {
                    let family = id.split('_').next().unwrap_or(&id).to_ascii_lowercase();
                    upsert_app(
                        out,
                        DiscoveredApp {
                            display_name: name,
                            app_id: family.clone(),
                            exe_path: format!("shell:AppsFolder\\{family}"),
                            icon_rgba: None,
                        },
                    );
                }
            }
        }
    }

    // SAFETY: `hkey` is valid.
    unsafe {
        let _ = RegCloseKey(hkey);
    }
}

fn query_reg_dword(hkey: HKEY, name: &str) -> Option<u32> {
    let name_w = to_wide_null(name);
    let mut reg_type: u32 = 0;
    let mut val: u32 = 0;
    let mut size: u32 = u32::try_from(size_of::<u32>()).unwrap_or(4);
    // SAFETY: `hkey` is open; `val` and `size` are valid stack pointers.
    let status = unsafe {
        RegQueryValueExW(
            hkey,
            name_w.as_ptr(),
            ptr::null(),
            &raw mut reg_type,
            (&raw mut val).cast::<u8>(),
            &raw mut size,
        )
    };
    if status == ERROR_SUCCESS && reg_type == REG_DWORD {
        Some(val)
    } else {
        None
    }
}

fn query_reg_string(hkey: HKEY, name: &str) -> Option<String> {
    let name_w = to_wide_null(name);
    let mut reg_type: u32 = 0;
    let mut size: u32 = 0;
    // SAFETY: First call queries required buffer byte length.
    let probe = unsafe {
        RegQueryValueExW(
            hkey,
            name_w.as_ptr(),
            ptr::null(),
            &raw mut reg_type,
            ptr::null_mut(),
            &raw mut size,
        )
    };
    if probe != ERROR_SUCCESS || size == 0 || (reg_type != REG_SZ && reg_type != REG_EXPAND_SZ) {
        return None;
    }
    let words = usize::try_from(size).unwrap_or(0) / 2;
    let mut buf = vec![0_u16; words.max(1)];
    // SAFETY: `buf` is sized to `size` bytes.
    let status = unsafe {
        RegQueryValueExW(
            hkey,
            name_w.as_ptr(),
            ptr::null(),
            &raw mut reg_type,
            buf.as_mut_ptr().cast::<u8>(),
            &raw mut size,
        )
    };
    if status != ERROR_SUCCESS {
        return None;
    }
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    let s = String::from_utf16_lossy(&buf[..end]).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Extracts a 32-bit RGBA icon buffer from an `.exe` or `.lnk` path using `SHGetFileInfoW`.
#[must_use]
pub fn extract_icon_rgba(path: &str) -> Option<(u32, u32, Vec<u8>)> {
    let path_w = to_wide_null(path);
    // SAFETY: `shfi` is zeroed; `hIcon` is destroyed via `DestroyIcon` before returning.
    unsafe {
        let mut shfi: SHFILEINFOW = zeroed();
        let res = SHGetFileInfoW(
            path_w.as_ptr(),
            0,
            &raw mut shfi,
            u32::try_from(size_of::<SHFILEINFOW>()).unwrap_or(0),
            SHGFI_ICON | SHGFI_LARGEICON,
        );
        if res == 0 || shfi.hIcon.is_null() {
            return None;
        }
        let rgba = hicon_to_rgba(shfi.hIcon);
        let _ = DestroyIcon(shfi.hIcon);
        rgba
    }
}

unsafe fn hicon_to_rgba(hicon: HICON) -> Option<(u32, u32, Vec<u8>)> {
    let mut info: ICONINFO = zeroed();
    if GetIconInfo(hicon, &raw mut info) == 0 {
        return None;
    }

    let target_bmp = if info.hbmColor.is_null() {
        info.hbmMask
    } else {
        info.hbmColor
    };
    let mut bmp: BITMAP = zeroed();
    let got = GetObjectW(
        target_bmp as HGDIOBJ,
        i32::try_from(size_of::<BITMAP>()).unwrap_or(0),
        (&raw mut bmp).cast(),
    );
    if got == 0 || bmp.bmWidth <= 0 || bmp.bmHeight <= 0 {
        if !info.hbmColor.is_null() {
            let _ = DeleteObject(info.hbmColor as HGDIOBJ);
        }
        if !info.hbmMask.is_null() {
            let _ = DeleteObject(info.hbmMask as HGDIOBJ);
        }
        return None;
    }

    let w = u32::try_from(bmp.bmWidth).ok()?;
    let h = u32::try_from(bmp.bmHeight).ok()?;
    let mut pixels = vec![0_u8; usize::try_from(w.saturating_mul(h).saturating_mul(4)).ok()?];

    let mut bmi: BITMAPINFO = zeroed();
    bmi.bmiHeader = BITMAPINFOHEADER {
        biSize: u32::try_from(size_of::<BITMAPINFOHEADER>()).unwrap_or(40),
        biWidth: bmp.bmWidth,
        biHeight: -bmp.bmHeight, // top-down
        biPlanes: 1,
        biBitCount: 32,
        biCompression: BI_RGB,
        ..zeroed()
    };

    let hdc = CreateCompatibleDC(ptr::null_mut());
    let lines = if hdc.is_null() {
        0
    } else {
        GetDIBits(
            hdc,
            target_bmp,
            0,
            h,
            pixels.as_mut_ptr().cast(),
            &raw mut bmi,
            DIB_RGB_COLORS,
        )
    };
    if !hdc.is_null() {
        let _ = DeleteDC(hdc);
    }
    if !info.hbmColor.is_null() {
        let _ = DeleteObject(info.hbmColor as HGDIOBJ);
    }
    if !info.hbmMask.is_null() {
        let _ = DeleteObject(info.hbmMask as HGDIOBJ);
    }

    if lines == 0 {
        return None;
    }

    // Convert BGRA (Windows DIB) to RGBA (Slint).
    for chunk in pixels.chunks_exact_mut(4) {
        chunk.swap(0, 2);
    }
    Some((w, h, pixels))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_out_uninstallers_and_runtimes() {
        assert!(is_filtered_entry(
            "Microsoft Visual C++ 2022 Redistributable",
            "vc.exe"
        ));
        assert!(is_filtered_entry(
            "My App",
            r"C:\Program Files\MyApp\unins000.exe"
        ));
        assert!(is_filtered_entry("AppLock", "applock-service.exe"));
        assert!(!is_filtered_entry(
            "Notepad",
            r"C:\Windows\System32\notepad.exe"
        ));
    }

    #[test]
    fn deduplicates_by_app_id_and_prefers_real_exe_path() {
        let mut map = HashMap::new();
        upsert_app(
            &mut map,
            DiscoveredApp {
                display_name: "Calculator".to_string(),
                app_id: "calc.exe".to_string(),
                exe_path: "shell:AppsFolder\\calc.exe".to_string(),
                icon_rgba: None,
            },
        );
        upsert_app(
            &mut map,
            DiscoveredApp {
                display_name: "Calculator".to_string(),
                app_id: "calc.exe".to_string(),
                exe_path: r"C:\Windows\System32\calc.exe".to_string(),
                icon_rgba: Some((1, 1, vec![255, 255, 255, 255])),
            },
        );
        assert_eq!(map.len(), 1);
        let entry = map.get("calc.exe");
        assert!(entry.is_some());
        if let Some(app) = entry {
            assert_eq!(app.exe_path, r"C:\Windows\System32\calc.exe");
            assert!(app.icon_rgba.is_some());
        }
    }

    #[test]
    fn enumerate_installed_apps_runs_cleanly() {
        let apps = enumerate_installed_apps();
        // On Windows CI runners, at least a few built-in apps/packages exist.
        assert!(!apps.is_empty());
    }
}
