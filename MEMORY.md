# AppLock for Windows — Persistent Memory

## Owner Preferences & Rules
- Product owner is **non-technical**. Always reply in plain, simple language (English or Roman Urdu, matching the owner's message) and keep updates **short and straightforward** unless asked for details.
- Explain any technical term in one sentence.
- **Remote-Build Mode:** owner's PC has very little free disk space. Never run `cargo` or install toolchains locally. All builds, tests, clippy, fmt, `cargo deny`, and headless benchmarks run on GitHub Actions.
- Repository `MirzaAhzam/applock` is intentionally **Public** (do not suggest making it private).
- `antislop` is installed in `.agents/skills/` and `%APPDATA%\antislop\settings.json` is set to `{"mode": "during"}`.
- Required reading order every session: `AGENTS.md` > `PRD.md` > `PROJECT_STRUCTURE.md` > `DESIGN.md` > `CONTEXT.md` > `MEMORY.md`.

## Measured M0 Baseline (CI Run #45498638927 / #45498345744)
- **OS:** Microsoft Windows Server 2025 (`10.0.26100` Datacenter, x64)
- **ETW `detect_to_frozen` (60/60 `cmd.exe` launches):** `p50 = 626.72 ms`, `p95 = 1038.89 ms` (exceeds 50 ms target due to default ~1 s Windows ETW real-time buffer flush).
- **Idle RAM:** `applock-service` = `1.74 MiB` (limit 8 MiB), `applock-agent` = `0.98 MiB` (limit 3 MiB).
- **Idle CPU:** `0.000%` for both service and agent.
- **Release binary sizes:** `applock-service.exe` = `217,088 B` (limit 2.5 MiB), `applock-agent.exe` = `184,320 B` (limit 1.0 MiB).
- **Owner PC visual test:** Confirmed `applock-service.exe` (run from elevated PowerShell via `& "path"`) freezes and unlocks/terminates apps; owner noted frozen window content remains visible behind the small M0 dialog (must hide/minimize + dim screen in M2).

## Technical Gotchas Learned
1. **PowerShell 5.1:** Does not support `&&`; use `;` or separate statements.
2. **Drag-and-drop to Admin PowerShell:** Blocked by Windows UIPI from non-admin Explorer; instruct owner to use **Copy as path** + `& <paste>`.
3. **PowerShell exit codes in CI:** `cmd 2>&1 | Out-String` overwrites `$LASTEXITCODE` if not captured immediately after the command. Always save `$exit = $LASTEXITCODE` on the next line.
4. **Line endings & `edit_file`:** `edit_file` on Windows can leave an extra trailing `\n`, failing `cargo fmt --check`. Always trim trailing newlines to a single `\n` before committing `.rs` files.
5. **`rustfmt` import order:** Sorts `snake_case` items before `UpperCamelCase` / `SCREAMING_SNAKE_CASE` items.
6. **`windows-sys` 0.61.2:**
   - `OpenTraceW` and `EVENT_TRACE_LOGFILEW` require feature `Win32_System_Time`.
   - `CreateProcessW` requires feature `Win32_Security`.
   - `SetFocus` requires feature `Win32_UI_Input_KeyboardAndMouse`.
   - `BOOL` is in `windows_sys::core::BOOL`.
   - `StartTraceW` / `EnableTraceEx2` / `ControlTraceW` use `CONTROLTRACE_HANDLE { Value: ... }`, not `u64`.
   - `EnableTraceEx2` rejects zeroed `ENABLE_TRACE_PARAMETERS` (`0x57 ERROR_INVALID_PARAMETER`); pass `ptr::null()`.
   - `EVENT_TRACE_PROPERTIES` buffers must be 8-byte aligned (`Vec<u64>`), not `Vec<u8>`, to satisfy `clippy::cast_ptr_alignment`.
7. **`cargo-deny`:** Use `allow-wildcard-paths = true` under `[bans]` in `deny.toml` for workspace path dependencies without `version`.
8. **Rust 1.85.0:** `i32::cast_unsigned` is unstable; use `u32::from_ne_bytes(status.to_ne_bytes())`.
