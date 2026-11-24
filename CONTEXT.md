# AppLock for Windows — Session Context

Last updated: 2026-11-25

## 1. Current State
- **Repository:** `https://github.com/MirzaAhzam/applock` (Public)
- **Completed:**
  - **M1 Minimal Foundation** (6 crates: `applock-core`, `applock-ipc`, `applock-sys`, `applock-service`, `applock-agent`, `xtask`, root configs, CI/release/security workflows, `Cargo.lock`).
  - **M0 Technical Spike** (merged to `main` via PR #2): ETW process-start detection, `NtSuspendProcess` / `NtResumeProcess` / `TerminateProcess`, `SetWinEventHook` foreground watcher with UWP `ApplicationFrameHost.exe` child resolution, minimal Win32 lock window, 60-launch CI benchmark, and owner PC visual test confirmed working.
- **Open PR:**
  - **PR #3** (`fix/release-sha`): fixes the truncated `release-please-action` commit SHA in `.github/workflows/release.yml`. All CI checks (`checks`, `pr-title`, `supply-chain`) are green and ready to squash-merge.
- **Owner Action Pending:**
  - Add `RELEASE_BOT_TOKEN` in **Repository secrets** (`Settings > Secrets and variables > Actions`) so `release-please` can open and auto-merge release PRs.
  - Decide on ETW latency (`PRD.md` 7.1): tune ETW buffer settings or update `PRD.md` 7.1 for user-mode ETW reality (~500–1000 ms p95).

## 2. Operating Mode: Remote-Build Mode
- **FORBIDDEN on owner's PC:** running `cargo build/test/clippy/check/bench/xtask`, installing Rust/VS/Build Tools/Windows SDK, creating a `target/` folder, or downloading anything over 200 MB.
- **ALLOWED locally:** editor, `git`, `gh` CLI.
- **Workflow:** every change goes on a `feat/...`, `fix/...`, `chore/...`, or `docs/...` branch -> `git push` -> `gh run watch` -> read logs on failure -> open PR -> squash merge on green CI.
- **Visual tests:** feature branches upload `target/release/*.exe` as artifact `applock-test-build-<sha>` (3-day retention).

## 3. Next Steps (Tomorrow)
1. Merge PR #3 (`fix/release-sha`) and verify `release.yml` runs cleanly.
2. **Privacy fix from M0 visual test:** Owner noticed a frozen app's window is still visible/readable behind the small M0 prompt. Fix in M2/Lock UI:
   - Hide/minimize the target app's window(s) immediately when frozen (and restore on unlock).
   - Render the 55% black full-screen dim overlay behind the centered lock card (`DESIGN.md` section 5.1) so nothing behind it is readable.
3. **M2 MVP & Installer:**
   - Implement `applock-ipc` (versioned binary protocol, size limit, nonce, client PID/path/signature check) and `applock-core` (Argon2id hashing, DPAPI config, lockout state machine, rules engine).
   - Add `applock-lockui`, `applock-manager`, `applock-i18n` (`locales/en.toml`, `locales/ur.toml` RTL), following `DESIGN.md` and `antislop` Delivery Gate.
   - Implement `xtask package` + `installer/applock.iss` (Inno Setup) + Windows service installation (SYSTEM, restrictive ACL, SCM recovery).
4. **Update `docs/decisions/0001-m0-spike-results.md`** with the owner's Windows version and visual test checkmarks once confirmed.
