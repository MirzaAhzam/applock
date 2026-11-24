# ADR 0001: M0 Technical Spike Results

- **Date:** 2026-11-25
- **Status:** Measured (CI headless complete; owner visual test pending)
- **CI Run:** https://github.com/MirzaAhzam/applock/actions/runs/45498345744
- **Environment:** Microsoft Windows Server 2025 (`10.0.26100` Datacenter, x64)

## 1. Headless CI Measurements

| Metric | PRD Target | Measured | Status |
|---|---|---|---|
| `captured_runs` | ≥ 50 | 60 / 60 | PASS |
| `detect_to_frozen_p50_ms` | — | 626.72 ms | Measured |
| `detect_to_frozen_p95_ms` | ≤ 50 ms | 1038.89 ms | **FAIL (20.8x over budget)** |
| `applock-service` idle RAM | ≤ 8.00 MiB | 1.74 MiB (1,822,720 bytes) | PASS |
| `applock-agent` idle RAM | ≤ 3.00 MiB | 0.98 MiB (1,028,096 bytes) | PASS |
| Idle CPU (service + agent) | ~0% | 0.000% + 0.000% | PASS |
| `applock-service.exe` size | ≤ 2.50 MiB (2,621,440 B) | 0.21 MiB (217,088 B) | PASS |
| `applock-agent.exe` size | ≤ 1.00 MiB (1,048,576 B) | 0.18 MiB (184,320 B) | PASS |

## 2. Why `detect_to_frozen_p95_ms` Exceeded 50 ms

`Microsoft-Windows-Kernel-Process` ETW real-time sessions in user mode batch events using Windows' default real-time buffer flush timer (~1 second). As a result, process-start notifications arrive roughly 0.0–1.0 s after `CreateProcessW` returns (p50 = 626.72 ms, p95 = 1038.89 ms).

## 3. Proposed Next Step / PRD Adjustment

- **Option 1 (Measure ETW tuning):** Test `EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING` with a 4 KB `BufferSize` in a follow-up check to see if buffer flushing reduces p95 latency.
- **Option 2 (Update PRD.md section 7.1):** Acknowledge that user-mode ETW process-start detection has ~500–1000 ms p95 latency (and `SetWinEventHook` foreground detection catches the window when it appears), reserving sub-50 ms pre-window blocking for the optional v2.x kernel driver (`PRD.md` section 9 already notes this trade-off).

## 4. Visual Test Matrix (Owner PC)

Pending owner test on Windows 10/11 with `applock-test-build-4d51d98...`:
- [ ] Notepad (`notepad.exe`) — ETW freeze -> PIN `1234` resumes, Cancel terminates
- [ ] Calculator (`CalculatorApp.exe`, Store/UWP) — ETW + `SetWinEventHook` (`ApplicationFrameHost.exe` child resolution)
- [ ] Browser (`msedge.exe` / `chrome.exe` / `firefox.exe`) — new launch + already-running foreground switch
