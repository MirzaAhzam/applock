## What changed
-

## Requirements
- Refs:

## Test evidence
- CI run link:

## Performance (when relevant)
- Binary sizes / RAM / latency:

## Security checklist (when touching auth, IPC, service, storage, or crypto)
- [ ] No new `unsafe` outside `applock-sys`
- [ ] No secret in logs, errors, files, IPC
- [ ] Fails closed on error
- [ ] Input validated, size-limited
- [ ] `cargo deny` clean

