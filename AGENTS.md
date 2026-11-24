# AGENTS.md: Rules for every AI agent working on AppLock

Read this file completely at the start of **every** session. These rules override your defaults. If a rule conflicts with a user request, explain the conflict and ask; do not silently break the rule.

Read order: `AGENTS.md` (this file) > `PRD.md` > `PROJECT_STRUCTURE.md` > `DESIGN.md`.

---

## 0. Prime directives

Priority order when goals conflict:

1. **Security**: never weaken it for speed, size or convenience.
2. **Correctness**: it must do what the PRD says.
3. **Lightweight and speed**: budgets in `PRD.md` section 7.1 are hard limits.
4. **User experience**: follows `DESIGN.md`.
5. **Delivery speed**: last.

Core beliefs:
- The product owner is **non-technical**. Explain decisions in plain language, in the language the owner writes in (English or Roman Urdu). Never hide behind jargon. When you must use a technical word, explain it in one sentence.
- Do not guess. If the PRD does not say, ask or write an ADR proposal. Never invent requirements, numbers, APIs or crate names. Verify an API or crate exists and check its current docs before using it.
- Small, verified steps. One logical change at a time. Run the checks before saying "done".
- Honesty over comfort. If something does not meet a budget or has a security limit, say so plainly.

---

## 1. How to work (every task)

1. **Restate** the task in one or two sentences and name the PRD requirement ID(s) (e.g. `FR-APP-03`).
2. **Plan** in a short list: files to touch, tests to add, risks. For anything touching security, IPC, crypto or performance, wait for the owner's OK on the plan.
3. **Implement** the smallest change that satisfies the requirement.
4. **Test**: add or update tests; run the full check list (section 9).
5. **Measure** if the change can affect size, RAM, CPU or latency (section 3). Report numbers before and after.
6. **Report** using this format:

```
What changed:      (plain language)
Requirement(s):    FR-...
Files:             (list)
Tests:             (added/updated, result)
Performance:       (before -> after, or "not affected, because ...")
Security notes:    (new risks, or "none")
Needs owner:       (decisions or actions, or "nothing")
```

Never claim something works without running it. Never say "should work". Say what you ran and what it printed.

---

## 2. Security rules

### 2.1 Architecture rules
- **Privilege separation is law:** only `applock-service` runs as SYSTEM. Agent, lock UI and Manager run as the normal user. Never move logic into the service just because it is convenient.
- **The service is the only judge.** UI processes send requests and receive yes/no. They never receive hashes, keys, or the locked-app rules beyond what they must display.
- **Fail closed.** On any error, crash, timeout, corrupt config or malformed message: the app stays blocked. Never "allow on error".
- **Defense in depth:** do not rely on one check where two cheap ones are possible.

### 2.2 Secrets and crypto
- Passwords and PINs: **Argon2id** only, per-install random salt, parameters stored with the hash. No MD5, SHA-1, SHA-256-for-passwords, bcrypt, or home-made schemes.
- Compare secrets in **constant time** (`subtle`).
- Randomness only from the OS CSPRNG (`getrandom` / `rand::rngs::OsRng`).
- Encrypt data at rest with vetted crates (`chacha20poly1305`, `aes-gcm`) or Windows DPAPI. **Never write your own crypto.**
- Secret buffers: use `zeroize` / `secrecy` types; never `Clone`/`Debug`/`Display` a secret; never put a secret in a `String` that lives longer than needed.
- **Never** log, print, serialize to disk, or send over IPC a plaintext password, PIN, recovery code, token or key.
- No secrets in source, tests, fixtures, commit history, CI logs or error messages. If a secret is committed by accident: stop, tell the owner, rotate it. Do not just delete it in a new commit.

### 2.3 Rust safety
- `#![forbid(unsafe_code)]` in every crate **except** `applock-sys` (and `applock-shellext` in v2). `unsafe` lives only there, in small functions with a `// SAFETY:` comment stating the invariant, plus a test.
- No `unwrap()`, `expect()`, `panic!`, `todo!`, `unimplemented!`, array indexing that can panic, or unchecked arithmetic in non-test code (clippy denies these; do not `#[allow]` them without an ADR).
- Release profile keeps `overflow-checks = true`.
- All errors are handled and typed (`thiserror` in libraries). Error messages shown to users never reveal internals.

### 2.4 IPC and input
- Treat **every** byte from another process, file, registry, network or user as hostile.
- Messages have: a version, a maximum size, a strict parser, a per-request nonce, and a timeout. Reject unknown versions and fields.
- The service verifies the client (process id, image path, Authenticode signature) on every connection.
- Every parser has a fuzz target in `tests/security/`.
- Pipe and file ACLs are explicit and minimal. Never use "Everyone" or a NULL DACL.

### 2.5 Network and privacy
- **No network access** except: OAuth recovery (user-initiated, system browser, PKCE, loopback redirect) and the opt-in update check. Anything else needs an ADR and owner approval.
- No telemetry, analytics, crash uploaders or "phone home". Ever.
- Intruder photos are opt-in, local, deletable. Never uploaded.

### 2.6 Supply chain
- `cargo deny` (advisories, licenses, bans, sources) must pass.
- Dependencies come only from crates.io. No git dependencies, no build scripts that download things, no proc-macros from unknown authors.
- Prefer well-known, maintained crates. Check download counts, last release date, and open advisories before adding one.
- GitHub Actions: pinned to full commit SHA, minimal `permissions`, no `pull_request_target` with untrusted code, secrets never echoed.
- Releases are signed (when a certificate exists), checksummed, and carry a provenance attestation.

### 2.7 Windows specifics
- Service: restrictive security descriptor, SCM recovery actions on, no accepting of the stop control for standard users.
- Config under `%ProgramData%\AppLock\` with an explicit ACL (SYSTEM and Administrators).
- Never disable or work around Windows security features, Defender, UAC or SmartScreen. Never hide or obfuscate the program. Antivirus false positives are solved with signing and submissions, not tricks.
- Be honest in UI and docs about what AppLock cannot do (PRD section 9).

### 2.8 Security review checklist (tick for every PR that touches auth, IPC, service, storage, or crypto)
- [ ] No new `unsafe` outside `applock-sys`
- [ ] No secret in logs, errors, files, IPC
- [ ] Fails closed on error
- [ ] Input validated, size-limited
- [ ] New or changed IPC message has a fuzz target and a spoofing test
- [ ] Tests for the abuse case, not just the happy path
- [ ] `cargo deny` clean

---

## 3. Optimization and lightweight rules

The product's promise is **zero lag and tiny footprint**. Budgets (hard limits, see `PRD.md` section 7.1 and `tests/perf/budgets.toml`):

| Metric | Limit |
|---|---|
| Idle CPU | ~0% |
| Service RAM idle | ≤ 8 MB |
| Agent RAM idle | ≤ 3 MB |
| Lock UI cold start to first frame | ≤ 150 ms |
| Detect to frozen (p95) | ≤ 50 ms |
| Binary sizes | service ≤ 2.5 MB, agent ≤ 1 MB, lockui ≤ 6 MB, manager ≤ 8 MB |
| Installer | ≤ 10 MB |

### 3.1 Rules
1. **Event-driven only.** No polling loops, no `sleep`-in-a-loop checks, no timers that wake the CPU without a reason. Use ETW, WinEvent hooks, SCM notifications, and waitable handles.
2. **No async runtime** (tokio, async-std) in `service` or `agent` unless an ADR proves it is needed and fits the budget. Use blocking I/O on a few OS threads or overlapped I/O.
3. **Decision path = in-memory lookup.** No disk, registry, or network access in the hot path (process start to freeze). Config is cached in memory and reloaded only on change notification.
4. **UI processes are not resident** (lock UI, Manager). They start on demand and exit when done. Only the service and the tiny agent stay running.
5. **Allocate little.** No per-event heap churn in the hot path; reuse buffers; avoid `String` formatting in hot paths; no logging at debug level in release hot paths.
6. **Dependencies are a cost.** Before adding a crate:
   - Can std or the `windows` crate do it in under ~50 lines? Then do that.
   - Check what it pulls in (`cargo tree`), its size impact (`cargo bloat`), and compile-time features. Turn off default features; enable only what you need.
   - Record the size delta in the PR.
7. **`windows` crate: enable only the features used.** Do not enable umbrella features.
8. **Release profile** (LTO, `codegen-units = 1`, `panic = "abort"`, `strip`) stays on. Compare `opt-level` `"s"`, `"z"`, `3` per binary and keep the one that meets budgets.
9. **UI:** Slint with the software renderer for the lock screen (fast start, no GPU init). No web views, no Electron, no embedded browsers, no bundled fonts unless justified, no animation that costs frames.
10. **Never optimize without measuring.** Measure first, change, measure again. Put the numbers in the PR. If a change breaks a budget, it does not merge; fix it or propose a PRD change with evidence.
11. **Measure with:** `cargo xtask bench`, `cargo bloat --release --crates`, Windows Performance Recorder / ETW traces for latency, Task Manager "private working set" and `Get-Process` for RAM.
12. **Regressions are bugs.** A change that raises idle CPU above ~0%, RAM above budget, or latency above budget is a `fix`-level issue even if all tests pass.

---

## 4. Rust code rules

- Toolchain pinned in `rust-toolchain.toml`. Do not change it inside a feature PR.
- `cargo fmt` clean. `cargo clippy --workspace --all-targets -- -D warnings` clean.
- Small functions, small modules, clear names. One responsibility per module.
- Public items documented. Comments explain **why**, not what. No comment that restates the code (antislop-code applies).
- Tests: unit tests next to code; integration tests in `tests/integration`; abuse and fuzz tests in `tests/security`.
- Time-based logic (grace, schedule, lockout) takes an injected clock so it is testable.
- No `println!` in release code paths; use a tiny structured logger with levels and **no secrets**.
- No dead code, no commented-out code, no `TODO` without an issue number.
- Do not add features that are not in the PRD. If you see a good idea, write it as a suggestion in the report; do not build it.

---

## 5. UI, design and copy rules (anti-slop)

UI direction lives in `DESIGN.md`. The anti-slop rulebook (https://github.com/miqdadbadjuber/anti-slop) is the **filter** that stops generic, AI-looking UI, text and code. It does not invent direction; `DESIGN.md` does. Both are mandatory.

### 5.1 Setup (once, by the owner or the first agent session)
```
npx antislop-ai
```
Choose the skills: **antislop** (core), **antislop-ui**, **antislop-human**, **antislop-copywriting**, **antislop-code**. Install for **this project**, and pick the agent(s) in use. Let the installer write its pointer block into this file. To skip the "during or after" question every session: `npx antislop-ai --mode during`. To update later: `npx antislop-ai --update` (in its own PR).

`antislop-layoutmobile` is for phone and responsive web layouts. AppLock is a desktop app, so skip it, but still handle window resizing, high DPI and multi-monitor correctly.

### 5.2 Rules for UI work
1. **Read `DESIGN.md` before touching any UI.** If it is missing or contradicts the task, stop and ask. Without it, anything you build is a draft without direction.
2. Use design tokens from `ui/tokens.slint`. No hard-coded colors, sizes, or fonts inside components.
3. Run the antislop skills and finish with its **Delivery Gate PASS/FAIL report**. Include that report in the PR description. A FAIL blocks the merge.
4. Apply `antislop-human` for every screen: contrast (WCAG AA), full keyboard navigation, visible focus, all states (default, hover, focus, active, disabled, error, loading, empty), clear affordances, screen-reader names.
5. **No invented content:** no fake statistics, fake testimonials, fake security claims, placeholder lorem ipsum, or marketing hype. Every number on screen is real.
6. **No decorative slop:** no sparkle icons, gradient blobs, glassmorphism glow, emoji as icons, pill badges that say "AI" or "NEW", stock illustrations, or "powered by" fluff. Every visual element must earn its place.
7. **Copy** follows `antislop-copywriting` and the tone in `DESIGN.md`: plain sentences, say what happens, no exclamation marks, no hype.
8. **Both languages:** every string exists in `locales/en.toml` and `locales/ur.toml`. Layout works in RTL. Test both before merging.
9. **Performance applies to UI:** no animation longer than ~120 ms, no per-frame allocation, honor reduced-motion.
10. **Honesty in UI:** "Quick Lock" is labelled as convenience; limits of protection are stated in plain words.

---

## 6. Project folder management

- **`PROJECT_STRUCTURE.md` is the map.** Put every file where that file says. If a new location is needed, update `PROJECT_STRUCTURE.md` in the same PR.
- One crate, one responsibility. Respect the dependency direction in `PROJECT_STRUCTURE.md` section 2. Never create a circular dependency.
- `unsafe` only in `applock-sys` (and `applock-shellext`).
- New top-level folders, new crates, or renamed crates need an ADR in `docs/decisions/` and owner approval.
- Do not create stray files: no `temp/`, `old/`, `backup/`, `final_v2/`, `copy of ...`. Git is the history.
- Never commit: `target/`, `dist/`, `*.pdb`, certificates, keys, `.env`, local logs, benchmark outputs, IDE junk.
- Keep the repo clean: delete files you no longer need in the same PR that makes them unused.
- Keep docs in sync: a PR that changes behavior updates `PRD.md` (if requirements change), `docs/`, and user-visible strings.
- Naming conventions: `PROJECT_STRUCTURE.md` section 4.
- Large binary files (over 500 KB) need justification. Prefer vector or generated assets.

---

## 7. Git rules

### 7.1 Workflow
- **Trunk-based.** `main` is always releasable. Never commit directly to `main`.
- Work on short-lived branches: `feat/<name>`, `fix/<name>`, `chore/<name>`, `docs/<name>`, `ci/<name>`, `perf/<name>`, `refactor/<name>`.
- **One branch = one logical change = one PR.** Do not mix a feature and an unrelated fix. Do not do drive-by refactors.
- Keep PRs small (aim under ~400 changed lines). Split big work into steps that each build and pass tests.
- Merge with **squash merge only**; the PR title becomes the commit on `main`.
- Never `git push --force` to `main`. Never rewrite published history. Force-push is allowed only on your own unmerged branch.
- Never skip hooks or checks (`--no-verify`). Never disable a failing test to get green; fix it or ask.
- Before starting: `git pull --rebase` on `main`. Before opening a PR: rebase on latest `main`.

### 7.2 Conventional Commits (this drives the version number)

Format: `type(scope): short imperative summary`

| Type | Meaning | Version bump | Creates a release |
|---|---|---|---|
| `feat` | New user-visible feature | **minor** | Yes |
| `fix` | Bug fix | **patch** | Yes |
| `perf` | Performance improvement | patch | Yes |
| `security` (use `fix(security): ...`) | Security fix | patch | Yes, mark as security in notes |
| `feat!` / `fix!` or `BREAKING CHANGE:` footer | Breaking change (config format, IPC protocol) | **major** (minor before 1.0) | Yes |
| `refactor`, `docs`, `test`, `chore`, `ci`, `build`, `style` | No user-visible change | none | No |

Scopes: `service`, `agent`, `lockui`, `manager`, `core`, `ipc`, `sys`, `i18n`, `vault`, `shellext`, `installer`, `ci`, `deps`, `docs`.

Examples:
```
feat(core): add per-app grace period
fix(service): keep lockout counter across reboot
perf(lockui): start window before loading icons
feat(manager)!: change config format to v2
```

Rules:
- Summary under 72 characters, imperative mood, no trailing period.
- The body explains **why**, and links the PRD requirement: `Refs: FR-APP-05`.
- **Every PR title must be a valid Conventional Commit.** CI enforces it.
- A PR that adds a feature or fixes a bug **must** use `feat` or `fix` so that it creates a release. Do not label a user-visible change as `chore` to dodge a release.
- Breaking changes must include a migration note and a config version bump with an automatic migration.

### 7.3 Pull request rules
Use `.github/PULL_REQUEST_TEMPLATE.md`. Every PR includes: what and why, requirement IDs, test evidence, performance numbers (when relevant), the security checklist (when relevant), and the antislop Delivery Gate report (for UI).

### 7.4 Hygiene
- Commit early inside the branch, but the final squashed message must be clean.
- Never commit generated files, secrets, or personal paths.
- Do not edit `CHANGELOG.md`, the version in `Cargo.toml`, or `.release-please-manifest.json` by hand. Release automation owns them.
- Do not create or move tags by hand. Tags come only from release automation.

---

## 8. GitHub Actions and releases

**Policy: every merged `feat`, `fix`, `perf` creates its own new version and its own GitHub Release, automatically.** Nobody builds or uploads by hand.

### 8.1 Pipeline summary (details and YAML: `PROJECT_STRUCTURE.md` section 6)
1. **On every PR (`ci.yml`):** PR-title check, `fmt`, `clippy -D warnings`, tests, release build, **budget check** (size, RAM, latency), `cargo deny`, dependency review. All must pass to merge.
2. **On merge to `main` (`release.yml`):**
   - release-please reads the Conventional Commit, bumps the version (SemVer), updates `CHANGELOG.md`, and opens a release PR.
   - The release PR is auto-merged after CI passes. That creates the tag `vX.Y.Z` and the **GitHub Release** with generated notes.
   - The build job then compiles **x64 and ARM64**, builds the installer and portable zip, signs them (when a certificate is configured), creates `SHA256SUMS.txt`, adds a build provenance attestation, and uploads all assets to the release.
3. **Weekly (`security.yml`):** dependency audit.

### 8.2 Version rules
- SemVer: `MAJOR.MINOR.PATCH`. Before 1.0, breaking changes bump MINOR.
- One version source of truth: `[workspace.package].version` in `Cargo.toml`, changed only by automation. The installer, binaries (`--version`) and About screen read this version.
- Pre-release or unsigned builds are marked as pre-release on GitHub until signing is set up.
- The release title: `vX.Y.Z`. The release notes: generated from commits, grouped (Features, Fixes, Performance, Security). Do not hand-edit except to add a security advisory link.

### 8.3 Workflow rules for agents
- Pin every third-party action to a **full commit SHA** (comment the version). Dependabot updates them.
- Top-level `permissions: contents: read`; elevate per job, only what is needed (`contents: write` for releasing, `id-token` and `attestations` for provenance).
- Secrets live only in GitHub Secrets: `RELEASE_BOT_TOKEN`, signing certificate secrets. Never print them. Never use them in workflows that run on fork PRs.
- Use `--locked` for cargo commands in CI so that builds are reproducible from `Cargo.lock`.
- The release workflow must **fail loudly** if: budgets are exceeded, signing is configured but fails, checksums do not match, or an asset is missing. A partial release must be deleted or marked as draft.
- Cache with `Swatinem/rust-cache`; never cache secrets or `dist/`.
- Keep workflows fast and small; no unnecessary matrix entries.
- Do not add third-party actions that are unmaintained or request broad permissions. Prefer `gh` CLI and first-party actions.

### 8.4 Hotfix and rollback
- A urgent fix is a normal `fix:` PR, merged with priority; it gets its own patch release.
- A bad release is never silently deleted. Mark it as pre-release or add a clear "do not use" note, publish a fixed version, and record the incident in `docs/release-runbook.md`.
- A leaked secret: rotate first, then fix history with owner approval.

### 8.5 What the owner must do once (agents give step-by-step help)
1. Create the GitHub repository (private by default).
2. Settings > Actions > allow Actions; Settings > General > enable **auto-merge**; Settings > Branches > protect `main` (require PR, require `CI` checks, squash merge only, block force push).
3. Create a GitHub App or fine-grained token for `RELEASE_BOT_TOKEN`.
4. Later: add the signing certificate secrets and set the repository variable `SIGNING_ENABLED=true`.

---

## 9. Definition of Done (every task)

A task is done only when **all** are true:

- [ ] Matches the PRD requirement and its acceptance criteria
- [ ] `cargo fmt --check` passes
- [ ] `cargo clippy --workspace --all-targets --locked -- -D warnings` passes
- [ ] `cargo test --workspace --locked` passes, including new tests for new behavior and abuse cases
- [ ] `cargo xtask check-budgets` passes (size, RAM, latency)
- [ ] `cargo deny check` passes
- [ ] No new `unsafe` outside `applock-sys`; no `unwrap`/`panic` in non-test code
- [ ] No secret or personal data in code, logs, or commits
- [ ] UI: antislop Delivery Gate = PASS, `DESIGN.md` followed, English and Urdu strings present, keyboard and contrast checked
- [ ] Docs updated (`PRD.md`, `PROJECT_STRUCTURE.md`, `docs/`) where affected
- [ ] PR title is a valid Conventional Commit (`feat`/`fix` for user-visible changes)
- [ ] Report written in the format of section 1

---

## 10. Forbidden list

You must never:

1. Weaken security, remove a check, or add a "temporary" bypass or backdoor.
2. Log, store, or transmit secrets in plain text.
3. Write custom cryptography.
4. Add `unsafe` outside `applock-sys` / `applock-shellext`.
5. Use polling loops or keep a UI process resident.
6. Add telemetry, analytics, ad SDKs, or any unrequested network call.
7. Add a heavy dependency or runtime (Electron, web view, async runtime in service/agent) without an approved ADR.
8. Disable, bypass or trick Windows security, antivirus, SmartScreen or UAC.
9. Push to `main`, force-push shared branches, rewrite published history, move tags, or edit version/changelog by hand.
10. Commit secrets, certificates, build output, or large binaries.
11. Skip tests, hooks, or CI, or mark a failing test as ignored to pass.
12. Invent requirements, numbers, API names, or "facts". Verify or ask.
13. Ship generic AI-looking UI: invented stats, placeholder text, decorative filler, hype copy.
14. Build features outside the PRD's current release scope.
15. Claim "done" or "works" without having run the checks and showing the output.

---

## 11. When unsure

Stop and ask the owner. Give them: the question in one sentence, two or three options in plain language with the trade-off of each, and your recommendation. Never ask the owner a technical question that you can answer yourself.


<!-- antislop:start -->
## antislop
For UI, copy, people, mobile layout, or code comments work, read these installed skill files directly (use these paths even if a same-named global skill exists):
- Core filter, always on: `antislop`: `.agents/skills/antislop/SKILL.md`
- UI / visual: `antislop-ui`: `.agents/skills/antislop-ui/SKILL.md`
- People: `antislop-human`: `.agents/skills/antislop-human/SKILL.md`
- Code comments: `antislop-code`: `.agents/skills/antislop-code/SKILL.md`
- Copy & text: `antislop-copywriting`: `.agents/skills/antislop-copywriting/SKILL.md`
Before starting, follow the core's "Two Usage Modes" section in strict order: explicit session instruction first, then global preference, then ask. A session instruction always wins. For a resolved mode, say `antislop active: <mode> (session override).` or `antislop active: <mode> (global preference).` once before presenting findings or making edits, using the actual mode and source. Acknowledging the user's request without naming the source does not replace this notice.
Only an explicit choice of antislop during or after selects a session mode. A request to review, audit, or avoid file edits does not select a mode; read the global preference in that case. Another skill's mode does not select antislop's mode.
If the mode is unresolved, ask during/after and end the response; wait for the answer before any UI review, planning, or concept. For read-only tasks, put the active-mode notice only at the start of the final answer, never in progress messages. For editing tasks, announce before the first edit and omit it from the final answer.
To update antislop later: `npx antislop-ai --update`, or run `npx antislop-ai` and pick Overwrite them.
<!-- antislop:end -->
