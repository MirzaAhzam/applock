# AppLock: Project Structure

Single source of truth for **where every file lives**. If a change needs a new folder or crate, update this file in the same pull request.

---

## 1. Repository layout

```
applock/
├── AGENTS.md                     # Rules every AI agent must follow
├── PRD.md                        # What we build
├── PROJECT_STRUCTURE.md          # This file
├── DESIGN.md                     # UI direction (required by antislop)
├── README.md                     # Short intro for humans
├── CHANGELOG.md                  # Written by release automation, never by hand
├── LICENSE
├── SECURITY.md                   # How to report a vulnerability
├── Cargo.toml                    # Workspace root + shared versions + release profile
├── Cargo.lock                    # Committed (this is an application)
├── rust-toolchain.toml           # Pinned Rust version and targets
├── rustfmt.toml
├── clippy.toml
├── deny.toml                     # cargo-deny: advisories, licenses, bans
├── release-please-config.json
├── .release-please-manifest.json
├── .gitignore
├── .gitattributes
├── .editorconfig
│
├── crates/
│   ├── applock-core/             # Pure logic: config, rules engine, auth logic, lockout, crypto wrappers
│   ├── applock-ipc/              # Message types, (de)serialization, pipe protocol, validation
│   ├── applock-sys/              # ALL unsafe Windows calls (ETW, suspend/resume, DPAPI, tokens, pipes)
│   ├── applock-service/          # bin: Windows service (SYSTEM)
│   ├── applock-agent/            # bin: hidden user-session helper
│   ├── applock-lockui/           # bin: lock screen (on demand)
│   ├── applock-manager/          # bin: settings app
│   ├── applock-i18n/             # Strings (en, ur), RTL helpers
│   ├── applock-vault/            # [v2.0] encrypted containers, mount (WinFsp)
│   └── applock-shellext/         # [v2.0] cdylib: Explorer context menu (COM)
│
├── ui/                           # Slint UI files (.slint), shared components, assets
│   ├── tokens.slint              # Design tokens generated from DESIGN.md values
│   ├── components/
│   ├── lockui/
│   └── manager/
│
├── assets/
│   ├── icons/                    # App icon (.ico), tray icons
│   └── fonts/                    # Only if licensed and justified (default: system fonts)
│
├── locales/
│   ├── en.toml
│   └── ur.toml
│
├── installer/
│   ├── applock.iss               # Inno Setup script
│   └── license.rtf
│
├── xtask/                        # Build helpers: `cargo xtask <command>`
│   └── src/main.rs               # package, check-budgets, sign, checksums, bench
│
├── tests/
│   ├── integration/              # Service + IPC + fake processes
│   ├── security/                 # Bypass attempts, fuzz targets, pipe spoofing
│   ├── perf/                     # Latency, RAM, CPU benchmarks + budget file
│   │   └── budgets.toml          # Hard limits from PRD section 7.1
│   └── app-matrix/               # Test checklist of the top 30 apps
│
├── docs/
│   ├── architecture.md           # Diagrams and decisions
│   ├── decisions/                # ADRs: 0001-title.md, 0002-title.md ...
│   ├── setup-google-oauth.md     # Step-by-step for the owner
│   ├── setup-microsoft-oauth.md
│   ├── setup-code-signing.md
│   └── release-runbook.md        # Hotfix, yank, rollback
│
└── .github/
    ├── workflows/
    │   ├── ci.yml                # fmt, clippy, tests, budgets, supply chain
    │   ├── release.yml           # release-please + build + sign + upload
    │   └── security.yml          # Weekly dependency audit
    ├── ISSUE_TEMPLATE/
    ├── PULL_REQUEST_TEMPLATE.md
    ├── CODEOWNERS
    └── dependabot.yml
```

> Note: the antislop installer (`npx antislop-ai`) will add its own skill folder and a pointer block into `AGENTS.md`. Let it. Do not move or rename what it creates.

## 2. What each crate does

| Crate | Type | Responsibility | May depend on | `unsafe` |
|---|---|---|---|---|
| `applock-core` | lib | Config model, rules engine (is this app locked right now?), grace and schedule logic, lockout state machine, Argon2id and DPAPI wrappers (through `sys`), recovery code logic | `ipc` types (read-only), `sys` | Forbidden |
| `applock-ipc` | lib | Message enums, size limits, parsing, versioning | none (pure) | Forbidden |
| `applock-sys` | lib | Thin safe wrappers over Win32/WinRT: ETW session, process suspend/resume/terminate, token and session helpers, pipe server/client with ACL, DPAPI, WinEvent hooks, Hello bridge | `windows` crate | **Allowed, only here** (plus `shellext`) |
| `applock-service` | bin | Service entry, ETW consumer loop, decision, enforcement, session and power events, credential verification | core, ipc, sys | Forbidden |
| `applock-agent` | bin | WinEvent hook, spawns lock UI, forwards events | core (read-only types), ipc, sys | Forbidden |
| `applock-lockui` | bin | Lock screen (Slint), Hello call, sends attempt to service | ipc, i18n, sys | Forbidden |
| `applock-manager` | bin | Settings UI, app discovery, wizard, logs, OAuth recovery | core, ipc, i18n, sys | Forbidden |
| `applock-i18n` | lib | Loads `locales/*.toml`, RTL flag | none | Forbidden |
| `applock-vault` | lib (v2) | Container format, encryption, mount | core, sys | Forbidden |
| `applock-shellext` | cdylib (v2) | `IExplorerCommand` handler | ipc, sys | Allowed (COM) |
| `xtask` | bin | Dev and CI helper commands | none of the above | Forbidden |

### Dependency direction (never break this)

```
 manager ─┐
 lockui  ─┼──► core ──► sys
 agent   ─┤       │
 service ─┘       └──► ipc
 i18n  (leaf, used by lockui + manager only)
```

Forbidden: `core` depending on any binary crate; any crate except `sys` and `shellext` using `unsafe`; UI crates reading config files directly (they ask the service through IPC); circular dependencies.

## 3. Where things go (quick answers)

| I need to add... | It goes in... |
|---|---|
| A new Windows API call | `applock-sys` (safe wrapper plus `// SAFETY:` comment plus test) |
| A rule about locking, grace, schedule | `applock-core/src/rules/` |
| A new IPC message | `applock-ipc` (plus parser fuzz test plus version note) |
| A new screen in Manager | `ui/manager/` plus handler in `applock-manager` |
| A UI color, spacing, font size | `ui/tokens.slint` (never hard-coded in components) |
| A user-visible string | `locales/en.toml` **and** `locales/ur.toml` |
| A new dependency | `Cargo.toml` of one crate only, justified in the PR (see `AGENTS.md` section 3) |
| A performance limit | `tests/perf/budgets.toml` and `PRD.md` section 7.1 |
| A design decision with trade-offs | `docs/decisions/NNNN-title.md` (ADR) |

## 4. Naming conventions

| Thing | Convention | Example |
|---|---|---|
| Crates | `applock-<role>` | `applock-core` |
| Rust files and modules | `snake_case` | `lockout.rs` |
| Types and traits | `UpperCamelCase` | `LockoutState` |
| Constants | `SCREAMING_SNAKE_CASE` | `MAX_MESSAGE_BYTES` |
| Branches | `feat/<short-name>`, `fix/<short-name>`, `chore/...`, `docs/...` | `feat/windows-hello` |
| Commits and PR titles | Conventional Commits | `fix(service): keep lockout across reboot` |
| Release assets | `AppLock-<version>-<arch>-setup.exe` | `AppLock-0.4.2-x64-setup.exe` |
| ADR files | `NNNN-kebab-title.md` | `0003-use-slint-software-renderer.md` |

## 5. Root configuration files

### `Cargo.toml` (workspace root)

```toml
[workspace]
resolver = "2"
members = [
  "crates/applock-core",
  "crates/applock-ipc",
  "crates/applock-sys",
  "crates/applock-service",
  "crates/applock-agent",
  "crates/applock-lockui",
  "crates/applock-manager",
  "crates/applock-i18n",
  "xtask",
]

[workspace.package]
version = "0.1.0"          # Changed only by release automation
edition = "2021"
rust-version = "1.85"      # Pin to the version in rust-toolchain.toml
license = "LicenseRef-Proprietary"
publish = false

[workspace.lints.rust]
unsafe_code = "forbid"     # applock-sys and applock-shellext override this locally
missing_docs = "warn"

[workspace.lints.clippy]
all = { level = "deny", priority = -1 }
pedantic = { level = "warn", priority = -1 }
unwrap_used = "deny"
expect_used = "deny"
panic = "deny"
todo = "deny"
dbg_macro = "deny"

[profile.release]
opt-level = "s"            # Measure "z" vs "s" vs 3 per binary; keep what meets budgets
lto = "fat"
codegen-units = 1
panic = "abort"
strip = "symbols"
debug = false
overflow-checks = true     # Security app: keep arithmetic checks on
```

Each crate's `Cargo.toml` uses `version.workspace = true`, `edition.workspace = true`, `[lints] workspace = true`.

### `rust-toolchain.toml`

```toml
[toolchain]
channel = "1.85.0"          # Update deliberately in its own PR
components = ["clippy", "rustfmt"]
targets = ["x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc"]
profile = "minimal"
```

### `.gitignore` (minimum)

```
/target
/dist
*.pdb
*.pfx
*.p12
*.key
*.pem
.env
.env.*
secrets/
/tests/perf/results/
.vscode/*
!.vscode/extensions.json
```

### `.gitattributes`

```
* text=auto eol=lf
*.bat text eol=crlf
*.ps1 text eol=crlf
*.iss text eol=crlf
*.ico binary
```

### `release-please-config.json`

```json
{
  "$schema": "https://raw.githubusercontent.com/googleapis/release-please/main/schemas/config.json",
  "packages": {
    ".": {
      "release-type": "simple",
      "package-name": "applock",
      "include-component-in-tag": false,
      "changelog-path": "CHANGELOG.md",
      "bump-minor-pre-major": true,
      "extra-files": [
        { "type": "toml", "path": "Cargo.toml", "jsonpath": "$.workspace.package.version" }
      ]
    }
  }
}
```

### `.release-please-manifest.json`

```json
{ ".": "0.1.0" }
```

### `.github/dependabot.yml`

```yaml
version: 2
updates:
  - package-ecosystem: cargo
    directory: "/"
    schedule: { interval: weekly }
    commit-message: { prefix: "chore(deps)" }
  - package-ecosystem: github-actions
    directory: "/"
    schedule: { interval: weekly }
    commit-message: { prefix: "ci(deps)" }
```

## 6. CI/CD workflows (reference implementation)

> Agents must pin every third-party action to a **full commit SHA** in the real files (the `@vN` tags below are for readability). Keep `permissions` minimal per job.

### 6.1 `.github/workflows/ci.yml`

```yaml
name: CI
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

concurrency:
  group: ci-${{ github.ref }}
  cancel-in-progress: true

env:
  CARGO_TERM_COLOR: always

jobs:
  pr-title:
    if: github.event_name == 'pull_request'
    runs-on: ubuntu-latest
    permissions:
      pull-requests: read
    steps:
      - uses: amannn/action-semantic-pull-request@v5   # PR title must be a Conventional Commit
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

  checks:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - run: rustup toolchain install          # reads rust-toolchain.toml
      - uses: Swatinem/rust-cache@v2
      - run: cargo fmt --all -- --check
      - run: cargo clippy --workspace --all-targets --locked -- -D warnings
      - run: cargo test --workspace --locked
      - run: cargo build --release --workspace --locked
      - run: cargo xtask check-budgets         # fails if size/RAM/latency budgets are broken

  supply-chain:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: EmbarkStudios/cargo-deny-action@v2
        with:
          command: check advisories bans licenses sources

  dependency-review:
    if: github.event_name == 'pull_request'
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: actions/dependency-review-action@v4
```

### 6.2 `.github/workflows/release.yml`

How it works: every merge to `main` runs release-please. For a `feat` or `fix` commit it opens (or updates) a release PR that bumps the version and writes the changelog. The release PR is **auto-merged**, which creates the tag and the GitHub Release, and the build job then attaches the signed installers.

```yaml
name: Release
on:
  push:
    branches: [main]

permissions:
  contents: write
  pull-requests: write

jobs:
  release-please:
    runs-on: ubuntu-latest
    outputs:
      release_created: ${{ steps.rp.outputs.release_created }}
      tag_name: ${{ steps.rp.outputs.tag_name }}
      version: ${{ steps.rp.outputs.version }}
    steps:
      - uses: googleapis/release-please-action@v4
        id: rp
        with:
          # Use a GitHub App token or fine-grained PAT, NOT the default GITHUB_TOKEN,
          # otherwise CI will not run on the release PR and auto-merge will be blocked.
          token: ${{ secrets.RELEASE_BOT_TOKEN }}
          config-file: release-please-config.json
          manifest-file: .release-please-manifest.json

  build:
    needs: release-please
    if: ${{ needs.release-please.outputs.release_created == 'true' }}
    runs-on: windows-latest
    permissions:
      contents: write
      id-token: write        # build provenance
      attestations: write
    strategy:
      fail-fast: true
      matrix:
        target: [x86_64-pc-windows-msvc, aarch64-pc-windows-msvc]
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ needs.release-please.outputs.tag_name }}
      - run: rustup toolchain install
      - uses: Swatinem/rust-cache@v2
        with:
          key: ${{ matrix.target }}
      - name: Refresh workspace versions in Cargo.lock
        run: cargo update --workspace          # only touches our own crates' versions
      - name: Test (x64 only; ARM64 is cross-compiled)
        if: matrix.target == 'x86_64-pc-windows-msvc'
        run: cargo test --workspace
      - name: Package (build, installer, zip, checksums)
        run: cargo xtask package --target ${{ matrix.target }} --version ${{ needs.release-please.outputs.version }}
      - name: Sign binaries and installer
        if: ${{ env.SIGNING_ENABLED == 'true' }}
        env:
          SIGNING_ENABLED: ${{ vars.SIGNING_ENABLED }}
        run: cargo xtask sign --dir dist       # implementation depends on the certificate type
      - uses: actions/attest-build-provenance@v2
        with:
          subject-path: dist/*
      - name: Upload assets to the GitHub Release
        shell: pwsh
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          Get-ChildItem dist -File | ForEach-Object {
            gh release upload "${{ needs.release-please.outputs.tag_name }}" $_.FullName --clobber
          }

  checksums:
    needs: [release-please, build]
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - name: Merge checksum files into one SHA256SUMS.txt
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          REPO: ${{ github.repository }}
          TAG: ${{ needs.release-please.outputs.tag_name }}
        run: |
          gh release download "$TAG" --repo "$REPO" --pattern 'SHA256SUMS-*.txt' --dir sums
          cat sums/SHA256SUMS-*.txt > SHA256SUMS.txt
          gh release upload "$TAG" SHA256SUMS.txt --repo "$REPO" --clobber
```

### 6.3 Auto-merge for release PRs

In the repository settings: enable **Allow auto-merge**, and require the `CI` checks on `main`. The release PR opened by release-please is set to auto-merge, so a feature or fix PR is followed by its own release within minutes. If the owner wants manual control, leave auto-merge off and merge the release PR by hand; the rest is identical.

### 6.4 `.github/workflows/security.yml`

```yaml
name: Security
on:
  schedule:
    - cron: "0 3 * * 1"      # Mondays 03:00 UTC
  workflow_dispatch:

permissions:
  contents: read

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: EmbarkStudios/cargo-deny-action@v2
        with:
          command: check advisories bans licenses sources
```

### 6.5 `cargo xtask` commands

| Command | Does |
|---|---|
| `cargo xtask package --target T --version V` | Release build, Inno Setup installer, portable zip, per-target `SHA256SUMS-<arch>.txt` in `dist/` |
| `cargo xtask check-budgets` | Compares binary sizes, RAM, latency against `tests/perf/budgets.toml`; non-zero exit on breach |
| `cargo xtask sign --dir dist` | Authenticode signing (certificate type decided by owner) |
| `cargo xtask bench` | Runs latency and RAM benchmarks and writes results |

## 7. Per-release asset list

```
AppLock-<ver>-x64-setup.exe
AppLock-<ver>-arm64-setup.exe
AppLock-<ver>-x64-portable.zip
AppLock-<ver>-arm64-portable.zip
SHA256SUMS.txt
(attestation: visible on the release, verify with `gh attestation verify`)
```

Release notes come from the changelog that release-please generates from Conventional Commit titles. Nobody writes them by hand.

## 8. Rules for changing this structure
1. Propose the change in a PR that also edits this file.
2. New crate: add a row to section 2 and update the dependency diagram.
3. Never leave empty placeholder crates; add `[v2.0]` folders only when work on them starts.
4. Generated or build output (`target/`, `dist/`) is never committed.
