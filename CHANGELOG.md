# Changelog

## [0.2.0](https://github.com/MirzaAhzam/applock/compare/v0.1.0...v0.2.0) (2026-11-27)


### Features

* **agent:** add 55% black privacy dim overlay and wire lockui ([#9](https://github.com/MirzaAhzam/applock/issues/9)) ([70a6afd](https://github.com/MirzaAhzam/applock/commit/70a6afd2bd95cb0d8d1cb8c1ab8dea74ef9749f6))
* **core:** implement Argon2id auth, lockout, DPAPI config, and named-pipe IPC ([#6](https://github.com/MirzaAhzam/applock/issues/6)) ([c65b80d](https://github.com/MirzaAhzam/applock/commit/c65b80d87cf2ab25e15724222f97f5c5c7953fb4))
* **installer:** add Inno Setup secure installer and xtask package ([#11](https://github.com/MirzaAhzam/applock/issues/11)) ([3a3439f](https://github.com/MirzaAhzam/applock/commit/3a3439fccbd379386568752a3a6a002c7c6c526e))
* **lockui:** add Slint lock screen and English/Urdu i18n ([#8](https://github.com/MirzaAhzam/applock/issues/8)) ([5427a1d](https://github.com/MirzaAhzam/applock/commit/5427a1d3367e058b4665c35d755397415b52ee64))
* **manager:** add Slint Manager UI, i18n, and service IPC ([#10](https://github.com/MirzaAhzam/applock/issues/10)) ([8ed3570](https://github.com/MirzaAhzam/applock/commit/8ed3570098d5af82caedd7bfa473862281fcd57f))
* **service:** wire Argon2id auth, DPAPI config, lockout, and named-pipe IPC ([#7](https://github.com/MirzaAhzam/applock/issues/7)) ([4337efc](https://github.com/MirzaAhzam/applock/commit/4337efcc1a20ab8f2ab9ed706c57d8026df4369a))
* **sys:** hide frozen windows and show 55% black dim overlay ([#5](https://github.com/MirzaAhzam/applock/issues/5)) ([e813b72](https://github.com/MirzaAhzam/applock/commit/e813b72113bd0384b045957e4d615f315546f1b3))
* **sys:** implement M0 ETW, freeze/resume, WinEventHook, and headless benchmark ([e0dc43b](https://github.com/MirzaAhzam/applock/commit/e0dc43bbbb49ad68be5e852356f5da2510fd79f3))


### Bug Fixes

* **ci:** use full 40-char SHA for release-please-action ([#3](https://github.com/MirzaAhzam/applock/issues/3)) ([39360dc](https://github.com/MirzaAhzam/applock/commit/39360dc1ad90e667746981bb97be7521ba64a9a7))
* **security:** harden config integrity, ACL verification, and tamper recovery ([#13](https://github.com/MirzaAhzam/applock/issues/13)) ([3ea9ad6](https://github.com/MirzaAhzam/applock/commit/3ea9ad6ee6aa0aa6825aea23e2258b0d27972005))
* **service:** fix clippy similar_names and collapsible_if ([acf10d4](https://github.com/MirzaAhzam/applock/commit/acf10d45456eb407259dfd816fa7e2a65545aee5))
* **sys:** fix clippy pedantic lints in M0 spike ([ac8f7ba](https://github.com/MirzaAhzam/applock/commit/ac8f7ba0506f8d7d94356295bff7e0a6cad9b9a8))
* **sys:** fix windows-sys 0.61 features and ETW handle types ([afc9859](https://github.com/MirzaAhzam/applock/commit/afc9859562d820dd3628f05a70456d2a56e6415d))
* **sys:** pass CallbackContext address as Send usize to ETW thread ([597d8d9](https://github.com/MirzaAhzam/applock/commit/597d8d923242e381229571422f9291c57898e33e))
* **sys:** pass null EnableParameters to EnableTraceEx2 and fail CI on bench error ([4d51d98](https://github.com/MirzaAhzam/applock/commit/4d51d98206a52e5129f64e489ba2a3af4f4f8c95))
* **sys:** use try_from for Win32 style constants ([d67e6b9](https://github.com/MirzaAhzam/applock/commit/d67e6b97a8bfd00fa497c4e502faa5b884730608))
