# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). From the first release onward,
entries are maintained automatically by [release-plz](https://release-plz.dev) from
Conventional Commits.

## [Unreleased]

### Added

- Cross-device metadata sync (CRDT) end-to-end encrypted under an **mID-bound sync key**, with a
  `--no-mid` toggle that binds to a local identity instead.
- mID is a runtime toggle: on by default, deactivatable (`DeputyService::open_local`,
  `deputy serve --no-mid`).

### Changed

- Dual-licensed under **MIT OR Apache-2.0** (was Apache-2.0) — free for any use, no restrictions.
- Depend on the published crates.io versions of the MATA mID and SpaceDB crates (no more
  `mata-master` path or git dependencies); the workspace is now fully portable and embeddable.

## [0.1.0] - Unreleased

Initial workspace. The full pipeline — acquire → analyze → scan → promote → gate → deploy —
plus encrypted-at-rest storage (Argon2id + AES-256-GCM, SpaceDB Layer 0), mID-gated access,
SpaceDB capabilities/durability/CRDT layers, and the localhost API + Dioxus UI.
