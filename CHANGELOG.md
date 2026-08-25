# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). From the first release onward,
entries are maintained automatically by [release-plz](https://release-plz.dev) from
Conventional Commits.

## [Unreleased]

### Changed

- **Send Plans copy** — each `docs/plans/deputy-upgrades.md` is explicitly **that GitHub repo's**
  `Cargo.lock` (direct + transitive), with guidance that compatible bumps are `cargo update` and
  new majors need a `Cargo.toml` change.

### Security

- `crossbeam-epoch` (and other compatible lockfile crates) refreshed via `cargo update`.
- House mID kit: `mid-signin` / `mid-issuer` / `kms-client` `0.1.0` → `0.1.1` (`mid-verify` stays `0.1.0`).

## [0.4.0] - 2026-08-25

### Added

- **Send Plans** — from New Versions, commit `docs/plans/deputy-upgrades.md` into each GitHub
  repo in the current workspace (`POST /folders/upgrade-plans`, `DeputyService::send_upgrade_plans`).
  Creates `docs/plans/` when it is missing. Each file is that repo's own `Cargo.lock` (direct +
  transitive). Only crates.io releases **at least 7 days old** are listed. Local ingest names
  are skipped.

## [0.3.0] - 2026-08-25

### Added

- **`deputy-alloc`** — the rusty_alloc seam for CLI and desktop deliverables (libraries never
  install a global allocator).
- **GitHub browser OAuth** — Connect with GitHub opens a browser; no personal access token
  required. Device-flow plus `gh` CLI fallback.
- **Workspace-scoped dashboard** — Overview, Scan, Analytics, New Versions, and Production
  follow the selected repo, group, or all-workspaces view.
- **Group version checks** composed from each child repo's cache, so a group is not stuck on a
  stale aggregate.
- **Dep Analytics** as a language-mix visualization (bars + per-crate languages/lines).
- **New Versions** tab — only crates with an update; check the ones to migrate, Check all, then
  Redeploy. Promote accepts an opt-in `only` list of name@version (stages the new release if
  needed) instead of promoting the whole lockfile minus a hold list.

### Changed

- Folder listings hydrate lockfile counts when a stored summary was zeroed.
- Staging → production from New Versions promotes the **checked new versions**, not every other
  crate in the vault.

## [0.2.0] - 2026-08-10

### Added

- **mID-bound vault access.** The vault stays sealed until an mID sign-in supplies a verified DID,
  then unlocks *bound to that identity* (`Vault::create_bound` / `unlock_bound`,
  `deputy_crypto::derive_master_bound`, `deputy_api::open_gated`) — another identity's sign-in
  cannot open it, even with the right passphrase. Identity authorizes; the passphrase decrypts.
- **Local-folder ingestion** (`POST /local/download`, `DeputyService::download_local`) alongside
  GitHub, with a native folder picker in the desktop UI.
- **Offline-coverage check** (`GET /folders/coverage`, `DeputyService::folder_coverage`) — which
  dependencies are safely archived vs. gaps (git deps, non-crates.io registries, failures).
- **Per-folder scanning** (`DeputyService::scan_folder`) and staging → production redeploy, which
  scans each dependency before promoting so flagged deps stay in staging.
- Persisted GitHub connections and folders, with downloads that keep running across tab switches.
- Desktop app: a native single-binary build with an embedded, self-contained API, and
  `deputy://` / `mata-mid://` deep-link mID sign-in with no browser hop.
- `deputy_api::default_vault_dir()` — cross-platform vault resolution honoring `$DEPUTY_VAULT`.

### Changed

- Folder operations read the **stored** lockfiles rather than re-fetching them from GitHub, so a
  scan reflects the bytes actually archived.
- Folder and connection listings are gated on vault unlock, like every other read.
- mID sign-in speaks the real `@matanetwork/sovereign-id` v1 wire protocol; audience origin fixed.
- Per-crate READMEs rewritten to the Remade With Rust format and branding.

### Fixed

- No runtime-drop panic on the desktop `deputy://` verify callback (it runs on its own thread).
- GitHub: multiple accounts, owner-scoped repository listing, and PAT-permission handling.

## [0.1.0] - 2026-06-25

Initial release. The full pipeline — acquire → analyze → scan → promote → gate → deploy — plus
encrypted-at-rest storage (Argon2id + AES-256-GCM, SpaceDB Layer 0), mID-gated access, SpaceDB
capabilities/durability/CRDT layers, and the localhost API + Dioxus UI.

### Added

- Cross-device metadata sync (CRDT) end-to-end encrypted under an **mID-bound sync key**, with a
  `--no-mid` toggle that binds to a local identity instead.
- mID is a runtime toggle: on by default, deactivatable (`DeputyService::open_local`,
  `deputy serve --no-mid`).

### Changed

- Dual-licensed under **MIT OR Apache-2.0** (was Apache-2.0) — free for any use, no restrictions.
- Depend on the published crates.io versions of the MATA mID and SpaceDB crates (no more
  `mata-master` path or git dependencies); the workspace is now fully portable and embeddable.
