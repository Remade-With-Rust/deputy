# Releasing Deputy to crates.io

Deputy is a Cargo workspace of `deputy-*` crates. Its entire third-party trust base
(`mid-verify`/`mid-issuer`/`kms-client` and the `spacedb-*` crates) is already published on
crates.io, and the internal crates depend on each other with `{ path, version }`, so the
workspace is publish-ready — no path or git dependencies remain.

## One-time setup

1. Create a crates.io account ("Log in with GitHub") at <https://crates.io>.
2. Create a **scoped API token** (Account Settings → API Tokens) with the `publish-new` and
   `publish-update` scopes. Then:
   - `cargo login <token>` locally (for the first manual publish), and
   - add it as the `CARGO_REGISTRY_TOKEN` repository **secret** (for the automation in
     `.github/workflows/release-plz.yml`).
3. After the first publish, hand each crate to the org team so it is not tied to one personal
   account:
   ```sh
   for c in deputy-alloc deputy-core deputy-crypto deputy-id deputy-ecosystem deputy-store \
            deputy-analyze deputy-scan deputy-acquire deputy-deploy deputy-api deputy-cli; do
     cargo owner --add github:Remade-With-Rust:owners "$c"
   done
   ```

## Publish order (bottom-up)

A crate cannot publish until every dependency is already on crates.io, so publish in
dependency order:

1. `deputy-alloc` — first publish; allocator seam for deliverables
2. `deputy-core`
3. `deputy-crypto`
4. `deputy-id`
5. `deputy-ecosystem`
6. `deputy-store`
7. `deputy-analyze`
8. `deputy-scan`
9. `deputy-acquire`
10. `deputy-deploy`
11. `deputy-api`
12. `deputy-cli` — installs the `deputy` binary (`cargo install deputy-cli`)

`deputy-ui` is a Dioxus **wasm application**, not a reusable library, and is intentionally
**not** published (`publish = false`).

## First publish (manual)

Dry-run the whole workspace, then publish for real:
```sh
./scripts/publish.sh --dry-run   # cargo package + verify each crate, no upload
./scripts/publish.sh             # publish in order (waits for crates.io to index between crates)
```

## Ongoing releases (automated)

Once the names are claimed, **release-plz** takes over. On every push to `main` it opens a
release PR that bumps versions (from [Conventional Commits](https://www.conventionalcommits.org))
and updates `CHANGELOG.md`; merging that PR tags the release and publishes every changed crate
in dependency order. After the first manual publish you should not need `cargo publish` again.

## Pre-publish gate

`cargo deny check`, `cargo clippy --all-targets --all-features -- -D warnings`, and
`cargo test --workspace` must pass. CI (`.github/workflows/ci.yml`) enforces this on every PR.

## Versioning

All crates currently share a version via `[workspace.package]`. Pre-1.0, a minor bump
(`0.x`) may carry breaking changes; document them in `CHANGELOG.md`.
