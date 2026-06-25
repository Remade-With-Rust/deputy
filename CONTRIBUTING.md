# Contributing to Deputy

Thanks for your interest in Deputy. It is a Rust workspace built security-first; contributions
are welcome via pull request.

## Development

Prerequisites: a recent stable Rust toolchain (see `rust-version` in `Cargo.toml`).

```sh
cargo build --workspace
cargo test  --workspace
```

The web UI (`deputy-ui`) is a Dioxus wasm app; run it with `dx serve --platform web`.

## Before you open a PR

Your change must pass the same gate CI enforces:

```sh
# Format only Deputy's crates (NEVER `cargo fmt --all` — see below).
cargo fmt -p deputy-core -p deputy-crypto -p deputy-store -p deputy-id -p deputy-api \
          -p deputy-cli -p deputy-ui -p deputy-acquire -p deputy-analyze -p deputy-scan \
          -p deputy-deploy -p deputy-ecosystem

cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test   --workspace
cargo deny   check          # license + advisory + source gate (dogfoods Deputy's mission)
```

Add tests for new behavior and validate outcomes — no bandaging problems with happy-path-only
code.

## Commit messages

We use [Conventional Commits](https://www.conventionalcommits.org) (`feat:`, `fix:`, `docs:`,
`refactor:`, `test:`, `chore:`…). Releases are automated by **release-plz**, which derives
version bumps and `CHANGELOG.md` entries from these prefixes, so accurate types matter.

## Licensing of contributions

By contributing, you agree that your contributions are licensed under the project's license
(see [`LICENSE`](./LICENSE)).

## Releases

Maintainers: see [`RELEASING.md`](./RELEASING.md) for the crates.io publishing flow.
