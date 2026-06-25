# Deputy

[![CI](https://github.com/Remade-With-Rust/deputy/actions/workflows/ci.yml/badge.svg)](https://github.com/Remade-With-Rust/deputy/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/deputy-cli.svg)](https://crates.io/crates/deputy-cli)
[![docs.rs](https://img.shields.io/docsrs/deputy-core)](https://docs.rs/deputy-core)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

A repository for your portfolio of github codebases dependencies. Recursive dep acquisition, language understanding/analytics, storage, scanning, staging, and deployment.

> Install the CLI: `cargo install deputy-cli` (provides the `deputy` binary). Embed the library: `deputy-api`. See [RELEASING.md](./RELEASING.md) for publishing and [CONTRIBUTING.md](./CONTRIBUTING.md) to hack on it.

## Coding Requirements

- All code must be production-grade application with security-first design decisions. No bandaging problems, create tests, validate outcomes, build production grade only.
- Dioxus for Rust development across web and native. Rust in all aspects of the program (or WASM for browser targets)
- Encryption: Argon2id key derivation + AES-256-GCM authenticated encryption
- Storage: Use spacedb found at https://github.com/Remade-With-Rust/spacedb
- Access management uses MATA's mID tools, https://www.npmjs.com/package/@matanetwork/sovereign-id, and https://www.npmjs.com/package/@matanetwork/sovereign-id-verify. The Crates are also found at https://github.com/orgs/Remade-With-Rust/repositories
- API first, UI second architecture to enable AI and user interaction with the tools.
- If https://www.memorysafety.org/ toolsets are useful to your codebase, use them where applicable.
- If https://github.com/rustcrypto is useful to your codebase, use it where applicable.
- If https://github.com/orgs/Remade-With-Rust/repositories tools are useful to your codebase, use them where applicable.

## Morning Ritual

1 - Read all completed documents
2 - Ask me if there are any  plans I need to read that are important to todays work.

## Platforms

Rust + Dioxus, targeting native (macOS · Linux · Windows) and web (WASM). Single codebase.

## How To Run

Deputy is an early-stage Cargo workspace (roadmap **M0** complete — see [docs/ROADMAP.md](docs/ROADMAP.md)).

```sh
cargo build --workspace      # build all crates
cargo test --workspace       # run tests (deputy-core domain + state machine)
cargo run -p deputy-cli      # the CLI (real commands land in M3)
cargo deny check             # supply-chain / license gate (dogfooding the mission)
```

## Architecture

> Full design lives in **[docs/](docs/)** — start with [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md),
> then [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md). Summary of the pipeline:

1 - sign in via mID from MATA
2 - connect your Github
3 - Deputy recursively scans your source code, downloads deps into a local repo for dirty deps
4 - social channels/comms for deps are tried to establish for breaches
5 - language understanding/analytics are performed on deps to understand the languages used by your core code
6 - scanning of deps in dirty repo compared to our prod repo
7 - deployment into prod repo for use in applications
8 - API to Github applications that validates all repos are clean

### What's Stored Where

See [docs/STORAGE.md](docs/STORAGE.md) — content-addressed dirty/prod repos, an encrypted
metadata DB, and a hash-chained audit log under `~/.deputy`, all sealed with AES-256-GCM
under an Argon2id-derived key.

### SSO interaction

MATA mID is the main sign on mechanism gating this tool for a user. Crates are available for mID for mid-verifier and mid-issuer

## Environment Variables (Build Time)

## License

Deputy is free for anyone to use, for any purpose, including commercially — no fees, no
copyleft. It is dual-licensed, at your option, under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](./LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](./LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
this project, as defined in the Apache-2.0 license, shall be dual-licensed as above, without any
additional terms or conditions.