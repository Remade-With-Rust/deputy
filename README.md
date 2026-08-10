# Deputy

[![crates.io](https://img.shields.io/crates/v/deputy-cli?logo=rust)](https://crates.io/crates/deputy-cli)
[![docs.rs](https://img.shields.io/docsrs/deputy-core?logo=docsdotrs)](https://docs.rs/deputy-core)
[![CI](https://github.com/Remade-With-Rust/deputy/actions/workflows/ci.yml/badge.svg)](https://github.com/Remade-With-Rust/deputy/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)
[![Remade With Rust](https://img.shields.io/badge/Remade%20With-Rust-000?logo=rust&logoColor=fff)](https://github.com/Remade-With-Rust)
[![By Mata Network](https://img.shields.io/badge/by-Mata%20Network-5b2be0)](https://www.mata.network/)

> **A personally-owned, verified vault and supply-chain gate for your code dependencies.**
> Archive every crate you build against, scan it, and gate what reaches production — so a
> registry outage, a takedown, or a hijacked release can't change your build.

Deputy takes the full transitive dependency closure of your repositories, downloads every
crate into a local encrypted vault you own, verifies and scans each one, and gates what
reaches production — so your builds can consume *your* verified copies instead of trusting a
live registry. If crates.io changes, disappears, or ships a compromised release, you still
hold the exact bytes you vetted.

Part of **[Remade With Rust](https://github.com/Remade-With-Rust)** by
**[Mata Network](https://www.mata.network/)**.

```sh
cargo install deputy-cli   # provides the `deputy` binary
```

## Why

A modern Rust app pulls in hundreds of transitive crates. You don't control them, you can't
easily prove what you're actually building against, and a single upstream incident — a yanked
crate, a hijacked maintainer account, a re-published tarball — can change your build out from
under you.

Deputy is the personal backstop:

- **Redundancy** — a private, content-addressed copy of every dependency's source, so an
  upstream outage or takedown can't stop you building.
- **Integrity** — every artifact is SHA-256-verified on acquisition and re-checked on scan; a
  re-published `name@version` with different bytes is flagged, not silently accepted.
- **A gate** — only dependencies you've scanned clean and promoted reach production; the
  deploy gate is fail-closed.

## Features

- **Recursive acquisition** — drives off `Cargo.lock` (the resolved transitive graph), fetches
  each `.crate` from crates.io, SHA-256-verifies it against the lockfile checksum, and seals it
  into the vault. Shared dependencies are de-duplicated — downloaded **once** across all your
  repos and sessions.
- **Content-addressed encrypted vault** — two stores (`dirty`/staging and `prod`), each
  AES-256-GCM-sealed under an Argon2id-derived key, addressed by SHA-256.
- **Advisory scanning** — checks pinned versions against the RUSTSEC database with computed
  CVSS v3.1 severity and correct multi-branch "not-patched" matching, plus integrity and
  **substitution** detection (same `name@version`, different hash).
- **Supply-chain analytics** — per-dependency language breakdown and risk signals: build
  scripts, proc-macros, `unsafe`, native/FFI surface.
- **Social Heartbeat** — tracks scanned dependencies for newer releases and surfaces
  advisories that have landed publicly on the version you're pinned to.
- **Staging → production** — promote scanned-clean dependencies into `prod` with hash-chained,
  mID-attributed receipts; hold anything not ready in staging.
- **Offline-coverage check** — reports exactly which dependencies are safely archived vs. gaps
  (git deps, non-crates.io registries, failed acquisitions).
- **mID authentication** — sign in with [MATA Sovereign ID](https://github.com/Remade-With-Rust/sovereign-id);
  every mutating operation is gated by a verified identity and a scoped capability.
- **Three surfaces** — an HTTP API (API-first), a `deputy` CLI, and a Dioxus web (WASM) UI.

## Quick start

```sh
# Build everything and run the test suite
cargo build --workspace
cargo test --workspace

# Run the API + UI locally (mID deactivated for local dev)
deputy serve --no-mid --port 7878
```

Then connect a GitHub fine-grained PAT, select repositories, and download + analyze them into
a named folder. See [docs/](docs/) for the full workflow.

## How it works

The pipeline is a content-addressed, identity-gated state machine
([docs/PIPELINE.md](docs/PIPELINE.md)):

```
Discover ─▶ Acquire ─▶ Analyze ─▶ Scan ─┬─ clean ────▶ Promote ─▶ Deploy
  (lockfile) (fetch+verify+seal)         └─ findings ─▶ Quarantine
```

1. **Discover** — read each repo's `Cargo.lock`; pin every crates.io dependency to its
   checksum.
2. **Acquire** — fetch, SHA-256-verify, and seal each unique crate into the `dirty` store.
3. **Analyze** — language + supply-chain risk analytics over the acquired set.
4. **Scan** — advisory, integrity, and substitution checks → a clean/findings verdict.
5. **Promote** — move clean artifacts `dirty → prod` with a hash-chained receipt.
6. **Deploy** — vendor the prod copies into your build behind a fail-closed gate.

## The crates

Deputy is a Cargo workspace. Each library crate is published independently; install
`deputy-cli` for the binary, or depend on the libraries to embed Deputy.

| Crate | Role |
|---|---|
| [`deputy-core`](crates/deputy-core) | Domain types, the artifact state machine, trait contracts. No I/O. |
| [`deputy-crypto`](crates/deputy-crypto) | Argon2id key derivation + AES-256-GCM sealing. |
| [`deputy-store`](crates/deputy-store) | The content-addressed dirty/prod vault + encrypted metadata DB. |
| [`deputy-id`](crates/deputy-id) | MATA mID verification and Deputy's session/identity model. |
| [`deputy-ecosystem`](crates/deputy-ecosystem) | Lockfile parsing + fetch/verify, behind the `DepEcosystem` trait (Cargo first). |
| [`deputy-acquire`](crates/deputy-acquire) | The fetch → verify → seal acquisition pipeline. |
| [`deputy-analyze`](crates/deputy-analyze) | Language + supply-chain risk analysis of crate sources. |
| [`deputy-scan`](crates/deputy-scan) | Advisory / integrity / substitution scanning → verdicts. |
| [`deputy-deploy`](crates/deputy-deploy) | Promotion receipts, the fail-closed gate, and vendoring. |
| [`deputy-api`](crates/deputy-api) | The HTTP API + service layer that composes the pipeline. |
| [`deputy-cli`](crates/deputy-cli) | The `deputy` command-line binary. |
| `deputy-ui` | The Dioxus web (WASM) dashboard (not published). |

## Design

- **Security-first, API-first.** Every mutating path is gated by a verified mID session and a
  scoped [SpaceDB](https://github.com/Remade-With-Rust/spacedb) capability; the API is the
  source of truth, with the CLI and UI as clients.
- **Confidentiality and authentication are separate.** At-rest encryption uses an Argon2id
  passphrase-derived key; mID (P-256, sign/verify only) authenticates *who is acting*. mID is
  never a key-derivation source.
- **Pure Rust, native + WASM.** The same codebase targets macOS/Linux/Windows and the browser
  via Dioxus.

Full design lives in **[docs/](docs/)** — start with [ARCHITECTURE.md](docs/ARCHITECTURE.md),
then [THREAT_MODEL.md](docs/THREAT_MODEL.md), [PIPELINE.md](docs/PIPELINE.md),
[STORAGE.md](docs/STORAGE.md), and [AUTH.md](docs/AUTH.md).

## Building from source

```sh
cargo build --workspace      # build all crates
cargo test --workspace       # run the test suite
cargo clippy --workspace --all-targets -- -D warnings
cargo deny check             # supply-chain / license gate (dogfooding the mission)
```

Requires Rust 1.85+. The web UI builds with [Dioxus](https://dioxuslabs.com/) (`dx serve` in
`crates/deputy-ui`).

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Security issues: please
follow [SECURITY.md](SECURITY.md). Release process: [RELEASING.md](RELEASING.md).

## The Remade With Rust ecosystem

<!-- ORG BOILERPLATE — keep identical across repos -->

**Remade With Rust** is an initiative by **[Mata Network](https://www.mata.network/)**
to rebuild essential C and C++ tools in Rust — for the memory safety, the
predictable performance, and the freedom of a permissive license. Each project
is a reimplementation, not a fork: same wire protocols and file formats, new
code you can actually depend on. No copyleft. No surprises.

| Project | What it is |
|---|---|
| 🎬 **[remade_ffmpeg_rs](https://github.com/Remade-With-Rust/remade_ffmpeg_rs)** | **Our FFmpeg alternative.** Drop-in `ffmpeg` and `ffprobe` binaries — demux → decode → filter → encode → mux, rebuilt as composable Rust crates with **zero GPL/LGPL**. Apache-2.0. |
| 🧠 **[FFAI](https://github.com/Remade-With-Rust/FFAI)** | **Our sister project: media *for* AI.** "The AI media toolkit, remade with rust." Embedded ASR + TTS (**Mercury**), OCR (**Carmenta**) and vision-language captioning (**Argus**) behind an ffmpeg-style, swap-by-name architecture — no Python, no CUDA. MIT OR Apache-2.0. |
| 🌐 **[Mata Network](https://www.mata.network/)** | **The home page.** *"Stop sacrificing your privacy for convenience."* Sovereign, self-hostable privacy infrastructure — wallet & identity, password manager, contact manager, and a browser extension that stops information leaking as you browse. Remade With Rust is its open-source arm. |

→ All projects: **[github.com/Remade-With-Rust](https://github.com/Remade-With-Rust)**

<!-- /ORG BOILERPLATE -->

## License

Deputy is free for anyone to use, for any purpose, including commercially — no fees, no
copyleft. It is dual-licensed, at your option, under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
this project, as defined in the Apache-2.0 license, shall be dual-licensed as above, without any
additional terms or conditions.
