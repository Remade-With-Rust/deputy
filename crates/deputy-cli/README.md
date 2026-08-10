# deputy-cli

[![crates.io](https://img.shields.io/crates/v/deputy-cli?logo=rust)](https://crates.io/crates/deputy-cli)
[![docs.rs](https://img.shields.io/docsrs/deputy-cli?logo=docsdotrs)](https://docs.rs/deputy-cli)
[![CI](https://github.com/Remade-With-Rust/deputy/actions/workflows/ci.yml/badge.svg)](https://github.com/Remade-With-Rust/deputy/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](https://github.com/Remade-With-Rust/deputy#license)
[![Remade With Rust](https://img.shields.io/badge/Remade%20With-Rust-000?logo=rust&logoColor=fff)](https://github.com/Remade-With-Rust)
[![By Mata Network](https://img.shields.io/badge/by-Mata%20Network-5b2be0)](https://www.mata.network/)

> **The front door.** `deputy` — a personally-owned, verified vault and
> supply-chain gate for your code dependencies: archive every crate you build against,
> scan it, and gate what reaches production.
> [Deputy](https://github.com/Remade-With-Rust/deputy) on the command line.

**This is the crate to install.** The libraries underneath are published separately if
you want to embed the pipeline — start with
[`deputy-api`](https://crates.io/crates/deputy-api).

Part of **[Deputy](https://github.com/Remade-With-Rust/deputy)**, an initiative of
**[Remade With Rust](https://github.com/Remade-With-Rust)** by
**[Mata Network](https://www.mata.network/)**.

---

## What it's for

A modern Rust app pulls in hundreds of transitive crates. You don't control them, and a single
upstream incident — a yanked crate, a hijacked maintainer account, a re-published tarball — can
change your build out from under you. `deputy` takes the resolved dependency closure of your
repositories, downloads every crate into a local encrypted vault **you** own, verifies and scans
each one, and refuses to let anything unvetted reach production. If crates.io changes,
disappears, or ships a compromised release, you still hold the exact bytes you vetted.

## Commands

| Command | What it does |
|---|---|
| `deputy discover <src>` | List the pinned crates.io dependencies a source would acquire. Reads `Cargo.lock` — no network, no vault |
| `deputy acquire <src>` | Fetch, SHA-256-verify, and seal the dependencies into the dirty store |
| `deputy analyze <src>` | Language analytics + critical-point-of-failure ranking. Blast radius from the lockfile alone; capability surface for whatever is acquired |
| `deputy scan <src>` | Integrity, advisory and substitution checks; records verdicts. **Non-zero exit if anything is flagged** |
| `deputy promote <src>` | Move scanned-clean dependencies into prod with a hash-chained receipt; quarantine the rest |
| `deputy gate <src>` | The fail-closed gate — non-zero unless every dependency is promoted, clean and receipted. **The command a CI step calls before shipping** |
| `deputy deploy <src>` | Gate, then vendor the prod copies into the source tree (Cargo source replacement). Refuses if the gate blocks |
| `deputy serve` | Serve the localhost API that the Dioxus UI and AI agents drive |
| `deputy snapshot` / `restore` | Reed-Solomon erasure-coded vault backup, recoverable from *k* of *n* shards |
| `deputy sync export` / `import` | Conflict-free multi-device metadata sync (CRDT), encrypted under an identity-bound key |

`scan` and `gate` exit non-zero on failure, so they compose with CI without a wrapper script.

## Environment

| Variable | Purpose |
|---|---|
| `DEPUTY_PASSPHRASE` | The vault passphrase — the at-rest encryption key is derived from it (Argon2id) |
| `DEPUTY_VAULT` | Vault directory; defaults to `~/.deputy` |
| `DEPUTY_MID_TOKEN` | The MATA mID wallet token, verified before the service opens |
| `DEPUTY_MID_NONCE` | The single-use nonce for that token (replay defence) |
| `DEPUTY_MID_AUDIENCE` | Expected audience, if it isn't the bind URL |
| `DEPUTY_MID_DID` | Your DID, for `sync` — the sync key is bound to it |

mID is **on by default**; pass `--no-mid` to run under a local identity instead. The vault key is
bound to the verified DID, so another identity's sign-in cannot open your vault.

## Install

```sh
cargo install deputy-cli   # provides the `deputy` binary
```

```sh
# Archive and vet a repository's dependency closure, then gate a deploy on it.
export DEPUTY_PASSPHRASE='…'

deputy discover ./my-app          # what would be acquired (no network, no vault)
deputy acquire  ./my-app          # fetch + verify + seal into the dirty store
deputy analyze  ./my-app          # blast radius + capability surface, most critical first
deputy scan     ./my-app          # integrity / advisories / substitution → verdicts
deputy promote  ./my-app          # clean ones into prod, with receipts
deputy gate     ./my-app          # exits non-zero unless every dep is promoted + receipted

deputy serve --no-mid --port 7878 # the API + UI, for local development
```

## Where this sits

| Crate | Role |
|---|---|
| [`deputy-core`](https://crates.io/crates/deputy-core) | domain types, the artifact state machine, trait contracts — **no I/O** |
| [`deputy-crypto`](https://crates.io/crates/deputy-crypto) | Argon2id key derivation + AES-256-GCM sealing |
| [`deputy-id`](https://crates.io/crates/deputy-id) | MATA mID verification, sessions, nonce + genesis-anchor stores |
| [`deputy-ecosystem`](https://crates.io/crates/deputy-ecosystem) | lockfile parsing + fetch/verify behind `DepEcosystem` (Cargo first) |
| [`deputy-store`](https://crates.io/crates/deputy-store) | the content-addressed dirty/prod vault + encrypted metadata |
| [`deputy-analyze`](https://crates.io/crates/deputy-analyze) | language analytics + critical-point-of-failure scoring |
| [`deputy-scan`](https://crates.io/crates/deputy-scan) | integrity / advisory / substitution scanning → verdicts |
| [`deputy-acquire`](https://crates.io/crates/deputy-acquire) | the fetch → verify → seal acquisition pipeline |
| [`deputy-deploy`](https://crates.io/crates/deputy-deploy) | promotion receipts, the fail-closed gate, vendoring |
| [`deputy-api`](https://crates.io/crates/deputy-api) | the API-first service layer — **embed Deputy with this** |
| **[`deputy-cli`](https://crates.io/crates/deputy-cli)** | **← you are here** — the `deputy` binary |
| `deputy-ui` | the Dioxus web + desktop dashboard — not published |

The crates mirror the pipeline they implement — discover → acquire → analyze → scan →
promote → deploy ([PIPELINE.md](https://github.com/Remade-With-Rust/deputy/blob/main/docs/PIPELINE.md)). Every crate in the
workspace is `#![forbid(unsafe_code)]`.

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

Dual-licensed, at your option, under either of:

- **Apache-2.0** — [LICENSE-APACHE](https://github.com/Remade-With-Rust/deputy/blob/main/LICENSE-APACHE)
- **MIT** — [LICENSE-MIT](https://github.com/Remade-With-Rust/deputy/blob/main/LICENSE-MIT)

Free for anyone to use, for any purpose, including commercially — no fees, no copyleft.
