# deputy-core

[![crates.io](https://img.shields.io/crates/v/deputy-core?logo=rust)](https://crates.io/crates/deputy-core)
[![docs.rs](https://img.shields.io/docsrs/deputy-core?logo=docsdotrs)](https://docs.rs/deputy-core)
[![CI](https://github.com/Remade-With-Rust/deputy/actions/workflows/ci.yml/badge.svg)](https://github.com/Remade-With-Rust/deputy/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](https://github.com/Remade-With-Rust/deputy#license)
[![Remade With Rust](https://img.shields.io/badge/Remade%20With-Rust-000?logo=rust&logoColor=fff)](https://github.com/Remade-With-Rust)
[![By Mata Network](https://img.shields.io/badge/by-Mata%20Network-5b2be0)](https://www.mata.network/)

> **The vocabulary every other crate agrees on.** Domain types, the
> dependency-artifact state machine, and the trait contracts of
> [Deputy](https://github.com/Remade-With-Rust/deputy) — the personally-owned,
> verified vault and supply-chain gate for your code dependencies.

**Most users want the CLI — [`deputy-cli`](https://crates.io/crates/deputy-cli) — or the
embeddable service, [`deputy-api`](https://crates.io/crates/deputy-api).** Depend on this crate
directly only if you are implementing against Deputy's contracts: a new dependency ecosystem, an
alternative store, your own scanner.

Part of **[Deputy](https://github.com/Remade-With-Rust/deputy)**, an initiative of
**[Remade With Rust](https://github.com/Remade-With-Rust)** by
**[Mata Network](https://www.mata.network/)**.

---

## Why it performs no I/O

An audited supply chain is only as trustworthy as the states it can be in. So the pipeline's
lifecycle lives here as a closed state machine with the legal edges spelled out, and
`transition` is the only way to move — an illegal move is an `Error::IllegalTransition`, not a
silently-accepted write:

```text
Discovered ─▶ Acquired ─▶ Analyzed ─▶ Scanned ─┬─▶ Promoted ─▶ Deployed
                                       ▲       │
                                       │       └─▶ Quarantined
                                       └────── re-scan ──────┘
```

Keeping this crate I/O-free is what lets the rest of the workspace depend on *contracts* rather
than on each other: `deputy-store` implements `ArtifactStore`, `deputy-ecosystem` implements
`DepEcosystem`, and both are swappable and testable without a vault, a network, or a disk.

## Contents

| Module | What's in it |
|---|---|
| `ids` | `ContentHash` (algorithm-tagged, hex round-tripping), `DepRef`, `Pin` (a dependency **plus** its expected hash), `ArtifactRef`, `SourceId`, `RepoId`, `EcosystemId` |
| `state` | `ArtifactState` + the legal-transition table, `ScanVerdict`, `Finding`, `Severity` |
| `traits` | `DepEcosystem` (discover + fetch/verify), `ArtifactStore`, `MetadataStore`, `StoreKind` (`Dirty` / `Prod`) |
| `error` | `Error` / `Result` — the shared error vocabulary |

A `Pin` is the load-bearing type: acquisition is driven by resolved `name@version` **with its
checksum**, never by a free-text name, which is what makes the pipeline tamper-evident and
typosquat-resistant.

## Install

```sh
cargo add deputy-core
```

```rust
use deputy_core::{ArtifactState, ContentHash, HashAlgo};

// The pipeline's legal edges are data, not convention.
let s = ArtifactState::Discovered.transition(ArtifactState::Acquired)?;
assert!(s.can_transition_to(ArtifactState::Analyzed));
assert!(!s.can_transition_to(ArtifactState::Deployed)); // must be scanned + promoted first

// Content addresses carry their algorithm, so a future migration is not a silent reinterpret.
let h = ContentHash::from_sha256_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")?;
assert_eq!(h.algo(), HashAlgo::Sha256);
```

## Where this sits

| Crate | Role |
|---|---|
| **[`deputy-core`](https://crates.io/crates/deputy-core)** | **← you are here** — domain types, the artifact state machine, trait contracts |
| [`deputy-crypto`](https://crates.io/crates/deputy-crypto) | Argon2id key derivation + AES-256-GCM sealing |
| [`deputy-id`](https://crates.io/crates/deputy-id) | MATA mID verification, sessions, nonce + genesis-anchor stores |
| [`deputy-ecosystem`](https://crates.io/crates/deputy-ecosystem) | lockfile parsing + fetch/verify behind `DepEcosystem` (Cargo first) |
| [`deputy-store`](https://crates.io/crates/deputy-store) | the content-addressed dirty/prod vault + encrypted metadata |
| [`deputy-analyze`](https://crates.io/crates/deputy-analyze) | language analytics + critical-point-of-failure scoring |
| [`deputy-scan`](https://crates.io/crates/deputy-scan) | integrity / advisory / substitution scanning → verdicts |
| [`deputy-acquire`](https://crates.io/crates/deputy-acquire) | the fetch → verify → seal acquisition pipeline |
| [`deputy-deploy`](https://crates.io/crates/deputy-deploy) | promotion receipts, the fail-closed gate, vendoring |
| [`deputy-api`](https://crates.io/crates/deputy-api) | the API-first service layer — **embed Deputy with this** |
| [`deputy-cli`](https://crates.io/crates/deputy-cli) | the `deputy` binary — **`cargo install deputy-cli`** |
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
