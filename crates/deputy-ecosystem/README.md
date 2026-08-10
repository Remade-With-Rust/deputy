# deputy-ecosystem

[![crates.io](https://img.shields.io/crates/v/deputy-ecosystem?logo=rust)](https://crates.io/crates/deputy-ecosystem)
[![docs.rs](https://img.shields.io/docsrs/deputy-ecosystem?logo=docsdotrs)](https://docs.rs/deputy-ecosystem)
[![CI](https://github.com/Remade-With-Rust/deputy/actions/workflows/ci.yml/badge.svg)](https://github.com/Remade-With-Rust/deputy/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](https://github.com/Remade-With-Rust/deputy#license)
[![Remade With Rust](https://img.shields.io/badge/Remade%20With-Rust-000?logo=rust&logoColor=fff)](https://github.com/Remade-With-Rust)
[![By Mata Network](https://img.shields.io/badge/by-Mata%20Network-5b2be0)](https://www.mata.network/)

> **Where dependencies come from.** `DepEcosystem` implementations —
> Cargo first — that read a resolved lockfile and fetch each artifact with its
> checksum verified, for [Deputy](https://github.com/Remade-With-Rust/deputy).

**Most users want the CLI — [`deputy-cli`](https://crates.io/crates/deputy-cli) — or
[`deputy-api`](https://crates.io/crates/deputy-api).** Depend on this crate directly to drive
discovery yourself, or to add a new ecosystem (npm, PyPI, Go) behind the same trait.

Part of **[Deputy](https://github.com/Remade-With-Rust/deputy)**, an initiative of
**[Remade With Rust](https://github.com/Remade-With-Rust)** by
**[Mata Network](https://www.mata.network/)**.

---

## Why acquisition is driven by the lockfile

`CargoEcosystem` reads `Cargo.lock` — the **resolved** transitive graph — and pins every
crates.io dependency to its recorded SHA-256. Acquisition then fetches the immutable `.crate`
tarball and verifies the bytes against that pin before anything is stored.

That ordering is the whole point. Nothing is ever fetched by free-text name, so there is no step
at which a typo, a lookalike name, or a re-published `name@version` can substitute different
bytes unnoticed (`THREAT_MODEL.md` ADV-3): the hash comes from *your* lockfile, and bytes that
don't match it are a failure, not a download.

## Adding an ecosystem

The pipeline crates are generic over `deputy_core::DepEcosystem` — `discover` a source's pins,
`fetch` the bytes for one pin. Implement those two and npm, PyPI or Go acquisition lands with no
change to acquire, scan, promote, or the gate.

## Contents

| Module | What's in it |
|---|---|
| `lockfile` | `parse_pins` — `Cargo.lock` → `Vec<Pin>`, skipping non-crates.io and checksum-less entries so gaps are visible rather than assumed-covered |
| `cargo` | `CargoEcosystem` — the `DepEcosystem` impl: CDN fetch over rustls (`ureq`), SHA-256 verified against the pin |

HTTP goes over [rustls](https://github.com/rustls/rustls) — pure Rust, no OpenSSL, no C in the
transport path.

## Install

```sh
cargo add deputy-ecosystem
```

```rust
use deputy_core::{DepEcosystem, SourceId};
use deputy_ecosystem::CargoEcosystem;

let eco = CargoEcosystem::new();

// Read the resolved graph: every pin carries the checksum the fetch must match.
let pins = eco.discover(&SourceId::new("/path/to/repo"))?;
println!("{} pinned crates.io dependencies", pins.len());

// Bytes that don't hash to `pin.expected` are an error, never a stored artifact.
let bytes = eco.fetch(&pins[0])?;
```

## Where this sits

| Crate | Role |
|---|---|
| [`deputy-core`](https://crates.io/crates/deputy-core) | domain types, the artifact state machine, trait contracts — **no I/O** |
| [`deputy-crypto`](https://crates.io/crates/deputy-crypto) | Argon2id key derivation + AES-256-GCM sealing |
| [`deputy-id`](https://crates.io/crates/deputy-id) | MATA mID verification, sessions, nonce + genesis-anchor stores |
| **[`deputy-ecosystem`](https://crates.io/crates/deputy-ecosystem)** | **← you are here** — lockfile parsing + fetch/verify behind `DepEcosystem` |
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
