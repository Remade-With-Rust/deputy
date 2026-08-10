# deputy-acquire

[![crates.io](https://img.shields.io/crates/v/deputy-acquire?logo=rust)](https://crates.io/crates/deputy-acquire)
[![docs.rs](https://img.shields.io/docsrs/deputy-acquire?logo=docsdotrs)](https://docs.rs/deputy-acquire)
[![CI](https://github.com/Remade-With-Rust/deputy/actions/workflows/ci.yml/badge.svg)](https://github.com/Remade-With-Rust/deputy/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](https://github.com/Remade-With-Rust/deputy#license)
[![Remade With Rust](https://img.shields.io/badge/Remade%20With-Rust-000?logo=rust&logoColor=fff)](https://github.com/Remade-With-Rust)
[![By Mata Network](https://img.shields.io/badge/by-Mata%20Network-5b2be0)](https://www.mata.network/)

> **Fetch, verify, seal.** Takes a source's resolved dependency pins, downloads
> each one, checks its content hash, and seals it into the dirty store with provenance —
> the acquisition stage of [Deputy](https://github.com/Remade-With-Rust/deputy).

**Most users want the CLI — [`deputy-cli`](https://crates.io/crates/deputy-cli) — or
[`deputy-api`](https://crates.io/crates/deputy-api).** Depend on this crate directly to run
acquisition inside your own tool, with your own progress reporting.

Part of **[Deputy](https://github.com/Remade-With-Rust/deputy)**, an initiative of
**[Remade With Rust](https://github.com/Remade-With-Rust)** by
**[Mata Network](https://www.mata.network/)**.

---

## Fail-closed, per dependency

Each dependency is handled independently, and the two properties that matter are kept separate:

- **Nothing unverified is ever stored.** Only bytes whose SHA-256 matches the pinned checksum
  reach the vault. A fetch error or a hash mismatch records a failure in the report and seals
  nothing.
- **One failure does not abort the run.** The remaining dependencies still acquire. You end up
  with a partial vault and an explicit list of what's missing — which is far more useful than
  a half-finished run whose coverage you have to guess at.

`AcquireReport` distinguishes newly `acquired`, `already_present`, and `failed`, and
`is_clean()` is true only when nothing failed. Because artifacts are content-addressed, a
dependency shared across repositories is downloaded **once** — `already_present` is the common
case after the first run.

## Ecosystem-agnostic

`acquire` is generic over `deputy_core::DepEcosystem`, so it works for Cargo today and for npm,
PyPI or Go the moment those implementations land — no change here.

## Contents

| Item | What it does |
|---|---|
| `acquire` | Discover the source's pins, then fetch → verify → seal each into the dirty store |
| `acquire_with_progress` | The same, with an `(done, total)` callback for a UI or progress bar |
| `AcquireReport` | `acquired` / `already_present` / `failed`, plus `total()` and `is_clean()` |
| `AcquiredCrate`, `AcquireFailure` | Per-dependency outcomes, with the error text preserved |

Every seal also writes a provenance record to the vault's hash-chained audit log.

## Install

```sh
cargo add deputy-acquire
```

```rust
use deputy_acquire::acquire_with_progress;
use deputy_core::SourceId;
use deputy_ecosystem::CargoEcosystem;

let report = acquire_with_progress(
    &vault,
    &CargoEcosystem::new(),
    &SourceId::new("/path/to/repo"),
    |done, total| println!("{done}/{total}"),
)?;

println!("{} new, {} already held", report.acquired.len(), report.already_present);
for f in &report.failed {
    eprintln!("{}@{} not archived: {}", f.name, f.version, f.error); // an explicit gap
}
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
| **[`deputy-acquire`](https://crates.io/crates/deputy-acquire)** | **← you are here** — the fetch → verify → seal acquisition pipeline |
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
