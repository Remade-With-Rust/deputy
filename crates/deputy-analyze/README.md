# deputy-analyze

[![crates.io](https://img.shields.io/crates/v/deputy-analyze?logo=rust)](https://crates.io/crates/deputy-analyze)
[![docs.rs](https://img.shields.io/docsrs/deputy-analyze?logo=docsdotrs)](https://docs.rs/deputy-analyze)
[![CI](https://github.com/Remade-With-Rust/deputy/actions/workflows/ci.yml/badge.svg)](https://github.com/Remade-With-Rust/deputy/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](https://github.com/Remade-With-Rust/deputy#license)
[![Remade With Rust](https://img.shields.io/badge/Remade%20With-Rust-000?logo=rust&logoColor=fff)](https://github.com/Remade-With-Rust)
[![By Mata Network](https://img.shields.io/badge/by-Mata%20Network-5b2be0)](https://www.mata.network/)

> **Which dependency would hurt most.** Blast-radius and capability-surface
> scoring plus a language breakdown over a resolved dependency tree — the analytics
> stage of [Deputy](https://github.com/Remade-With-Rust/deputy).

**Most users want the CLI — [`deputy-cli`](https://crates.io/crates/deputy-cli) — or
[`deputy-api`](https://crates.io/crates/deputy-api).** Depend on this crate directly to score a
dependency tree from your own tooling; it needs a `Cargo.lock` and nothing else.

Part of **[Deputy](https://github.com/Remade-With-Rust/deputy)**, an initiative of
**[Remade With Rust](https://github.com/Remade-With-Rust)** by
**[Mata Network](https://www.mata.network/)**.

---

## Why blast radius dominates the score

Two signals are combined per dependency:

- **Blast radius** — how many crates transitively depend on it, computed from the `Cargo.lock`
  graph. This needs no network, no vault, and no acquisition, and it dominates the score: a
  compromise in a crate 400 others pull in is a different event from one in a leaf, whatever
  either crate's contents look like.
- **Capability surface** — from inspecting the acquired `.crate`: build scripts, proc-macros,
  `unsafe`, native/FFI surface, and the language mix (C/C++/asm raise risk). This is what the
  dependency *can do* at build and run time.

Ranking on contents alone flatters leaves; ranking on position alone ignores what the code
actually reaches for. `analyze` returns risks sorted most-critical first.

## Decoupled from storage

`analyze` takes the lockfile plus a `fetch_crate(name, version) -> Option<Vec<u8>>` callback. Pass
one that reads the dirty store for a full analysis; pass `|_, _| None` and every crate is still
scored on blast radius. That keeps this crate free of any storage dependency and trivial to test,
and means an incompletely-acquired tree degrades to a partial answer instead of an error.

Tarballs are inspected with pure-Rust gzip + tar (`miniz_oxide`, `tar`) — no network, no C.

## Contents

| Module | What's in it |
|---|---|
| `graph` | `parse_lockfile`, `DepGraph::blast_radius` — the transitive reverse-dependency count |
| `inspect` | `inspect` → `CrateFacts`: build scripts, proc-macros, `unsafe`, native/FFI, per-language line counts |
| `language` | `Language` — the classification behind the language mix |
| `risk` | `RiskScore`, `LanguageReport`, `AnalysisReport` — the combined, ranked output |

## Install

```sh
cargo add deputy-analyze
```

```rust
use deputy_analyze::analyze;

// Blast radius needs only the lockfile; the callback adds capability surface where a crate
// has actually been acquired, so a partial vault still yields a ranked report.
let report = analyze(&lockfile_toml, |name, version| {
    vault_lookup(name, version) // -> Option<Vec<u8>>, the `.crate` tarball
})?;

for risk in report.risks.iter().take(5) {
    println!("{} {} — blast radius {}", risk.name, risk.version, risk.blast_radius);
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
| **[`deputy-analyze`](https://crates.io/crates/deputy-analyze)** | **← you are here** — language analytics + critical-point-of-failure scoring |
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
