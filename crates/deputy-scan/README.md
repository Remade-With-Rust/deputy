# deputy-scan

[![crates.io](https://img.shields.io/crates/v/deputy-scan?logo=rust)](https://crates.io/crates/deputy-scan)
[![docs.rs](https://img.shields.io/docsrs/deputy-scan?logo=docsdotrs)](https://docs.rs/deputy-scan)
[![CI](https://github.com/Remade-With-Rust/deputy/actions/workflows/ci.yml/badge.svg)](https://github.com/Remade-With-Rust/deputy/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](https://github.com/Remade-With-Rust/deputy#license)
[![Remade With Rust](https://img.shields.io/badge/Remade%20With-Rust-000?logo=rust&logoColor=fff)](https://github.com/Remade-With-Rust)
[![By Mata Network](https://img.shields.io/badge/by-Mata%20Network-5b2be0)](https://www.mata.network/)

> **The promote-or-quarantine decision.** Integrity, advisory and substitution
> checks over one pinned dependency, producing the verdict that the deploy gate later
> enforces — the scan stage of [Deputy](https://github.com/Remade-With-Rust/deputy).

**Most users want the CLI — [`deputy-cli`](https://crates.io/crates/deputy-cli) — or
[`deputy-api`](https://crates.io/crates/deputy-api), which keeps the advisory database current for
you.** Depend on this crate directly to run the checks under your own orchestration.

Part of **[Deputy](https://github.com/Remade-With-Rust/deputy)**, an initiative of
**[Remade With Rust](https://github.com/Remade-With-Rust)** by
**[Mata Network](https://www.mata.network/)**.

---

## Blocking findings vs. notes

`scan` is fail-closed and reports two different kinds of thing, because conflating them either
blocks everything or blocks nothing:

**Blocking** — the verdict is not clean, so the artifact cannot be promoted:

- **Integrity failure** — the sealed artifact does not decrypt, or does not hash to its address.
- **Substitution** — prod already holds a *different* hash for the same `name@version`. A
  re-published tarball is flagged here rather than silently accepted; this is the check a live
  registry cannot perform for you, because it no longer has the old bytes. You do.
- **Advisory match** — the pinned version is hit by a known advisory, matched with real semver
  ranges across multiple patched branches (so a fix backported to `1.2.x` doesn't wrongly clear a
  `2.0.x` pin, or vice versa) and scored with CVSS v3.1 severity.

**Notes** — informational, non-blocking: build scripts, proc-macros, `unsafe`, native code. Real
signal for review, not grounds for a block.

An unacquired dependency is not silently clean: it's recorded as such, and the gate in
[`deputy-deploy`](https://crates.io/crates/deputy-deploy) refuses to pass anything unscanned.

## Contents

| Module | What's in it |
|---|---|
| `scan` | `scan(vault, pin, advisories)` → `ScanReport`; the fail-closed check order |
| `advisory` | `AdvisoryDb`, `Advisory`, `VulnMatch` — semver-range matching with CVSS v3.1 severity |

Verdicts are recorded in the vault's encrypted metadata, so promotion and the gate read a stored
decision rather than re-deriving one at deploy time.

## Install

```sh
cargo add deputy-scan
```

```rust
use deputy_core::ScanVerdict;
use deputy_scan::{scan, AdvisoryDb};

// From a local advisory TOML, or import RUSTSEC via `deputy_api::fetch_rustsec`.
let advisories = AdvisoryDb::from_toml(&advisory_toml)?;

let report = scan(&vault, &pin, &advisories)?;
match &report.verdict {
    ScanVerdict::Clean => { /* eligible for promotion into prod */ }
    ScanVerdict::Findings(findings) => {
        for f in findings {
            eprintln!("[{:?}] {} — {}", f.severity, f.id, f.summary);
        }
    }
}
for note in &report.notes {
    println!("note: {note}");   // build script, proc-macro, unsafe — signal, not a block
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
| **[`deputy-scan`](https://crates.io/crates/deputy-scan)** | **← you are here** — integrity / advisory / substitution scanning → verdicts |
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
