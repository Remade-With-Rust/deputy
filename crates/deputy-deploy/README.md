# deputy-deploy

[![crates.io](https://img.shields.io/crates/v/deputy-deploy?logo=rust)](https://crates.io/crates/deputy-deploy)
[![docs.rs](https://img.shields.io/docsrs/deputy-deploy?logo=docsdotrs)](https://docs.rs/deputy-deploy)
[![CI](https://github.com/Remade-With-Rust/deputy/actions/workflows/ci.yml/badge.svg)](https://github.com/Remade-With-Rust/deputy/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](https://github.com/Remade-With-Rust/deputy#license)
[![Remade With Rust](https://img.shields.io/badge/Remade%20With-Rust-000?logo=rust&logoColor=fff)](https://github.com/Remade-With-Rust)
[![By Mata Network](https://img.shields.io/badge/by-Mata%20Network-5b2be0)](https://www.mata.network/)

> **What actually reaches production.** Promotion with hash-chained receipts, a
> fail-closed deploy gate, and vendoring of the owned copies back into a build — the last
> two stages of [Deputy](https://github.com/Remade-With-Rust/deputy).

**Most users want the CLI — [`deputy-cli`](https://crates.io/crates/deputy-cli), whose
`deputy gate` is the command a CI step calls.** Depend on this crate directly to wire the gate
into your own release tooling.

Part of **[Deputy](https://github.com/Remade-With-Rust/deputy)**, an initiative of
**[Remade With Rust](https://github.com/Remade-With-Rust)** by
**[Mata Network](https://www.mata.network/)**.

---

## Why the gate is fail-closed

`gate` allows a deployment only if **every** dependency is promoted, clean, and receipted. Not
"no known problems" — an affirmative record for each one. Anything unscanned, unpromoted, or
missing a receipt is a `GateViolation`, and violations are returned as data so the caller can
report exactly what blocked.

The inversion matters: a gate that blocks on *findings* passes everything it failed to look at, so
a scan that never ran reads as success. A gate that requires *receipts* cannot be passed by
silence.

## The three stages

- **`promote`** — `Scanned → Promoted | Quarantined`. Copies clean, verified bytes from the dirty
  store into the append-only prod store, writing a hash-chained `Receipt` attributed to the mID
  that authorized it. A non-clean verdict is quarantined instead: held in staging, not promoted,
  and not deleted.
- **`gate`** — the fail-closed check above, returning a `GateDecision`.
- **`materialize`** — gate first, then extract the prod copies into a Cargo vendor tree
  (source replacement), so the build consumes *your* verified artifacts instead of a live
  registry. If the gate blocks, nothing is written.

Because prod is append-only and content-addressed, a receipt names bytes that still exist and
still hash the same. A promotion is auditable after the fact, not just at the moment it happened.

## Contents

| Module | What's in it |
|---|---|
| `promote` | `promote` → `Promotion`, `Receipt` — dirty → prod with a hash-chained, mID-attributed receipt |
| `gate` | `gate` → `GateDecision`, `GateViolation` — the fail-closed check, with reasons |
| `materialize` | `materialize` → `MaterializePlan`, `MaterializedCrate` — the Cargo vendor tree |

Extraction uses pure-Rust gzip + tar (`miniz_oxide`, `tar`); no C in the path.

## Install

```sh
cargo add deputy-deploy
```

```rust
use deputy_deploy::{gate, materialize, promote, GateDecision, Promotion};

// One dependency at a time: a clean verdict moves to prod with a receipt, findings are
// quarantined. Promotion re-checks integrity, so a tamper *after* the scan is caught here.
for pin in &pins {
    match promote(
        &vault,
        pin.dep.ecosystem,
        pin.dep.name.as_str(),
        pin.dep.version.as_str(),
        &pin.expected,
        Some(&did),                      // the mID the receipt is attributed to
    )? {
        Promotion::Promoted(receipt) => println!("promoted, chain {}", receipt.chain_hash),
        Promotion::Quarantined { findings } => eprintln!("held: {} findings", findings.len()),
    }
}

// The gate demands an affirmative record per dependency — silence never passes.
match gate(&vault, &pins)? {
    GateDecision::Allowed { cleared } => {
        println!("{cleared} dependencies cleared");
        let plan = materialize(&vault, &pins, out_dir)?;   // vendor your own verified copies
        println!("vendored {} into {}", plan.materialized.len(), plan.vendor_dir.display());
    }
    GateDecision::Blocked { violations } => {
        for v in &violations {
            eprintln!("blocked: {v:?}");
        }
    }
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
| [`deputy-acquire`](https://crates.io/crates/deputy-acquire) | the fetch → verify → seal acquisition pipeline |
| **[`deputy-deploy`](https://crates.io/crates/deputy-deploy)** | **← you are here** — promotion receipts, the fail-closed gate, vendoring |
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
