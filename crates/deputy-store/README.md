# deputy-store

[![crates.io](https://img.shields.io/crates/v/deputy-store?logo=rust)](https://crates.io/crates/deputy-store)
[![docs.rs](https://img.shields.io/docsrs/deputy-store?logo=docsdotrs)](https://docs.rs/deputy-store)
[![CI](https://github.com/Remade-With-Rust/deputy/actions/workflows/ci.yml/badge.svg)](https://github.com/Remade-With-Rust/deputy/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](https://github.com/Remade-With-Rust/deputy#license)
[![Remade With Rust](https://img.shields.io/badge/Remade%20With-Rust-000?logo=rust&logoColor=fff)](https://github.com/Remade-With-Rust)
[![By Mata Network](https://img.shields.io/badge/by-Mata%20Network-5b2be0)](https://www.mata.network/)

> **The vault you own.** Two content-addressed artifact stores (`dirty` and
> `prod`), an encrypted metadata database, and a hash-chained audit log — all sealed
> at rest. The storage layer of [Deputy](https://github.com/Remade-With-Rust/deputy).

**Most users want the CLI — [`deputy-cli`](https://crates.io/crates/deputy-cli) — or
[`deputy-api`](https://crates.io/crates/deputy-api).** Depend on this crate directly if you want
Deputy's encrypted, content-addressed store under your own pipeline.

Part of **[Deputy](https://github.com/Remade-With-Rust/deputy)**, an initiative of
**[Remade With Rust](https://github.com/Remade-With-Rust)** by
**[Mata Network](https://www.mata.network/)**.

---

## Two stores, one address space

`Vault` is the unlocked context. `create` initializes a store (deriving Argon2id params and a key
verifier); `unlock` re-derives the key hierarchy from the passphrase and rejects the wrong one.
Subkeys exist in memory only and zeroize on drop.

- **`StoreKind::Dirty`** — staging. Everything acquired lands here, verified but not yet trusted.
- **`StoreKind::Prod`** — append-only. Only scanned-clean artifacts are promoted in, each with a
  receipt.

Artifacts are addressed by the SHA-256 of their bytes, sealed with AES-256-GCM under a
per-artifact subkey, with the content address bound in as AEAD additional data. So the address is
not a filename convention — it is authenticated. `get_artifact` re-derives the hash on the way
out; a tampered or relocated blob fails to open rather than returning wrong bytes. And because
the address *is* the content, a dependency shared across ten repositories is stored once.

## What else is sealed

**Metadata** (scan verdicts, crate→hash maps, app state) lives in a
[SpaceDB](https://github.com/Remade-With-Rust/spacedb) Layer 0 transactional KV store, each record
sealed under the metadata subkey. The **audit log** is append-only and hash-chained, so
`audit_verify` detects a deleted or edited entry instead of trusting the log it is reading.

## Contents

| Module | What's in it |
|---|---|
| `vault` | `Vault::create` / `unlock` and the identity-bound `create_bound` / `unlock_bound`; the on-disk layout under `~/.deputy` |
| `artifacts` | `put_artifact` / `get_artifact` / `has_artifact` — content-addressed, AAD-bound sealing |
| `meta` | Verdicts, crate→hash maps, `list_store_crates`, app state — encrypted KV |
| `audit` | `audit_append` / `audit_entries` / `audit_verify` — the hash-chained provenance log |
| `snapshot` | `snapshot` / `restore` — Reed-Solomon erasure-coded backups, recoverable from *k* of *n* shards |
| `sync` | `export_metadata` / `import_metadata` — conflict-free multi-device metadata sync (CRDT) under an identity-bound key |

The SpaceDB layers (`spacedb-store`, `spacedb-crdt`, `spacedb-durability`) are pinned **exactly**
(`=`): Deputy freezes its own trust base.

## Install

```sh
cargo add deputy-store
```

```rust
use deputy_store::{StoreKind, Vault};

let vault = Vault::unlock(&vault_dir, passphrase)?;   // wrong passphrase → Err, not garbage

// The returned hash *is* the address; re-storing identical bytes is a no-op.
let hash = vault.put_artifact(StoreKind::Dirty, &crate_bytes)?;
assert_eq!(vault.get_artifact(StoreKind::Dirty, &hash)?, crate_bytes);

// The audit log verifies its own chain rather than being taken on trust.
let verified = vault.audit_verify()?;   // entries checked; Err on a broken or edited chain
```

## Where this sits

| Crate | Role |
|---|---|
| [`deputy-core`](https://crates.io/crates/deputy-core) | domain types, the artifact state machine, trait contracts — **no I/O** |
| [`deputy-crypto`](https://crates.io/crates/deputy-crypto) | Argon2id key derivation + AES-256-GCM sealing |
| [`deputy-id`](https://crates.io/crates/deputy-id) | MATA mID verification, sessions, nonce + genesis-anchor stores |
| [`deputy-ecosystem`](https://crates.io/crates/deputy-ecosystem) | lockfile parsing + fetch/verify behind `DepEcosystem` (Cargo first) |
| **[`deputy-store`](https://crates.io/crates/deputy-store)** | **← you are here** — the content-addressed dirty/prod vault + encrypted metadata |
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
