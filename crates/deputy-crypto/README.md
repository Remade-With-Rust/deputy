# deputy-crypto

[![crates.io](https://img.shields.io/crates/v/deputy-crypto?logo=rust)](https://crates.io/crates/deputy-crypto)
[![docs.rs](https://img.shields.io/docsrs/deputy-crypto?logo=docsdotrs)](https://docs.rs/deputy-crypto)
[![CI](https://github.com/Remade-With-Rust/deputy/actions/workflows/ci.yml/badge.svg)](https://github.com/Remade-With-Rust/deputy/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](https://github.com/Remade-With-Rust/deputy#license)
[![Remade With Rust](https://img.shields.io/badge/Remade%20With-Rust-000?logo=rust&logoColor=fff)](https://github.com/Remade-With-Rust)
[![By Mata Network](https://img.shields.io/badge/by-Mata%20Network-5b2be0)](https://www.mata.network/)

> **The key hierarchy behind the vault.** Argon2id passphrase derivation,
> HKDF-SHA256 domain separation, and AES-256-GCM sealing — the encryption-at-rest
> primitives of [Deputy](https://github.com/Remade-With-Rust/deputy).

**Most users want the CLI — [`deputy-cli`](https://crates.io/crates/deputy-cli) — or the
vault itself, [`deputy-store`](https://crates.io/crates/deputy-store), which drives this crate for
you.** Depend on this one directly only if you need the same key hierarchy in your own storage
layer.

Part of **[Deputy](https://github.com/Remade-With-Rust/deputy)**, an initiative of
**[Remade With Rust](https://github.com/Remade-With-Rust)** by
**[Mata Network](https://www.mata.network/)**.

---

## The hierarchy

```text
passphrase ──Argon2id(salt, params)──▶ MasterKey            (memory only, zeroized on drop)
                                           │ HKDF-SHA256(domain)
                      ┌────────────────────┼────────────────────┐
                      ▼                    ▼                    ▼
                SubKey(Store)         SubKey(Meta)         SubKey(Audit)
                      │ HKDF(content_hash)
                      ▼
              per-artifact SubKey ──▶ AES-256-GCM seal/open
```

Every artifact gets its own key, derived from the content hash that addresses it. Two artifacts
never share a key, and the address is bound in as AEAD additional data — so a sealed blob moved
to a different address fails to open rather than decrypting into the wrong slot.

## Why confidentiality and identity are separate keys

Deputy authenticates *who is acting* with [MATA mID](https://github.com/Remade-With-Rust/mid)
(P-256, **sign/verify only** — it exports no secret), and protects bytes at rest with a
passphrase-derived key. mID is never a key-derivation source; it can *bind* a key
(`derive_master_bound` mixes the verified DID into the derivation, so another identity's sign-in
cannot open your vault) but it can never *be* one.

No key material is serialized, logged, or written to disk. `MasterKey` and `SubKey` zeroize on
drop. Only the non-secret `KdfParams` and a `make_verifier` blob are persisted — enough to detect
a wrong passphrase without storing anything that could recover the key.

## Contents

| Module | What's in it |
|---|---|
| `kdf` | `KdfParams::recommended()`, `derive_master`, `derive_master_bound` (identity-bound derivation) |
| `derive` | `derive_subkey` (HKDF domain separation), `derive_artifact_subkey`, `derive_sync_key`, `KeyDomain` |
| `aead` | `seal` / `open` — AES-256-GCM with a fresh random nonce and caller-supplied AAD |
| `verify` | `make_verifier` / `check_verifier` — wrong-passphrase detection that stores no key |
| `key` | `MasterKey`, `SubKey` — zeroize-on-drop wrappers that never `Debug`-print their bytes |

Dependency posture: `argon2` and `aes-gcm` are pulled with `default-features = false` so they
don't bring their own RNG; nonces come from `getrandom` alone, keeping the randomness surface to
one crate.

## Install

```sh
cargo add deputy-crypto
```

```rust
use deputy_crypto::{
    derive_artifact_subkey, derive_master, derive_subkey, open, seal, KdfParams, KeyDomain,
};

let params = KdfParams::recommended()?;          // persist this; it is not secret
let master = derive_master(b"correct horse battery staple", &params)?;
let store = derive_subkey(&master, KeyDomain::Store);

// One key per artifact, derived from the hash that addresses it...
let key = derive_artifact_subkey(&store, &content_hash);
// ...and the address is bound in as AAD, so a relocated blob will not open.
let sealed = seal(&key, crate_bytes, &content_hash)?;
assert_eq!(open(&key, &sealed, &content_hash)?, crate_bytes);
```

## Where this sits

| Crate | Role |
|---|---|
| [`deputy-core`](https://crates.io/crates/deputy-core) | domain types, the artifact state machine, trait contracts — **no I/O** |
| **[`deputy-crypto`](https://crates.io/crates/deputy-crypto)** | **← you are here** — Argon2id key derivation + AES-256-GCM sealing |
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
