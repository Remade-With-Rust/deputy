# deputy-id

[![crates.io](https://img.shields.io/crates/v/deputy-id?logo=rust)](https://crates.io/crates/deputy-id)
[![docs.rs](https://img.shields.io/docsrs/deputy-id?logo=docsdotrs)](https://docs.rs/deputy-id)
[![CI](https://github.com/Remade-With-Rust/deputy/actions/workflows/ci.yml/badge.svg)](https://github.com/Remade-With-Rust/deputy/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](https://github.com/Remade-With-Rust/deputy#license)
[![Remade With Rust](https://img.shields.io/badge/Remade%20With-Rust-000?logo=rust&logoColor=fff)](https://github.com/Remade-With-Rust)
[![By Mata Network](https://img.shields.io/badge/by-Mata%20Network-5b2be0)](https://www.mata.network/)

> **Who is acting, proven cryptographically.** MATA mID token verification plus
> the replay and rollback duties a verifier leaves to the relying party — the
> authentication layer of [Deputy](https://github.com/Remade-With-Rust/deputy).

**Most users want the CLI — [`deputy-cli`](https://crates.io/crates/deputy-cli) — or
[`deputy-api`](https://crates.io/crates/deputy-api), which gates every mutating call for you.**
Depend on this crate directly if you are adding mID sign-in to your own Rust service.

Part of **[Deputy](https://github.com/Remade-With-Rust/deputy)**, an initiative of
**[Remade With Rust](https://github.com/Remade-With-Rust)** by
**[Mata Network](https://www.mata.network/)**.

---

## What the verifier leaves to you

`mid-verify` does the cryptography — signature, expiry, audience, the DID document. It cannot do
the two checks that require *state*, and both are load-bearing, so `Authenticator` composes them
into the sign-in flow:

1. **Verify** the wallet token (`verify` → a `Session` carrying the proven DID and claims).
2. **Consume the nonce, exactly once** (`NonceStore`). A token replayed to a second request is
   cryptographically perfect and must still be rejected.
3. **Check the genesis anchor** (`AnchorStore`). First sign-in pins the identity's genesis; a
   later token presenting a *different* genesis for the same DID is a key-rollback attempt, not a
   rotation, and is refused.

Skipping either turns a valid-once token into a bearer credential. That's why they live here
rather than in each caller.

## Identity authorizes; it does not decrypt

mID is sign/verify-only and exports no secret, so a `Session` *authorizes* an action but derives
no encryption key — the at-rest key comes from a separate passphrase via
[`deputy-crypto`](https://crates.io/crates/deputy-crypto). The two compose at the vault boundary:
the session decides *whether* the vault may open and *whose* it is; the passphrase decides
*how* it opens.

## Contents

| Module | What's in it |
|---|---|
| `session` | `verify`, `VerifyParams`, `Session` — the verified DID + claims |
| `auth` | `Authenticator` — verify → nonce consumption → anchor/rollback check, in order |
| `nonce` | `NonceStore` trait + `InMemoryNonceStore`; single-use replay defence |
| `anchor` | `AnchorStore` trait + `InMemoryAnchorStore`; genesis pinning and rollback detection |
| `error` | `IdError`, plus re-exported `mid_verify::{ClaimValue, VerifyError}` |

The `mid-verify` / `mid-issuer` / `kms-client` versions are pinned **exactly** (`=`). Deputy
practises its own thesis: the trust base does not float.

## Install

```sh
cargo add deputy-id
```

```rust
use deputy_id::{Authenticator, VerifyParams};

let auth = Authenticator::in_memory();       // or ::new(nonces, anchors) with your own stores
let nonce = auth.issue_nonce();              // hand this to the wallet; it is good exactly once

// Verifies the token, burns the nonce so a replay fails, and refuses a rolled-back genesis.
let session = auth.authenticate(&jwt, &params)?;
println!("signed in as {}", session.did);
```

## Where this sits

| Crate | Role |
|---|---|
| [`deputy-core`](https://crates.io/crates/deputy-core) | domain types, the artifact state machine, trait contracts — **no I/O** |
| [`deputy-crypto`](https://crates.io/crates/deputy-crypto) | Argon2id key derivation + AES-256-GCM sealing |
| **[`deputy-id`](https://crates.io/crates/deputy-id)** | **← you are here** — MATA mID verification, sessions, nonce + genesis-anchor stores |
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
