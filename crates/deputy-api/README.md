# deputy-api

[![crates.io](https://img.shields.io/crates/v/deputy-api?logo=rust)](https://crates.io/crates/deputy-api)
[![docs.rs](https://img.shields.io/docsrs/deputy-api?logo=docsdotrs)](https://docs.rs/deputy-api)
[![CI](https://github.com/Remade-With-Rust/deputy/actions/workflows/ci.yml/badge.svg)](https://github.com/Remade-With-Rust/deputy/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](https://github.com/Remade-With-Rust/deputy#license)
[![Remade With Rust](https://img.shields.io/badge/Remade%20With-Rust-000?logo=rust&logoColor=fff)](https://github.com/Remade-With-Rust)
[![By Mata Network](https://img.shields.io/badge/by-Mata%20Network-5b2be0)](https://www.mata.network/)

> **The one surface everything drives.** `DeputyService` composes the whole
> pipeline as an in-process capability layer, and `serve` exposes it as a localhost
> HTTP/JSON API — the API-first core of
> [Deputy](https://github.com/Remade-With-Rust/deputy).

**Most users want the CLI — [`deputy-cli`](https://crates.io/crates/deputy-cli).**
Depend on this crate to **embed Deputy** in your own software, or to drive the vault from an agent
over HTTP.

Part of **[Deputy](https://github.com/Remade-With-Rust/deputy)**, an initiative of
**[Remade With Rust](https://github.com/Remade-With-Rust)** by
**[Mata Network](https://www.mata.network/)**.

---

## API-first, not API-also

The CLI, the Dioxus UI, and any AI agent all call the *same* `DeputyService` methods — the HTTP
router is a transport over it, not a second implementation. There is one place where a capability
is authorized, so a client cannot reach a path the service didn't sanction, and a new surface
inherits the gate for free instead of re-deriving it.

## mID-gated by default

Opening a service is authenticated **and** encrypted, by two separate mechanisms
(`docs/AUTH.md` §8):

- `open_gated` — the secure default. The vault stays sealed until an
  [mID](https://github.com/Remade-With-Rust/mid) sign-in supplies a verified DID, then unlocks
  **bound to that identity**: another mID's sign-in, even with the right passphrase, cannot open
  it. Identity authorizes; the passphrase decrypts; neither substitutes for the other.
- `open_or_create_local` — mID deactivated, for embedding in software that already owns its auth.
  Access rests on the passphrase alone.

Every mutating operation is additionally gated by a scoped
[SpaceDB](https://github.com/Remade-With-Rust/spacedb) Layer 5 capability — signed, scoped,
expiring, revocable — **and** a typed [`mata-cap`](https://crates.io/crates/mata-cap)
`deputy:<action>` grant, which is what makes handing an *agent* narrow access a bounded grant
rather than a shared secret.

## Contents

| Module | What's in it |
|---|---|
| `service` | `DeputyService` — the canonical capability layer: discover, acquire, analyze, scan, promote, gate, deploy, folders, coverage, heartbeat, upgrade plans |
| `http` | `router` — the axum HTTP/JSON transport (`/health`, `/discover`, `/acquire`, `/analyze`, `/scan`, `/promote`, `/gate`, `/deploy`, `/folders/*` including `/folders/upgrade-plans`, `/github/*`, `/auth/*`, `/session`) |
| `rustsec` | The RUSTSEC advisory-db importer — download, decompress, parse |
| `error` | `ApiError` — the single error type across both surfaces |

Also exported: `default_vault_dir()` (honors `$DEPUTY_VAULT`, else `~/.deputy`, cross-platform),
the identity types (`Session`, `VerifyParams`, `verify`), and the capability vocabulary
(`Capability`, `Scope`, `Ops`, `SignedCapability`). TLS is rustls throughout — no OpenSSL.

## Install

```sh
cargo add deputy-api
```

```rust
use deputy_api::{default_vault_dir, open_gated, serve_blocking};

let dir = default_vault_dir().expect("no home directory — pass an explicit path");

// Sealed until a verified mID signs in, then unlocked *bound to that DID*.
let service = open_gated(&dir, passphrase)?;

// The CLI, the UI and any agent all drive these same methods; HTTP is just a transport.
serve_blocking(service, "127.0.0.1:7878".parse()?)?;
```

Upgrade plans (WRITE): `POST /folders/upgrade-plans` with `{ "name": "<workspace>", "repo": "owner/name" }`
(`repo` omitted = every GitHub repo in that workspace, or all workspaces when `name` is `*`).
Each repo gets `docs/plans/deputy-upgrades.md` for **that repo's** `Cargo.lock` (direct +
transitive). Only crates.io releases at least a week old. Compatible bumps are `cargo update`;
new majors need a `Cargo.toml` change. See [the root README How to](https://github.com/Remade-With-Rust/deputy#how-to).

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
| **[`deputy-api`](https://crates.io/crates/deputy-api)** | **← you are here** — the API-first service layer + localhost HTTP transport |
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
