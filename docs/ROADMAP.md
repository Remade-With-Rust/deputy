# Deputy — Roadmap

> Status: **Design** · Last updated: 2026-06-24
> Phased delivery. Each milestone is shippable and tested before the next begins
> (production-grade only — no half-wired stages on `main`).

## Guiding order

Build the **trust base** before the features that depend on it: core types → crypto/storage
→ identity → then the pipeline stages in dependency order → then UI. The CLI exists from
early on so every capability is exercised headlessly (API-first) before any UI work.

## M0 — Workspace & contracts ✅ Done
- Cargo workspace, the crate skeleton from [ARCHITECTURE.md §5](./ARCHITECTURE.md).
- `deputy-core`: domain types, the `Discovered→…→Deployed` state machine, trait contracts.
- CI: build, test, `clippy -D warnings`, `cargo-deny` (license + advisories), fmt.
- **Exit:** empty but compiling workspace, green CI, license gate live.

## M1 — Crypto & storage (the trust base) ✅ Done
- `deputy-crypto`: Argon2id KDF, HKDF domain-separated subkeys, per-artifact subkeys,
  AES-256-GCM seal/open, zeroizing key types, passphrase verifier. (12 tests)
- `deputy-store`: `Vault` lock/unlock, content-addressed sealed dirty/prod stores, `redb`
  metadata with app-level AEAD, hash-chained audit log; implements the core `ArtifactStore`
  + `MetadataStore` contracts. (10 tests) ([STORAGE.md](./STORAGE.md))
- **Exit met:** seal/open round-trips, wrong-key/tamper/wrong-AAD rejection, KDF determinism,
  domain separation, wrong-passphrase rejection, artifact tamper detection, audit-chain
  integrity — all tested. Workspace green: clippy `-D warnings`, fmt, `cargo deny`.

## M2 — Identity (mID) ✅ Done
- `deputy-id`: vendored MATA `mid-verify` (path dep). Exposes `verify` → `Session`; the
  `Authenticator` composes verify + a single-use `NonceStore` + a genesis-anchor/rollback
  `AnchorStore` (the RP duties from [AUTH.md §5](./AUTH.md)). 9 tests against **real
  wallet-minted tokens** (built via `mid-issuer` + an in-memory device signer).
- **Session-gating:** `Session::ensure_valid` + the `Authenticator` are the gate mechanism.
  The literal composition with `Vault::unlock` (session gates unlock; passphrase derives the
  key — [AUTH.md §8](./AUTH.md)) lands in `deputy-api` (M7), to avoid coupling
  `deputy-store` ↔ `deputy-id`.
- **Exit met:** known-good sign-in plus known-bad (tamper / wrong-audience / expired / replay /
  unissued-nonce) all verified against real tokens; anchor rollback + genesis-spoof + single-use
  nonce tested.
- **Accepted caveats** (per the M2 backend decision): vendoring `mid-verify` pulls ~306 crates
  (reqwest/tokio/rustls/ring) for an offline verifier, and the absolute local path dep means the
  workspace only resolves where `mata-master` is checked out — CI/portability is unresolved.
  See [AUTH.md §10](./AUTH.md).

## M3 — Acquire (Cargo) ✅ Done
- `deputy-ecosystem`: `CargoEcosystem` — `Cargo.lock` → pins (crates.io + checksum only),
  `.crate` fetch from the CDN over rustls (`ureq`), SHA-256 integrity verify. (3 tests)
- `deputy-acquire`: generic over `DepEcosystem`; discover → fetch → verify → seal into the
  dirty store → hash-chained provenance. Fail-closed per crate (nothing sealed until SHA-256
  matches), idempotent. (2 tests)
- `deputy-cli`: `deputy discover <src>` (offline pin listing) and `deputy acquire <src>`
  (passphrase via `DEPUTY_PASSPHRASE`; auto create/unlock vault).
- **Exit met (dogfood):** `discover .` lists Deputy's **223** pinned crates.io deps; a real
  `acquire` fetched crates from crates.io, verified each SHA-256 against the lockfile checksum,
  and sealed them — the `.sealed` content addresses equal the crates.io checksums exactly.
  Idempotent re-run + wrong-passphrase rejection confirmed.
- **Deferred:** `deputy connect` / the GitHub-connected recursive multi-repo crawl — `discover`
  currently reads a local `Cargo.lock` path. Lands with the source layer.

## M4 — Analyze ✅ Done
- `deputy-analyze` (pure Rust, no network): **blast radius** (transitive dependents) from the
  Cargo.lock graph; `.crate` tarball inspection (language line counts, build script,
  proc-macro, `unsafe`, native `links`) via `flate2`/`tar`; composite `RiskScore` with
  transparent reasons, ranked most-critical first. (4 tests)
- `deputy-cli`: `deputy analyze <src> [--vault] [--top N]` — blast radius always; capability +
  language inspection of acquired crates when a vault is open.
- **Exit met (dogfood):** analyzed Deputy's own tree (242 graph nodes). Correctly flagged
  `ring` (build script + ~187K lines native C/asm + 233 `unsafe`), `libc` (24% blast radius +
  build script), and the proc-macro backbone `unicode-ident` / `proc-macro2` / `quote` / `syn`
  (~46% blast radius each). Surfaced 156K lines of assembly + 31K of C hiding in a "pure Rust"
  tree. Validated against hand-checked expectations.

## M5 — Scan & promote ✅ Done
- `deputy-scan`: fail-closed `scan` → `ScanVerdict`. **Blocking findings**: integrity failure,
  dirty-vs-prod **substitution**, and **advisory** matches (semver engine + TOML advisory DB).
  **Non-blocking notes**: build scripts / proc-macros / `unsafe` / native code. (6 tests)
- `deputy-deploy` (promote half): `promote` — clean-verdict dirty→prod copy (re-verifying
  integrity on the way), prod crate index, and a **hash-chained promotion receipt** in the
  audit log. Quarantines non-clean; refuses un-scanned. (3 tests)
- `deputy-store`: prod/dirty crate index (`name@version → hash`) enabling substitution
  detection. (1 test)
- CLI: `deputy scan <src> [--advisory-db]` (exits non-zero if flagged) · `deputy promote <src> [--actor]`.
- **Exit met:** unit tests cover tamper→quarantine (integrity finding) and clean→promote with a
  valid receipt chain. Dogfood: scanned 5 acquired crates vs a demo advisory → `cfg-if`
  quarantined, the other 4 promoted into prod with receipts (#6–9); prod holds exactly 4 sealed
  artifacts.
- **Deferred:** importing the full RUSTSEC advisory-db (the matching engine is real; loading
  uses our TOML schema / an injected DB for now) and maintenance-health signals.

## M6 — Deploy & gate ✅ Done
- `deputy-deploy::gate` — the **fail-closed deploy gate**: allows only if *every* pin is in prod
  with a clean verdict, a matching prod crate-index, and a promotion **receipt** in an intact
  audit chain. Blocks on unknown / dirty-only / unscanned / substituted / broken-chain. Checks
  are on content hashes (no TOCTOU). (5 tests)
- `deputy-deploy::materialize` — vendors prod `.crate`s into `out_dir/vendor/<crate>/` with a
  faithful `.cargo-checksum.json` (per-file + `package` SHA-256, path-traversal-safe extraction)
  and writes `.cargo/config.toml` source replacement, so builds consume Deputy's owned copies. (2 tests)
- CLI: `deputy gate <src>` (CI entry point; non-zero on block) and `deputy deploy <src> --into`
  (gate, then vendor). GitHub Action template: `.github/workflows/deputy-gate.yml`.
- **Exit met (dogfood):** gate BLOCKS the 5-crate source (cfg-if quarantined → no receipt). A
  real itoa-only project: gate ALLOWED → `deputy deploy` vendored prod `itoa` →
  `cargo build --offline` compiled **and ran** against Deputy's owned copy (no crates.io).

## M7 — API server & Dioxus UI ✅ Done
- `deputy-api`: `DeputyService` (the canonical in-process surface the CLI/server/UI share) + a
  localhost **axum** HTTP/JSON server. Opening is **mID-session-gated** — the M2 session↔unlock
  composition lands here (a valid `Session` authorizes the unlock; the passphrase derives the
  key). Endpoints: health, session, discover, acquire, analyze, scan, promote, gate, deploy.
  (4 tests incl. an HTTP smoke test; live-verified via curl.)
- `deputy serve` CLI runs the API (loopback-bound). Uses a local dev session for now; the
  production path verifies a real mID token from the wallet (`deputy-id`).
- `deputy-ui`: a **Dioxus 0.7** web app (wasm) — sign-in, source input, and the deploy-gate +
  analysis dashboards, a pure HTTP client of `deputy-api`. Compiles to wasm32, clippy-clean; the
  host build is a stub so `cargo build --workspace` stays green. Run with `dx serve --platform web`.
- **Exit met:** the API drives the full pipeline (curl-verified: `/gate` → `{"Allowed":{"cleared":1}}`,
  `/analyze` → full risk JSON); the UI is a pure API client. (Browser-interactive run is
  documented via `dx serve`, not validated in this environment.)

## M8 — Hardening & docs
- Threat-model review pass, fuzzing on parsers (lockfile, artifact), key rotation, revocation.
- README from `TEMPLATE.md` (positioning per the agreed framing), install/quickstart, examples.
- **Exit:** v0.1.0 — Cargo ecosystem, full pipeline, mID-gated, encrypted, gated deploys.

## Beyond v0.1
- Additional ecosystems (npm, PyPI, Go) via `DepEcosystem`.
- Sandboxed build-script/proc-macro execution during analysis.
- Breach/social-channel monitoring per dependency (README architecture step 4).
- Optional, opt-in key escrow / recovery.
