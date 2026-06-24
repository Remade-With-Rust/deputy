# Deputy — Design Documents

Foundational design for Deputy. Read in this order; later docs assume the earlier ones.
These are the "completed documents" referenced by the Morning Ritual in the root `README.md`.

| # | Document | What it covers |
|---|---|---|
| 1 | [ARCHITECTURE.md](./ARCHITECTURE.md) | What Deputy is, principles, workspace/crate layout, the pipeline, API-first surface, why Cargo first. **Start here.** |
| 2 | [THREAT_MODEL.md](./THREAT_MODEL.md) | Assets, trust boundaries, adversaries, STRIDE mitigations, the fail-closed deploy gate. |
| 3 | [STORAGE.md](./STORAGE.md) | What's stored where, Argon2id + AES-256-GCM, key hierarchy, dirty/prod repos, on-disk layout. |
| 4 | [AUTH.md](./AUTH.md) | MATA mID, pure-Rust verification, identity & session model. **Spec-complete** (grounded in the published `sovereign-id` packages). |
| 5 | [PIPELINE.md](./PIPELINE.md) | The Cargo acquire → analyze → scan → promote → deploy flow + `DepEcosystem` trait. |
| 6 | [ROADMAP.md](./ROADMAP.md) | Phased milestones M0–M8 and beyond. |

## Status

Design docs complete. **Roadmap M0–M7 are implemented — Deputy is feature-complete:**

- **M0** — Cargo workspace + 12 `deputy-*` crates compile; `deputy-core` (domain types, the
  artifact state machine, trait contracts) is real and tested (7 tests).
- **M1** — `deputy-crypto` (Argon2id KDF, HKDF subkeys, AES-256-GCM, zeroizing keys,
  verifier; 12 tests) and `deputy-store` (`Vault` lock/unlock, content-addressed sealed
  dirty/prod stores, encrypted `redb` metadata, hash-chained audit log; 10 tests).
- **M2** — `deputy-id` (vendored MATA `mid-verify`; `verify` → `Session`, `Authenticator`
  with single-use nonces + genesis-anchor/rollback; 9 tests vs. real wallet-minted tokens).
- **M3** — `deputy-ecosystem` (`CargoEcosystem`: Cargo.lock → pins, `.crate` fetch over
  rustls, SHA-256 verify; 3 tests), `deputy-acquire` (discover→fetch→verify→seal→provenance;
  2 tests), and `deputy-cli` (`deputy discover` / `deputy acquire`). Dogfooded against
  Deputy's own 223 deps with a real crates.io fetch.
- **M4** — `deputy-analyze` (blast radius from the Cargo.lock graph; `.crate` inspection for
  language mix + capability surface; ranked `RiskScore`; 4 tests) + `deputy analyze` CLI.
  Dogfooded over Deputy's tree (flagged `ring`/`libc` + the proc-macro backbone).
- **M5** — `deputy-scan` (fail-closed verdict: integrity / substitution / advisory findings +
  capability notes; 6 tests) and `deputy-deploy` (clean-verdict promotion dirty→prod with
  hash-chained receipts, quarantine otherwise; 3 tests) + `deputy scan` / `deputy promote` CLI.
- **M6** — `deputy-deploy` (fail-closed `gate` + `materialize` vendoring; 7 tests) +
  `deputy gate` / `deputy deploy` CLI + a GitHub Action gate template. Dogfooded the full loop:
  a real project built `--offline` against Deputy's vendored, owned `itoa`; the gate blocked a
  quarantined dep.
- **M7** — `deputy-api` (`DeputyService` + axum HTTP server, mID-session-gated; 4 tests),
  `deputy serve` CLI, and `deputy-ui` (a Dioxus 0.7 wasm web app — sign-in + gate/analysis
  dashboards, a pure API client). API live-verified via curl.

The full mission pipeline runs end to end — **acquire → analyze → scan → promote → gate →
deploy** — drivable from the CLI, the HTTP API, and the UI. Locally green: clippy `-D warnings`
(host + wasm), scoped fmt, `cargo deny`, **69 tests total**. Two open caveats from M2's
vendoring (heavy dep tree + the absolute path dep blocking CI) are tracked in
[AUTH.md §10](./AUTH.md). See [ROADMAP.md](./ROADMAP.md).

## Decisions locked (2026-06-24)

- **First ecosystem:** Cargo / Rust (dogfoods Deputy's own stack).
- **mID:** reimplemented in pure Rust (no second runtime in the trust base).
- **README positioning:** Deputy as a rebuild of an existing tool — *recommended framing:*
  "a sovereign, local-first Artifactory + Snyk." Exact "original" to confirm at README time.
- **Build approach:** documentation-first, then implement against these docs in roadmap order.
