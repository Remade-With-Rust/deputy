# Deputy — Architecture

> Status: **Design** · Last updated: 2026-06-24
> Audience: contributors and AI agents working on Deputy. Read this first.

## 1. What Deputy is

Deputy is a **personally-owned, local-first repository for the dependencies of all the
code you ship**. Instead of trusting that the registry version you pulled yesterday is
the same one serving you today, you *own* a verified copy and promote it through a
controlled pipeline before any of your applications are allowed to use it.

Deputy does four things:

1. **Acquire** — recursively discover every dependency of your GitHub source and pull a
   verified, content-addressed copy into a local **dirty repo**.
2. **Understand** — language analytics across your core code, plus a per-dependency
   *critical-point-of-failure* score (blast radius if this dep is compromised).
3. **Stage & scan** — scanners run on the dirty repo on change; clean artifacts are
   promoted into a trusted **prod repo**.
4. **Deploy & gate** — redeploy promoted dependencies back into your GitHub source, and
   expose an API that **blocks any deployment using a dependency that isn't clean**.

The first supported ecosystem is **Cargo / Rust** (see [§7](#7-ecosystem-first-target-cargo)).

## 2. Design principles (non-negotiable)

These come from `README.md` → *Coding Requirements*. Every PR is held to them.

| Principle | What it means in practice |
|---|---|
| **Rust everywhere** | All logic in Rust. Browser targets compile to WASM. No second runtime in the core path. |
| **Security-first** | Untrusted-by-default inputs; content-addressed storage; signed provenance; encrypted at rest. No bandaids — see [THREAT_MODEL.md](./THREAT_MODEL.md). |
| **Production-grade only** | Real tests, validated outcomes, no TODO-shaped holes in shipped paths. |
| **API-first, UI-second** | The capability surface is a typed Rust API (`deputy-api`). The CLI and the Dioxus UI are *both clients*. AI agents drive the same API. |
| **Encrypted at rest** | Argon2id KDF → AES-256-GCM. Keys are derived, never persisted. See [STORAGE.md](./STORAGE.md). |
| **mID-gated** | Every privileged operation requires a verified MATA mID. See [AUTH.md](./AUTH.md). |
| **Permissive license** | Apache-2.0. No GPL/LGPL in the dependency tree (CI-enforced via `cargo-deny`). |

## 3. The pipeline (data flow)

```
                ┌──────────────┐
   MATA mID ───▶│  deputy-id   │  identity & session (root of trust)
                └──────┬───────┘
                       │ gates every stage below
        ┌──────────────┼───────────────────────────────────────────────┐
        ▼              ▼                                                 ▼
  ┌───────────┐  ┌───────────┐   ┌───────────┐   ┌───────────┐   ┌────────────┐
  │  GitHub   │─▶│  ACQUIRE  │──▶│   DIRTY   │──▶│   SCAN    │──▶│    PROD    │
  │  source   │  │ discover+ │   │   repo    │   │ on-change │   │   repo     │
  │  (repos)  │  │ download  │   │ (staging) │   │  diff vs  │   │ (trusted,  │
  └───────────┘  └───────────┘   └─────┬─────┘   │   prod    │   │  golden)   │
                                       │         └───────────┘   └─────┬──────┘
                                       ▼                               │
                                 ┌───────────┐                         │
                                 │  ANALYZE  │  language analytics +    │
                                 │           │  critical-point-of-      │
                                 └───────────┘  failure scoring         │
                                                                        ▼
                                                                 ┌────────────┐
                                                                 │   DEPLOY   │
                                                                 │  redeploy  │
                                                                 │  into src  │
                                                                 │  + GATE    │──▶ CI / GitHub
                                                                 │    API     │   (block if dirty)
                                                                 └────────────┘
```

**Stages map 1:1 to crates** ([§5](#5-workspace-layout)) and to a state machine on each
dependency artifact: `Discovered → Acquired → Analyzed → Scanned → {Promoted | Quarantined} → Deployed`.
A dependency may only advance one state at a time, and only an mID-verified actor may
advance it. The `Promoted` → `Deployed` edge is the **gate**: deployment is refused
unless the exact content hash being deployed exists in the prod repo with a clean scan
verdict and a recorded promotion provenance.

## 4. The two repos: dirty vs prod

| | **Dirty repo** | **Prod repo** |
|---|---|---|
| Purpose | Staging ground for freshly acquired deps | Trusted, "golden" set cleared for use |
| Trust | Untrusted until scanned | Trusted by construction |
| Write path | `ACQUIRE` writes here | Only `DEPLOY/promote` writes here, only on a clean scan |
| Addressing | Content-addressed (hash of artifact) | Content-addressed; promotion records `dirty_hash == prod_hash` |
| Mutation | Re-acquisition overwrites by hash | Append-only; promotions are logged, never silently replaced |

Both are encrypted at rest. Layout and key hierarchy: [STORAGE.md](./STORAGE.md).

## 5. Workspace layout

A single Cargo workspace. **`deputy-core` has no I/O** — it holds the domain types and
trait contracts so every other crate (and tests) depends on stable interfaces, not
implementations.

```
deputy/
├─ Cargo.toml                     # workspace manifest
├─ crates/
│  ├─ deputy-core/                # domain types, state machine, trait contracts. No I/O.
│  ├─ deputy-alloc/               # rusty_alloc seam — declared only in deliverables
│  ├─ deputy-crypto/              # Argon2id KDF, AES-256-GCM, key hierarchy, sealed blobs
│  ├─ deputy-id/                  # MATA mID verify (pure Rust), identity & session
│  ├─ deputy-store/               # dirty repo, prod repo, encrypted metadata DB
│  ├─ deputy-ecosystem/           # trait DepEcosystem + registry of impls
│  │  └─ ecosystems/cargo/        #   first impl: Cargo index, .crate fetch, Cargo.lock
│  ├─ deputy-acquire/             # recursive discovery + verified download → dirty store
│  ├─ deputy-analyze/             # language analytics + critical-point-of-failure scoring
│  ├─ deputy-scan/                # scanners: integrity, advisories, dirty-vs-prod diff
│  ├─ deputy-deploy/              # promote dirty→prod, redeploy into source, gate API
│  ├─ deputy-api/                 # the capability surface: in-proc API + local HTTP/IPC
│  ├─ deputy-cli/                 # headless CLI (client of deputy-api)
│  └─ deputy-ui/                  # Dioxus app, web (WASM) + native (client of deputy-api)
└─ docs/
```

Dependency direction (arrows = "depends on"):

```
deputy-ui ─┐
deputy-cli ─┴─▶ deputy-api ─▶ {acquire, analyze, scan, deploy} ─▶ {ecosystem, store, id} ─▶ {crypto, core}
                                                                                              core ◀── everything
```

No crate below `deputy-api` may depend on `deputy-ui`/`deputy-cli`. `deputy-core` depends
on nothing internal. This keeps the API the single source of truth and makes the UI
genuinely optional.

## 6. API-first surface

`deputy-api` defines every capability as a typed Rust trait, exposed two ways:

1. **In-process** — `deputy-ui` (native) and `deputy-cli` link it directly.
2. **Local transport** — a localhost-bound HTTP/JSON (and/or IPC) server for the WASM UI
   and for AI agents / scripts. Bound to loopback, mID-gated, never exposed to the network
   by default.

Illustrative surface (final shape lives in `deputy-api`):

```
identity:   verify_mid(assertion) -> Session
            current_session() -> Option<Session>
sources:    connect_github(token) -> SourceId
            list_repos(SourceId) -> Vec<Repo>
acquire:    discover(SourceId) -> DependencyGraph
            acquire(DepRef) -> ArtifactRef            # → dirty repo
analyze:    language_report(SourceId) -> LanguageReport
            failure_points(SourceId) -> Vec<RiskScore>
scan:       scan(ArtifactRef) -> ScanVerdict
            diff(dirty: ArtifactRef, prod: ArtifactRef) -> Diff
deploy:     promote(ArtifactRef) -> PromotionReceipt   # dirty → prod, requires clean scan
            redeploy(SourceId) -> DeployPlan
            gate(deploy_request) -> GateDecision        # block if any dep not clean
plans:      send_upgrade_plans(folder, repo?)           # per-repo Cargo.lock → docs/plans/
                                                        # (direct + transitive; crates.io latest ≥ 7 days)
```

Every mutating call takes a `Session` and is rejected without a valid mID
([AUTH.md](./AUTH.md)). Calls are designed to be **idempotent and content-addressed** so
an interrupted run is safe to retry.

## 7. Ecosystem-first target: Cargo

"All dependencies across all repos" spans npm, PyPI, Go, Maven, and more — far too much
for one beachhead. We start with **Cargo** because:

- It dogfoods Deputy's own stack (Deputy's deps are the first thing it secures).
- The registry model is clean: a sparse index, immutable `.crate` tarballs, and
  `Cargo.lock` gives an exact, already-pinned transitive graph.
- Local source replacement (`[source.crates-io] replace-with` / vendoring) is a
  first-class Cargo feature, so "deploy from the prod repo" maps onto an existing,
  well-understood mechanism instead of a hack.

`deputy-ecosystem` defines a `DepEcosystem` trait (discover graph, resolve pins, fetch
artifact, verify integrity, materialize into source). Cargo is the first implementor;
adding npm/PyPI later means implementing the trait, no pipeline-core changes. See
[PIPELINE.md](./PIPELINE.md) for the Cargo flow in detail.

## 8. Technology choices

| Concern | Choice | Note |
|---|---|---|
| Language | Rust (stable) | WASM for browser |
| UI | Dioxus | one codebase, web + native |
| Async runtime | Tokio | server/CLI; WASM uses wasm-bindgen-futures |
| KDF / AEAD | Argon2id / AES-256-GCM | via `argon2`, `aes-gcm` ([STORAGE.md](./STORAGE.md)) |
| mID verify | pure Rust port | crate choice pending auth research ([AUTH.md](./AUTH.md)) |
| Metadata store | encrypted embedded DB | candidate: SQLite (SQLCipher-style sealing) or redb + sealed blobs; decided in STORAGE.md |
| License gate | `cargo-deny` | CI fails on GPL/LGPL or banned crates |

## 9. Related documents

- [THREAT_MODEL.md](./THREAT_MODEL.md) — assets, adversaries, trust boundaries, the gate.
- [STORAGE.md](./STORAGE.md) — what's stored where, encryption, key hierarchy, on-disk layout.
- [AUTH.md](./AUTH.md) — MATA mID, pure-Rust verification, identity/session model.
- [PIPELINE.md](./PIPELINE.md) — the Cargo acquire → analyze → scan → promote → deploy flow.
- [ROADMAP.md](./ROADMAP.md) — phased milestones.
