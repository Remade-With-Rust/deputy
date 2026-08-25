# Deputy — Pipeline (Cargo-first)

> Status: **Design** · Last updated: 2026-06-24
> The concrete acquire → analyze → scan → promote → deploy flow, specialized to the first
> ecosystem, **Cargo / Rust**. The flow generalizes via the `DepEcosystem` trait.

## 0. The `DepEcosystem` trait

Every ecosystem (Cargo first; npm/PyPI later) implements:

```rust
// As implemented in deputy-core (M3). A lockfile already pins exact versions to hashes, so
// `discover` returns Pins directly rather than a graph + separate resolve step.
trait DepEcosystem {
    fn id(&self) -> EcosystemId;
    fn discover(&self, source: &SourceId) -> Result<Vec<Pin>>;          // pins from the lockfile
    fn fetch(&self, pin: &Pin) -> Result<Vec<u8>>;                      // download bytes (untrusted)
    fn verify_integrity(&self, pin: &Pin, raw: &[u8]) -> Result<()>;    // SHA-256 vs pinned checksum
}
```

Core enforces the state machine; the impl supplies ecosystem-specific mechanics. An impl
produces candidates for the **dirty** repo only — never prod ([THREAT_MODEL.md](./THREAT_MODEL.md) ADV-6).
Materialization back into source (`deploy`) is a separate concern handled in M6, not part of
this trait.

## 1. Discover (GitHub source → dependency graph)

For Cargo:

1. Connect GitHub (scoped token, sealed in `meta.db`), enumerate repos.
2. For each repo, read **`Cargo.lock`** — this is the exact, already-resolved transitive
   graph. We drive acquisition from the lockfile, **not** from `Cargo.toml` version ranges or
   free-text names (defeats typosquat/confusion — [THREAT_MODEL.md](./THREAT_MODEL.md) ADV-3).
3. Parse `[[package]]` entries → `(name, version, source, checksum)`. The
   `checksum` (and the registry index `cksum`) is the **expected content hash** we pin to.
4. Build a `DependencyGraph`: nodes = crates, edges = dependency relations, annotated with
   which of *your* repos/targets pull each one in (used by analytics §3).

> Workspaces with no committed `Cargo.lock` (libraries): we resolve once, record the
> resolution as provenance, and flag it as "resolved by Deputy at <time>" so the pin source
> is auditable.

## 2. Acquire (download → dirty repo)

For each pinned crate:

1. **Fetch** the immutable `.crate` tarball from the crates.io CDN by exact version (TLS).
2. **Verify integrity:** SHA-256 of the bytes must equal the lockfile/index `checksum`.
   Mismatch ⇒ reject, log, alarm. No "download and hope."
3. **Seal & store** under `store/dirty/sha256/<hash>.sealed` (content-addressed,
   [STORAGE.md](./STORAGE.md)). Re-acquisition of the same hash is a no-op (idempotent).
4. **Record provenance:** source URL, resolved version, hash, timestamp, acquiring mID.

State: `Discovered → Acquired`.

## 3. Analyze (language analytics + critical points of failure)

Runs over the acquired graph + your source.

- **Language analytics:** classify your core code and each dependency by language and lines,
  produce the `LanguageReport` (what your stack actually depends on, and in which languages
  your risk concentrates).
- **Critical-point-of-failure scoring** — per dependency, a `RiskScore` combining:
  - **Blast radius:** how many of your repos/build targets transitively depend on it
    (fan-in from §1's annotations).
  - **Criticality of path:** is it on a build, runtime, auth, or crypto path?
  - **Capability surface:** does it use `unsafe`, run build scripts / proc-macros, touch
    network / filesystem / process?
  - **Maintenance health:** single-maintainer / low bus-factor, staleness, yanked versions.
  - **Advisory exposure:** open RUSTSEC advisories for the pinned version.
  - Output: a ranked "if this is compromised, here's the damage" list — the analytics the
    README promises.

State annotation: `Acquired → Analyzed`.

## 4. Scan (on change, dirty vs prod)

Scanners run automatically when the dirty repo changes:

- **Integrity scan:** re-verify the sealed artifact's hash matches its address.
- **Advisory scan:** check pinned versions against RUSTSEC / advisory data.
- **Diff vs prod:** for any crate already in prod, compute `diff(dirty, prod)`. A changed
  hash for the "same" name+version is a red flag (immutability violation upstream) and blocks
  promotion pending review.
- **Build-script / proc-macro policy** (open question, [THREAT_MODEL.md](./THREAT_MODEL.md)):
  initially **static-only** inspection of `build.rs` / proc-macro crates with findings
  surfaced; sandboxed execution is a later milestone, never a silent default.

Output: a `ScanVerdict { clean | findings[] }`. State: `Analyzed → Scanned`.

## 5. Promote (dirty → prod)

- Only an **mID-verified** actor may promote, and only a `Scanned` artifact with a **clean**
  verdict.
- Promotion: seal into `store/prod/...`, append a **promotion receipt** to the hash-chained
  log ([STORAGE.md §5](./STORAGE.md)) recording `(content_hash, verdict_id, mID, time)`.
- Promotion is **append-only** and atomic. A dirty artifact whose scan found issues is
  `Quarantined`, not promoted.

State: `Scanned → Promoted` (or `→ Quarantined`).

## 6. Deploy & gate (prod → your source → CI)

- **Redeploy into source:** `materialize` produces a plan that points your repo at the prod
  copies. For Cargo this is **source replacement / vendoring** — generate a vendored source
  dir from prod artifacts and a `[source.crates-io] replace-with = "deputy-prod"` config, so
  builds consume the owned, verified copies instead of live crates.io.
- **The gate (fail-closed):** the deploy/gate API refuses unless **every** dependency hash in
  the deploy request exists in prod with a clean verdict and a valid receipt. Any unknown
  hash, dirty-only hash, stale scan, or broken receipt chain ⇒ **blocked**. This is the
  "gate any hacked deployments" requirement, enforced on content hashes (no TOCTOU).
- Exposed as an API a GitHub Action / CI step calls before shipping; a non-clean tree fails
  the build.

State: `Promoted → Deployed`.

## 7. Upgrade plans (GitHub write, not a vault transition)

**Send Plans** (`POST /folders/upgrade-plans`) commits `docs/plans/deputy-upgrades.md` into
each GitHub repo in the current workspace. GitHub creates `docs/plans/` if it is missing.
This is a documentation write (Contents API), **not** a `Promoted` → `Deployed` edge and not
Redeploy-to-production.

Each file is **that repo's** `Cargo.lock` — crates declared there **and** their transitive
graph — whose latest crates.io release is at least **7 days old**. It is not Deputy's vault
and not a copy of another repo's list. Group / all-workspaces views write one file per child
repo. Local ingest names are skipped.

`latest` is the newest crates.io version of that crate **name**. Compatible (same-major) bumps
are usually `cargo update`; a new major needs a `Cargo.toml` change in the crate that pulled
it in. Several rows for one crate mean the lockfile still contains more than one major.

## 8. End-to-end state machine

```
Discovered ─▶ Acquired ─▶ Analyzed ─▶ Scanned ─┬─ clean ─▶ Promoted ─▶ Deployed
                                                └─ findings ─▶ Quarantined ─(re-scan)─▶ …
```

Every edge is mID-gated, content-addressed, and provenance-logged. Only `Promoted` artifacts
are eligible for `Deployed`, and the gate re-checks at deploy time.

## 9. Generalizing beyond Cargo

To add npm: implement `DepEcosystem` reading `package-lock.json` (pins + integrity hashes),
fetch tarballs, verify `integrity` (SRI), materialize via a vendored registry / `.npmrc`. No
changes to the state machine, gate, storage, or auth. PyPI, Go modules follow the same shape.
