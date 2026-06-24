# Deputy — Threat Model

> Status: **Design** · Last updated: 2026-06-24
> Deputy is a security tool. If this document and the code disagree, the code is wrong.

This is a living threat model. It states what Deputy protects, who it protects against,
where the trust boundaries are, and how each threat is mitigated. New features must extend
it before they ship.

## 1. Assets (what we protect)

| # | Asset | Why it matters |
|---|---|---|
| A1 | **Your source code** (cloned from GitHub) | The thing dependencies get deployed into. |
| A2 | **Dependency artifacts** (dirty + prod repos) | The supply chain itself; the primary attack surface. |
| A3 | **The prod ("golden") set** | The trust anchor for what's allowed to ship. Corrupting it defeats Deputy. |
| A4 | **mID identity & session** | Root of authority. Forging it grants every privileged action. |
| A5 | **Encryption keys / Argon2id-derived master key** | Decrypts everything at rest. |
| A6 | **The deploy gate decision** | The last line of defense; if bypassable, hacked deps ship. |
| A7 | **Provenance / audit log** | How we prove a given artifact was scanned, promoted, and by whom. |

## 2. Trust boundaries

```
   UNTRUSTED                          SEMI-TRUSTED                 TRUSTED (local, mID-gated)
 ┌───────────┐   network    ┌──────────────┐   API token   ┌─────────────────────────────┐
 │  Package  │◀────────────▶│    GitHub    │◀─────────────▶│  Deputy core on your device │
 │ registry  │   (TLS)      │  (your src)  │               │  - dirty repo  - prod repo  │
 │ (crates.io│              └──────────────┘               │  - metadata    - keys (mem) │
 │  + index) │                                             │  - gate decision            │
 └───────────┘                                             └──────────────┬──────────────┘
        ▲                                                                  │ root of trust
        │ artifacts arrive untrusted; trusted only after                  ▼
        │ integrity + signature + scan verification                  ┌─────────┐
                                                                     │ MATA mID│
                                                                     └─────────┘
```

- **Registry & network: untrusted.** Anything fetched is hostile until verified by content
  hash + (where available) signature, then cleared by a scan.
- **GitHub: semi-trusted.** Authenticated over TLS with a scoped token, but treated as an
  integrity-checkable source, not an authority on what is safe to ship.
- **Local device: trusted but theft-aware.** Data is encrypted at rest so a stolen disk
  doesn't leak assets. The live process holds keys in memory only.
- **MATA mID: root of trust.** Authorizes every state transition.

## 3. Adversaries

| ID | Adversary | Goal |
|---|---|---|
| ADV-1 | **Compromised upstream package / malicious maintainer** | Ship malware via a dep you already use. |
| ADV-2 | **Registry / index MITM** | Substitute a tampered artifact in transit. |
| ADV-3 | **Typosquatter / dependency-confusion attacker** | Get you to acquire the wrong package. |
| ADV-4 | **Local attacker / stolen device** | Read assets at rest or impersonate you. |
| ADV-5 | **Compromised CI / deploy pipeline** | Push a hacked dependency into production. |
| ADV-6 | **Malicious or buggy Deputy plugin/ecosystem impl** | Bypass verification from inside. |
| ADV-7 | **Supply chain on Deputy itself** | Compromise Deputy's own dependencies. |

## 4. Threats & mitigations (STRIDE, per boundary)

### Acquisition (registry → dirty repo) — ADV-1, ADV-2, ADV-3
- **Tampering (T):** every artifact is **content-addressed**; we pin to the exact hash from
  `Cargo.lock` and reject any download whose hash differs. Where the ecosystem provides
  signatures/checksums (crates.io index `cksum`), verify them too.
- **Spoofing (S):** TLS to the registry; pin expected checksums from the resolved lockfile,
  not from the live index alone, so a malicious index can't relax a pin.
- **Confusion/typosquat (ADV-3):** acquisition is driven by the *resolved dependency graph
  of your own source*, never free-text names. Private/internal names are flagged so a
  public package can't shadow an internal one.
- **Repudiation (R):** every acquisition writes a provenance record (source URL, resolved
  version, hash, timestamp, acquiring mID) to the audit log (A7).

### Storage at rest — ADV-4
- **Information disclosure (I):** AES-256-GCM over all repos + metadata; keys derived via
  Argon2id from a secret never written to disk. See [STORAGE.md](./STORAGE.md).
- **Tampering (T):** AEAD tags detect modification; the prod repo is append-only with a
  hash-chained promotion log so silent edits are detectable.

### Identity & authorization — ADV-4, ADV-5
- **Spoofing (S):** every privileged op requires a verified mID session
  ([AUTH.md](./AUTH.md)). Pure-Rust verification removes a second runtime from the trust
  base. Sessions are short-lived and bound to the local device.
- **Elevation (E):** the API rejects mutating calls without a valid `Session`; there is no
  "anonymous write" path.

### Promotion & deploy gate — ADV-5 (the headline defense)
- **The gate is fail-closed.** `deploy` / `gate` refuse unless the exact content hash being
  deployed exists in the **prod** repo with (a) a clean scan verdict and (b) a promotion
  receipt signed under the user's mID. Unknown hash, dirty-only hash, stale scan, or
  missing receipt → **blocked**.
- **No TOCTOU:** the hash checked at gate time is the hash of the bytes being deployed, not
  a name/version label that could be re-pointed after the check.
- **Elevation (E):** promotion (dirty→prod) and deploy are distinct, separately-authorized
  transitions; compromising CI alone (which can request deploy) cannot promote.

### Plugins / ecosystem implementations — ADV-6
- Ecosystem impls run behind the `DepEcosystem` trait and **cannot write to the prod repo**;
  they only produce candidates for the dirty repo. Verification (hash, signature, scan) is
  enforced by core, not by the plugin, so a malicious impl cannot self-certify.

### Deputy's own supply chain — ADV-7
- `cargo-deny` in CI: deny GPL/LGPL, deny known-vulnerable advisories, restrict sources.
- Minimal `unsafe`; every `unsafe`/FFI boundary documented and isolated.
- Deputy's own `Cargo.lock` is committed and is itself a first acquisition target
  (dogfooding).

## 5. Explicit non-goals / out of scope (for now)

- **Runtime sandboxing of dependency code execution** — Deputy verifies and gates *what you
  ship*; it is not a runtime EDR. (Build-script / proc-macro execution risk is tracked
  separately in [PIPELINE.md](./PIPELINE.md).)
- **Defending a fully root-compromised live device** — if the attacker already has your
  unlocked process memory, encryption-at-rest cannot help. We reduce, not eliminate, this.
- **Multi-tenant / shared-server deployment** — Deputy is personally owned and local-first
  by design.

## 6. Open security questions (to resolve before relevant code ships)

- [x] Exact mID verification algorithm & primitives — **resolved**, specified in [AUTH.md](./AUTH.md)
      (P-256/ES256, embedded roster chain, fail-closed verify, nonce/rollback are Deputy's duty).
- [ ] Build-script / proc-macro execution policy during analysis (execute in a sandbox vs.
      static-only analysis).
- [ ] Revocation: how a previously-promoted prod artifact is recalled when a later advisory
      lands, and how the gate learns about it.
- [ ] Key recovery / rotation story if the Argon2id secret is lost (and the deliberate
      trade-off: lost secret = unrecoverable data, by design).
