# Deputy — Storage & Encryption ("What's Stored Where")

> Status: **Design** · Last updated: 2026-06-24
> Implements the encryption requirements in `README.md` and the at-rest threats in
> [THREAT_MODEL.md](./THREAT_MODEL.md) (A2–A5, ADV-4).

## 1. On-disk layout

Everything lives under a single Deputy home (default `~/.deputy`, overridable). Nothing
sensitive is written outside it.

```
~/.deputy/
├─ deputy.toml              # non-secret config (paths, ecosystem settings)
├─ identity/
│  └─ device.json           # device-bound public material + KDF params (salt). NO secrets.
├─ keys/
│  └─ master.kdf            # Argon2id params + salt + verifier. NOT the key itself.
├─ store/
│  ├─ dirty/                # staging artifacts, content-addressed, each AEAD-sealed
│  │  └─ <algo>/<hash[..2]>/<hash>.sealed
│  ├─ prod/                 # promoted artifacts, content-addressed, AEAD-sealed, append-only
│  │  └─ <algo>/<hash[..2]>/<hash>.sealed
│  └─ meta.db               # encrypted metadata DB (graph, verdicts, provenance, receipts)
└─ logs/
   └─ audit.log             # hash-chained, append-only provenance log (encrypted records)
```

**Content addressing.** An artifact's filename *is* its hash (e.g. SHA-256 of the canonical
artifact bytes). This makes "is this exact dependency clean?" a hash lookup, makes the gate
TOCTOU-resistant, and makes re-acquisition idempotent.

## 2. Encryption design

Two layers, both required by `README.md`:

- **KDF:** Argon2id derives the **master key (MK)** from a **user passphrase** + a per-device
  random salt. (mID is sign/verify-only and exports no secret, so it gates *unlock* but does
  not supply the key — see [AUTH.md §8](./AUTH.md).) Argon2id parameters (memory, iterations,
  parallelism) are stored in `keys/master.kdf` alongside the salt and a key *verifier* (an
  AEAD encryption of a known constant) so we can detect a wrong secret without storing the
  key. **The MK is never written to disk** — derived into memory on unlock, zeroized on lock.
- **AEAD:** AES-256-GCM protects everything at rest. **Artifacts and the audit log** are sealed
  directly by Deputy (`nonce ‖ ciphertext ‖ tag`, 96-bit random nonces). **Metadata** is
  encrypted by SpaceDB's collection layer instead: `K_meta` is the *key-encryption key (KEK)*
  that wraps a per-collection *data-encryption key (DEK)*, and SpaceDB AES-256-GCM-encrypts each
  metadata row under the DEK (see §4). Deputy no longer seals metadata rows itself.

### Key hierarchy

```
user passphrase ──Argon2id(salt, params)──▶  Master Key (MK)  [memory only]
   (mID session gates unlock; see AUTH.md §8)
                                                          │ HKDF-SHA256(MK, context)
                          ┌───────────────────────────────┼───────────────────────────┐
                          ▼                                ▼                            ▼
                  K_store ("store")             K_meta ("metadata")          K_audit ("audit")
                          │                          │ = SpaceDB vault key (KEK)
            per-artifact subkey =                    ▼ wraps a per-collection DEK
            HKDF(K_store, content_hash)         SpaceDB encrypts metadata rows under the DEK
                          ▼
              seal artifact bytes (Deputy)     K_audit ──▶ seal audit records (Deputy)
```

Deriving a **per-artifact subkey from the content hash** means each artifact is encrypted
under a distinct key, so random 96-bit nonces are collision-safe even across very large
stores, and the encryption is deterministic in key (not in ciphertext, since the nonce is
random) — good for dedupe-by-hash without leaking equality of plaintext beyond the hash we
already store.

## 3. What's stored where (asset → location → protection)

| Asset | Location | At rest | In memory |
|---|---|---|---|
| Dependency artifacts (dirty) | `store/dirty/**` | AES-256-GCM, per-artifact subkey | decrypted on demand, dropped after use |
| Dependency artifacts (prod) | `store/prod/**` | AES-256-GCM, per-artifact subkey, append-only | same |
| Dependency graph, scan verdicts, promotion receipts, risk scores | `store/meta.db` | AES-256-GCM (K_meta) | decrypted rows only while needed |
| Provenance / audit | `logs/audit.log` | AES-256-GCM records (K_audit), hash-chained | — |
| Argon2id params + salt + verifier | `keys/master.kdf` | plaintext params, **no key** | — |
| Master key & subkeys | — | **never persisted** | memory only, zeroized on lock |
| GitHub token | `store/meta.db` (sealed) | AES-256-GCM | decrypted only for API calls |
| mID public/device material | `identity/device.json` | non-secret | — |

## 4. Metadata store choice

Requirements: embedded (no server), encryptable at rest, transactional (promotion must be
atomic), queryable for the dependency graph.

- **Chosen: SpaceDB Layer 0** (`spacedb-store`, Remade With Rust) — the engine-agnostic,
  transactional, order-preserving KV store, on its durable `RedbEngine` (redb is now an
  *internal engine detail* of SpaceDB, not a direct Deputy dep), `Durability::Immediate` (fsync)
  on writes. This fulfils the requirement *use redb until spacedb is available*.
- **Encryption: SpaceDB's native per-collection AEAD.** Deputy opens an encrypted
  `Collection<String, Vec<u8>>`; `K_meta` is the **KEK** (`StaticKeyProvider`) under which
  SpaceDB wraps a fresh per-collection **DEK**, then AES-256-GCM-encrypts each row (AAD =
  collection name + key + schema version). Deputy stores **plaintext** values and lets SpaceDB
  encrypt — it no longer seals metadata itself. (Tested: a value marker never appears in the
  on-disk `meta.db`.)
- **History:** M1 shipped on `redb` + Deputy's manual seal; we then swapped the engine to
  SpaceDB, then adopted SpaceDB's native encryption — each step a single-crate change in
  `deputy-store`, exactly as the `MetadataStore` abstraction promised. SQLite/SQLCipher was
  rejected (C library; opaque crypto boundary).
- **Available next:** SpaceDB's higher layers (CRDT, replica, durability modes) — deferred.

**Status:** implemented on SpaceDB with native row encryption. Keys are namespaced strings
(`verdict:<eco>:<hash>`, `crate:<store>:<name>:<version>`); values are DEK-encrypted by SpaceDB.
The graph is small (thousands of nodes), so KV + in-memory query is sufficient.

## 5. Integrity & append-only guarantees

- **Prod is append-only.** Promotions add sealed artifacts and append a **promotion receipt**
  to a hash-chained log (`receipt_n.prev_hash = H(receipt_{n-1})`). Removing or rewriting a
  promotion breaks the chain and is detectable at unlock.
- **AEAD everywhere** means any bit-flip in an artifact or record fails decryption — silent
  corruption/tampering cannot pass unnoticed.
- The **gate** ([THREAT_MODEL.md §4](./THREAT_MODEL.md)) trusts only `store/prod` entries
  that have a valid receipt in the chain and a clean verdict in `meta.db`.

## 6. Lock / unlock lifecycle

1. **Unlock:** obtain user secret (mID-bound) → Argon2id → MK → HKDF subkeys → verify against
   `master.kdf` verifier. On success the session is live.
2. **Operate:** subkeys live in a zeroize-on-drop wrapper; artifacts decrypted just-in-time.
3. **Lock:** explicit lock, session expiry, or process exit zeroizes MK and all subkeys. After
   lock, the on-disk store is opaque without re-deriving the MK.

## 7. SpaceDB layers (beyond Layer 0)

Deputy builds on SpaceDB (Remade With Rust) as more than a KV. Each layer slots in behind an
existing seam, so the rest of Deputy is unaffected:

| Layer | SpaceDB crate | In Deputy | Surface |
|---|---|---|---|
| **0** storage | `spacedb-store` | the durable, transactional metadata KV (redb engine) | — |
| **1+3** CRDT/consistency | `spacedb-crdt` | metadata as LWW registers in a `CrdtDoc`; conflict-free **multi-device sync** (export/import; new entries union, same key resolves LWW) | `deputy sync export/import` |
| **2 cold** durability | `spacedb-durability` | Reed-Solomon erasure-coded **vault snapshots** (k-of-n recovery; survives lost shards) | `deputy snapshot` / `deputy restore` |
| **2 hot** replica | `spacedb-replica` | the delta primitive (`state_vector`/`encode_update_since`) is in place; the **live always-on transport** is the documented networked extension (a daemon, not the CLI's model) | — |
| **5** access | `spacedb-access` | every API op gated by a **signed, scoped, expiring, revocable capability** (P-256, mID family) — for humans AND AI agents | `DeputyService::grant` / `revoke` |

Encryption boundaries: metadata rows are encrypted by SpaceDB's per-collection DEK (KEK =
`K_meta`, §2/§4). Snapshots archive the already-encrypted vault files (no passphrase needed).
The CRDT sync blob is a **portable, unencrypted** update — transfer it over a secure channel
between your own devices (a future revision derives a shared sync key from the user's mID).

## 8. Open questions

- [x] mID vs. the Argon2id secret: **resolved** — separate factors. Passphrase derives the key;
      mID session gates unlock ([AUTH.md §8](./AUTH.md)). Optional future: bind a passphrase-wrapping
      factor to an mID device key.
- [ ] Shared sync key from the user's mID, so the CRDT sync blob can be encrypted across devices.
- [ ] Key rotation: re-seal under a new MK without exposing plaintext to disk (stream re-seal).
- [ ] Deliberate trade-off to confirm with the user: **lost secret ⇒ unrecoverable store**
      (no backdoor). Optional, explicitly-opt-in escrow is a possible future feature, not a default.
