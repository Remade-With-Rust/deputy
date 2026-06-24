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
- **AEAD:** AES-256-GCM seals every artifact and every metadata record. Each sealed blob is
  `nonce ‖ ciphertext ‖ tag`. Nonces are 96-bit, random per blob (we never reuse a nonce
  under a given subkey — see §3 for the per-blob subkey scheme that makes this safe at scale).

### Key hierarchy

```
user passphrase ──Argon2id(salt, params)──▶  Master Key (MK)  [memory only]
   (mID session gates unlock; see AUTH.md §8)
                                                          │ HKDF-SHA256(MK, context)
                          ┌───────────────────────────────┼───────────────────────────┐
                          ▼                                ▼                            ▼
                  K_store ("store")             K_meta ("metadata")          K_audit ("audit")
                          │                                                  
            per-artifact subkey =                                           
            HKDF(K_store, content_hash)  ──▶ seal artifact bytes            
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

- **Chosen:** `redb` (pure-Rust embedded KV, ACID) with **application-level AEAD** — each
  value is sealed with K_meta before write, so the DB file leaks nothing in the clear. Keeps
  us pure-Rust and puts encryption under our control. This is also the project requirement:
  *use redb on local devices until spacedb is available*. `redb` sits behind the
  `MetadataStore` contract, so swapping in spacedb later is a single-crate change.
- **Rejected:** SQLite/SQLCipher — pulls in a C library (tension with "Rust everywhere") and
  a less transparent crypto boundary.

**Status (M1):** implemented. Keys are namespaced strings (`verdict:<eco>:<hash>`); values are
AEAD-sealed (AAD = the key). The graph is small (thousands of nodes), so KV + in-memory query
is sufficient.

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

## 7. Open questions

- [x] mID vs. the Argon2id secret: **resolved** — separate factors. Passphrase derives the key;
      mID session gates unlock ([AUTH.md §8](./AUTH.md)). Optional future: bind a passphrase-wrapping
      factor to an mID device key.
- [ ] Key rotation: re-seal under a new MK without exposing plaintext to disk (stream re-seal).
- [ ] Deliberate trade-off to confirm with the user: **lost secret ⇒ unrecoverable store**
      (no backdoor). Optional, explicitly-opt-in escrow is a possible future feature, not a default.
