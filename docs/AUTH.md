# Deputy — Authentication (MATA mID, pure-Rust)

> Status: **Design (spec-complete, port pending)** · Last updated: 2026-06-24
> This is the authoritative port spec for Deputy's `deputy-id` crate. It is grounded in
> the published `@matanetwork/sovereign-id*` packages (v0.1.0, MIT, zero-dependency,
> unminified), which mirror a private Rust reference (`mid-verify`, `mid-issuer::canonical`,
> `mid-consent-types`). **If that reference crate is available, it — not the JS — is the
> source of truth; see [§10](#10-open-questions).**

## 1. Role of mID in Deputy

mID is Deputy's **authentication & authorization** mechanism — the "main sign-on" from the
root `README.md`. A verified mID assertion yields a `Session`; every mutating API call and
every pipeline state transition requires one ([THREAT_MODEL.md](./THREAT_MODEL.md) A4).

**mID is *not* a key-derivation source.** The protocol is sign/verify-only: P-256 ECDSA over
signed tokens, **no KDF, no encryption, no secret export**. So the at-rest encryption key
([STORAGE.md](./STORAGE.md)) is derived from a separate **user passphrase**, and the mID
session *gates* unlock/operations. Authentication (mID) and at-rest confidentiality
(Argon2id passphrase) are deliberately separate concerns — see [§8](#8-relationship-to-storage).

## 2. Identity model

- **Self-issued, permissionless DIDs.** Method `did:mata:`. **No central issuer, no DID
  registry, no JWKS, no network call during verify** — everything needed travels inside the
  token.
- **The DID *is* the genesis public key.** `did:mata:<base58btc(33-byte SEC1-compressed
  P-256 pubkey)>`. The suffix base58-decodes to exactly 33 bytes = the genesis verification key.
- **Versioned roster of verification methods (VMs).** A "roster" is a DID-document-like
  object `{version, did, verification_methods[], signed_at, …}`. Devices are added/revoked by
  appending **signed roster-chain entries**. The current signing device must appear in the
  **head** roster — that, with zero network calls, is how revocation works.
- **Claims are self-attested.** Each claim is `{value, attested_by:'self', verified_at_signup?,
  computed_at?, formula_version?}`. Catalog: `did, email, name, created_at,
  paired_devices_count, level_rating.{trust,security,incentive}`. Treat `value` as untrusted
  JSON.

## 3. Token format (JWS compact, ES256)

`base64url(header) "." base64url(payload) "." base64url(64-byte r‖s signature)`

- **Header:** exactly `{"alg":"ES256","typ":"JWT"}` — anything else is rejected (no `kid`;
  the signing key is embedded in the payload, so there is no `alg`-confusion surface).
- **Signature:** raw **64-byte `r‖s`** (NOT ASN.1/DER). Length ≠ 64 ⇒ reject.
- **Payload fields:**
  - `iss` — the `did:mata:…` DID → `verified.did`
  - `aud` — relying-party bare origin (compared to `expectedAudience`)
  - `nonce` — RP single-use nonce
  - `iat`, `exp` — unix **seconds**
  - `claims` — `Record<string, ClaimValue>`
  - `embedded_genesis_roster` — `{version, did, verification_methods[], signed_at,
    self_signed_by_genesis_key}` (the last is base64url(64-byte sig))
  - `embedded_roster_chain` — array (maybe empty/absent) of `{version, did,
    verification_methods[], signed_at, signer_kid, signed_by_signer_in_prior_roster}`
  - `embedded_verification_method` — `{id, type, controller, public_key_multibase}` for the
    current signing device. `id` ends in `#<kid>`; `public_key_multibase` is
    `z<base58btc(33-byte key)>`.

## 4. Canonical byte encoding (must match byte-for-byte)

Roster signatures are **not over JSON** — they're over a hand-built, length-prefixed binary
encoding (mirrors `mid-issuer::canonical`). Get this wrong and every signature fails.

- **Primitives:** string = `u32-BE length ‖ UTF-8`; integer = `u64-BE`; VM array =
  `u32-BE count` then per VM `str(id) ‖ str(type) ‖ str(controller) ‖ str(public_key_multibase)`.
  **All length prefixes and integers are big-endian.**
- **Genesis canonical** — domain `"mid-genesis-roster-v1"`:
  `domain ‖ u64BE(version) ‖ str(did) ‖ vms(verification_methods) ‖ u64BE(signed_at)`
- **Chain-entry canonical** — domain `"mid-roster-chain-v1"`:
  `domain ‖ u64BE(version) ‖ str(did) ‖ vms(…) ‖ u64BE(signed_at) ‖ str(signer_kid)`
- **JWS outer signature** is over the ASCII signing input `base64url(header) "." base64url(payload)`
  (standard JWS, no domain prefix).
- **Genesis anchor hash** = `hex(SHA-256(genesisCanonicalBytes))` → `verified.genesisRosterHash`.

## 5. Verification algorithm (`verify(token, config) -> Verified`)

Config: `{ expected_audience, expected_nonce, now_unix_secs, max_iat_skew_secs = 120 }`.

1. **Split & shape:** exactly 3 segments; base64url-decode each; signature exactly 64 bytes;
   header valid JSON.
2. **Header:** `alg == "ES256" && typ == "JWT"`.
3. **Parse** payload JSON.
4. **Metadata, in order:** `aud == expected_audience`; `nonce == expected_nonce`;
   `now < exp` (else `expired`); `iat <= now + skew` (else `not_yet_valid`).
   ⚠️ There is **no lower-bound `iat`/`nbf` and no max-lifetime check** — only forward skew.
5. **Genesis self-signature:** recover the 33-byte key from `iss`, verify
   `embedded_genesis_roster.self_signed_by_genesis_key` over the genesis canonical bytes.
6. **Roster-chain walk:** start from genesis VMs/version. For each chain entry: enforce
   strictly monotonic `version > prior`; find the signer VM in the **prior** roster by
   `vm.id` ending in `#<signer_kid>`; verify `signed_by_signer_in_prior_roster` over the
   chain-entry canonical bytes; advance prior. (This is key-rotation history / chain of trust.)
7. **Head-roster membership:** `embedded_verification_method.id` must exist in the head roster
   (last chain entry, else genesis). **This is the revocation check.**
8. **JWS signature:** verify the 64-byte token signature over `header.payload` using the
   current VM's key.
9. **Return** `Verified { did, genesis_roster_hash, current_version, claims, iat, exp, aud }`.

**Caller's responsibility (NOT done inside verify) — Deputy must wire these:**
- **Nonce single-use** — verify only checks equality; replay prevention requires Deputy to
  generate, store, and consume each nonce.
- **Anchoring / rollback** — persist `(did, genesis_roster_hash, last_seen_version)`; assert
  the genesis hash is **immutable per DID** (a different genesis for a known DID = spoofing)
  and that `current_version` never decreases (`rollback_detected`).

## 6. Error taxonomy (snake_case, mirrors `mid-verify::VerifyError`)

`invalid_jws_shape, base64_decode, invalid_jws_header, payload_json, audience_mismatch,
nonce_mismatch, expired, not_yet_valid, malformed_did, malformed_vm_pubkey,
signature_wrong_length, genesis_signature_invalid, chain_signer_not_in_prior_roster,
chain_signature_invalid, chain_version_not_monotonic, current_vm_not_in_head_roster,
jwt_signature_invalid, rollback_detected`

Deputy reproduces these variants verbatim so behavior matches the reference and logs are
comparable across the JS SDK and the Rust port.

## 7. Rust crate mapping

| Need | Crate | Note |
|---|---|---|
| ECDSA P-256 verify (raw r‖s, SHA-256) | **`p256`** (`ecdsa::Signature::from_bytes` 64-byte fixed, `VerifyingKey::verify`) | RustCrypto |
| SEC1 compressed pubkey parse | **`p256`** `VerifyingKey::from_sec1_bytes(&compressed_33)` | handles decompression + on-curve + identity rejection — **do not hand-roll** |
| SHA-256 | **`sha2`** | |
| base64url unpadded | **`base64`** `URL_SAFE_NO_PAD` | decide strictness deliberately ([§10](#10-open-questions)) |
| base58btc | **`bs58`** | Bitcoin alphabet matches the JS |
| multibase `z…` | **`multibase`** or strip `z` + `bs58` | |
| JSON | **`serde_json`** | `claims.value` = untrusted `Value` |
| canonical bytes | plain `Vec<u8>` + `to_be_bytes()` | match §4 exactly |

**Do NOT use a generic JWT/JOSE library** (`jsonwebtoken`, `josekit`, `jose`). The token uses
raw r‖s signatures, an embedded key (no JWKS/`kid`), and a hard-pinned `ES256`. A generic lib
reintroduces `alg`-confusion and DER/raw-encoding mismatches we've specifically designed out.
Hand-split the three segments and verify with `p256`. No `argon2`/`aes-gcm`/`ed25519`/`k256`
here — the protocol is P-256, sign/verify-only.

## 8. Relationship to storage

```
mID assertion ──verify(§5)──▶ Session  ──gates──▶  unlock + every pipeline transition
user passphrase ──Argon2id──▶ Master Key ──▶ AES-256-GCM at rest   (STORAGE.md)
```

Two independent factors: the **mID session** proves *who* is acting (authorization); the
**passphrase-derived key** provides *confidentiality at rest*. Unlock requires both — a
verified mID session **and** the correct passphrase. Neither alone is sufficient, which means
a stolen device (no mID) and a forged session (no passphrase) both fail. Optional future work
([STORAGE.md §7](./STORAGE.md)) could bind a passphrase-wrapping factor to an mID-held device
key, but mID itself exports no such secret today.

## 9. Session model

- `verify` success → a short-lived, device-bound `Session { did, claims, expires_at }`.
- Sessions live in memory only; expiry or lock drops them (and zeroizes storage subkeys).
- The API layer rejects any mutating call without a live `Session` — no anonymous write path.
- `deputy-id` exposes `verify`, plus `check_rollback(verified, last_seen_version)` and the
  nonce store, so the out-of-band duties in [§5](#5-verification-algorithm-verifytoken-config---verified) are first-class, not afterthoughts.

## 10. Open questions

1. **Use the private Rust reference directly?** — **Resolved: crates.io dependency on the
   published mID crates.** `deputy-id` depends on `mid-signin` (`=0.1.1`; its `mid-verify` core
   remains `=0.1.0`) and, in tests, `mid-issuer`/`kms-client` (`=0.1.1`) from crates.io — published from
   [`github.com/Remade-With-Rust/mid`](https://github.com/Remade-With-Rust/mid) (Deputy practises
   its own thesis — a trust-base dependency is frozen, never a moving range). `verify` is
   implemented; 9 tests pass against real wallet-minted tokens.

   **Portability — fully resolved.** Both the mID crates *and* the SpaceDB crates now resolve
   from crates.io (`=0.1.0`); **no path or git dependencies remain**, so the workspace builds
   anywhere and every `deputy-*` crate is publishable (`mata-master` is no longer required —
   `cargo fmt --all` can no longer escape into it, but keep scoped `-p` flags out of habit). See
   [`RELEASING.md`](../RELEASING.md).

   **Accepted cost (unchanged):** the chain `mid-verify → mid-issuer → kms-client` still drags a
   full async HTTP/TLS stack (`reqwest`/`tokio`/`hyper`/`rustls`/`ring`) into the identity path,
   even though verification makes zero network calls — `mid-issuer` hard-depends on `kms-client`
   (the *signing*/nonce-HTTP side) only for the `DeviceSigner` trait. `cargo deny` allows
   `CDLA-Permissive-2.0` (webpki-roots) accordingly.

   **Still open (one follow-up):** *slim it* — feature-gate `kms-client`'s `reqwest` (or split a
   trait/types-only crate) upstream, so Deputy's verifier pulls only `p256`/`sha2`/`base64`/`bs58`.

1a. **mID is a runtime toggle — on by default, deactivatable.** The service surface gates on a
   verified mID `Session` by default (`DeputyService::open`), but can run under a synthetic local
   identity (`DeputyService::open_local`, DID `did:deputy:local`) for embedding Deputy in software
   that owns its own auth, or for local development. The capability layer (§ SpaceDB Layer 5)
   still gates every op in both modes. CLI: `deputy serve` requires `DEPUTY_MID_TOKEN`
   (+ `DEPUTY_MID_NONCE`, and `DEPUTY_MID_AUDIENCE` if not the bind URL) by default; `--no-mid`
   deactivates it. The `/health` endpoint reports `mid_active`. **The headless pipeline commands
   (`acquire`/`scan`/`promote`/`gate`/`deploy`) carry no mID** — they operate on the local vault,
   gated by passphrase possession; mID authenticates the *principal driving the API*, the
   passphrase authenticates *local device access*.
2. **Issuer side is absent from the JS.** We can verify but not see exactly how the wallet
   builds `self_signed_by_genesis_key`, assigns `signer_kid`, or formats `signed_at`. Test
   vectors must be validated against a real wallet-issued token before we trust the encoder.
3. **VM `type`/`controller` exact strings** are length-prefixed into canonical bytes verbatim;
   unknown values would break chain signatures — confirm against a real token.
4. **base64url strictness** — the JS decoder is lenient; decide whether the Rust port is strict
   (recommended) to avoid token-mutation quirks.
5. **No `nbf`/max-lifetime** in the reference verifier. If Deputy's threat model wants them,
   they're an explicit Deputy addition, documented as such — not part of the faithful port.
