# deputy-crypto

[![crates.io](https://img.shields.io/crates/v/deputy-crypto.svg)](https://crates.io/crates/deputy-crypto)
[![docs.rs](https://img.shields.io/docsrs/deputy-crypto)](https://docs.rs/deputy-crypto)

Argon2id key derivation, AES-256-GCM sealing, and the key hierarchy for Deputy's encryption at rest.

Part of **[Deputy](https://github.com/Remade-With-Rust/deputy)** — a personally-owned, verified vault and supply-chain gate for your code dependencies.

## What it does

Provides Deputy's encryption-at-rest primitives. A passphrase is stretched with Argon2id into a master key, which is split via HKDF-SHA256 into per-domain and per-artifact subkeys used for AES-256-GCM seal/open. No key material is ever serialized, logged, or written to disk — keys zeroize on drop, and only non-secret KDF params plus a verifier blob are persisted, so a wrong passphrase is detectable without storing the key.

## Usage

```toml
[dependencies]
deputy-crypto = "0.1"
```

## License

Dual-licensed under [MIT](https://github.com/Remade-With-Rust/deputy/blob/main/LICENSE-MIT) OR [Apache-2.0](https://github.com/Remade-With-Rust/deputy/blob/main/LICENSE-APACHE), at your option.
