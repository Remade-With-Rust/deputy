# deputy-store

[![crates.io](https://img.shields.io/crates/v/deputy-store.svg)](https://crates.io/crates/deputy-store)
[![docs.rs](https://img.shields.io/docsrs/deputy-store)](https://docs.rs/deputy-store)

Content-addressed dirty/prod stores and the encrypted metadata database.

Part of **[Deputy](https://github.com/Remade-With-Rust/deputy)** — a personally-owned, verified vault and supply-chain gate for your code dependencies.

## What it does

Deputy's encrypted-at-rest storage layer. A `Vault` is the unlocked context: `create` initializes a new store and `unlock` re-derives the key hierarchy from a passphrase, rejecting the wrong one. It holds content-addressed dirty and prod artifact stores — each artifact sealed with AES-256-GCM under a per-artifact subkey and addressed by the SHA-256 of its bytes — plus an encrypted metadata database and a hash-chained, append-only audit log. Everything lives under one Deputy home directory (default `~/.deputy`).

## Usage

```toml
[dependencies]
deputy-store = "0.1"
```

## License

Dual-licensed under [MIT](https://github.com/Remade-With-Rust/deputy/blob/main/LICENSE-MIT) OR [Apache-2.0](https://github.com/Remade-With-Rust/deputy/blob/main/LICENSE-APACHE), at your option.
