# deputy-acquire

[![crates.io](https://img.shields.io/crates/v/deputy-acquire.svg)](https://crates.io/crates/deputy-acquire)
[![docs.rs](https://img.shields.io/docsrs/deputy-acquire)](https://docs.rs/deputy-acquire)

Recursive dependency discovery and verified download into the dirty store.

Part of **[Deputy](https://github.com/Remade-With-Rust/deputy)** — a personally-owned, verified vault and supply-chain gate for your code dependencies.

## What it does

Orchestrates acquisition: discover a source's pinned dependencies, fetch each, verify its content hash, and seal it into the **dirty** store with a provenance record. It is generic over `deputy_core::DepEcosystem`, so it works for Cargo today and any future ecosystem without change. Each dependency is handled independently and fail-closed — a fetch or integrity failure is recorded in the report and the artifact is not sealed, but the run continues — so only bytes whose SHA-256 matches the pinned checksum ever reach the store.

## Usage

```toml
[dependencies]
deputy-acquire = "0.1"
```

## License

Dual-licensed under [MIT](https://github.com/Remade-With-Rust/deputy/blob/main/LICENSE-MIT) OR [Apache-2.0](https://github.com/Remade-With-Rust/deputy/blob/main/LICENSE-APACHE), at your option.
