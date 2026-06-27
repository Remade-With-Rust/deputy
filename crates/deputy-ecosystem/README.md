# deputy-ecosystem

[![crates.io](https://img.shields.io/crates/v/deputy-ecosystem.svg)](https://crates.io/crates/deputy-ecosystem)
[![docs.rs](https://img.shields.io/docsrs/deputy-ecosystem)](https://docs.rs/deputy-ecosystem)

Dependency-ecosystem implementations behind the DepEcosystem trait (Cargo first).

Part of **[Deputy](https://github.com/Remade-With-Rust/deputy)** — a personally-owned, verified vault and supply-chain gate for your code dependencies.

## What it does

Implements the `deputy_core::DepEcosystem` trait for concrete package ecosystems. `CargoEcosystem` (the first and currently only implementor) reads a `Cargo.lock` for pinned crates.io dependencies, fetches each immutable `.crate` tarball from the CDN, and verifies its SHA-256 against the lockfile checksum. Acquisition is driven by the resolved dependency graph, never free-text names — which is what makes it tamper-evident and typosquat-resistant. npm/PyPI/Go can follow without pipeline-core changes.

## Usage

```toml
[dependencies]
deputy-ecosystem = "0.1"
```

## License

Dual-licensed under [MIT](https://github.com/Remade-With-Rust/deputy/blob/main/LICENSE-MIT) OR [Apache-2.0](https://github.com/Remade-With-Rust/deputy/blob/main/LICENSE-APACHE), at your option.
