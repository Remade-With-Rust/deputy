# deputy-core

[![crates.io](https://img.shields.io/crates/v/deputy-core.svg)](https://crates.io/crates/deputy-core)
[![docs.rs](https://img.shields.io/docsrs/deputy-core)](https://docs.rs/deputy-core)

Domain types, the dependency-artifact state machine, and trait contracts for Deputy. No I/O.

Part of **[Deputy](https://github.com/Remade-With-Rust/deputy)** — a personally-owned, verified vault and supply-chain gate for your code dependencies.

## What it does

Defines the stable interface layer that every other Deputy crate builds on: the domain types, the dependency-artifact state machine, and the trait contracts that implementations and tests depend on. This crate performs no I/O — it lets the rest of the workspace depend on contracts rather than on each other.

## Usage

```toml
[dependencies]
deputy-core = "0.1"
```

## License

Dual-licensed under [MIT](https://github.com/Remade-With-Rust/deputy/blob/main/LICENSE-MIT) OR [Apache-2.0](https://github.com/Remade-With-Rust/deputy/blob/main/LICENSE-APACHE), at your option.
