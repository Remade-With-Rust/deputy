# deputy-analyze

[![crates.io](https://img.shields.io/crates/v/deputy-analyze.svg)](https://crates.io/crates/deputy-analyze)
[![docs.rs](https://img.shields.io/docsrs/deputy-analyze)](https://docs.rs/deputy-analyze)

Language analytics and critical-point-of-failure scoring.

Part of **[Deputy](https://github.com/Remade-With-Rust/deputy)** — a personally-owned, verified vault and supply-chain gate for your code dependencies.

## What it does

Scores critical points of failure across a dependency tree by combining two signals per dependency. **Blast radius** — how many crates transitively depend on it, read from the `Cargo.lock` graph offline — dominates the score. **Capability surface** comes from inspecting an acquired `.crate`: build scripts, proc-macros, `unsafe`, native FFI, and language mix. `analyze` takes a `Cargo.lock` plus a callback that supplies `.crate` bytes when available, keeping it decoupled from storage and easy to test.

## Usage

```toml
[dependencies]
deputy-analyze = "0.1"
```

## License

Dual-licensed under [MIT](https://github.com/Remade-With-Rust/deputy/blob/main/LICENSE-MIT) OR [Apache-2.0](https://github.com/Remade-With-Rust/deputy/blob/main/LICENSE-APACHE), at your option.
