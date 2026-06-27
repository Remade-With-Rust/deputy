# deputy-deploy

[![crates.io](https://img.shields.io/crates/v/deputy-deploy.svg)](https://crates.io/crates/deputy-deploy)
[![docs.rs](https://img.shields.io/docsrs/deputy-deploy)](https://docs.rs/deputy-deploy)

Promotion (dirty to prod), redeploy into source, and the fail-closed deploy gate.

Part of **[Deputy](https://github.com/Remade-With-Rust/deputy)** — a personally-owned, verified vault and supply-chain gate for your code dependencies.

## What it does

Provides the final pipeline stages. `promote` moves clean, verified bytes from the dirty store into the append-only prod store with a hash-chained receipt (quarantining anything not clean). `gate` is the fail-closed deploy gate — it allows a deployment only if every dependency is promoted, clean, and receipted, and blocks otherwise. `materialize` vendors the prod copies back into a source tree via Cargo source replacement, so builds consume Deputy's owned, verified artifacts.

## Usage

```toml
[dependencies]
deputy-deploy = "0.1"
```

## License

Dual-licensed under [MIT](https://github.com/Remade-With-Rust/deputy/blob/main/LICENSE-MIT) OR [Apache-2.0](https://github.com/Remade-With-Rust/deputy/blob/main/LICENSE-APACHE), at your option.
