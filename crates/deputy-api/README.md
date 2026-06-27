# deputy-api

[![crates.io](https://img.shields.io/crates/v/deputy-api.svg)](https://crates.io/crates/deputy-api)
[![docs.rs](https://img.shields.io/docsrs/deputy-api)](https://docs.rs/deputy-api)

The API-first capability surface: in-process API plus a localhost transport.

Part of **[Deputy](https://github.com/Remade-With-Rust/deputy)** — a personally-owned, verified vault and supply-chain gate for your code dependencies.

## What it does

Deputy's API-first surface. `DeputyService` is the canonical in-process capability layer that the CLI, the HTTP server, and the UI all drive through the same methods, and `serve` exposes it as a localhost HTTP/JSON server. Opening the service is mID-gated: a valid `deputy_id::Session` authorizes the vault unlock, while the passphrase derives the at-rest key — composing session authorization with key-based unlock.

## Usage

```toml
[dependencies]
deputy-api = "0.1"
```

## License

Dual-licensed under [MIT](https://github.com/Remade-With-Rust/deputy/blob/main/LICENSE-MIT) OR [Apache-2.0](https://github.com/Remade-With-Rust/deputy/blob/main/LICENSE-APACHE), at your option.
