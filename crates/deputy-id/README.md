# deputy-id

[![crates.io](https://img.shields.io/crates/v/deputy-id.svg)](https://crates.io/crates/deputy-id)
[![docs.rs](https://img.shields.io/docsrs/deputy-id)](https://docs.rs/deputy-id)

MATA mID verification (pure Rust) and Deputy's identity & session model.

Part of **[Deputy](https://github.com/Remade-With-Rust/deputy)** — a personally-owned, verified vault and supply-chain gate for your code dependencies.

## What it does

Deputy's authentication layer. `verify` runs the cryptographic mID checks via MATA's vendored `mid-verify` reference and yields a `Session`; `Authenticator` composes the full sign-in flow — verify, single-use nonce consumption, and genesis-anchor plus rollback check. Because mID is sign/verify-only and exports no secret, a session authorizes actions but does not derive any encryption key; the at-rest key comes from a separate passphrase via `deputy-crypto` / `deputy-store`.

## Usage

```toml
[dependencies]
deputy-id = "0.1"
```

## License

Dual-licensed under [MIT](https://github.com/Remade-With-Rust/deputy/blob/main/LICENSE-MIT) OR [Apache-2.0](https://github.com/Remade-With-Rust/deputy/blob/main/LICENSE-APACHE), at your option.
