# deputy-cli

[![crates.io](https://img.shields.io/crates/v/deputy-cli.svg)](https://crates.io/crates/deputy-cli)
[![docs.rs](https://img.shields.io/docsrs/deputy-cli)](https://docs.rs/deputy-cli)

Headless CLI over deputy-api.

Part of **[Deputy](https://github.com/Remade-With-Rust/deputy)** — a personally-owned, verified vault and supply-chain gate for your code dependencies.

## What it does

The `deputy` command: a headless, thin client over Deputy's library crates that drives the full supply-chain pipeline — discover, acquire, analyze, scan, promote, gate, and materialize — plus serving the localhost API, snapshot/restore backups, and multi-device metadata sync.

## Install

```sh
cargo install deputy-cli   # provides the `deputy` binary
```

```sh
# List the pinned crates.io dependencies a source would acquire (no network, no vault)
deputy discover ./my-repo

# Fetch, verify, and seal a source's dependencies into the dirty store
DEPUTY_PASSPHRASE=… deputy acquire ./my-repo

# The fail-closed deploy gate: exit non-zero unless every dependency is promoted and clean
deputy gate ./my-repo
```

## License

Dual-licensed under [MIT](https://github.com/Remade-With-Rust/deputy/blob/main/LICENSE-MIT) OR [Apache-2.0](https://github.com/Remade-With-Rust/deputy/blob/main/LICENSE-APACHE), at your option.
