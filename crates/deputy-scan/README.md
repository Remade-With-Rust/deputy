# deputy-scan

[![crates.io](https://img.shields.io/crates/v/deputy-scan.svg)](https://crates.io/crates/deputy-scan)
[![docs.rs](https://img.shields.io/docsrs/deputy-scan)](https://docs.rs/deputy-scan)

Scanners: integrity, advisories, and dirty-vs-prod diffing.

Part of **[Deputy](https://github.com/Remade-With-Rust/deputy)** — a personally-owned, verified vault and supply-chain gate for your code dependencies.

## What it does

Decides whether a dirty artifact is safe to promote. `scan` runs fail-closed against one pinned dependency and records a `ScanVerdict`. Blocking findings make a verdict non-promotable: an integrity failure (the sealed artifact does not decrypt or hash to its address), substitution (prod holds a different hash for the same `name@version`), or an advisory match against a known `AdvisoryDb`. Build scripts, proc-macros, and `unsafe` / native code are recorded as informational, non-blocking notes.

## Usage

```toml
[dependencies]
deputy-scan = "0.1"
```

## License

Dual-licensed under [MIT](https://github.com/Remade-With-Rust/deputy/blob/main/LICENSE-MIT) OR [Apache-2.0](https://github.com/Remade-With-Rust/deputy/blob/main/LICENSE-APACHE), at your option.
