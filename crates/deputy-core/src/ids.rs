use crate::error::{Error, Result};
use std::fmt;

/// Hash algorithm used for content addressing. SHA-256 today; the enum exists so the
/// on-disk address format (`<algo>:<hex>`) can evolve without ambiguity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HashAlgo {
    Sha256,
}

impl HashAlgo {
    pub const fn as_str(self) -> &'static str {
        match self {
            HashAlgo::Sha256 => "sha256",
        }
    }
}

impl fmt::Display for HashAlgo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The content address of an artifact: the hash of its canonical bytes. An artifact's
/// identity *is* this value — see `docs/STORAGE.md` §1. Renders as `sha256:<lower-hex>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ContentHash {
    algo: HashAlgo,
    bytes: Vec<u8>,
}

impl ContentHash {
    pub fn new(algo: HashAlgo, bytes: Vec<u8>) -> Self {
        Self { algo, bytes }
    }

    /// Construct a SHA-256 content hash from a 32-byte digest.
    pub fn sha256(digest: [u8; 32]) -> Self {
        Self {
            algo: HashAlgo::Sha256,
            bytes: digest.to_vec(),
        }
    }

    /// Parse a 64-character lowercase-hex SHA-256 (e.g. a `Cargo.lock` checksum) into a
    /// content hash. Errors on wrong length or non-hex input.
    pub fn from_sha256_hex(hex: &str) -> Result<Self> {
        if hex.len() != 64 {
            return Err(Error::Malformed {
                what: format!("sha256 hex must be 64 chars, got {}", hex.len()),
            });
        }
        let mut digest = [0u8; 32];
        for (i, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
            let s = std::str::from_utf8(pair).map_err(|_| Error::Malformed {
                what: "sha256 hex is not valid UTF-8".to_owned(),
            })?;
            digest[i] = u8::from_str_radix(s, 16).map_err(|_| Error::Malformed {
                what: format!("invalid hex byte `{s}`"),
            })?;
        }
        Ok(Self::sha256(digest))
    }

    pub fn algo(&self) -> HashAlgo {
        self.algo
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Lower-hex encoding of the digest (no algorithm prefix).
    pub fn to_hex(&self) -> String {
        use fmt::Write as _;
        let mut s = String::with_capacity(self.bytes.len() * 2);
        for b in &self.bytes {
            let _ = write!(s, "{b:02x}");
        }
        s
    }
}

impl fmt::Display for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.algo, self.to_hex())
    }
}

/// A supported dependency ecosystem. Cargo is the first beachhead
/// (`docs/ARCHITECTURE.md` §7); npm/PyPI/Go follow via the `DepEcosystem` trait.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EcosystemId {
    Cargo,
}

impl EcosystemId {
    pub const fn as_str(self) -> &'static str {
        match self {
            EcosystemId::Cargo => "cargo",
        }
    }
}

impl fmt::Display for EcosystemId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

macro_rules! string_newtype {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl From<String> for $name {
            fn from(value: String) -> Self {
                Self(value)
            }
        }

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                Self(value.to_owned())
            }
        }
    };
}

string_newtype!(
    /// A connected source-provider account (e.g. a linked GitHub account).
    SourceId
);
string_newtype!(
    /// A repository within a connected source.
    RepoId
);
string_newtype!(
    /// A dependency's package name within its ecosystem.
    DepName
);
string_newtype!(
    /// A resolved, exact dependency version (not a range).
    Version
);

/// A reference to a specific dependency at a specific version within an ecosystem.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DepRef {
    pub ecosystem: EcosystemId,
    pub name: DepName,
    pub version: Version,
}

/// A `DepRef` bound to the exact content hash we expect to download — the pin that makes
/// acquisition tamper-evident (`docs/PIPELINE.md` §2).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Pin {
    pub dep: DepRef,
    pub expected: ContentHash,
}

/// A handle to a stored artifact: its ecosystem plus its content address.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ArtifactRef {
    pub ecosystem: EcosystemId,
    pub hash: ContentHash,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_hash_renders_with_algo_prefix() {
        let h = ContentHash::sha256([0xab; 32]);
        assert_eq!(h.algo(), HashAlgo::Sha256);
        assert_eq!(h.to_string(), format!("sha256:{}", "ab".repeat(32)));
    }

    #[test]
    fn string_newtypes_roundtrip() {
        let name = DepName::from("serde");
        assert_eq!(name.as_str(), "serde");
        assert_eq!(name, DepName::new("serde"));
    }

    #[test]
    fn from_sha256_hex_roundtrips_and_validates() {
        let hex = "ab".repeat(32);
        let h = ContentHash::from_sha256_hex(&hex).unwrap();
        assert_eq!(h.to_hex(), hex);
        assert_eq!(h, ContentHash::sha256([0xab; 32]));

        assert!(ContentHash::from_sha256_hex("tooshort").is_err());
        assert!(ContentHash::from_sha256_hex(&"zz".repeat(32)).is_err());
    }
}
