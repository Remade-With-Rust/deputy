//! # deputy-core
//!
//! Domain types, the dependency-artifact state machine, and the trait contracts every
//! other Deputy crate depends on. **This crate performs no I/O** — it is the stable
//! interface layer described in `docs/ARCHITECTURE.md` §5, so implementations and tests
//! depend on contracts rather than on each other.
#![forbid(unsafe_code)]

mod error;
mod ids;
mod state;
mod traits;

pub use error::{Error, Result};
pub use ids::{
    ArtifactRef, ContentHash, DepName, DepRef, EcosystemId, HashAlgo, Pin, RepoId, SourceId,
    Version,
};
pub use state::{ArtifactState, Finding, ScanVerdict, Severity};
pub use traits::{ArtifactStore, DepEcosystem, MetadataStore, StoreKind};
