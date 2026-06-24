use crate::error::Result;
use crate::ids::{ArtifactRef, ContentHash, EcosystemId, Pin, SourceId};
use crate::state::ScanVerdict;

/// Which store a content-addressed artifact lives in. The dirty store is staging; the
/// prod store is the trusted, append-only golden set (`docs/ARCHITECTURE.md` §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreKind {
    Dirty,
    Prod,
}

/// An acquirable dependency ecosystem. Cargo is the first implementor; npm/PyPI/Go follow
/// without pipeline-core changes (`docs/PIPELINE.md` §0).
///
/// Method signatures are synchronous contracts; I/O-bound implementations may bridge to an
/// async runtime internally. An implementor produces candidates for the **dirty** store
/// only — it can never write to prod, and verification (hash/signature) is enforced by core
/// callers, not by the implementor (`docs/THREAT_MODEL.md` ADV-6).
pub trait DepEcosystem {
    fn id(&self) -> EcosystemId;

    /// Read the source's resolved, pinned dependency graph as [`Pin`]s — each an exact
    /// name+version bound to its expected content hash. For Cargo these come straight from
    /// `Cargo.lock` (`name`, `version`, `checksum`), so the pins are already tamper-evident.
    /// Dependencies without a fetchable registry checksum (path/git/workspace members) are
    /// omitted.
    fn discover(&self, source: &SourceId) -> Result<Vec<Pin>>;

    /// Download the artifact bytes for a pin. The bytes are untrusted until verified.
    fn fetch(&self, pin: &Pin) -> Result<Vec<u8>>;

    /// Verify downloaded bytes against the pin's expected hash. Errors on mismatch.
    fn verify_integrity(&self, pin: &Pin, raw: &[u8]) -> Result<()>;
}

/// Content-addressed artifact storage. The address is the hash of the bytes (ecosystem is a
/// higher-level annotation, not part of storage). Implementations seal every artifact at rest
/// with AES-256-GCM under a per-artifact subkey (`docs/STORAGE.md` §2).
pub trait ArtifactStore {
    /// Store bytes and return their content address. Idempotent: storing the same bytes
    /// twice yields the same `ContentHash` and is a no-op the second time.
    fn put(&self, kind: StoreKind, raw: &[u8]) -> Result<ContentHash>;

    /// Retrieve and decrypt previously stored bytes by content address.
    fn get(&self, kind: StoreKind, hash: &ContentHash) -> Result<Vec<u8>>;

    /// Whether the given store holds the artifact with this content address.
    fn contains(&self, kind: StoreKind, hash: &ContentHash) -> Result<bool>;
}

/// Encrypted metadata: scan verdicts, promotion receipts, and graph annotations
/// (`docs/STORAGE.md` §4).
pub trait MetadataStore {
    fn record_verdict(&self, artifact: &ArtifactRef, verdict: &ScanVerdict) -> Result<()>;
    fn verdict(&self, artifact: &ArtifactRef) -> Result<Option<ScanVerdict>>;
}
