use std::collections::HashMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use deputy_acquire::{acquire, AcquireReport};
use deputy_analyze::{analyze, AnalysisReport};
use deputy_core::{ContentHash, DepEcosystem, Pin, SourceId, StoreKind};
use deputy_deploy::{gate, materialize, promote, GateDecision, MaterializePlan, Promotion};
use deputy_ecosystem::{parse_pins, CargoEcosystem};
use deputy_id::Session;
use deputy_scan::{scan, AdvisoryDb, ScanReport};
use deputy_store::Vault;
use spacedb_access::{
    authorize, AccessRequest, Capability, Did, Identity, MemKeyDirectory, Ops, RevocationSet,
    Scope, SignedCapability,
};

use crate::error::ApiError;

/// The capability scope covering Deputy's whole vault.
const DEPUTY_SCOPE: &str = "deputy";

/// The synthetic owner DID used when mID is deactivated ([`DeputyService::open_local`], and the
/// `deputy sync --no-mid` key binding). It is deliberately *not* a `did:mata:` identity, so it
/// is obvious in logs that no mID backs it.
pub const LOCAL_DID: &str = "did:deputy:local";

/// The in-process capability surface — the canonical API the CLI, the HTTP server, and the UI
/// all drive. Holds an unlocked [`Vault`], the mID [`Session`] that authorized the unlock, and a
/// SpaceDB **capability** (Layer 5) that gates every operation for the acting principal — a
/// human or an AI agent.
pub struct DeputyService {
    vault: Vault,
    session: Session,
    ecosystem: CargoEcosystem,
    advisories: AdvisoryDb,

    // SpaceDB Layer 5 — signed, scoped, revocable capability gating.
    owner: Identity,
    directory: MemKeyDirectory,
    revocations: RevocationSet,
    capability: SignedCapability,

    /// Whether a verified mID session authorized this service. `false` when opened in local mode
    /// ([`Self::open_local`]) — capabilities still gate ops, but the owner is a local identity.
    mid_active: bool,
}

impl DeputyService {
    /// Open the service with **mID active** (the default): the verified mID `session` gates the
    /// unlock, and the opener becomes the **owner** with a self-granted full capability over the
    /// vault (the owner DID is the mID DID). The `passphrase` derives the at-rest key. Scoped
    /// capabilities for agents come from [`Self::grant`].
    pub fn open(
        root: impl AsRef<Path>,
        passphrase: &[u8],
        session: Session,
        now_unix_secs: u64,
    ) -> Result<Self, ApiError> {
        session.ensure_valid(now_unix_secs)?;
        Self::assemble(root, passphrase, session, true)
    }

    /// Open the service with **mID deactivated**: no mID token is required, and the owner is a
    /// synthetic local identity ([`LOCAL_DID`]). For embedding Deputy in software that owns its
    /// own auth, and for local development. Access is then gated only by passphrase possession
    /// (plus the capability layer); there is no federated identity behind the owner.
    pub fn open_local(root: impl AsRef<Path>, passphrase: &[u8]) -> Result<Self, ApiError> {
        let session = Session {
            did: LOCAL_DID.to_owned(),
            claims: std::collections::BTreeMap::new(),
            current_version: 0,
            genesis_roster_hash: [0u8; 32],
            iat: 0,
            exp: u64::MAX,
            aud: LOCAL_DID.to_owned(),
        };
        Self::assemble(root, passphrase, session, false)
    }

    /// Unlock the vault and mint the owner's self-granted capability. Shared by [`Self::open`]
    /// (mID active) and [`Self::open_local`] (mID deactivated).
    fn assemble(
        root: impl AsRef<Path>,
        passphrase: &[u8],
        session: Session,
        mid_active: bool,
    ) -> Result<Self, ApiError> {
        let vault = Vault::unlock(root, passphrase)?;

        let owner = Identity::generate(session.did.clone())?;
        let directory = MemKeyDirectory::new();
        directory.publish(&owner)?;
        let cap = Capability::grant(
            owner.did().clone(),
            owner.did().clone(),
            Scope::Collection(DEPUTY_SCOPE.to_owned()),
            Ops::READ | Ops::WRITE | Ops::COMPUTE,
        )?;
        let capability = SignedCapability::sign(cap, &owner)?;

        Ok(Self {
            vault,
            session,
            ecosystem: CargoEcosystem::new(),
            advisories: AdvisoryDb::new(),
            owner,
            directory,
            revocations: RevocationSet::new(),
            capability,
            mid_active,
        })
    }

    /// Attach an advisory database used by [`DeputyService::scan`].
    pub fn with_advisories(mut self, advisories: AdvisoryDb) -> Self {
        self.advisories = advisories;
        self
    }

    pub fn session(&self) -> &Session {
        &self.session
    }

    /// Whether a verified mID session backs this service (`false` in local mode).
    pub fn mid_active(&self) -> bool {
        self.mid_active
    }

    /// The vault owner's DID — the capability issuer.
    pub fn owner_did(&self) -> &Did {
        self.owner.did()
    }

    /// The owner grants `bearer` (a human or an AI agent) a scoped, optionally-expiring capability
    /// over the vault, signed under the owner's key.
    pub fn grant(
        &self,
        bearer: impl Into<Did>,
        ops: Ops,
        expiry: Option<u64>,
    ) -> Result<SignedCapability, ApiError> {
        let mut cap = Capability::grant(
            self.owner.did().clone(),
            bearer,
            Scope::Collection(DEPUTY_SCOPE.to_owned()),
            ops,
        )?;
        if let Some(exp) = expiry {
            cap = cap.with_expiry(exp);
        }
        Ok(SignedCapability::sign(cap, &self.owner)?)
    }

    /// Act under a different capability (e.g. an agent's grant) for subsequent operations.
    pub fn act_as(&mut self, capability: SignedCapability) {
        self.capability = capability;
    }

    /// Revoke a capability by id; subsequent checks under it are denied.
    pub fn revoke(&mut self, capability_id: [u8; 16]) {
        self.revocations.revoke(capability_id);
    }

    /// Check that the acting capability authorizes `op` over the vault scope (signature, scope,
    /// ops, expiry, and revocation are all enforced).
    pub(crate) fn authorize_op(&self, op: Ops) -> Result<(), ApiError> {
        let scope = Scope::Collection(DEPUTY_SCOPE.to_owned());
        let request = AccessRequest {
            bearer: &self.capability.capability.bearer,
            scope: &scope,
            op,
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let decision = authorize(
            &self.capability,
            &request,
            &self.directory,
            now,
            &self.revocations,
        )?;
        if decision.is_allowed() {
            Ok(())
        } else {
            Err(ApiError::forbidden(decision))
        }
    }

    fn pins(&self, source: &str) -> Result<Vec<Pin>, ApiError> {
        Ok(self.ecosystem.discover(&SourceId::new(source))?)
    }

    fn lock_text(&self, source: &str) -> Result<String, ApiError> {
        let path = Path::new(source);
        let lock = if path.is_dir() {
            path.join("Cargo.lock")
        } else {
            path.to_path_buf()
        };
        std::fs::read_to_string(&lock)
            .map_err(|e| ApiError::bad_request(format!("read {}: {e}", lock.display())))
    }

    /// List the source's pinned crates.io dependencies. (capability: READ)
    pub fn discover(&self, source: &str) -> Result<Vec<Pin>, ApiError> {
        self.authorize_op(Ops::READ)?;
        self.pins(source)
    }

    /// Fetch, verify, and seal the source's dependencies into the dirty store. (capability: WRITE)
    pub fn acquire(&self, source: &str) -> Result<AcquireReport, ApiError> {
        self.authorize_op(Ops::WRITE)?;
        Ok(acquire(
            &self.vault,
            &self.ecosystem,
            &SourceId::new(source),
        )?)
    }

    /// Language analytics + critical-point-of-failure scoring. (capability: READ)
    pub fn analyze(&self, source: &str) -> Result<AnalysisReport, ApiError> {
        self.authorize_op(Ops::READ)?;
        let lock = self.lock_text(source)?;
        let hashes: HashMap<(String, String), ContentHash> = parse_pins(&lock)?
            .into_iter()
            .map(|p| {
                (
                    (
                        p.dep.name.as_str().to_owned(),
                        p.dep.version.as_str().to_owned(),
                    ),
                    p.expected,
                )
            })
            .collect();
        Ok(analyze(&lock, |name, version| {
            let hash = hashes.get(&(name.to_owned(), version.to_owned()))?;
            self.vault.get_artifact(StoreKind::Dirty, hash).ok()
        })?)
    }

    /// Scan every dependency, recording verdicts. (capability: WRITE)
    pub fn scan(&self, source: &str) -> Result<Vec<ScanReport>, ApiError> {
        self.authorize_op(Ops::WRITE)?;
        self.pins(source)?
            .iter()
            .map(|pin| scan(&self.vault, pin, &self.advisories).map_err(ApiError::from))
            .collect()
    }

    /// Promote scanned-clean dependencies into prod. (capability: WRITE)
    pub fn promote(&self, source: &str) -> Result<Vec<Promotion>, ApiError> {
        self.authorize_op(Ops::WRITE)?;
        let did = self.session.did.clone();
        let outcomes = self
            .pins(source)?
            .iter()
            .filter_map(|pin| {
                promote(
                    &self.vault,
                    pin.dep.ecosystem,
                    pin.dep.name.as_str(),
                    pin.dep.version.as_str(),
                    &pin.expected,
                    Some(&did),
                )
                .ok()
            })
            .collect();
        Ok(outcomes)
    }

    /// Run the fail-closed deploy gate over the source's dependencies. (capability: READ)
    pub fn gate(&self, source: &str) -> Result<GateDecision, ApiError> {
        self.authorize_op(Ops::READ)?;
        Ok(gate(&self.vault, &self.pins(source)?)?)
    }

    /// Gate, then vendor prod copies into `into`. (capability: WRITE)
    pub fn deploy(&self, source: &str, into: &str) -> Result<MaterializePlan, ApiError> {
        self.authorize_op(Ops::WRITE)?;
        let pins = self.pins(source)?;
        match gate(&self.vault, &pins)? {
            GateDecision::Blocked { violations } => Err(ApiError::gate_blocked(violations)),
            GateDecision::Allowed { .. } => Ok(materialize(&self.vault, &pins, Path::new(into))?),
        }
    }
}
