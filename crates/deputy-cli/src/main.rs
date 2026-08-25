//! # deputy-cli
//!
//! Headless CLI for Deputy: discover → acquire → analyze → scan → promote → gate → deploy,
//! plus `deputy serve` for the localhost API (the Dioxus UI and agents). Thin client of
//! `deputy-api`.
#![forbid(unsafe_code)]

#[global_allocator]
static ALLOC: deputy_alloc::Alloc = deputy_alloc::Alloc;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use deputy_acquire::acquire;
use deputy_analyze::analyze;
use deputy_api::{serve_blocking, DeputyService, Session, VerifyParams};
use deputy_core::{ContentHash, Pin, SourceId, StoreKind};
use deputy_deploy::{gate, materialize, promote, GateDecision, Promotion};
use deputy_ecosystem::CargoEcosystem;
use deputy_scan::{scan, AdvisoryDb};
use deputy_store::{StoreError, Vault};

#[derive(Parser)]
#[command(
    name = "deputy",
    version,
    about = "A personally-owned vault for your dependencies"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List the pinned crates.io dependencies a source would acquire (reads Cargo.lock, no
    /// network, no vault).
    Discover {
        /// Path to a repo directory (containing Cargo.lock) or a Cargo.lock file.
        source: PathBuf,
    },
    /// Fetch, verify, and seal a source's Cargo dependencies into the dirty store.
    ///
    /// The vault passphrase is read from the DEPUTY_PASSPHRASE environment variable.
    Acquire {
        /// Path to a repo directory (containing Cargo.lock) or a Cargo.lock file.
        source: PathBuf,
        /// Deputy home directory. Defaults to $HOME/.deputy.
        #[arg(long)]
        vault: Option<PathBuf>,
    },
    /// Language analytics + critical-point-of-failure ranking for a source's dependencies.
    ///
    /// Blast radius is computed from Cargo.lock alone. If DEPUTY_PASSPHRASE is set and the
    /// vault opens, acquired crates are also inspected for capability surface + languages.
    Analyze {
        /// Path to a repo directory (containing Cargo.lock) or a Cargo.lock file.
        source: PathBuf,
        /// Deputy home directory. Defaults to $HOME/.deputy.
        #[arg(long)]
        vault: Option<PathBuf>,
        /// How many top risks to print.
        #[arg(long, default_value_t = 15)]
        top: usize,
    },
    /// Scan a source's acquired dependencies (integrity, advisories, substitution) and record
    /// verdicts. Exits non-zero if any dependency is flagged.
    Scan {
        /// Path to a repo directory (containing Cargo.lock) or a Cargo.lock file.
        source: PathBuf,
        /// Deputy home directory. Defaults to $HOME/.deputy.
        #[arg(long)]
        vault: Option<PathBuf>,
        /// Optional advisory database (TOML) to check pinned versions against.
        #[arg(long)]
        advisory_db: Option<PathBuf>,
    },
    /// Promote scanned, clean dependencies from the dirty store into the trusted prod store,
    /// each with a hash-chained receipt. Non-clean dependencies are quarantined.
    Promote {
        /// Path to a repo directory (containing Cargo.lock) or a Cargo.lock file.
        source: PathBuf,
        /// Deputy home directory. Defaults to $HOME/.deputy.
        #[arg(long)]
        vault: Option<PathBuf>,
        /// Actor recorded in each promotion receipt (e.g. an mID DID).
        #[arg(long)]
        actor: Option<String>,
    },
    /// The fail-closed deploy gate: exits non-zero unless every dependency is promoted, clean,
    /// and receipted. The entry point a CI step calls before shipping.
    Gate {
        /// Path to a repo directory (containing Cargo.lock) or a Cargo.lock file.
        source: PathBuf,
        /// Deputy home directory. Defaults to $HOME/.deputy.
        #[arg(long)]
        vault: Option<PathBuf>,
    },
    /// Gate, then vendor the prod copies into a source tree (Cargo source replacement) so it
    /// builds against Deputy's owned, verified artifacts. Refuses if the gate blocks.
    Deploy {
        /// Path to a repo directory (containing Cargo.lock) or a Cargo.lock file.
        source: PathBuf,
        /// Directory to materialize into (writes `vendor/` and `.cargo/config.toml`).
        #[arg(long)]
        into: PathBuf,
        /// Deputy home directory. Defaults to $HOME/.deputy.
        #[arg(long)]
        vault: Option<PathBuf>,
    },
    /// Serve the localhost API (the surface the Dioxus UI and AI agents drive).
    ///
    /// mID is ON by default: set DEPUTY_MID_TOKEN (+ DEPUTY_MID_NONCE, and DEPUTY_MID_AUDIENCE if
    /// it isn't the bind URL) to the wallet token, which is verified before the service opens.
    /// Pass --no-mid to deactivate mID and run under a local identity instead.
    Serve {
        /// Deputy home directory. Defaults to $HOME/.deputy.
        #[arg(long)]
        vault: Option<PathBuf>,
        /// Loopback port to bind.
        #[arg(long, default_value_t = 7878)]
        port: u16,
        /// Deactivate mID: open under a local identity, with no token required.
        #[arg(long)]
        no_mid: bool,
    },
    /// Snapshot the vault into Reed-Solomon erasure-coded shards (durable backup; no passphrase
    /// needed — it archives the already-encrypted files).
    Snapshot {
        /// Deputy home directory. Defaults to $HOME/.deputy.
        #[arg(long)]
        vault: Option<PathBuf>,
        /// Directory to write the manifest + shards into.
        #[arg(long)]
        into: PathBuf,
        /// Number of data shards (also the number required to restore).
        #[arg(long, default_value_t = 4)]
        data: usize,
        /// Number of parity shards (also the number of shard losses tolerated).
        #[arg(long, default_value_t = 2)]
        parity: usize,
    },
    /// Reconstruct a vault from a snapshot directory (needs at least `data` of the shards).
    Restore {
        /// Snapshot directory (manifest + shards).
        #[arg(long)]
        from: PathBuf,
        /// Deputy home directory to restore into (must not already hold a vault).
        #[arg(long)]
        vault: Option<PathBuf>,
    },
    /// Conflict-free multi-device metadata sync (CRDT). Export this vault's metadata as a
    /// portable update, or merge another device's update into this vault.
    Sync {
        #[command(subcommand)]
        action: SyncAction,
    },
}

#[derive(Subcommand)]
enum SyncAction {
    /// Export this vault's metadata to a portable CRDT update file.
    Export(SyncArgs),
    /// Merge another device's CRDT update file into this vault.
    Import(SyncArgs),
}

#[derive(Args)]
struct SyncArgs {
    /// The CRDT update file to write (export) or read (import).
    #[arg(long)]
    file: PathBuf,
    /// Your mID DID — the sync key is bound to it (so only your devices can read the blob).
    /// Falls back to the DEPUTY_MID_DID environment variable.
    #[arg(long)]
    mid_did: Option<String>,
    /// Deactivate mID: bind the sync key to a local identity instead of an mID DID. The blob is
    /// still encrypted (confidentiality rests on the passphrase alone).
    #[arg(long, conflicts_with = "mid_did")]
    no_mid: bool,
    /// Deputy home directory. Defaults to $HOME/.deputy.
    #[arg(long)]
    vault: Option<PathBuf>,
}

fn main() -> ExitCode {
    deputy_alloc::configure(deputy_alloc::Profile::ShortLived);
    match Cli::parse().command {
        Command::Discover { source } => run_discover(&source),
        Command::Acquire { source, vault } => run_acquire(&source, vault),
        Command::Analyze { source, vault, top } => run_analyze(&source, vault, top),
        Command::Scan {
            source,
            vault,
            advisory_db,
        } => run_scan(&source, vault, advisory_db),
        Command::Promote {
            source,
            vault,
            actor,
        } => run_promote(&source, vault, actor),
        Command::Gate { source, vault } => run_gate(&source, vault),
        Command::Deploy {
            source,
            into,
            vault,
        } => run_deploy(&source, into, vault),
        Command::Serve {
            vault,
            port,
            no_mid,
        } => run_serve(vault, port, no_mid),
        Command::Snapshot {
            vault,
            into,
            data,
            parity,
        } => run_snapshot(vault, into, data, parity),
        Command::Restore { from, vault } => run_restore(from, vault),
        Command::Sync { action } => run_sync(action),
    }
}

fn run_sync(action: SyncAction) -> ExitCode {
    let (args, exporting) = match action {
        SyncAction::Export(args) => (args, true),
        SyncAction::Import(args) => (args, false),
    };

    // The mID-bound sync key needs the passphrase (confidentiality) + the mID DID (shared
    // identity). Both must match across the user's devices for the blob to open.
    let passphrase = match std::env::var("DEPUTY_PASSPHRASE") {
        Ok(p) if !p.is_empty() => p,
        _ => return fail("set DEPUTY_PASSPHRASE to the vault passphrase"),
    };
    // Resolve the identity the sync key binds to: an mID DID (default), or the local identity
    // when mID is deactivated. Either way the blob is encrypted; mID just namespaces the key.
    let binding_did =
        if args.no_mid {
            deputy_api::LOCAL_DID.to_owned()
        } else {
            match args.mid_did.clone().or_else(|| {
                std::env::var("DEPUTY_MID_DID")
                    .ok()
                    .filter(|d| !d.is_empty())
            }) {
                Some(d) => d,
                None => return fail(
                    "set --mid-did or DEPUTY_MID_DID to your mID, or pass --no-mid to bind the \
                     sync key to a local identity",
                ),
            }
        };
    let sync = match deputy_store::derive_sync_key(passphrase.as_bytes(), &binding_did) {
        Ok(k) => k,
        Err(e) => return fail(&format!("deriving sync key: {e}")),
    };

    let vault = match open_vault_from_env(args.vault) {
        Ok(v) => v,
        Err(e) => return fail(&e),
    };

    if exporting {
        match deputy_store::export_metadata(&vault, &sync) {
            Ok(update) => match std::fs::write(&args.file, &update) {
                Ok(()) => {
                    println!(
                        "exported {} bytes of metadata -> {}",
                        update.len(),
                        args.file.display()
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => fail(&format!("write {}: {e}", args.file.display())),
            },
            Err(e) => fail(&format!("export failed: {e}")),
        }
    } else {
        let update = match std::fs::read(&args.file) {
            Ok(u) => u,
            Err(e) => return fail(&format!("read {}: {e}", args.file.display())),
        };
        match deputy_store::import_metadata(&vault, &update, &sync) {
            Ok(report) => {
                println!(
                    "merged — {} metadata entries after sync",
                    report.merged_entries
                );
                ExitCode::SUCCESS
            }
            Err(e) => fail(&format!(
                "import failed (wrong passphrase or mID? the blob is sealed to your identity): {e}"
            )),
        }
    }
}

fn run_snapshot(vault_dir: Option<PathBuf>, into: PathBuf, data: usize, parity: usize) -> ExitCode {
    let dir = match vault_dir.or_else(default_vault_dir) {
        Some(d) => d,
        None => return fail("could not determine a vault directory; pass --vault"),
    };
    match deputy_store::snapshot(&dir, &into, data, parity) {
        Ok(info) => {
            println!(
                "snapshot: {} shards ({} data + {} parity, {} archived bytes) -> {}",
                info.total_shards,
                info.data_shards,
                info.parity_shards,
                info.archive_bytes,
                into.display()
            );
            println!("tolerates up to {parity} lost shard(s).");
            ExitCode::SUCCESS
        }
        Err(e) => fail(&format!("snapshot failed: {e}")),
    }
}

fn run_restore(from: PathBuf, vault_dir: Option<PathBuf>) -> ExitCode {
    let dir = match vault_dir.or_else(default_vault_dir) {
        Some(d) => d,
        None => return fail("could not determine a vault directory; pass --vault"),
    };
    match deputy_store::restore(&from, &dir) {
        Ok(info) => {
            println!(
                "restored {} files from {} shard(s) -> {}",
                info.files_restored,
                info.shards_used,
                dir.display()
            );
            ExitCode::SUCCESS
        }
        Err(e) => fail(&format!("restore failed: {e}")),
    }
}

fn run_serve(vault_dir: Option<PathBuf>, port: u16, no_mid: bool) -> ExitCode {
    deputy_alloc::configure(deputy_alloc::Profile::LongLived);
    let passphrase = match std::env::var("DEPUTY_PASSPHRASE") {
        Ok(p) if !p.is_empty() => p,
        _ => return fail("set DEPUTY_PASSPHRASE to the vault passphrase"),
    };
    let dir = match vault_dir.or_else(default_vault_dir) {
        Some(d) => d,
        None => return fail("could not determine a vault directory; pass --vault"),
    };
    // Ensure the vault exists before the service unlocks it.
    if let Err(e) = open_or_create_vault(&dir, passphrase.as_bytes()) {
        return fail(&format!("opening vault at {}: {e}", dir.display()));
    }

    let service = if no_mid {
        // mID deactivated: a local identity, no token. Anyone with the passphrase can drive it.
        eprintln!(
            "deputy: WARNING — mID is DEACTIVATED (--no-mid); serving under a local identity. \
             Access is gated only by the passphrase."
        );
        DeputyService::open_local(&dir, passphrase.as_bytes())
    } else {
        // mID active (default): verify a wallet token into a Session before opening.
        let session = match session_from_mid_env(port) {
            Ok(s) => s,
            Err(e) => return fail(&e),
        };
        println!(
            "deputy: mID verified for {} — serving as the mID owner.",
            session.did
        );
        DeputyService::open(&dir, passphrase.as_bytes(), session, unix_now())
    };
    let service = match service {
        Ok(s) => s,
        Err(e) => return fail(&format!("opening service: {e:?}")),
    };

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    println!("deputy: serving the API on http://{addr}  (Ctrl-C to stop)");
    match serve_blocking(service, addr) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fail(&format!("server error: {e}")),
    }
}

/// Build a verified mID [`Session`] from the environment (the default, mID-active serve path).
/// Requires `DEPUTY_MID_TOKEN` (the wallet JWS) and `DEPUTY_MID_NONCE` (the nonce it was minted
/// against). The audience defaults to the bind URL unless `DEPUTY_MID_AUDIENCE` overrides it.
fn session_from_mid_env(port: u16) -> Result<Session, String> {
    let token = std::env::var("DEPUTY_MID_TOKEN")
        .ok()
        .filter(|t| !t.is_empty());
    let Some(token) = token else {
        return Err(
            "mID is active: set DEPUTY_MID_TOKEN (+ DEPUTY_MID_NONCE) to a wallet token, \
             or pass --no-mid to serve under a local identity"
                .to_owned(),
        );
    };
    let nonce = std::env::var("DEPUTY_MID_NONCE")
        .ok()
        .filter(|n| !n.is_empty())
        .ok_or("set DEPUTY_MID_NONCE to the nonce the token was minted for")?;
    let audience = std::env::var("DEPUTY_MID_AUDIENCE")
        .ok()
        .filter(|a| !a.is_empty())
        .unwrap_or_else(|| format!("http://127.0.0.1:{port}"));

    let params = VerifyParams::new(audience, nonce, unix_now());
    deputy_api::verify(&token, &params).map_err(|e| format!("mID verification failed: {e}"))
}

/// Current wall-clock time in Unix seconds (saturating at 0 before the epoch).
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn run_gate(source: &Path, vault_dir: Option<PathBuf>) -> ExitCode {
    let vault = match open_vault_from_env(vault_dir) {
        Ok(v) => v,
        Err(e) => return fail(&e),
    };
    let pins = match source_pins(source) {
        Ok(p) => p,
        Err(e) => return fail(&e),
    };
    match gate(&vault, &pins) {
        Ok(GateDecision::Allowed { cleared }) => {
            println!("gate: ALLOWED — {cleared} dependencies promoted, clean, and receipted");
            ExitCode::SUCCESS
        }
        Ok(GateDecision::Blocked { violations }) => {
            println!("gate: BLOCKED — {} violation(s):", violations.len());
            for v in &violations {
                println!("  {} {}: {}", v.name, v.version, v.reason);
            }
            ExitCode::FAILURE
        }
        Err(e) => fail(&format!("gate failed: {e}")),
    }
}

fn run_deploy(source: &Path, into: PathBuf, vault_dir: Option<PathBuf>) -> ExitCode {
    let vault = match open_vault_from_env(vault_dir) {
        Ok(v) => v,
        Err(e) => return fail(&e),
    };
    let pins = match source_pins(source) {
        Ok(p) => p,
        Err(e) => return fail(&e),
    };

    // Gate is the precondition for deploy: never materialize an un-gated tree.
    match gate(&vault, &pins) {
        Ok(GateDecision::Blocked { violations }) => {
            println!(
                "deploy refused — gate BLOCKED ({} violation(s)):",
                violations.len()
            );
            for v in &violations {
                println!("  {} {}: {}", v.name, v.version, v.reason);
            }
            return ExitCode::FAILURE;
        }
        Ok(GateDecision::Allowed { .. }) => {}
        Err(e) => return fail(&format!("gate failed: {e}")),
    }

    match materialize(&vault, &pins, &into) {
        Ok(plan) => {
            println!(
                "deployed {} crate(s) into {}",
                plan.materialized.len(),
                plan.vendor_dir.display()
            );
            println!(
                "wrote source-replacement config: {}",
                plan.config_path.display()
            );
            ExitCode::SUCCESS
        }
        Err(e) => fail(&format!("materialize failed: {e}")),
    }
}

/// Open (or create) the vault from DEPUTY_PASSPHRASE + the optional vault dir.
fn open_vault_from_env(vault_dir: Option<PathBuf>) -> Result<Vault, String> {
    let passphrase = match std::env::var("DEPUTY_PASSPHRASE") {
        Ok(p) if !p.is_empty() => p,
        _ => return Err("set DEPUTY_PASSPHRASE to the vault passphrase".to_owned()),
    };
    let dir = vault_dir
        .or_else(default_vault_dir)
        .ok_or_else(|| "could not determine a vault directory; pass --vault".to_owned())?;
    open_or_create_vault(&dir, passphrase.as_bytes())
        .map_err(|e| format!("opening vault at {}: {e}", dir.display()))
}

/// Resolve a source's pinned crates.io dependencies.
fn source_pins(source: &Path) -> Result<Vec<Pin>, String> {
    deputy_core_discover(&CargoEcosystem::new(), source)
        .map_err(|e| format!("discover failed: {e}"))
}

fn run_scan(source: &Path, vault_dir: Option<PathBuf>, advisory_db: Option<PathBuf>) -> ExitCode {
    let vault = match open_vault_from_env(vault_dir) {
        Ok(v) => v,
        Err(e) => return fail(&e),
    };
    let pins = match source_pins(source) {
        Ok(p) => p,
        Err(e) => return fail(&e),
    };
    let advisories = match advisory_db {
        Some(path) => match std::fs::read_to_string(&path).map(|t| AdvisoryDb::from_toml(&t)) {
            Ok(Ok(db)) => {
                eprintln!("deputy: loaded {} advisories", db.len());
                db
            }
            Ok(Err(e)) => return fail(&format!("advisory db {}: {e}", path.display())),
            Err(e) => return fail(&format!("read {}: {e}", path.display())),
        },
        None => {
            eprintln!("deputy: no --advisory-db; advisory checks skipped");
            AdvisoryDb::new()
        }
    };

    let (mut clean, mut flagged) = (0usize, 0usize);
    for pin in &pins {
        match scan(&vault, pin, &advisories) {
            Ok(report) if report.is_clean() => {
                clean += 1;
            }
            Ok(report) => {
                flagged += 1;
                println!("FAIL  {} {}", pin.dep.name, pin.dep.version);
                if let deputy_core::ScanVerdict::Findings(findings) = &report.verdict {
                    for f in findings {
                        println!("        - [{:?}] {}: {}", f.severity, f.id, f.summary);
                    }
                }
            }
            Err(e) => {
                flagged += 1;
                println!("ERROR {} {}: {e}", pin.dep.name, pin.dep.version);
            }
        }
    }

    println!(
        "\nScanned {} dependencies: {clean} clean, {flagged} flagged.",
        pins.len()
    );
    if flagged == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn run_promote(source: &Path, vault_dir: Option<PathBuf>, actor: Option<String>) -> ExitCode {
    let vault = match open_vault_from_env(vault_dir) {
        Ok(v) => v,
        Err(e) => return fail(&e),
    };
    let pins = match source_pins(source) {
        Ok(p) => p,
        Err(e) => return fail(&e),
    };

    let (mut promoted, mut quarantined, mut skipped) = (0usize, 0usize, 0usize);
    for pin in &pins {
        let name = pin.dep.name.as_str();
        let version = pin.dep.version.as_str();
        match promote(
            &vault,
            pin.dep.ecosystem,
            name,
            version,
            &pin.expected,
            actor.as_deref(),
        ) {
            Ok(Promotion::Promoted(receipt)) => {
                promoted += 1;
                let short: String = receipt.chain_hash.chars().take(12).collect();
                println!(
                    "promoted   {name} {version}  (receipt #{} {short})",
                    receipt.audit_seq
                );
            }
            Ok(Promotion::Quarantined { findings }) => {
                quarantined += 1;
                println!(
                    "quarantined {name} {version}  ({} finding(s))",
                    findings.len()
                );
            }
            Err(_) => {
                // Most commonly: not scanned yet.
                skipped += 1;
            }
        }
    }

    println!(
        "\nPromoted {promoted}, quarantined {quarantined}, skipped {skipped} (of {} dependencies).",
        pins.len()
    );
    if quarantined == 0 && skipped == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn resolve_lock(source: &Path) -> PathBuf {
    if source.is_dir() {
        source.join("Cargo.lock")
    } else {
        source.to_path_buf()
    }
}

fn run_discover(source: &Path) -> ExitCode {
    let eco = CargoEcosystem::new();
    let pins = match deputy_core_discover(&eco, source) {
        Ok(pins) => pins,
        Err(e) => return fail(&format!("discover failed: {e}")),
    };
    println!("{} pinned crates.io dependencies:", pins.len());
    for pin in &pins {
        println!("  {} {}  {}", pin.dep.name, pin.dep.version, pin.expected);
    }
    ExitCode::SUCCESS
}

/// Tiny adapter so `main` can call the trait method without importing the trait at call sites.
fn deputy_core_discover(
    eco: &CargoEcosystem,
    source: &Path,
) -> deputy_core::Result<Vec<deputy_core::Pin>> {
    use deputy_core::DepEcosystem as _;
    eco.discover(&SourceId::new(source.to_string_lossy().into_owned()))
}

fn run_analyze(source: &Path, vault_dir: Option<PathBuf>, top: usize) -> ExitCode {
    let lock_path = resolve_lock(source);
    let lock_text = match std::fs::read_to_string(&lock_path) {
        Ok(text) => text,
        Err(e) => return fail(&format!("read {}: {e}", lock_path.display())),
    };

    // name@version -> expected content hash, so acquired crates can be located in the store.
    let hashes: HashMap<(String, String), ContentHash> =
        match deputy_ecosystem::parse_pins(&lock_text) {
            Ok(pins) => pins
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
                .collect(),
            Err(e) => return fail(&format!("parse Cargo.lock: {e}")),
        };

    // Optionally open the vault to enable per-crate inspection (capability surface + languages).
    let vault = match std::env::var("DEPUTY_PASSPHRASE") {
        Ok(pw) if !pw.is_empty() => vault_dir
            .or_else(default_vault_dir)
            .and_then(|dir| Vault::unlock(&dir, pw.as_bytes()).ok()),
        _ => None,
    };
    if vault.is_none() {
        eprintln!(
            "deputy: no vault opened — blast-radius only (set DEPUTY_PASSPHRASE + --vault to inspect acquired crates)"
        );
    }

    let report = match analyze(&lock_text, |name, version| {
        let vault = vault.as_ref()?;
        let hash = hashes.get(&(name.to_owned(), version.to_owned()))?;
        vault.get_artifact(StoreKind::Dirty, hash).ok()
    }) {
        Ok(report) => report,
        Err(e) => return fail(&format!("analyze failed: {e}")),
    };

    println!(
        "Analyzed {} dependencies ({} inspected).",
        report.total_crates, report.inspected
    );

    if !report.language_report.by_language.is_empty() {
        println!(
            "\nLanguages across {} inspected crate(s):",
            report.language_report.crates_analyzed
        );
        let mut langs: Vec<_> = report.language_report.by_language.iter().collect();
        langs.sort_by(|a, b| b.1.cmp(a.1));
        for (lang, lines) in langs {
            println!("  {lang:<12} {lines} lines");
        }
    }

    println!(
        "\nTop {} critical points of failure:",
        top.min(report.risks.len())
    );
    for risk in report.risks.iter().take(top) {
        let tag = if risk.inspected {
            ""
        } else {
            " (not acquired)"
        };
        println!(
            "  [{:>5.1}] {} {}{}",
            risk.score, risk.name, risk.version, tag
        );
        for reason in &risk.reasons {
            println!("           - {reason}");
        }
    }

    ExitCode::SUCCESS
}

fn run_acquire(source: &Path, vault_dir: Option<PathBuf>) -> ExitCode {
    let passphrase = match std::env::var("DEPUTY_PASSPHRASE") {
        Ok(p) if !p.is_empty() => p,
        _ => return fail("set DEPUTY_PASSPHRASE to the vault passphrase"),
    };
    let vault_dir = match vault_dir.or_else(default_vault_dir) {
        Some(d) => d,
        None => return fail("could not determine a vault directory; pass --vault"),
    };

    let vault = match open_or_create_vault(&vault_dir, passphrase.as_bytes()) {
        Ok(v) => v,
        Err(e) => return fail(&format!("opening vault at {}: {e}", vault_dir.display())),
    };

    let eco = CargoEcosystem::new();
    let source_id = SourceId::new(source.to_string_lossy().into_owned());
    let report = match acquire(&vault, &eco, &source_id) {
        Ok(r) => r,
        Err(e) => return fail(&format!("acquire failed: {e}")),
    };

    println!(
        "acquired {} · already present {} · failed {} (of {} dependencies)",
        report.acquired.len(),
        report.already_present,
        report.failed.len(),
        report.total()
    );
    for failure in &report.failed {
        eprintln!(
            "  ! {} {}: {}",
            failure.name, failure.version, failure.error
        );
    }

    if report.is_clean() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn open_or_create_vault(dir: &Path, passphrase: &[u8]) -> Result<Vault, StoreError> {
    match Vault::unlock(dir, passphrase) {
        Err(StoreError::NotInitialized) => Vault::create(dir, passphrase),
        other => other,
    }
}

fn default_vault_dir() -> Option<PathBuf> {
    // Cross-platform `<home>/.deputy` (+ `$DEPUTY_VAULT` override), shared with the desktop app.
    deputy_api::default_vault_dir()
}

fn fail(message: &str) -> ExitCode {
    eprintln!("deputy: {message}");
    ExitCode::FAILURE
}
