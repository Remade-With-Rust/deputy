//! # deputy-cli
//!
//! Headless CLI for Deputy. M3 ships `acquire` and `discover` for the Cargo ecosystem; more
//! commands follow as later milestones land. This is a thin client over the library crates
//! (the API-first surface in `deputy-api` arrives in M7).
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use deputy_acquire::acquire;
use deputy_analyze::analyze;
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
}

fn main() -> ExitCode {
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
    }
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
    std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".deputy"))
}

fn fail(message: &str) -> ExitCode {
    eprintln!("deputy: {message}");
    ExitCode::FAILURE
}
