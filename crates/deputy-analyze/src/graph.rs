use std::collections::{HashMap, HashSet, VecDeque};

use deputy_core::{Error, Result};
use serde::Deserialize;

/// One resolved crate from a `Cargo.lock`, with its direct dependency identifiers.
#[derive(Debug, Clone)]
pub struct LockedCrate {
    pub name: String,
    pub version: String,
    pub dependencies: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct LockFile {
    #[serde(default)]
    package: Vec<LockPackage>,
}

#[derive(Debug, Deserialize)]
struct LockPackage {
    name: String,
    version: String,
    #[serde(default)]
    dependencies: Vec<String>,
}

/// Parse all resolved crates (and their dependency edges) from a `Cargo.lock`.
pub fn parse_lockfile(lock_toml: &str) -> Result<Vec<LockedCrate>> {
    let lock: LockFile = toml::from_str(lock_toml).map_err(|e| Error::Malformed {
        what: format!("Cargo.lock: {e}"),
    })?;
    Ok(lock
        .package
        .into_iter()
        .map(|p| LockedCrate {
            name: p.name,
            version: p.version,
            dependencies: p.dependencies,
        })
        .collect())
}

/// The resolved dependency DAG. Supports computing each crate's **blast radius**: the number of
/// crates that transitively depend on it (its reverse-reachable set). A high blast radius means
/// "if this crate is compromised, this many crates in your tree are affected" — the headline
/// critical-point-of-failure signal (`docs/PIPELINE.md` §3).
pub struct DepGraph {
    nodes: Vec<(String, String)>,
    reverse: Vec<Vec<usize>>,
    index: HashMap<(String, String), usize>,
}

impl DepGraph {
    pub fn from_locked(crates: &[LockedCrate]) -> Self {
        let mut nodes = Vec::with_capacity(crates.len());
        let mut index = HashMap::new();
        let mut by_name: HashMap<String, Vec<usize>> = HashMap::new();
        for c in crates {
            let key = (c.name.clone(), c.version.clone());
            let idx = nodes.len();
            nodes.push(key.clone());
            index.insert(key, idx);
            by_name.entry(c.name.clone()).or_default().push(idx);
        }

        // reverse[child] = parents that depend on child
        let mut reverse = vec![Vec::new(); nodes.len()];
        for (parent_idx, c) in crates.iter().enumerate() {
            for dep in &c.dependencies {
                if let Some(child_idx) = resolve(&index, &by_name, dep) {
                    reverse[child_idx].push(parent_idx);
                }
            }
        }

        Self {
            nodes,
            reverse,
            index,
        }
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// The number of crates that transitively depend on `(name, version)` (excluding itself).
    pub fn blast_radius(&self, name: &str, version: &str) -> usize {
        let Some(&start) = self.index.get(&(name.to_owned(), version.to_owned())) else {
            return 0;
        };
        let mut seen = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(start);
        while let Some(node) = queue.pop_front() {
            for &parent in &self.reverse[node] {
                if seen.insert(parent) {
                    queue.push_back(parent);
                }
            }
        }
        seen.len()
    }
}

/// Resolve a `Cargo.lock` dependency identifier (`"name"`, `"name version"`, or
/// `"name version (source)"`) to a node index.
fn resolve(
    index: &HashMap<(String, String), usize>,
    by_name: &HashMap<String, Vec<usize>>,
    dep: &str,
) -> Option<usize> {
    let mut parts = dep.split_whitespace();
    let name = parts.next()?;
    let version = parts.next().filter(|t| !t.starts_with('('));
    match version {
        Some(v) => index.get(&(name.to_owned(), v.to_owned())).copied(),
        None => match by_name.get(name) {
            // Only resolvable without a version when the name is unambiguous.
            Some(idxs) if idxs.len() == 1 => Some(idxs[0]),
            _ => None,
        },
    }
}
