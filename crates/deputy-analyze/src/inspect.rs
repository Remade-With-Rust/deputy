use std::collections::BTreeMap;
use std::io::Read as _;

use deputy_core::{Error, Result};
use flate2::read::GzDecoder;
use serde::Deserialize;
use tar::Archive;

use crate::language::Language;

/// What inspecting a crate's `.crate` tarball revealed: its language line counts and the
/// capability signals that bear on supply-chain risk (`docs/PIPELINE.md` §3).
#[derive(Debug, Clone, Default)]
pub struct CrateFacts {
    /// Lines of code per language.
    pub languages: BTreeMap<Language, usize>,
    pub total_lines: usize,
    /// Has a `build.rs` (or `build = …`) — arbitrary code runs at build time.
    pub has_build_script: bool,
    /// Is a proc-macro crate — code runs inside the compiler.
    pub is_proc_macro: bool,
    /// Heuristic count of `unsafe` occurrences in Rust sources.
    pub unsafe_occurrences: usize,
    /// `links = "…"` native library, if any (FFI / sys crate).
    pub links_native: Option<String>,
}

impl CrateFacts {
    /// Total lines written in memory-unsafe native languages (C / C++ / assembly).
    pub fn native_unsafe_lines(&self) -> usize {
        self.languages
            .iter()
            .filter(|(lang, _)| lang.is_memory_unsafe_native())
            .map(|(_, lines)| *lines)
            .sum()
    }
}

#[derive(Debug, Default, Deserialize)]
struct Manifest {
    #[serde(default)]
    package: ManifestPackage,
    #[serde(default)]
    lib: ManifestLib,
}

#[derive(Debug, Default, Deserialize)]
struct ManifestPackage {
    #[serde(default)]
    links: Option<String>,
    #[serde(default)]
    build: Option<toml::Value>,
}

#[derive(Debug, Default, Deserialize)]
struct ManifestLib {
    #[serde(default, rename = "proc-macro")]
    proc_macro: bool,
}

/// Inspect a crates.io `.crate` tarball (gzip'd tar) and extract its [`CrateFacts`].
pub fn inspect(crate_tar_gz: &[u8]) -> Result<CrateFacts> {
    let mut archive = Archive::new(GzDecoder::new(crate_tar_gz));
    let mut facts = CrateFacts::default();

    let entries = archive.entries().map_err(|e| Error::Malformed {
        what: format!("not a .crate tarball: {e}"),
    })?;

    for entry in entries {
        let mut entry = entry.map_err(|e| Error::Malformed {
            what: format!("tar entry: {e}"),
        })?;
        let path = entry
            .path()
            .map_err(|e| Error::Malformed {
                what: format!("tar path: {e}"),
            })?
            .into_owned();

        // Tarball paths are `<name>-<version>/...`; the file is at depth ≥ 2.
        let components: Vec<String> = path
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect();
        if components.len() < 2 {
            continue;
        }
        let at_crate_root = components.len() == 2;
        let file_name = components.last().map(String::as_str).unwrap_or_default();

        let mut content = Vec::new();
        entry
            .read_to_end(&mut content)
            .map_err(|e| Error::Malformed {
                what: format!("read tar entry: {e}"),
            })?;
        let lines = content.iter().filter(|&&b| b == b'\n').count();

        if at_crate_root && file_name == "build.rs" {
            facts.has_build_script = true;
        }
        if at_crate_root && file_name == "Cargo.toml" {
            if let Ok(text) = std::str::from_utf8(&content) {
                apply_manifest(&mut facts, text);
            }
        }

        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            let lang = Language::from_ext(ext);
            *facts.languages.entry(lang).or_default() += lines;
            facts.total_lines += lines;
            if lang == Language::Rust {
                if let Ok(text) = std::str::from_utf8(&content) {
                    facts.unsafe_occurrences += text.matches("unsafe").count();
                }
            }
        }
    }

    Ok(facts)
}

fn apply_manifest(facts: &mut CrateFacts, text: &str) {
    let Ok(manifest) = toml::from_str::<Manifest>(text) else {
        return;
    };
    facts.is_proc_macro = manifest.lib.proc_macro;
    facts.links_native = manifest.package.links;
    let build_truthy = !matches!(
        manifest.package.build,
        None | Some(toml::Value::Boolean(false))
    );
    if build_truthy {
        facts.has_build_script = true;
    }
}
