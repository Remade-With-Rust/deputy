use flate2::write::GzEncoder;
use flate2::Compression;

use crate::{analyze, inspect, parse_lockfile, DepGraph, Language};

/// Build a synthetic `.crate` tarball (gzip'd tar) from `(path, content)` pairs.
fn make_crate(files: &[(&str, &str)]) -> Vec<u8> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut builder = tar::Builder::new(encoder);
    for (path, content) in files {
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, path, content.as_bytes())
            .unwrap();
    }
    builder.into_inner().unwrap().finish().unwrap()
}

#[test]
fn blast_radius_counts_transitive_dependents() {
    const LOCK: &str = r#"
version = 4
[[package]]
name = "app"
version = "0.1.0"
dependencies = ["mid", "leaf"]

[[package]]
name = "mid"
version = "1.0.0"
dependencies = ["leaf"]

[[package]]
name = "leaf"
version = "2.0.0"
"#;
    let crates = parse_lockfile(LOCK).unwrap();
    let graph = DepGraph::from_locked(&crates);

    assert_eq!(graph.len(), 3);
    assert_eq!(
        graph.blast_radius("leaf", "2.0.0"),
        2,
        "app + mid depend on leaf"
    );
    assert_eq!(graph.blast_radius("mid", "1.0.0"), 1, "app depends on mid");
    assert_eq!(
        graph.blast_radius("app", "0.1.0"),
        0,
        "nothing depends on app"
    );
    assert_eq!(graph.blast_radius("ghost", "9.9.9"), 0, "unknown crate");
}

#[test]
fn inspect_extracts_languages_and_capabilities() {
    let manifest = "[package]\nname = \"demo\"\nversion = \"1.0.0\"\nlinks = \"z\"\n\n[lib]\nproc-macro = true\n";
    let crate_bytes = make_crate(&[
        ("demo-1.0.0/Cargo.toml", manifest),
        ("demo-1.0.0/build.rs", "fn main() {}\n"),
        (
            "demo-1.0.0/src/lib.rs",
            "pub fn f() {\n    unsafe { }\n    let _ = unsafe { 0 };\n}\n",
        ),
        ("demo-1.0.0/cbits/x.c", "int x(void) { return 0; }\n"),
    ]);

    let facts = inspect(&crate_bytes).unwrap();
    assert!(facts.has_build_script);
    assert!(facts.is_proc_macro);
    assert_eq!(facts.links_native.as_deref(), Some("z"));
    assert_eq!(facts.unsafe_occurrences, 2);
    assert!(facts.languages.get(&Language::Rust).copied().unwrap_or(0) > 0);
    assert!(facts.languages.get(&Language::C).copied().unwrap_or(0) > 0);
    assert!(facts.native_unsafe_lines() > 0);
}

#[test]
fn malformed_tarball_is_rejected() {
    assert!(inspect(b"not a gzip tarball at all").is_err());
}

#[test]
fn analyze_ranks_by_criticality_and_aggregates_languages() {
    const LOCK: &str = r#"
version = 4
[[package]]
name = "app-a"
version = "0.1.0"
dependencies = ["core-lib"]

[[package]]
name = "app-b"
version = "0.1.0"
dependencies = ["core-lib"]

[[package]]
name = "core-lib"
version = "1.0.0"

[[package]]
name = "lonely"
version = "0.1.0"
"#;
    let core_tar = make_crate(&[
        (
            "core-lib-1.0.0/Cargo.toml",
            "[package]\nname = \"core-lib\"\nversion = \"1.0.0\"\n",
        ),
        ("core-lib-1.0.0/build.rs", "fn main() {}\n"),
        ("core-lib-1.0.0/src/lib.rs", "pub fn x() {}\n"),
    ]);

    let report = analyze(LOCK, |name, _version| {
        (name == "core-lib").then(|| core_tar.clone())
    })
    .unwrap();

    assert_eq!(report.total_crates, 4);
    assert_eq!(report.inspected, 1);

    // core-lib has the highest blast radius (2) and a build script => ranks first.
    let top = &report.risks[0];
    assert_eq!(top.name, "core-lib");
    assert_eq!(top.blast_radius, 2);
    assert!(top.has_build_script);
    assert!(top.score > report.risks.last().unwrap().score);

    assert_eq!(report.language_report.crates_analyzed, 1);
    assert!(
        report
            .language_report
            .by_language
            .get(&Language::Rust)
            .copied()
            .unwrap_or(0)
            > 0
    );
}
