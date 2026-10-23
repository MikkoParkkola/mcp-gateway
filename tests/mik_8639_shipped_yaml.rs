// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8639 DEPTH.4: every shipped YAML file the backend accepts, the guarded
//! seam accepts too.
//!
//! Passes on the skeleton by design (its guard accepts everything) and pins
//! the no-false-refusal contract the implementation must keep green.

#[path = "common/yaml.rs"]
mod yaml;

use serde::Deserialize;
use std::path::{Path, PathBuf};

/// Collect `*.yaml`/`*.yml` files under `root`, skipping `target` and `.git`.
fn collect_yaml_files(root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let skipped = path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name == "target" || name == ".git");
            if !skipped {
                collect_yaml_files(&path, out);
            }
        } else if path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext == "yaml" || ext == "yml")
        {
            out.push(path);
        }
    }
}

/// Whether `root` is the unpacked published crate, where the packaged suite
/// runs the tests: the repo YAML walked below is not published there
/// (Cargo.toml `include`). Same rule as the lib's `packaged_crate_at`
/// (`src/gateway/meta_mcp/boundary_pins/packaged.rs`): `cargo package` writes
/// `Cargo.toml.orig`, and an unpacked crate has no `.git`.
fn is_packaged_crate(root: &Path) -> bool {
    root.join("Cargo.toml.orig").exists() && !root.join(".git").exists()
}

/// The package root: cargo runs an integration test from it, and the walk
/// below reads its paths relative to it.
fn package_root() -> PathBuf {
    std::env::current_dir().expect("the test's working directory")
}

#[test]
fn shipped_yaml_accepted_by_backend_stays_accepted() {
    if is_packaged_crate(&package_root()) {
        eprintln!(
            "mik-8639 shipped-yaml: skipped in the packaged crate: the repo YAML it checks is not published; the full-checkout CI job runs it"
        );
        return;
    }
    let mut files = Vec::new();
    for root in [
        "capabilities",
        "examples",
        "deploy",
        "tests/fixtures",
        "playbooks",
        "benchmarks",
    ] {
        assert!(
            Path::new(root).is_dir(),
            "shipped root {root} is missing; a rename must fail, not drop coverage"
        );
        collect_yaml_files(Path::new(root), &mut files);
    }
    for file in ["gateway.example.yaml", "smithery.yaml"] {
        files.push(PathBuf::from(file));
    }
    assert!(!files.is_empty(), "expected to find shipped YAML files");
    let mut single = 0;
    let mut multi = 0;
    let mut refused = Vec::new();
    for path in &files {
        let content = match std::fs::read_to_string(path) {
            Ok(content) => content,
            Err(err) => panic!("shipped file {} unreadable: {err}", path.display()),
        };
        if serde_yaml::from_str::<serde_yaml::Value>(&content).is_ok() {
            single += 1;
            if yaml::from_str::<yaml::Value>(&content).is_err() {
                refused.push(path.clone());
            }
            continue;
        }
        // serde_yaml's stream can keep yielding after a malformed document,
        // so stop at the first error (collecting it unbounded aborted at 77 GB).
        let mut backend = Vec::new();
        for document in serde_yaml::Deserializer::from_str(&content) {
            let read = serde_yaml::Value::deserialize(document);
            let failed = read.is_err();
            backend.push(read);
            if failed {
                break;
            }
        }
        if !backend.is_empty() && backend.iter().all(std::result::Result::is_ok) {
            multi += 1;
            let guarded: Vec<_> = yaml::documents(&content).collect();
            let ok =
                guarded.len() == backend.len() && guarded.iter().all(std::result::Result::is_ok);
            if !ok {
                refused.push(path.clone());
            }
        }
    }
    eprintln!(
        "mik-8639 shipped-yaml: {single} single-document, {multi} multi-document backend-accepted files, {} refused",
        refused.len()
    );
    assert!(
        refused.is_empty(),
        "seam refused shipped files: {refused:?}"
    );
}

/// The packaged-crate switch both ways. A root with `Cargo.toml.orig` and no
/// `.git` is the unpacked crate (skip); without the marker, or with a `.git`
/// beside a stray `Cargo.toml.orig`, the strict check runs. On the live root
/// the skip may fire only where the walked YAML is missing.
#[test]
fn packaged_marker_skips_and_its_absence_stays_strict() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    assert!(
        !is_packaged_crate(dir.path()),
        "without the marker the strict check runs"
    );
    std::fs::write(dir.path().join("Cargo.toml.orig"), "").expect("write the marker");
    assert!(
        is_packaged_crate(dir.path()),
        "with the marker and no .git the check is skipped"
    );
    std::fs::create_dir(dir.path().join(".git")).expect("create .git");
    assert!(
        !is_packaged_crate(dir.path()),
        "a checkout with a stray marker keeps the strict check"
    );
    let root = package_root();
    assert!(
        !is_packaged_crate(&root) || !root.join("playbooks").exists(),
        "the skip fires only where the repo YAML it checks is absent"
    );
}
