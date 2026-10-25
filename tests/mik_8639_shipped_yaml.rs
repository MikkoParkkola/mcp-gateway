// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8639 DEPTH.4: every shipped YAML file the backend accepts, the guarded
//! seam accepts too.
//!
//! The backend's verdicts are recorded per file in
//! `tests/fixtures/mik_8425_yaml/shipped.tsv` (MIK-8425 MIG.2), so the
//! no-false-refusal contract outlives the parser it was measured against.

#[path = "common/mik_8425_golden.rs"]
mod golden;

#[path = "common/yaml.rs"]
mod yaml;

use std::fmt::Write as _;
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

/// Every shipped YAML file as a sorted repo-relative path.
fn shipped_files() -> Vec<String> {
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
    let mut paths: Vec<String> = files
        .iter()
        .map(|path| {
            path.components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/")
        })
        .collect();
    paths.sort();
    paths
}

/// The backend's verdict on one file: `single` when it reads as one
/// document, `stream <n>` when it reads as `n` documents, else `refused`.
/// The golden was recorded with the replaced backend before the MIK-8425 swap; a
/// re-recording now reads through the adapter, which is the backend.
fn backend_reading(content: &str) -> String {
    if yaml::from_str::<yaml::Value>(content).is_ok() {
        return "single".to_owned();
    }
    let documents: Vec<_> = yaml::documents(content).collect();
    if !documents.is_empty() && documents.iter().all(std::result::Result::is_ok) {
        format!("stream {}", documents.len())
    } else {
        "refused".to_owned()
    }
}

/// A Helm chart template: Go template text, so not YAML until rendered.
fn is_helm_template(path: &str) -> bool {
    path.starts_with("deploy/helm/") && path.contains("/templates/")
}

fn read(path: &str) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("shipped file {path} unreadable: {err}"))
}

/// Every file the replaced backend accepted, the seam accepts with the same
/// document count. A recorded file edited or removed since the recording is
/// skipped only when `reviewed_skips.tsv` lists it (there is no old backend
/// left to re-record it with). A new file has no row, but the
/// seam must still accept it, unless it is a Helm template.
#[test]
fn shipped_yaml_accepted_by_backend_stays_accepted() {
    if is_packaged_crate(&package_root()) {
        eprintln!(
            "mik-8639 shipped-yaml: skipped in the packaged crate: the repo YAML it checks is not published; the full-checkout CI job runs it"
        );
        return;
    }
    let table = std::fs::read_to_string(GOLDEN).expect("the shipped-YAML golden");
    let mut recorded = std::collections::BTreeMap::new();
    for row in table.lines() {
        let cols: Vec<&str> = row.split('\t').collect();
        let [path, sha, reading] = cols[..] else {
            panic!("{GOLDEN}: malformed row {row:?}");
        };
        recorded.insert(path.to_owned(), (sha.to_owned(), reading.to_owned()));
    }
    let files = shipped_files();
    assert!(!files.is_empty(), "expected to find shipped YAML files");
    let rows: Vec<String> = recorded.keys().cloned().collect();
    let mut skipped = Vec::new();
    let mut new_files = Vec::new();
    let mut refused = Vec::new();
    let mut accepted = 0usize;
    for path in &files {
        let content = read(path);
        let Some((sha, reading)) = recorded.remove(path) else {
            // No golden can be recorded for a new file, but it still has to
            // load. Helm templates are Go template text, refused by design.
            let new_reading = backend_reading(&content);
            if new_reading == "refused" && !is_helm_template(path) {
                refused.push(path.clone());
            }
            new_files.push(format!("{path} (reads as {new_reading})"));
            continue;
        };
        if sha != digest(&content) {
            skipped.push(path.clone());
            continue;
        }
        let ok = if reading == "single" {
            yaml::from_str::<yaml::Value>(&content).is_ok()
        } else if let Some(count) = reading.strip_prefix("stream ") {
            let guarded: Vec<_> = yaml::documents(&content).collect();
            count.parse() == Ok(guarded.len()) && guarded.iter().all(std::result::Result::is_ok)
        } else {
            continue;
        };
        accepted += 1;
        if !ok {
            refused.push(path.clone());
        }
    }
    skipped.extend(recorded.into_keys());
    let skipped: Vec<&str> = skipped.iter().map(String::as_str).collect();
    golden::assert_skips_reviewed("shipped.tsv", rows.iter().map(String::as_str), &skipped);
    if !new_files.is_empty() {
        eprintln!(
            "shipped-yaml: {} new file(s) without a row: {new_files:?}",
            new_files.len()
        );
    }
    eprintln!(
        "mik-8639 shipped-yaml: {accepted} backend-accepted files of {}, {} refused",
        files.len(),
        refused.len()
    );
    assert!(
        refused.is_empty(),
        "seam refused shipped files: {refused:?}"
    );
}

const GOLDEN: &str = "tests/fixtures/mik_8425_yaml/shipped.tsv";

fn digest(content: &str) -> String {
    use sha2::Digest as _;
    format!(
        "sha256:{}",
        hex::encode(sha2::Sha256::digest(content.as_bytes()))
    )
}

/// Prints the golden for review; never part of a normal run.
#[test]
#[ignore = "records tests/fixtures/mik_8425_yaml/shipped.tsv; run with --ignored --nocapture"]
fn record_shipped_yaml_golden() {
    let mut out = String::new();
    for path in shipped_files() {
        let content = read(&path);
        let _ = writeln!(
            out,
            "{path}\t{}\t{}",
            digest(&content),
            backend_reading(&content)
        );
    }
    print!("----- BEGIN shipped.tsv -----\n{out}----- END shipped.tsv -----\n");
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
