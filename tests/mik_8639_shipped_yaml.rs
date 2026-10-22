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
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(_) => return,
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

#[test]
fn shipped_yaml_accepted_by_backend_stays_accepted() {
    let mut files = Vec::new();
    for root in [
        "capabilities",
        "examples",
        "config",
        "deploy",
        "tests/fixtures",
        "playbooks",
        "benchmarks",
    ] {
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
        if !backend.is_empty() && backend.iter().all(|read| read.is_ok()) {
            multi += 1;
            let guarded: Vec<_> = yaml::documents(&content).collect();
            let ok = guarded.len() == backend.len() && guarded.iter().all(|read| read.is_ok());
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
