// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8425 MIG.0: what `serde_yaml` 0.9.34 reads from every YAML file in the
//! repository, recorded before the parser is replaced.
//!
//! For each file the golden records three readings, each as a digest or as
//! the refusal:
//! - `value`: the untyped tree (`serde_yaml::Value`), as `strict_keys`,
//!   skills and the rewriters read it, digested as its structure (node
//!   kinds, tags, key types, document order; see `yaml_structure`);
//! - `dict`: figment's `Dict`, as the config loader reads it (a repeated key
//!   keeps the last value here and nowhere else), digested as JSON, which
//!   loses nothing because a `Dict` has no tags;
//! - `stream`: the multi-document stream, as `kubernetes.rs` reads it, as
//!   document count plus the digest of each document's structure.
//!
//! The backend swap must reproduce every digest. A refusal row keeps
//! `serde_yaml`'s text: a later stage compares refusal against refusal, never
//! the wording.

#[path = "common/mik_8425_golden.rs"]
mod golden;

use figment::providers::Format as _;

/// Places that hold YAML read by the gateway, its deploy assets or its
/// tests. `.github` is CI configuration, which the gateway never parses.
const ROOTS: &[&str] = &[
    "benchmarks",
    "capabilities",
    "deploy",
    "examples",
    "playbooks",
    "tests/fixtures",
];
const ROOT_FILES: &[&str] = &["gateway.example.yaml", "smithery.yaml"];

/// Rows recorded on 2026-10-17. At least this many must still be comparable
/// (unchanged since recording); otherwise the golden is stale.
const MIN_COMPARED: usize = 150;

fn paths() -> Vec<String> {
    let mut paths: Vec<String> = ROOTS
        .iter()
        .flat_map(|root| golden::files_under(root, &["yaml", "yml"]))
        .chain(ROOT_FILES.iter().map(|f| (*f).to_owned()))
        .collect();
    paths.sort();
    paths
}

/// The tree as its structure (kinds, tags, key types), digested: JSON would
/// read a tagged node and a one-key map as the same thing.
fn tree_reading(result: Result<serde_yaml::Value, serde_yaml::Error>) -> String {
    match result {
        Ok(value) => golden::digest(golden::yaml_structure(&value).as_bytes()),
        Err(error) => format!("ERR {}", golden::one_line(&error.to_string())),
    }
}

/// figment's `Dict` carries no YAML tags, so its JSON form loses nothing.
fn dict_reading(result: Result<figment::value::Dict, serde_yaml::Error>) -> String {
    match result {
        Ok(dict) => match serde_json::to_vec(&dict) {
            Ok(json) => golden::digest(&json),
            Err(error) => format!("JSON-ERR {}", golden::one_line(&error.to_string())),
        },
        Err(error) => format!("ERR {}", golden::one_line(&error.to_string())),
    }
}

/// At most this many documents per stream; a longer stream is marked.
const MAX_DOCS: usize = 256;

fn stream(text: &str) -> String {
    let mut structure = String::new();
    let mut count = 0usize;
    let mut documents = serde_yaml::Deserializer::from_str(text);
    for document in documents.by_ref().take(MAX_DOCS) {
        count += 1;
        match <serde_yaml::Value as serde::Deserialize>::deserialize(document) {
            Ok(value) => {
                structure.push_str(&golden::yaml_structure(&value));
                structure.push('\n');
            }
            Err(error) => {
                return format!("ERR doc {count}: {}", golden::one_line(&error.to_string()));
            }
        }
    }
    let truncated = if documents.next().is_some() {
        " truncated"
    } else {
        ""
    };
    format!(
        "{count}{truncated}:{}",
        golden::digest(structure.as_bytes())
    )
}

fn readings(text: &str) -> String {
    let value = tree_reading(serde_yaml::from_str::<serde_yaml::Value>(text));
    let dict = dict_reading(figment::providers::Yaml::from_str::<figment::value::Dict>(
        text,
    ));
    format!("value={value}\tdict={dict}\tstream={}", stream(text))
}

/// Every unchanged repository YAML file reads exactly as `serde_yaml` 0.9.34
/// read it when the golden was recorded.
#[test]
fn every_repository_yaml_file_reads_as_recorded() {
    golden::assert_keyed_golden("trees.tsv", MIN_COMPARED, readings);
}

/// Compares the recorded paths with the YAML files on disk, and requires
/// every root to be represented. A file added after the recording has no
/// row and is NOT baselined: it is listed here, and MIG.2 re-records the
/// golden on the last commit that still has `serde_yaml`. Failing on every new
/// file would break unrelated PRs that add a capability.
#[test]
fn the_golden_is_compared_with_the_yaml_files_on_disk() {
    let recorded =
        std::fs::read_to_string(golden::repo_root().join("tests/fixtures/mik_8425_yaml/trees.tsv"))
            .expect("trees golden");
    let recorded: std::collections::BTreeSet<String> = recorded
        .lines()
        .filter_map(|row| row.split('\t').next())
        .map(str::to_owned)
        .collect();
    let on_disk: std::collections::BTreeSet<String> = paths().into_iter().collect();
    let unrecorded: Vec<&String> = on_disk.difference(&recorded).collect();
    let gone: Vec<&String> = recorded.difference(&on_disk).collect();
    eprintln!(
        "trees golden: {} recorded, {} on disk; not baselined: {unrecorded:?}; gone: {gone:?}",
        recorded.len(),
        on_disk.len()
    );
    for root in ROOTS {
        assert!(
            recorded.iter().any(|p| p.starts_with(&format!("{root}/"))),
            "no recorded row under {root}/"
        );
    }
    for file in ROOT_FILES {
        assert!(recorded.contains(*file), "{file} not recorded");
    }
    assert!(
        recorded.intersection(&on_disk).count() >= MIN_COMPARED,
        "fewer than {MIN_COMPARED} recorded files still exist; re-record the golden"
    );
}

/// Prints the golden for review; never part of a normal run.
#[test]
#[ignore = "records tests/fixtures/mik_8425_yaml/trees.tsv; run with --ignored --nocapture"]
fn record_trees_golden() {
    print!(
        "----- BEGIN trees.tsv -----\n{}----- END trees.tsv -----\n",
        golden::keyed_rows(&paths(), readings)
    );
}
