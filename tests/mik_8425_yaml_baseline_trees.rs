// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8425 MIG.0: what serde_yaml 0.9.34 reads from every YAML file in the
//! repository, recorded before the parser is replaced.
//!
//! For each file the golden records three readings, each as a digest of its
//! JSON form or as the refusal:
//! - `value`: the untyped tree (`serde_yaml::Value`), as `strict_keys`,
//!   skills and the rewriters read it;
//! - `dict`: figment's `Dict`, as the config loader reads it (a repeated key
//!   keeps the last value here and nowhere else);
//! - `stream`: the multi-document stream, as `kubernetes.rs` reads it.
//!
//! The JSON form is parser-neutral, so the backend swap must reproduce every
//! digest. A refusal row keeps serde_yaml's text: a later stage compares
//! refusal against refusal, never the wording.

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

fn reading<T: serde::Serialize, E: std::fmt::Display>(result: Result<T, E>) -> String {
    match result {
        Ok(value) => match serde_json::to_vec(&value) {
            Ok(json) => golden::digest(&json),
            Err(error) => format!("JSON-ERR {}", golden::one_line(&error.to_string())),
        },
        Err(error) => format!("ERR {}", golden::one_line(&error.to_string())),
    }
}

fn stream(text: &str) -> String {
    let mut json = Vec::new();
    let mut count = 0usize;
    for document in serde_yaml::Deserializer::from_str(text).take(256) {
        count += 1;
        let value = match <serde_yaml::Value as serde::Deserialize>::deserialize(document) {
            Ok(value) => value,
            Err(error) => {
                return format!("ERR doc {count}: {}", golden::one_line(&error.to_string()));
            }
        };
        match serde_json::to_vec(&value) {
            Ok(bytes) => {
                json.extend_from_slice(&bytes);
                json.push(b'\n');
            }
            Err(error) => {
                return format!(
                    "JSON-ERR doc {count}: {}",
                    golden::one_line(&error.to_string())
                );
            }
        }
    }
    format!("{count}:{}", golden::digest(&json))
}

fn readings(text: &str) -> String {
    let value = reading(serde_yaml::from_str::<serde_yaml::Value>(text));
    let dict = reading(figment::providers::Yaml::from_str::<figment::value::Dict>(
        text,
    ));
    format!("value={value}\tdict={dict}\tstream={}", stream(text))
}

/// Every unchanged repository YAML file reads exactly as serde_yaml 0.9.34
/// read it when the golden was recorded.
#[test]
fn every_repository_yaml_file_reads_as_recorded() {
    golden::assert_keyed_golden("trees.tsv", MIN_COMPARED, readings);
}

/// The golden covers the YAML files that exist, so a missed directory shows.
#[test]
fn the_golden_covers_every_repository_yaml_file_recorded() {
    let recorded =
        std::fs::read_to_string(golden::repo_root().join("tests/fixtures/mik_8425_yaml/trees.tsv"))
            .expect("trees golden");
    let recorded: std::collections::BTreeSet<&str> = recorded
        .lines()
        .filter_map(|row| row.split('\t').next())
        .collect();
    assert!(
        recorded.len() >= MIN_COMPARED,
        "only {} rows",
        recorded.len()
    );
    assert!(recorded.iter().any(|p| p.starts_with("capabilities/")));
    assert!(recorded.iter().any(|p| p.starts_with("deploy/")));
    assert!(recorded.contains("gateway.example.yaml"));
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
