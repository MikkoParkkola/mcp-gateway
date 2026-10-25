// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The `trees.tsv` readings, over whichever backend the including crate
//! binds as `crate::yaml`: the adapter in `mik_8425_yaml_baseline_trees`,
//! the same adapter in `mik_8425_mig2_parity`, which bound `yaml::next`
//! until the MIK-8425 MIG.2 switch.
#![allow(
    dead_code,
    reason = "each including crate uses a different part of the report"
)]

use crate::{golden, yaml};

/// Places that hold YAML read by the gateway, its deploy assets or its
/// tests. `.github` is CI configuration, which the gateway never parses.
pub(crate) const ROOTS: &[&str] = &[
    "benchmarks",
    "capabilities",
    "deploy",
    "examples",
    "playbooks",
    "tests/fixtures",
];
pub(crate) const ROOT_FILES: &[&str] = &["gateway.example.yaml", "smithery.yaml"];

/// Rows recorded on 2026-10-17. At least this many must still be comparable
/// (unchanged since recording); otherwise the golden is stale.
pub(crate) const MIN_COMPARED: usize = 150;

pub(crate) fn paths() -> Vec<String> {
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
fn tree_reading(result: Result<yaml::Value, yaml::Error>) -> String {
    match result {
        Ok(value) => golden::digest(golden::yaml_structure(&value).as_bytes()),
        Err(error) => format!("ERR {}", golden::one_line(&error.to_string())),
    }
}

/// figment's `Dict` carries no YAML tags, so its JSON form loses nothing.
fn dict_reading(result: Result<figment::value::Dict, yaml::Error>) -> String {
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
    let mut documents = yaml::documents(text);
    for document in documents.by_ref().take(MAX_DOCS) {
        count += 1;
        match document {
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

pub(crate) fn readings(text: &str) -> String {
    let value = tree_reading(yaml::from_str::<yaml::Value>(text));
    let dict = dict_reading(yaml::from_str_loose(text));
    format!("value={value}\tdict={dict}\tstream={}", stream(text))
}
