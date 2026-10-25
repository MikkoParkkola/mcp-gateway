// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8425 MIG.0: what `serde-yaml` 0.9.34 reads from every YAML file in the
//! repository, recorded before the parser is replaced.
//!
//! For each file the golden records three readings, each as a digest or as
//! the refusal:
//! - `value`: the untyped tree (`yaml::Value`), as `strict_keys`,
//!   skills and the rewriters read it, digested as its structure (node
//!   kinds, tags, key types, document order; see `yaml_structure`);
//! - `dict`: figment's `Dict`, as the config loader reads it (a repeated key
//!   keeps the last value here and nowhere else), digested as JSON, which
//!   loses nothing because a `Dict` has no tags;
//! - `stream`: the multi-document stream, as `kubernetes.rs` reads it, as
//!   document count plus the digest of each document's structure.
//!
//! The backend swap must reproduce every digest. A refusal row keeps
//! `serde-yaml`'s text: a later stage compares refusal against refusal, never
//! the wording.

#[path = "common/mik_8425_golden.rs"]
mod golden;

#[path = "common/yaml.rs"]
mod yaml;

#[path = "mik_8425_yaml_baseline_trees/report.rs"]
mod report;

use report::{MIN_COMPARED, ROOT_FILES, ROOTS, paths, readings};

/// Every unchanged repository YAML file reads exactly as `serde-yaml` 0.9.34
/// read it when the golden was recorded.
#[test]
fn every_repository_yaml_file_reads_as_recorded() {
    golden::assert_keyed_golden("trees.tsv", MIN_COMPARED, readings);
}

/// Compares the recorded paths with the YAML files on disk, and requires
/// every root to be represented. A file added after the recording has no
/// row and is NOT baselined: it is listed here, and MIG.2 re-records the
/// golden on the last commit that still has `serde-yaml`. Failing on every new
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
