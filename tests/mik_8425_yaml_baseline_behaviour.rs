// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8425 MIG.0: `serde-yaml` 0.9.34's behaviour on the cases where the
//! replacement parser is known or suspected to differ, recorded before the
//! swap. One golden, `behaviour.txt`, one row per case:
//! `case \t OK <reading>` or `case \t ERR <serde-yaml text>`.
//!
//! The destinations matter as much as the input. A repeated key is refused
//! in a struct and in the tree, but keeps the last value in any map,
//! including figment's `Dict` and a map field inside a struct. The rows name
//! the destination so that a later stage cannot match one and miss another.

#[path = "common/mik_8425_golden.rs"]
mod golden;

#[path = "common/yaml.rs"]
mod yaml;

#[path = "mik_8425_yaml_baseline_behaviour/report.rs"]
mod report;

use report::report;

/// `serde-yaml` 0.9.34's outcome on every recorded case is unchanged.
#[test]
fn yaml_behaviour_matches_the_recording() {
    golden::assert_golden("behaviour.txt", &report());
}

/// The structural form keeps what JSON loses: a tagged node is not a one-key
/// map, and a numeric key is not a string key. Without this, the tree
/// digests could not tell those readings apart.
#[test]
fn the_structural_form_separates_tags_from_maps_and_key_types() {
    let structure =
        |doc: &str| golden::yaml_structure(&yaml::from_str::<yaml::Value>(doc).expect("parses"));
    assert_ne!(structure("a: !exact x\n"), structure("a: {'!exact': x}\n"));
    assert_ne!(structure("1: x\n"), structure("'1': x\n"));
    assert_ne!(structure("a: 1\n"), structure("a: '1'\n"));
}

/// Prints the golden for review; never part of a normal run.
#[test]
#[ignore = "records tests/fixtures/mik_8425_yaml/behaviour.txt; run with --ignored --nocapture"]
fn record_behaviour_golden() {
    print!(
        "----- BEGIN behaviour.txt -----\n{}----- END behaviour.txt -----\n",
        report()
    );
}
