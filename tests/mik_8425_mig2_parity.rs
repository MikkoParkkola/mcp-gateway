// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8425 MIG.2: the replacement YAML backend reproduces every golden the
//! guarded adapter recorded over the old backend (plan
//! `docs/internal/plans/2026-10-24-mik-8425-mig2-swap.md`, sections 3 and 3b).
//!
//! Each row compiles a baseline suite's own report over `yaml::next`
//! (`tests/common/yaml_next.rs`) and compares it with that suite's golden,
//! so the baseline crate and this one run one report over two backends.
//! Until step 4 every `next` entry point is a stub, and every row here is
//! red while the baseline suites stay green. At the switch the binding moves
//! to the adapter itself.

#[path = "common/mik_8425_golden.rs"]
mod golden;

#[path = "common/yaml_next.rs"]
mod yaml;

#[path = "mik_8425_yaml_baseline_behaviour/report.rs"]
mod behaviour;

#[path = "mik_8425_yaml_baseline_trees/report.rs"]
mod trees;

#[path = "mik_8425_yaml_baseline_configs/report.rs"]
mod configs;

#[path = "mik_8425_yaml_baseline_capabilities/report.rs"]
mod capabilities;

#[path = "mik_8425_yaml_baseline_redaction/report.rs"]
mod redaction;

/// The `redaction.txt` rows that start with `prefix`, as recorded.
fn recorded_rows(name: &str, prefix: &str) -> String {
    let text = std::fs::read_to_string(
        golden::repo_root()
            .join("tests/fixtures/mik_8425_yaml")
            .join(name),
    )
    .expect("golden");
    text.lines()
        .filter(|row| row.starts_with(prefix))
        .map(|row| format!("{row}\n"))
        .collect()
}

/// P1, P3-P5, P7, P11, P12 and the P6 write rows: every `behaviour.txt` row.
#[test]
fn behaviour_rows_read_as_recorded() {
    golden::assert_golden("behaviour.txt", &behaviour::report());
}

/// P2: every repository YAML file's tree, `Dict` and stream.
#[test]
fn every_repository_yaml_file_reads_as_recorded() {
    golden::assert_keyed_golden("trees.tsv", trees::MIN_COMPARED, trees::readings);
}

/// P13: the `Config` each shipped config and Helm ConfigMap extracts to.
#[test]
fn every_shipped_config_extracts_as_recorded() {
    golden::assert_keyed_golden("configs.tsv", configs::CONFIGS.len(), configs::reading);
}

/// P9: every shipped capability reads to the recorded definition.
#[test]
fn every_capability_reads_as_recorded() {
    golden::assert_keyed_golden("capabilities.tsv", 120, capabilities::reading);
}

/// P8: a capability refused for a wrongly typed value or a syntax error
/// names its place and never prints the value.
#[test]
fn capability_refusals_are_redacted_as_recorded() {
    let mut rows = String::new();
    redaction::capability_rows(&mut rows, redaction::load_capability_bound);
    assert_eq!(rows, recorded_rows("redaction.txt", "capability/"));
}

/// How many golden rows the new backend already reproduces, per golden.
/// Step 3's evidence that the binding reaches the stubs: every count is 0,
/// or the row is listed with the reason it never reaches the reader.
#[test]
#[ignore = "step 3 evidence; run with --ignored --nocapture"]
fn rows_the_stubs_still_match() {
    let fixtures = golden::repo_root().join("tests/fixtures/mik_8425_yaml");
    let read = |name: &str| std::fs::read_to_string(fixtures.join(name)).expect("golden");
    let behaviour_now = behaviour::report();
    let recorded = read("behaviour.txt");
    let now: std::collections::HashSet<&str> = behaviour_now.lines().collect();
    let same: Vec<&str> = recorded.lines().filter(|l| now.contains(l)).collect();
    println!(
        "behaviour.txt: {} of {} rows match: {same:?}",
        same.len(),
        recorded.lines().count()
    );
    let mut rows = String::new();
    redaction::capability_rows(&mut rows, redaction::load_capability_bound);
    let recorded = recorded_rows("redaction.txt", "capability/");
    let same: Vec<&str> = recorded
        .lines()
        .filter(|row| rows.lines().any(|now| now == *row))
        .collect();
    println!(
        "redaction.txt capability rows: {} of 2 match: {same:?}",
        same.len()
    );
    for (name, read_row) in [
        ("trees.tsv", trees::readings as fn(&str) -> String),
        ("configs.tsv", configs::reading),
        ("capabilities.tsv", capabilities::reading),
    ] {
        let recorded = read(name);
        let mut total = 0;
        let mut same = Vec::new();
        for row in recorded.lines() {
            let mut cols = row.splitn(3, '\t');
            let (Some(path), Some(_), Some(expected)) = (cols.next(), cols.next(), cols.next())
            else {
                continue;
            };
            let Ok(text) = std::fs::read_to_string(golden::repo_root().join(path)) else {
                continue;
            };
            total += 1;
            if read_row(&text) == expected {
                same.push(path.to_owned());
            }
        }
        println!("{name}: {} of {total} rows match: {same:?}", same.len());
    }
}
