// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8425 MIG.2: the YAML backend reproduces every golden the guarded
//! adapter recorded over the replaced backend (plan
//! `docs/internal/plans/2026-10-24-mik-8425-mig2-swap.md`, sections 3 and 3b).
//!
//! Each row compiles a baseline suite's own report and compares it with that
//! suite's golden. Before the switch this crate bound the reports to
//! `yaml::next`, the backend under construction; since the switch that is
//! the adapter itself, so it binds `tests/common/yaml.rs` like the baseline
//! suites.
//!
//! A reading the design allows to change (D13, D14) is never fixed by
//! editing a golden: it is a row in `deviations.tsv` (`golden`, `key`, the
//! new reading, the D-id, its `upgrading.d` fragment), which every
//! comparison here applies and the seats review row by row.

#[path = "common/mik_8425_golden.rs"]
mod golden;

#[path = "common/yaml.rs"]
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

const FIXTURES: &str = "tests/fixtures/mik_8425_yaml";

fn fixture(name: &str) -> String {
    std::fs::read_to_string(golden::repo_root().join(FIXTURES).join(name)).expect("golden")
}

/// The allowed reading changes for `name`, keyed by row key. Each row must
/// name a design D-id and an existing `upgrading.d` fragment.
fn deviations(name: &str) -> std::collections::BTreeMap<String, String> {
    let mut out = std::collections::BTreeMap::new();
    for row in fixture("deviations.tsv")
        .lines()
        .filter(|r| !r.trim().is_empty())
    {
        let cols: Vec<&str> = row.split('\t').collect();
        let [file, key, reading, d_id, fragment] = cols[..] else {
            panic!("deviations.tsv: malformed row {row:?}");
        };
        assert!(
            d_id.starts_with('D') && golden::repo_root().join(fragment).is_file(),
            "deviations.tsv: {key} needs a D-id and an existing upgrading.d fragment"
        );
        if file == name {
            out.insert(key.to_owned(), reading.to_owned());
        }
    }
    out
}

/// One comparison: the row keys whose reading differs from the golden
/// (after deviations), and how many rows were compared.
struct Outcome {
    compared: usize,
    differ: Vec<String>,
}

/// `behaviour.txt`-shaped rows (`key \t reading`) selected by `keep`.
fn compare_rows(name: &str, now: &str, keep: impl Fn(&str) -> bool) -> Outcome {
    let allowed = deviations(name);
    let now: std::collections::BTreeMap<&str, &str> =
        now.lines().filter_map(|r| r.split_once('\t')).collect();
    let mut outcome = Outcome {
        compared: 0,
        differ: Vec::new(),
    };
    for row in fixture(name).lines() {
        let Some((key, recorded)) = row.split_once('\t') else {
            continue;
        };
        if !keep(key) {
            continue;
        }
        outcome.compared += 1;
        let expected = allowed.get(key).map_or(recorded, String::as_str);
        if now.get(key).copied() != Some(expected) {
            outcome.differ.push(key.to_owned());
        }
    }
    outcome
}

/// A keyed golden (`path \t sha256 \t reading`); a row whose file is gone,
/// or edited since recording so that it reads differently, is skipped only
/// when `reviewed_skips.tsv` lists it, as `assert_keyed_golden` does.
fn compare_keyed(name: &str, read: impl Fn(&str) -> String) -> Outcome {
    let allowed = deviations(name);
    let mut outcome = Outcome {
        compared: 0,
        differ: Vec::new(),
    };
    let table = fixture(name);
    let mut unchanged = Vec::new();
    let mut skipped = Vec::new();
    for row in table.lines() {
        let mut cols = row.splitn(3, '\t');
        let (Some(path), Some(sha), Some(recorded)) = (cols.next(), cols.next(), cols.next())
        else {
            panic!("{name}: malformed row {row:?}");
        };
        let Ok(text) = std::fs::read_to_string(golden::repo_root().join(path)) else {
            // The package does not ship it: not a skip the list must name.
            if golden::in_packaged_crate() {
                eprintln!("{name}: {path} is not in the package");
            } else {
                skipped.push(path);
            }
            continue;
        };
        let expected = allowed.get(path).map_or(recorded, String::as_str);
        let same = read(&text) == expected;
        // An edited file that still reads as recorded is compared, not skipped.
        if golden::digest(text.as_bytes()) == sha {
            unchanged.push(path);
        } else if !same {
            skipped.push(path);
            continue;
        }
        outcome.compared += 1;
        if !same {
            outcome.differ.push(path.to_owned());
        }
    }
    golden::assert_skips_reviewed(name, unchanged, &skipped);
    outcome
}

fn assert_outcome(group: &str, outcome: &Outcome, min_compared: usize) {
    assert!(
        outcome.compared >= min_compared,
        "{group}: only {} rows comparable (need {min_compared})",
        outcome.compared
    );
    assert!(
        outcome.differ.is_empty(),
        "{group}: {} of {} rows differ: {:?}",
        outcome.differ.len(),
        outcome.compared,
        outcome.differ
    );
}

/// The `behaviour.txt` groups, each its own red-to-green row of the plan.
/// P1 is every read row the others do not claim.
const GROUPS: &[(&str, &[&str])] = &[
    ("P11 tags", &["mig2/tag/"]),
    ("P7 figment", &["mig2/figment/"]),
    ("P12 from_value", &["mig2/from-value/"]),
    (
        "P6 writer",
        &[
            "write/",
            "mig2/r1/write/",
            "mig2/r2/write/",
            "mig2/r3/write/",
        ],
    ),
];

fn in_group(key: &str, prefixes: &[&str]) -> bool {
    prefixes.iter().any(|p| key.starts_with(p))
}

fn behaviour_group(group: &str) -> Outcome {
    let now = behaviour::report();
    match GROUPS.iter().find(|(name, _)| *name == group) {
        Some((_, prefixes)) => compare_rows("behaviour.txt", &now, |k| in_group(k, prefixes)),
        None => compare_rows("behaviour.txt", &now, |k| {
            !GROUPS.iter().any(|(_, p)| in_group(k, p))
        }),
    }
}

/// P1 (with P3-P5): every `behaviour.txt` read row outside the groups below.
#[test]
fn p1_read_rows_as_recorded() {
    assert_outcome("P1 reads", &behaviour_group("P1 reads"), 100);
}

/// P11: standard tags resolve, local tags stay tagged, a URI tag is dropped.
#[test]
fn p11_tag_rows_as_recorded() {
    assert_outcome("P11 tags", &behaviour_group("P11 tags"), 20);
}

/// P7: what `figment_data` hands the config loader.
#[test]
fn p7_figment_rows_as_recorded() {
    assert_outcome("P7 figment", &behaviour_group("P7 figment"), 4);
}

/// P12: `from_value` on the recorded enum shapes.
#[test]
fn p12_from_value_rows_as_recorded() {
    assert_outcome("P12 from_value", &behaviour_group("P12 from_value"), 5);
}

/// P6 (behaviour part): `to_string` output and its read-back.
#[test]
fn p6_write_rows_as_recorded() {
    assert_outcome("P6 writer", &behaviour_group("P6 writer"), 3);
}

/// P6 (round trips): every repository YAML file that reads as one tree is
/// written by the new writer and read back by the new reader unchanged.
#[test]
fn p6_every_repository_tree_round_trips() {
    let mut checked = 0usize;
    let mut differ = Vec::new();
    for path in trees::paths() {
        let Ok(text) = std::fs::read_to_string(golden::repo_root().join(&path)) else {
            continue;
        };
        let Ok(tree) = yaml::from_str::<yaml::Value>(&text) else {
            continue;
        };
        checked += 1;
        let written = yaml::to_string(&tree).expect("a read tree writes");
        match yaml::from_str::<yaml::Value>(&written) {
            Ok(back) if back == tree => {}
            Ok(_) => differ.push(format!("{path}: reads back differently")),
            Err(error) => differ.push(format!("{path}: written text refused: {error}")),
        }
    }
    assert!(checked >= 100, "only {checked} trees checked");
    assert!(
        differ.is_empty(),
        "{} of {checked} trees do not round-trip: {differ:?}",
        differ.len()
    );
}

/// P2: every repository YAML file's tree, `Dict` and stream, as recorded
/// with the replaced backend.
///
/// Before the swap this compared the walked files exactly (MIK-8425 MIG.2,
/// a seat finding), and every recorded row matched; that is the swap's
/// evidence. After it, there is no old backend to re-record with, so a file
/// another change edits or removes is skipped only when
/// `reviewed_skips.tsv` lists it, as the baseline suites do.
#[test]
fn p2_trees_as_recorded() {
    let outcome = compare_keyed("trees.tsv", trees::readings);
    assert_outcome("P2 trees", &outcome, 1);
}

/// P13: the `Config` each shipped config and Helm `ConfigMap` extracts to.
#[test]
fn p13_configs_as_recorded() {
    assert_outcome(
        "P13 configs",
        &compare_keyed("configs.tsv", configs::reading),
        1,
    );
}

/// P9: every shipped capability reads to the recorded definition.
#[test]
fn p9_capabilities_as_recorded() {
    assert_outcome(
        "P9 capabilities",
        &compare_keyed("capabilities.tsv", capabilities::reading),
        1,
    );
}

/// P8: a capability refused for a wrongly typed value or a syntax error
/// names its place and never prints the value.
#[test]
fn p8_capability_redaction_as_recorded() {
    let mut rows = String::new();
    redaction::capability_rows(&mut rows, redaction::load_capability_bound);
    let outcome = compare_rows("redaction.txt", &rows, |k| k.starts_with("capability/"));
    assert_outcome("P8 redaction", &outcome, 2);
}

/// Matching rows per group: the step 4 progress number, and step 3's
/// evidence that every row reaches `next` (all zero on the stubs).
#[test]
#[ignore = "progress count; run with --ignored --nocapture"]
fn rows_matching_per_group() {
    let mut report = Vec::new();
    for group in [
        "P1 reads",
        "P11 tags",
        "P7 figment",
        "P12 from_value",
        "P6 writer",
    ] {
        report.push((group, behaviour_group(group)));
    }
    report.push(("P2 trees", compare_keyed("trees.tsv", trees::readings)));
    report.push((
        "P13 configs",
        compare_keyed("configs.tsv", configs::reading),
    ));
    report.push((
        "P9 capabilities",
        compare_keyed("capabilities.tsv", capabilities::reading),
    ));
    let mut rows = String::new();
    redaction::capability_rows(&mut rows, redaction::load_capability_bound);
    report.push((
        "P8 redaction",
        compare_rows("redaction.txt", &rows, |k| k.starts_with("capability/")),
    ));
    for (group, outcome) in &report {
        println!(
            "{group}: {} of {} match",
            outcome.compared - outcome.differ.len(),
            outcome.compared
        );
    }
}
