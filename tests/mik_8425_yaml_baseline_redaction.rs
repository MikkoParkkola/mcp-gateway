// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8425 MIG.0 baseline, gate G2 "after" (B3): no YAML error prints
//! the value that caused it (CWE-532), recorded with `serde-yaml` 0.9.34.
//!
//! The config load path removes values (`config/load_error.rs`, MIK-8375).
//! The direct capability path did not, until B3 moved the redaction into the
//! adapter (`src/yaml/`), so a value in a wrongly typed field no longer
//! reaches the log. The leak MIG.0 recorded as `leaks=true` is closed here;
//! the golden shows `leaks=false` on every value row (the key-name control
//! still prints its key by design).

#[path = "common/mik_8425_golden.rs"]
mod golden;

#[path = "common/yaml.rs"]
mod yaml;

use mcp_gateway::capability::parse_capability;
use mcp_gateway::config::Config;
use std::fmt::Write as _;

#[path = "mik_8425_yaml_baseline_redaction/report.rs"]
mod report;

use report::{Case, SENTINEL, capability, capability_rows, load_capability_bound, outcome};

fn load_capability(text: &str) -> Result<(), String> {
    parse_capability(text)
        .map(|_| ())
        .map_err(|e| format!("{e} {e:?}"))
}

fn load_config(text: &str) -> Result<(), String> {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(&path, text).expect("write config");
    Config::load(Some(&path))
        .map(|_| ())
        .map_err(|e| format!("{e} {e:?}"))
}

fn config_rows(out: &mut String) {
    let cases = [
        Case {
            name: "config/type-error",
            bad: format!("server:\n  port: {SENTINEL}\n"),
            good: "server:\n  port: 39400\n".to_owned(),
            names: "server.port",
        },
        // A key name is printed by design (load_error keeps key paths), so
        // a sentinel used as a key is expected to appear: a control row
        // proving the check can see the sentinel, not a leak.
        Case {
            name: "config/key-name-control",
            bad: format!("{SENTINEL}: 1\n"),
            good: "server: {}\n".to_owned(),
            names: SENTINEL,
        },
        Case {
            name: "config/syntax-error",
            bad: format!("server: \"unterminated {SENTINEL}\n"),
            good: "server: {}\n".to_owned(),
            names: "quoted text is not closed, or continues with too little indentation",
        },
        Case {
            name: "config/nested-type-error",
            bad: format!("backends:\n  x:\n    command: y\n    timeout: [{SENTINEL}]\n"),
            good: "backends:\n  x:\n    command: y\n    timeout: 5s\n".to_owned(),
            names: "backends.x.timeout",
        },
        // MIK-8425 MIG.2 (hard requirement 3, G2): an undefined alias, with
        // the sentinel as a resolved value elsewhere in the same document, so
        // the check is not vacuous; the refusal names its place.
        Case {
            name: "config/undefined-alias",
            bad: format!("server:\n  host: {SENTINEL}\n  port: *nope\n"),
            good: "server:\n  host: localhost\n  port: 39400\n".to_owned(),
            names: "line",
        },
        // A second document is refused; the sentinel is in it.
        Case {
            name: "config/multi-document",
            bad: format!("server:\n  port: 39400\n---\nserver:\n  host: {SENTINEL}\n"),
            good: "server:\n  port: 39400\n".to_owned(),
            names: "document",
        },
    ];
    for case in &cases {
        let _ = writeln!(out, "{}\t{}", case.name, outcome(case, load_config));
    }
}

fn report() -> String {
    let mut out = String::new();
    capability_rows(&mut out, load_capability);
    config_rows(&mut out);
    out
}

/// Which paths print the sentinel today is exactly as recorded.
#[test]
fn yaml_error_leaks_are_as_recorded() {
    golden::assert_golden("redaction.txt", &report());
}

/// B3 closes the leak MIG.0 recorded: every value row refuses without
/// printing the sentinel.
#[test]
fn no_baseline_path_prints_the_value() {
    let report = report();
    for name in [
        "capability/type-error",
        "capability/syntax-error",
        "config/type-error",
        "config/syntax-error",
        "config/nested-type-error",
        "config/undefined-alias",
        "config/multi-document",
    ] {
        assert!(
            report.contains(&format!(
                "{name}\trefused names=true leaks=false control=loads"
            )),
            "B3: {name} must refuse without printing the value: {report}"
        );
    }
    // The key-name control still prints the sentinel by design (key paths are
    // kept): it proves the check can see the sentinel, not a leak.
    assert!(
        report.contains("config/key-name-control\trefused names=true leaks=true control=loads"),
        "the key-name control still shows the key: {report}"
    );
}

/// The parity suite's capability reading, which repeats `parse_capability`
/// over its own binding, gives the same rows as `parse_capability`.
#[test]
fn the_parity_capability_rows_match_parse_capability() {
    let mut library = String::new();
    capability_rows(&mut library, load_capability);
    let mut bound = String::new();
    capability_rows(&mut bound, load_capability_bound);
    assert_eq!(bound, library);
}

/// Prints the golden for review; never part of a normal run.
#[test]
#[ignore = "records tests/fixtures/mik_8425_yaml/redaction.txt; run with --ignored --nocapture"]
fn record_redaction_golden() {
    print!(
        "----- BEGIN redaction.txt -----\n{}----- END redaction.txt -----\n",
        report()
    );
    // For the reviewer, not the golden: the refusal each capability row saw.
    for text in [
        capability(SENTINEL),
        format!("name: \"unterminated {SENTINEL}\n"),
    ] {
        println!("capability refusal: {:?}", load_capability(&text).err());
    }
}
