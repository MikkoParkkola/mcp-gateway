// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8425 MIG.0, gate G2 "before": where a YAML error prints the value
//! that caused it today (CWE-532), recorded with serde_yaml 0.9.34.
//!
//! The config load path removes values (`config/load_error.rs`, MIK-8375).
//! The direct capability path does not: `capability/parser.rs` formats the
//! whole serde_yaml error, so a value in a wrongly typed field reaches the
//! log. That leak is recorded here as the current state, as a fact this test
//! pins, not as an endorsement. After the backend swap, G2 requires the
//! sentinel to be absent on every path; this golden is then updated in the
//! swap PR, and the change shows as `leaks=true` turning to `leaks=false`.

#[path = "common/mik_8425_golden.rs"]
mod golden;

use mcp_gateway::capability::parse_capability;
use mcp_gateway::config::Config;

/// Stands in for a secret typed into the wrong field. Not shaped like any
/// real credential, so secret scanners do not flag the test.
const SENTINEL: &str = "MIK8425-SENTINEL-7f3a";

fn capability(provider_timeout: &str) -> String {
    format!(
        "fulcrum: \"1.0\"\nname: g2_probe\ndescription: G2 probe.\nschema:\n  input:\n    \
         type: object\n    properties: {{}}\nproviders:\n  primary:\n    service: rest\n    \
         timeout: {provider_timeout}\n    config:\n      base_url: https://api.example.test\n      \
         path: /x\n      method: GET\n"
    )
}

fn outcome(message: Result<(), String>) -> String {
    match message {
        Ok(()) => "accepted".to_owned(),
        Err(message) => format!("refused leaks={}", message.contains(SENTINEL)),
    }
}

fn capability_rows(out: &mut String) {
    let cases = [
        ("capability/type-error", capability(SENTINEL)),
        ("capability/syntax-error", format!("name: [{SENTINEL}\n")),
    ];
    for (case, text) in cases {
        let result = parse_capability(&text)
            .map(|_| ())
            .map_err(|e| format!("{e} {e:?}"));
        out.push_str(&format!("{case}\t{}\n", outcome(result)));
    }
}

fn config_rows(out: &mut String) {
    let cases = [
        (
            "config/type-error",
            format!("server:\n  port: {SENTINEL}\n"),
        ),
        // A key name is printed by design (load_error keeps key paths), so
        // a sentinel used as a key is expected to appear: a control row
        // proving the check can see the sentinel, not a leak.
        ("config/key-name-control", format!("{SENTINEL}: 1\n")),
        ("config/syntax-error", format!("server: [{SENTINEL}\n")),
        (
            "config/nested-type-error",
            format!("backends:\n  x:\n    command: y\n    timeout: [{SENTINEL}]\n"),
        ),
    ];
    for (case, text) in cases {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("gateway.yaml");
        mcp_gateway::gateway::test_helpers::write_owner_only(&path, &text).expect("write config");
        let result = Config::load(Some(&path))
            .map(|_| ())
            .map_err(|e| format!("{e} {e:?}"));
        out.push_str(&format!("{case}\t{}\n", outcome(result)));
    }
}

fn report() -> String {
    let mut out = String::new();
    capability_rows(&mut out);
    config_rows(&mut out);
    out
}

/// Which paths print the sentinel today is exactly as recorded.
#[test]
fn yaml_error_leaks_are_as_recorded() {
    golden::assert_golden("redaction.txt", &report());
}

/// The recording itself proves both halves of the baseline: the capability
/// type error leaks today, and the config path does not.
#[test]
fn the_baseline_shows_the_capability_leak_and_a_clean_config_path() {
    let report = report();
    assert!(
        report.contains("capability/type-error\trefused leaks=true"),
        "the recorded before-state is a leak on the capability path: {report}"
    );
    assert!(
        report.contains("config/type-error\trefused leaks=false"),
        "the config path removes values today: {report}"
    );
}

/// Prints the golden for review; never part of a normal run.
#[test]
#[ignore = "records tests/fixtures/mik_8425_yaml/redaction.txt; run with --ignored --nocapture"]
fn record_redaction_golden() {
    print!(
        "----- BEGIN redaction.txt -----\n{}----- END redaction.txt -----\n",
        report()
    );
}
