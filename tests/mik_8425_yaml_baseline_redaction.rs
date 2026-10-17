// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8425 MIG.0, gate G2 "before": where a YAML error prints the value
//! that caused it today (CWE-532), recorded with `serde_yaml` 0.9.34.
//!
//! The config load path removes values (`config/load_error.rs`, MIK-8375).
//! The direct capability path does not: `capability/parser.rs` formats the
//! whole `serde_yaml` error, so a value in a wrongly typed field reaches the
//! log. That leak is recorded here as the current state, as a fact this test
//! pins, not as an endorsement. After the backend swap, G2 requires the
//! sentinel to be absent on every path; this golden is then updated in the
//! swap PR, and the change shows as `leaks=true` turning to `leaks=false`.

#[path = "common/mik_8425_golden.rs"]
mod golden;

use mcp_gateway::capability::parse_capability;
use mcp_gateway::config::Config;
use std::fmt::Write as _;

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

/// One case: input with the sentinel, the same input corrected, and a
/// fragment the refusal must contain to prove it is refused for the reason
/// the case names (the key path, or a location for a syntax error).
struct Case {
    name: &'static str,
    bad: String,
    good: String,
    names: &'static str,
}

/// `refused names=<bool> leaks=<bool> control=<loads|refused>`: a refusal
/// counts only if it names the expected key or place, and only if the
/// corrected input loads, so an unrelated refusal cannot pass as redaction.
fn outcome(case: &Case, load: impl Fn(&str) -> Result<(), String>) -> String {
    let control = if load(&case.good).is_ok() {
        "loads"
    } else {
        "refused"
    };
    match load(&case.bad) {
        Ok(()) => format!("accepted control={control}"),
        Err(message) => format!(
            "refused names={} leaks={} control={control}",
            message.contains(case.names),
            message.contains(SENTINEL)
        ),
    }
}

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

fn capability_rows(out: &mut String) {
    let cases = [
        Case {
            name: "capability/type-error",
            bad: capability(SENTINEL),
            good: capability("30"),
            names: "providers.primary: invalid type: string",
        },
        Case {
            name: "capability/syntax-error",
            bad: format!("name: \"unterminated {SENTINEL}\n"),
            good: capability("30"),
            names: "while scanning a quoted scalar",
        },
    ];
    for case in &cases {
        let _ = writeln!(out, "{}\t{}", case.name, outcome(case, load_capability));
    }
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
            names: "while scanning a quoted scalar",
        },
        Case {
            name: "config/nested-type-error",
            bad: format!("backends:\n  x:\n    command: y\n    timeout: [{SENTINEL}]\n"),
            good: "backends:\n  x:\n    command: y\n    timeout: 5s\n".to_owned(),
            names: "backends.x.timeout",
        },
    ];
    for case in &cases {
        let _ = writeln!(out, "{}\t{}", case.name, outcome(case, load_config));
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
        report.contains("capability/type-error\trefused names=true leaks=true control=loads"),
        "the recorded before-state is a leak on the capability path: {report}"
    );
    assert!(
        report.contains("config/type-error\trefused names=true leaks=false control=loads"),
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
    // For the reviewer, not the golden: the refusal each capability row saw.
    for text in [
        capability(SENTINEL),
        format!("name: \"unterminated {SENTINEL}\n"),
    ] {
        println!("capability refusal: {:?}", load_capability(&text).err());
    }
}
