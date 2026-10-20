// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8358.CAPCFG.2: an input schema that is neither null, empty nor an
//! object (a scalar, an array) is a CAP-003 error, and the loader skips the
//! capability. A null schema (webhook-only) and an object schema still load.

use std::io::Write;

use super::loader::CapabilityLoader;
use super::validator::{IssueSeverity, validate_capability_definition};

/// One REST capability whose `schema.input` is the YAML `input`.
fn capability_yaml(name: &str, input: &str) -> String {
    format!(
        "name: {name}
description: schema shape row
schema:
  input: {input}
providers:
  primary:
    service: rest
    config:
      base_url: https://api.invalid
      path: /x
"
    )
}

/// The names the loader serves from a directory holding one file per case.
async fn loaded(cases: &[(&str, &str)]) -> Vec<String> {
    let dir = tempfile::TempDir::new().expect("a temp dir");
    for (name, input) in cases {
        let mut file =
            std::fs::File::create(dir.path().join(format!("{name}.yaml"))).expect("a file");
        file.write_all(capability_yaml(name, input).as_bytes())
            .expect("written");
    }
    let mut names: Vec<String> =
        CapabilityLoader::load_directory(dir.path().to_str().expect("a UTF-8 path"))
            .await
            .expect("the directory loads")
            .into_iter()
            .map(|cap| cap.name)
            .collect();
    names.sort();
    names
}

/// Red on the line: the scalar and array schemas load.
#[tokio::test]
async fn a_scalar_or_array_input_schema_keeps_the_capability_from_loading() {
    let names = loaded(&[
        ("as_string", "\"text\""),
        ("as_empty_string", "\"\""),
        ("as_number", "42"),
        ("as_bool", "true"),
        ("as_array", "[{type: string}]"),
        ("as_empty_array", "[]"),
    ])
    .await;
    assert!(names.is_empty(), "CAPCFG.2: these loaded: {names:?}");
}

/// Control: a null, an empty and an object schema load as before.
#[tokio::test]
async fn null_empty_and_object_input_schemas_still_load() {
    let names = loaded(&[
        ("as_null", "null"),
        ("as_empty", "{}"),
        ("as_untyped_object", "{properties: {q: {type: string}}}"),
        (
            "as_object",
            "{type: object, properties: {q: {type: string}}}",
        ),
    ])
    .await;
    assert_eq!(
        names,
        ["as_empty", "as_null", "as_object", "as_untyped_object"],
        "CAPCFG.2 control"
    );
}

/// The refusal is CAP-003, an error, on `schema.input`, naming the kind.
#[test]
fn the_refusal_is_a_cap_003_error_on_schema_input() {
    for (input, kind) in [
        ("\"text\"", "a string"),
        ("\"\"", "a string"),
        ("42", "a number"),
        ("true", "a boolean"),
        ("[{type: string}]", "an array"),
        ("[]", "an array"),
    ] {
        let cap = super::parse_capability(&capability_yaml("shape", input))
            .expect("the capability parses");
        let issues = validate_capability_definition(&cap, None);
        assert!(
            issues.iter().any(|issue| issue.code == "CAP-003"
                && issue.severity == IssueSeverity::Error
                && issue.field == Some("schema.input")
                && issue.message.ends_with(&format!("got {kind}"))),
            "CAPCFG.2: {input}: {issues:?}"
        );
    }
}

/// Control: a capability with no `schema` at all still loads.
#[tokio::test]
async fn an_omitted_input_schema_still_loads() {
    let dir = tempfile::TempDir::new().expect("a temp dir");
    let yaml = capability_yaml("no_schema", "null").replace("schema:\n  input: null\n", "");
    assert!(!yaml.contains("input:"), "premise: {yaml}");
    std::fs::write(dir.path().join("no_schema.yaml"), yaml).expect("written");
    let caps = CapabilityLoader::load_directory(dir.path().to_str().expect("a UTF-8 path"))
        .await
        .expect("the directory loads");
    assert_eq!(caps.len(), 1, "CAPCFG.2 control: an omitted schema loads");
}
