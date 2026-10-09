// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! MIK-7507: a Linear write that sends a long text field asks for it back, so
//! a caller can compare what it sent with what Linear stored. Without the
//! field in the response, a write that did not apply looks like one that did.

use std::path::Path;

use serde_yaml::Value;

/// The long text fields a Linear write can send.
const LONG_TEXT: [&str; 2] = ["description", "body"];

/// Whether `value` holds a key named `field`, at any depth.
fn sends(value: &Value, field: &str) -> bool {
    match value {
        Value::Mapping(map) => map
            .iter()
            .any(|(k, v)| k.as_str() == Some(field) || sends(v, field)),
        Value::Sequence(items) => items.iter().any(|v| sends(v, field)),
        _ => false,
    }
}

/// Whether the GraphQL `query` selects `field`: a word `field` left once the
/// variable references (`$field`) and input assignments (`field: $field`)
/// are taken out.
fn selects(query: &str, field: &str) -> bool {
    let without_inputs = query
        .replace(&format!("{field}: ${field}"), "")
        .replace(&format!("${field}"), "");
    without_inputs
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .any(|word| word == field)
}

#[test]
fn every_linear_write_selects_the_long_text_it_sends() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("capabilities/linear");
    let mut checked = Vec::new();
    let mut missing = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("capabilities/linear exists") {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("yaml") {
            continue;
        }
        let cap: Value = serde_yaml::from_str(&std::fs::read_to_string(&path).unwrap())
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let Some(providers) = cap["providers"].as_mapping() else {
            continue;
        };
        for provider in providers.values() {
            let body = &provider["config"]["body"];
            let Some(query) = body["query"].as_str() else {
                continue;
            };
            if !query.trim_start().starts_with("mutation") {
                continue;
            }
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            for field in LONG_TEXT {
                if sends(&body["variables"], field) || query.contains(&format!("${field}")) {
                    checked.push(format!("{name}:{field}"));
                    if !selects(query, field) {
                        missing.push(format!("{name}:{field}"));
                    }
                }
            }
        }
    }
    assert!(
        checked
            .iter()
            .any(|c| c == "linear_update_issue.yaml:description"),
        "linear_update_issue was not checked: {checked:?}"
    );
    assert!(
        missing.is_empty(),
        "writes that do not ask for their text back: {missing:?}"
    );
}
