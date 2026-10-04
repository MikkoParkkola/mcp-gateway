// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Every shipped capability declares its effect as data (`MIK-7216.IDEM.1`).
//!
//! `metadata.read_only` defaults to `false` when omitted, so an omission reads
//! as "side-effecting" by accident. The catalogue must say it on purpose.

use std::path::Path;

use serde_yaml::Value;

#[test]
fn every_capability_yaml_declares_an_explicit_boolean_read_only() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut checked = 0usize;
    let mut missing = Vec::new();
    for entry in walkdir::WalkDir::new(root.join("capabilities"))
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .filter(|e| {
            e.path()
                .extension()
                .is_some_and(|x| x == "yaml" || x == "yml")
        })
    {
        checked += 1;
        let text = std::fs::read_to_string(entry.path()).expect("capability file is readable");
        let doc: Value = serde_yaml::from_str(&text).expect("capability file is valid YAML");
        let declared = doc
            .get("metadata")
            .and_then(|m| m.get("read_only"))
            .is_some_and(Value::is_bool);
        if !declared {
            missing.push(
                entry
                    .path()
                    .strip_prefix(root)
                    .unwrap()
                    .display()
                    .to_string(),
            );
        }
    }
    assert!(
        checked > 0,
        "no capability YAMLs found; the check is vacuous"
    );
    assert!(
        missing.is_empty(),
        "capabilities without an explicit boolean metadata.read_only:\n  {}",
        missing.join("\n  ")
    );
}
