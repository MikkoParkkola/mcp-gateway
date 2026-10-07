// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! #2256: Linear accepts `createAsUser` only from an OAuth application. A
//! Linear capability that authenticates with a personal API key must not send
//! it, or every call fails (as `linear_create_issue` did before #165).
//! `displayIconUrl` carries the same OAuth-only constraint (#165 removed both).

use std::path::Path;

use serde_yaml::Value;

#[test]
fn api_key_linear_capabilities_never_send_oauth_only_fields() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("capabilities/linear");
    let mut checked = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("capabilities/linear exists") {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("yaml") {
            continue;
        }
        let cap: Value = serde_yaml::from_str(&std::fs::read_to_string(&path).unwrap())
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        if cap["auth"]["type"].as_str() != Some("api_key") {
            continue;
        }
        let Some(providers) = cap["providers"].as_mapping() else {
            continue;
        };
        for provider in providers.values() {
            let body = &provider["config"]["body"];
            // A provider with no request body sends nothing to check, so it
            // must not count toward the coverage assert below.
            if body.is_null() {
                continue;
            }
            let body = serde_yaml::to_string(body).unwrap();
            for field in ["createAsUser", "displayIconUrl"] {
                assert!(
                    !body.contains(field),
                    "{} sends {field} under api_key auth",
                    path.display()
                );
            }
            checked.push(path.file_name().unwrap().to_string_lossy().into_owned());
        }
    }
    assert!(
        checked.iter().any(|f| f == "linear_attach_url.yaml"),
        "linear_attach_url was not checked: {checked:?}"
    );
}
