// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `cap import --auth-key` accepts exactly what the credential resolver
//! reads: one literal table, checked against the parser both use
//! and against the resolver's own fetch path where that path has no side
//! effect (refusals, and the environment-variable forms).

use super::super::CapabilityExecutor;
use super::credential_form;
use crate::capability::CapabilityExecutionContext;
use crate::capability::definition::AuthConfig;

/// Every input with whether it is a reference: the six forms, each form with
/// an empty payload (it parses, and fails later at resolve time), then four
/// that are not references.
const TABLE: &[(&str, bool)] = &[
    ("env:API_TOKEN", true),
    ("keychain:probe", true),
    ("oauth:github", true),
    ("file:/run/probe.key", true),
    ("{env.API_TOKEN}", true),
    ("API_TOKEN", true),
    ("env:", true),
    ("keychain:", true),
    ("oauth:", true),
    ("file:", true),
    ("{env.}", true),
    ("plain-text-not-a-reference", false),
    ("vault:probe", false),
    ("x-env:NAME", false),
    ("", false),
];

/// The resolver's two refusals of a key that is not a reference.
fn is_format_refusal(message: &str) -> bool {
    message.contains("credential format") || message.contains("No credential key configured")
}

fn bearer(key: &str) -> AuthConfig {
    let quoted = serde_json::to_string(key).expect("a JSON string");
    crate::yaml::from_str(&format!("required: true\ntype: bearer\nkey: {quoted}\n"))
        .expect("an auth block")
}

#[tokio::test]
async fn auth_key_accepts_exactly_what_the_resolver_accepts() {
    for (key, reference) in TABLE {
        assert_eq!(
            credential_form(key).is_ok(),
            *reference,
            "{key:?}: the parser --auth-key and the resolver share"
        );
        // The fetch path only where it has no side effect: a non-reference
        // is refused before any lookup, and the environment forms only read
        // the environment. Keychain, OAuth and file lookups stay out of a
        // unit test; they reach the resolver through the same parser.
        let env_family = key.starts_with("env:") || key.starts_with("{env.") || *key == "API_TOKEN";
        if *reference && !env_family {
            continue;
        }
        let said = CapabilityExecutor::new()
            .fetch_credential(&bearer(key), &CapabilityExecutionContext::default())
            .await
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert_eq!(
            is_format_refusal(&said),
            !reference,
            "{key:?}: the resolver said {said:?}"
        );
    }
}
