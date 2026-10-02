// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7775: a key inside a provider block that nothing reads is ignored by
//! serde, so a misspelling loads silently. It must be reported (CAP-012).

use super::*;

const HEAD: &str = r"
name: unread_cap
description: Reads one endpoint.
providers:
  primary:
    config:
      base_url: https://api.example.com
      path: /v1
";

fn cap012(yaml: &str) -> Vec<Issue> {
    let cap: CapabilityDefinition = serde_yaml::from_str(yaml).expect("parses");
    validate_capability_definition(&cap, None)
        .into_iter()
        .filter(|i| i.code == "CAP-012")
        .collect()
}

#[test]
fn a_misspelled_provider_config_key_is_warned_with_its_path() {
    let issues = cap012(&format!("{HEAD}      methd: POST\n"));
    assert_eq!(issues.len(), 1, "one CAP-012 issue: {issues:?}");
    assert_eq!(issues[0].severity, IssueSeverity::Warning, "{issues:?}");
    assert!(
        issues[0].message.contains("providers.primary.config.methd"),
        "the warning names the key's path: {issues:?}"
    );
}

#[test]
fn an_unread_key_beside_config_is_warned_too() {
    let yaml = HEAD.replace("    config:\n", "    timout: 5\n    config:\n");
    let issues = cap012(&yaml);
    assert_eq!(issues.len(), 1, "{issues:?}");
    assert!(
        issues[0].message.contains("providers.primary.timout"),
        "{issues:?}"
    );
}

#[test]
fn every_unread_key_is_named() {
    let issues = cap012(&format!("{HEAD}      command: gws\n      args: [a]\n"));
    let text = format!("{issues:?}");
    assert!(text.contains("providers.primary.config.command"), "{text}");
    assert!(text.contains("providers.primary.config.args"), "{text}");
}

#[test]
fn a_provider_with_only_known_keys_has_no_cap012() {
    assert!(cap012(HEAD).is_empty());
}
