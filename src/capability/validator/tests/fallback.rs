// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7768: `providers.fallback` is parsed but never executed, so declaring it
//! must say so (CAP-011) instead of loading as a silent no-op.

use super::*;
use crate::capability::CapabilityLoader;

const WITH_FALLBACK: &str = r"
name: fallback_cap
description: Has a fallback provider.
providers:
  primary:
    config:
      base_url: https://primary.example.com
      path: /v1
  fallback:
    - config:
        base_url: https://backup.example.com
        path: /v1
";

const WITHOUT_FALLBACK: &str = r"
name: fallback_cap
description: Has a fallback provider.
providers:
  primary:
    config:
      base_url: https://primary.example.com
      path: /v1
";

fn cap011(yaml: &str) -> Vec<Issue> {
    let cap: CapabilityDefinition = serde_yaml::from_str(yaml).expect("parses");
    validate_capability_definition(&cap, None)
        .into_iter()
        .filter(|i| i.code == "CAP-011")
        .collect()
}

#[test]
fn a_declared_fallback_is_warned_as_not_executed() {
    let issues = cap011(WITH_FALLBACK);
    assert_eq!(issues.len(), 1, "one CAP-011 issue: {issues:?}");
    assert_eq!(issues[0].severity, IssueSeverity::Warning, "{issues:?}");
    assert_eq!(issues[0].field, Some("providers.fallback"), "{issues:?}");
    assert!(
        issues[0].message.contains("not executed"),
        "the warning says the fallback does nothing: {issues:?}"
    );
}

#[test]
fn no_fallback_means_no_cap011() {
    assert!(cap011(WITHOUT_FALLBACK).is_empty());
}

/// A malformed entry used to be dropped, leaving an empty list and no warning.
#[test]
fn a_malformed_fallback_entry_is_a_parse_error() {
    for fallback in ["\n    - timeout: soon", "\n    timeout: soon"] {
        let yaml = format!("{WITHOUT_FALLBACK}  fallback:{fallback}\n");
        let parsed = serde_yaml::from_str::<CapabilityDefinition>(&yaml);
        assert!(parsed.is_err(), "must not parse: {yaml}");
    }
}

/// A warning, not an error: the primary still serves, so the tool stays loaded.
#[tokio::test]
async fn a_capability_with_a_fallback_still_loads() {
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(dir.path().join("fallback_cap.yaml"), WITH_FALLBACK).unwrap();
    let caps = CapabilityLoader::load_directory(dir.path().to_str().unwrap())
        .await
        .unwrap();
    assert_eq!(caps.len(), 1, "the capability loads despite CAP-011");
}
