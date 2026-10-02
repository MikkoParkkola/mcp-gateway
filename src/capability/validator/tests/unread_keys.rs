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
    let issues = cap012(&format!("{HEAD}      comand: gws\n      argz: [a]\n"));
    let text = format!("{issues:?}");
    assert!(text.contains("providers.primary.config.comand"), "{text}");
    assert!(text.contains("providers.primary.config.argz"), "{text}");
}

#[test]
fn a_provider_with_only_known_keys_has_no_cap012() {
    assert!(cap012(HEAD).is_empty());
}

#[test]
fn a_fallback_entry_key_is_named_by_its_index() {
    let yaml = format!(
        "{HEAD}  fallback:\n    - config:\n        base_url: https://b.invalid\n        pth: /v1\n"
    );
    let text = format!("{:?}", cap012(&yaml));
    assert!(text.contains("providers.fallback[0].config.pth"), "{text}");
}

#[test]
fn an_annotation_key_is_not_reported() {
    assert!(cap012(&format!("{HEAD}      _note: why\n      x-owner: me\n")).is_empty());
}

/// The annotation test reads the real mapping key, not the rendered path: a
/// key named `http.x-method` is not an annotation.
#[test]
fn a_dotted_key_ending_like_an_annotation_is_still_reported() {
    let issues = cap012(&format!("{HEAD}      \"http.x-method\": POST\n"));
    assert_eq!(issues.len(), 1, "{issues:?}");
}

#[test]
fn a_key_inside_path_selector_is_named_without_option_markers() {
    let yaml = format!(
        "{HEAD}      path_selector:\n        parameter: kind\n        default: a\n        paths:\n          a: /a\n        dflt: b\n"
    );
    let issues = cap012(&yaml);
    assert_eq!(
        issues.len(),
        1,
        "only the typo, not `paths` entries: {issues:?}"
    );
    assert!(
        issues[0]
            .message
            .contains("providers.primary.config.path_selector.dflt"),
        "{issues:?}"
    );
}

/// The falsifier for a false positive: across the shipped catalog, CAP-012 may
/// name only keys no provider field reads today (the CLI/MCP and transform
/// keys an executor will read once it exists). A field such as `headers`,
/// `body` or `static_params` reported here would warn on every REST capability.
#[test]
fn the_shipped_catalog_reports_only_keys_no_field_reads() {
    const NOT_YET_READ: &[&str] = &[
        "command",
        "args",
        "args_template",
        "transport",
        "env",
        "timeout_ms",
        "response_transform",
    ];
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("capabilities");
    let mut stack = vec![root];
    let mut checked = 0;
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read capabilities/") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().is_none_or(|e| e != "yaml") {
                continue;
            }
            let yaml = std::fs::read_to_string(&path).expect("read capability");
            for issue in cap012(&yaml) {
                let key = issue.message.split_whitespace().next().unwrap_or_default();
                let leaf = key.rsplit('.').next().unwrap_or_default();
                assert!(
                    NOT_YET_READ.contains(&leaf),
                    "{}: unexpected CAP-012 {issue}",
                    path.display()
                );
            }
            checked += 1;
        }
    }
    assert!(checked > 100, "the catalog was read: {checked} files");
}
