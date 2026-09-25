// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Role-filter cells for `search.rs`, split out so the module keeps headroom
//! under the file-size ratchet.

use super::{effective_role, infer_role, parse_role_filter, tool_matches_role};
use crate::projection::Role;
use crate::protocol::{Tool, ToolAnnotations};
use serde_json::json;

fn tool(name: &str, read_only: Option<bool>, role: Option<Role>) -> Tool {
    Tool {
        name: name.to_string(),
        title: None,
        description: None,
        input_schema: json!({"type": "object"}),
        output_schema: None,
        annotations: read_only.map(|ro| ToolAnnotations {
            read_only_hint: Some(ro),
            ..Default::default()
        }),
        role,
        projection: None,
    }
}

#[test]
fn infer_role_from_name_and_readonly() {
    assert_eq!(
        infer_role(&tool("search_issues", Some(true), None)),
        Role::Selector
    );
    assert_eq!(
        infer_role(&tool("list_repos", Some(true), None)),
        Role::Selector
    );
    assert_eq!(
        infer_role(&tool("get_issue", Some(true), None)),
        Role::Extractor
    );
    assert_eq!(
        infer_role(&tool("read_file", Some(true), None)),
        Role::Extractor
    );
    // read-only but unclear name -> extractor (still not an action)
    assert_eq!(
        infer_role(&tool("weather", Some(true), None)),
        Role::Extractor
    );
    // not read-only -> action regardless of name
    assert_eq!(
        infer_role(&tool("search_and_delete", Some(false), None)),
        Role::Action
    );
    // no annotations -> action (safe default)
    assert_eq!(infer_role(&tool("mystery", None, None)), Role::Action);
}

#[test]
fn effective_role_prefers_explicit_tag_over_inference() {
    // A tool named "search" but explicitly tagged Action stays Action.
    let t = tool("search_x", Some(true), Some(Role::Action));
    assert_eq!(effective_role(&t), Role::Action);
}

#[test]
fn tool_matches_role_filter() {
    let selector = tool("search_x", Some(true), None);
    let action = tool("create_x", Some(false), None);
    // None = no filter, matches everything
    assert!(tool_matches_role(&selector, None));
    assert!(tool_matches_role(&action, None));
    // Some filters by effective role
    assert!(tool_matches_role(&selector, Some(Role::Selector)));
    assert!(!tool_matches_role(&selector, Some(Role::Action)));
    assert!(tool_matches_role(&action, Some(Role::Action)));
    assert!(!tool_matches_role(&action, Some(Role::Selector)));
}

#[test]
fn parse_role_filter_handles_case_missing_and_invalid() {
    assert_eq!(parse_role_filter(&json!({})).unwrap(), None);
    assert_eq!(
        parse_role_filter(&json!({"role": "Selector"})).unwrap(),
        Some(Role::Selector)
    );
    assert_eq!(
        parse_role_filter(&json!({"role": "action"})).unwrap(),
        Some(Role::Action)
    );
    assert!(parse_role_filter(&json!({"role": "bogus"})).is_err());
    // Absent / null = no filter; present-but-non-string must fail fast.
    assert_eq!(parse_role_filter(&json!({"role": null})).unwrap(), None);
    assert!(parse_role_filter(&json!({"role": 123})).is_err());
    assert!(parse_role_filter(&json!({"role": ["selector"]})).is_err());
}
