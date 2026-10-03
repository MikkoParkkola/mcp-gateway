// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The `transform.data` mapping grammar (MIK-7771): a template, or a literal
//! when it has no braces; never a raw payload path.

use serde_json::json;

use super::tests::{make_definition, make_handler_state, make_multiplexer};
use super::{project_data, transform_payload};
use crate::capability::WebhookTransform;

#[test]
fn a_mapping_without_braces_is_a_literal_and_an_unresolved_template_is_omitted() {
    // GIVEN: one literal, one resolving template, one template for a path the
    // payload lacks, and a brace-less text that looks like a path
    let mut transform = WebhookTransform::default();
    transform
        .data
        .insert("source".to_string(), "linear".to_string());
    transform
        .data
        .insert("id".to_string(), "{data.id}".to_string());
    transform
        .data
        .insert("missing".to_string(), "{data.nope}".to_string());
    transform
        .data
        .insert("looks_like_a_path".to_string(), "data.id".to_string());
    let payload = json!({ "data": { "id": "ABC-123" } });

    // WHEN: projected, the one function notifications and events share
    let data = project_data(&transform, &payload);

    // THEN: literals stay literal, nothing is read as a raw path
    assert_eq!(data["source"], "linear");
    assert_eq!(data["id"], "ABC-123");
    assert_eq!(data["looks_like_a_path"], "data.id");
    assert!(!data.contains_key("missing"));
}

#[test]
fn a_notification_whose_mappings_all_fail_carries_the_whole_payload() {
    let multiplexer = make_multiplexer();
    let mut def = make_definition(true);
    def.transform
        .data
        .insert("id".to_string(), "{data.nope}".to_string());
    let state = make_handler_state(multiplexer, def);
    let payload = json!({ "action": "created" });

    let notif = transform_payload(&payload, &state).unwrap();
    assert_eq!(notif.data, payload);
}
