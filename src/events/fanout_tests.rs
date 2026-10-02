// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::*;

#[test]
fn event_id_is_stable_and_distinct_per_subscription() {
    let a = event_id(SourceKind::Webhook, "github.push:d-1", "sub_a");
    assert_eq!(a, event_id(SourceKind::Webhook, "github.push:d-1", "sub_a"));
    assert_ne!(a, event_id(SourceKind::Webhook, "github.push:d-1", "sub_b"));
    assert_ne!(a, event_id(SourceKind::Webhook, "github.push:d-2", "sub_a"));
    assert!(a.starts_with("evt_") && a.len() == 36);
}

#[test]
fn body_carries_only_protocol_fields_and_data() {
    let event = SourceEvent {
        kind: SourceKind::Webhook,
        name: "webhook.c.r.received".into(),
        backend: "hooks".into(),
        upstream_id: "x".into(),
        occurred_at: Utc::now(),
        data: json!({"event_type": "t", "fields": {}}),
    };
    let body: Value = serde_json::from_slice(&body("evt_1", &event, &event.data)).expect("json");
    let mut keys: Vec<&str> = body
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, ["cursor", "data", "eventId", "name", "timestamp"]);
    assert_eq!(body["cursor"], Value::Null);
}
