// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The webhook-route source's catalogue (design §9): each route with an
//! `event:` block and a field mapping is one event type,
//! `webhook.<capability>.<route>.received`. Emission lands in I2.

use serde_json::{Map, Value, json};

use super::types::{EventDescriptor, SourceKind, Visibility};
use crate::gateway::WebhookRegistry;

/// The descriptors `registry` currently derives, sorted by name.
pub(crate) fn descriptors(registry: &WebhookRegistry) -> Vec<EventDescriptor> {
    let backend = registry.backend().to_owned();
    registry
        .event_routes()
        .into_iter()
        .filter(|(_, _, def)| !def.transform.data.is_empty())
        .filter_map(|(capability, route, def)| {
            let event = def.event?;
            let mut filters = Map::new();
            filters.insert(
                "event_type".into(),
                json!({"type": "string", "description": "Glob over the transformed event type."}),
            );
            for filter in &event.filters {
                filters.insert(filter.clone(), json!({"type": "string"}));
            }
            let mut keys: Vec<&String> = def.transform.data.keys().collect();
            keys.sort();
            let fields: Map<String, Value> =
                keys.into_iter().map(|k| (k.clone(), json!({}))).collect();
            Some(EventDescriptor {
                name: format!("webhook.{capability}.{route}.received"),
                description: event.description,
                input_schema: json!({
                    "type": "object",
                    "properties": filters,
                    "additionalProperties": false,
                }),
                payload_schema: json!({
                    "type": "object",
                    "properties": {
                        "event_type": {"type": "string"},
                        "fields": {
                            "type": "object",
                            "properties": fields,
                            "additionalProperties": false,
                        },
                    },
                    "additionalProperties": false,
                }),
                scope: Visibility::Backend(backend.clone()),
                kind: SourceKind::Webhook,
            })
        })
        .collect()
}
