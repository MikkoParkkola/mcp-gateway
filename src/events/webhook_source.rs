// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The webhook-route source's catalogue (design §9): each route with an
//! `event:` block and a field mapping is one event type,
//! `webhook.<capability>.<route>.received`. An accepted inbound POST is
//! projected from the route's mapping alone, deduped per route and queued.

use serde_json::{Map, Value, json};

use std::sync::Arc;

use chrono::Utc;

use super::fanout::SourceEvent;
use super::types::{EventDescriptor, SourceKind, Visibility};
use super::{EventSource, EventsHub};
use crate::capability::WebhookEvent;
use crate::gateway::WebhookRegistry;

/// The webhook-route source: its catalogue follows the live registry, so a
/// capability reload changes it.
pub(crate) struct WebhookSource {
    pub registry: Arc<parking_lot::RwLock<WebhookRegistry>>,
}

impl EventSource for WebhookSource {
    fn kind(&self) -> SourceKind {
        SourceKind::Webhook
    }

    fn descriptors(&self) -> Vec<EventDescriptor> {
        descriptors(&self.registry.read())
    }

    /// `event_type` matches by glob, every other argument by equality on
    /// the projected field of that name.
    fn matches(&self, arguments: &Value, event: &SourceEvent) -> bool {
        let Some(arguments) = arguments.as_object() else {
            return false;
        };
        arguments.iter().all(|(key, want)| {
            let Some(want) = want.as_str() else {
                return false;
            };
            if key == "event_type" {
                let got = event.data["event_type"].as_str().unwrap_or_default();
                glob::Pattern::new(want).is_ok_and(|p| p.matches(got))
            } else {
                event.data["fields"].get(key).and_then(Value::as_str) == Some(want)
            }
        })
    }
}

/// One accepted inbound POST on an `event:` route, already projected.
pub(crate) struct Inbound<'a> {
    pub capability: &'a str,
    pub route: &'a str,
    pub backend: &'a str,
    pub event: &'a WebhookEvent,
    pub headers: &'a axum::http::HeaderMap,
    /// The signed body bytes.
    pub body: &'a [u8],
    pub event_type: String,
    /// Each mapped key whose placeholder resolved; never the raw body.
    pub fields: Map<String, Value>,
}

impl EventsHub {
    /// Turn one accepted inbound POST into a queued occurrence. Never
    /// blocks the inbound answer on delivery: a full queue drops and counts.
    pub(crate) async fn webhook_received(self: &Arc<Self>, inbound: Inbound<'_>) {
        if inbound.fields.is_empty() {
            self.runtime.count_projection_failed();
            tracing::warn!(
                capability = %inbound.capability,
                route = %inbound.route,
                "events: projection_failed, no mapped field resolved; no event emitted"
            );
            return;
        }
        let route = format!("{}.{}", inbound.capability, inbound.route);
        let key = dedupe_key(&inbound);
        if let Some(key) = &key {
            let (hub, at, seen_key) = (Arc::clone(self), route.clone(), key.clone());
            let first = tokio::task::spawn_blocking(move || {
                hub.runtime.seen.first_sighting(&at, &seen_key, Utc::now())
            })
            .await
            .unwrap_or(true);
            if !first {
                tracing::debug!(%route, "events: inbound repeat dropped");
                return;
            }
        }
        let upstream = key.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        self.emit(SourceEvent {
            kind: SourceKind::Webhook,
            name: format!("webhook.{route}.received"),
            backend: inbound.backend.to_owned(),
            upstream_id: format!("{route}:{upstream}"),
            occurred_at: Utc::now(),
            data: json!({ "event_type": inbound.event_type, "fields": inbound.fields }),
        });
    }
}

/// The route's dedupe key: its delivery id header when configured and
/// present, the signed body's hash under `dedupe: body`, else none.
fn dedupe_key(inbound: &Inbound<'_>) -> Option<String> {
    if let Some(header) = &inbound.event.delivery_id_header {
        return inbound
            .headers
            .get(header.as_str())
            .and_then(|v| v.to_str().ok())
            .filter(|v| !v.is_empty())
            // Hashed: the seen-set's bound is a count, so its entries must be
            // fixed-size whatever the sender puts in the header.
            .map(|v| {
                use sha2::Digest as _;
                format!("id:{}", hex::encode(sha2::Sha256::digest(v.as_bytes())))
            });
    }
    (inbound.event.dedupe.as_deref() == Some("body")).then(|| {
        use sha2::Digest as _;
        format!("body:{}", hex::encode(sha2::Sha256::digest(inbound.body)))
    })
}

/// The descriptors `registry` currently derives, sorted by name.
fn descriptors(registry: &WebhookRegistry) -> Vec<EventDescriptor> {
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
