// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The webhook side of MCP Events (MIK-7630): an accepted POST on an
//! `event:` route is projected from the route's mapping and handed to the
//! events hub, and a capability reload re-registers the routes.

use std::sync::Arc;

use axum::http::HeaderMap;
use serde_json::Value;

use super::{WebhookHandlerState, WebhookRegistry, project_data};
use crate::capability::CapabilityDefinition;

impl WebhookRegistry {
    /// Route `event:` webhooks into `hub`.
    pub(crate) fn set_events(&mut self, hub: Arc<crate::events::EventsHub>) {
        self.events = Some(hub);
    }

    /// Replace every route with those of `capabilities`, keeping the stats
    /// of a path that stays. Used by a capability reload while events are
    /// on; the dynamic dispatcher reads the registry per request.
    pub(crate) fn replace_capabilities(&mut self, capabilities: &[CapabilityDefinition]) {
        let old = std::mem::take(&mut self.webhooks);
        self.limiters.clear();
        for cap in capabilities.iter().filter(|c| !c.webhooks.is_empty()) {
            self.register_capability(cap);
        }
        for (path, entry) in &mut self.webhooks {
            if let Some((_, _, _, stats)) = old.get(path) {
                entry.3 = Arc::clone(stats);
            }
        }
    }
}

/// Emit the MCP event of an accepted POST, when the route declares one.
/// The event's data is the mapping alone: a key that does not resolve is
/// omitted, and no raw-body fallback exists (design §9, T42b).
pub(super) async fn emit(
    state: &WebhookHandlerState,
    headers: &HeaderMap,
    body: &[u8],
    payload: &Value,
    event_type: &str,
) {
    let (Some(hub), Some(event)) = (&state.events, &state.definition.event) else {
        return;
    };
    if state.definition.transform.data.is_empty() {
        return;
    }
    hub.webhook_received(crate::events::Inbound {
        capability: &state.capability_name,
        route: &state.webhook_name,
        backend: &state.backend,
        event,
        headers,
        body,
        event_type: event_type.to_owned(),
        fields: project_data(&state.definition.transform, payload),
    })
    .await;
}
