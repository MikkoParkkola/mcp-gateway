// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The MCP Events hub on the meta layer (MIK-7630), shared by every
//! surface that reports capabilities.

use std::sync::Arc;

use super::MetaMcp;
use crate::events::EventsHub;

impl MetaMcp {
    /// Install the events hub. Called once by the HTTP server when
    /// `events.enabled`; a second call is ignored.
    pub(crate) fn set_events(&self, hub: Arc<EventsHub>) {
        let _ = self.events.set(hub);
    }

    /// The events hub, when events are on for this transport.
    pub(crate) fn events(&self) -> Option<&Arc<EventsHub>> {
        self.events.get()
    }

    /// Event entries for a keyword search, visible to `caller` by the same
    /// predicate `events/list` uses (design §3.9, §17).
    pub(super) fn event_search_matches(
        &self,
        query: &str,
        limit: usize,
        caller: &super::MetaMcpCallerContext<'_>,
        session_id: Option<&str>,
    ) -> Vec<serde_json::Value> {
        use crate::events::Visibility;
        let Some(hub) = self.events() else {
            return Vec::new();
        };
        let api_key = (caller.credential_kind == crate::security::audit::CredentialKind::ApiKey)
            .then(|| {
                Some(crate::events::ApiKeyRef {
                    name: caller.api_key_name?.to_owned(),
                    principal: caller.credential_principal?.to_owned(),
                })
            })
            .flatten();
        hub.search(query, limit, |scope| match scope {
            Visibility::Backend(backend) => {
                self.admits_backend(backend, caller.scope(), session_id)
                    && hub.live_admits(api_key.as_ref(), backend)
            }
            Visibility::Owner => caller.credential_principal.is_some(),
            Visibility::Operator => false,
        })
    }

    /// Append up to `limit` visible event entries to `matches`; how many
    /// matched in all, for the search's `total_available`.
    pub(super) fn add_event_matches(
        &self,
        query: &str,
        limit: usize,
        caller: &super::MetaMcpCallerContext<'_>,
        session_id: Option<&str>,
        matches: &mut Vec<serde_json::Value>,
    ) -> usize {
        let events = self.event_search_matches(query, usize::MAX, caller, session_id);
        let found = events.len();
        matches.extend(events.into_iter().take(limit));
        found
    }

    /// `capabilities` as JSON, with `events` advertised when it applies.
    pub(super) fn capabilities_with_events(
        &self,
        capabilities: impl serde::Serialize,
    ) -> serde_json::Value {
        let mut capabilities = serde_json::to_value(capabilities).unwrap_or_default();
        self.advertise_events(&mut capabilities);
        capabilities
    }

    /// An initialize result as JSON, with `events` advertised in its
    /// capabilities when it applies.
    pub(super) fn initialize_with_events(
        &self,
        result: impl serde::Serialize,
    ) -> serde_json::Value {
        let mut result = serde_json::to_value(result).unwrap_or_default();
        self.advertise_events(&mut result["capabilities"]);
        result
    }

    /// Add `events: {listChanged: true}` to a capabilities object when the
    /// hub is installed and some source offers an event type (design §6.1).
    /// With events off the object is untouched, byte for byte.
    fn advertise_events(&self, capabilities: &mut serde_json::Value) {
        if let Some(advertised) = self.events().and_then(|hub| hub.capability())
            && let Some(map) = capabilities.as_object_mut()
        {
            map.insert("events".to_owned(), advertised);
        }
    }

    /// The controls every event payload passes, borrowed from this layer:
    /// the firewall, the audit log and the budget, with the live config.
    pub(crate) fn events_services(
        &self,
        live: Arc<crate::config_reload::LiveConfig>,
        credentials: crate::events::LiveCredentials,
    ) -> crate::events::Services {
        crate::events::Services {
            live,
            credentials,
            #[cfg(feature = "firewall")]
            firewall: self.firewall.clone(),
            audit: self.transparency_logger.clone(),
            provenance: self.provenance_signer.clone(),
            #[cfg(feature = "cost-governance")]
            budget: self.budget_enforcer.clone().zip(self.cost_registry.clone()),
        }
    }

    /// After a reload of capability backend `backend`, re-register the
    /// webhook routes, unless the reload narrows a live event type (T52).
    /// Only while events are on: without them the routes keep today's
    /// startup-only registration.
    pub(crate) fn events_capabilities_reloaded(&self, backend: &str) {
        let (Some(hub), Some(capabilities), Some(registry)) = (
            self.events(),
            self.get_capabilities(),
            self.get_webhook_registry(),
        ) else {
            return;
        };
        if capabilities.name != backend || !capabilities.initial_scan_complete() {
            return;
        }
        match crate::events::refresh_webhooks(&registry, &capabilities.list_capabilities()) {
            Ok(removed) => hub.withdraw(&removed),
            Err(event) => tracing::error!(
                %event,
                "capability reload not applied to webhook routes: it removes a filter or \
                 mapped field of a live event type; the previous routes stay live"
            ),
        }
    }
}
