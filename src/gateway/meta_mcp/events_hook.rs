// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The MCP Events hub on the meta layer (MIK-7630), shared by every
//! surface that reports capabilities.

use std::sync::Arc;

use super::MetaMcp;
use crate::events::EventsHub;

/// How often a startup scan that has not finished is reported while waited on.
const SCAN_WAIT_WARN_SECS: u64 = 30;

impl MetaMcp {
    /// Install the events hub. Called once by the HTTP server when
    /// `events.enabled`; a second call is ignored.
    pub(crate) fn set_events(&self, hub: Arc<EventsHub>) {
        let _ = self.events.set(hub);
    }

    /// The backend registry, for the events backend source's catalogue.
    pub(crate) fn events_backend_registry(&self) -> Arc<crate::backend::BackendRegistry> {
        Arc::clone(&self.backends)
    }

    /// Backend `backend`'s tool set changed: an event, when events are on.
    pub(crate) fn events_tools_changed(&self, backend: &str) {
        if let Some(hub) = self.events() {
            hub.backend_tools_changed(backend);
        }
    }

    /// Reconcile the hub's stored subscriptions with the capability catalogue
    /// once the startup scan has registered its routes. Called after the
    /// hub is installed and started.
    ///
    /// A directory the startup scan failed to load makes the scan partial,
    /// and a partial scan withdraws nothing.
    pub(crate) fn reconcile_events_after_scan(&self) {
        let Some(hub) = self.events().cloned() else {
            return;
        };
        let capabilities = self.get_capabilities();
        let registry = self.get_webhook_registry();
        tokio::spawn(async move {
            if let Some(capabilities) = &capabilities {
                let started = std::time::Instant::now();
                let mut warned = 0;
                while !capabilities.initial_scan_complete() {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    let periods = started.elapsed().as_secs() / SCAN_WAIT_WARN_SECS;
                    if periods > warned {
                        warned = periods;
                        tracing::warn!(
                            waited_secs = started.elapsed().as_secs(),
                            "events: the startup capability scan has not finished; \
                             subscription reconcile and delivery are waiting for it"
                        );
                    }
                }
            }
            // A reload that arrived mid-scan was held: apply it before the
            // catalogue is reconciled against the routes.
            if let (Some(capabilities), Some(registry)) = (&capabilities, &registry)
                && capabilities.take_held_reload()
            {
                apply_webhook_refresh(&hub, capabilities, registry);
            }
            // The loader's own outcome, read once the scan is over.
            let scan = if capabilities
                .as_ref()
                .is_none_or(|c| c.initial_scan_loaded_every_directory())
            {
                crate::events::CatalogueScan::Complete
            } else {
                crate::events::CatalogueScan::Partial
            };
            // Disk work, off the async workers; a removal that failed is
            // retried and logged, the worker held meanwhile.
            hub.reconcile_until_done(scan, std::time::Duration::from_secs(5))
                .await;
        });
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

    /// Fill a search answer `out` with visible event entries after its tool
    /// rows, up to `limit` rows in all (MIK-7819), counting every event match
    /// in `total_available`.
    pub(super) fn add_events_to(
        &self,
        out: &mut serde_json::Value,
        query: &str,
        limit: usize,
        caller: &super::MetaMcpCallerContext<'_>,
        session_id: Option<&str>,
    ) {
        let events = self.event_search_matches(query, usize::MAX, caller, session_id);
        let found = events.len() as u64;
        let Some(matches) = out["matches"].as_array_mut().filter(|_| found > 0) else {
            return;
        };
        let room = limit.saturating_sub(matches.len());
        matches.extend(events.into_iter().take(room));
        let shown = matches.len();
        out["total"] = shown.into();
        out["total_available"] = (out["total_available"].as_u64().unwrap_or(0) + found).into();
        // Suggestions are for an empty answer only.
        if let Some(object) = out.as_object_mut().filter(|_| shown > 0) {
            object.remove("suggestions");
        }
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

    /// Add `events: {listChanged: false}` to a capabilities object when the
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
        if capabilities.name != backend {
            return;
        }
        // Before the startup scan completes the reload is held, not dropped:
        // `reconcile_events_after_scan` applies it once the scan is over.
        if capabilities.hold_reload_until_scan_complete() {
            return;
        }
        apply_webhook_refresh(hub, &capabilities, &registry);
    }

    /// Every REST-only capability as the events watch source sees it: its
    /// read-only classification (data, MIK-7216.IDEM.1) and whose credential
    /// a call needs. Empty without a capability backend.
    pub(crate) fn watch_targets(&self) -> Vec<crate::events::watch_source::Target> {
        use crate::events::watch_source::{CredentialUse, Target};
        let Some(capabilities) = self.get_capabilities() else {
            return Vec::new();
        };
        capabilities
            .list_capabilities()
            .into_iter()
            .filter(crate::capability::served_over_rest)
            .map(|definition| Target {
                credential: if definition.auth.account.is_some() {
                    CredentialUse::Account
                } else if definition.auth.required || !definition.auth.key.is_empty() {
                    CredentialUse::Keyed
                } else {
                    CredentialUse::Free
                },
                read_only: definition.metadata.read_only,
                input_schema: definition.to_mcp_tool().input_schema,
                backend: capabilities.name.clone(),
                capability: definition.name,
            })
            .collect()
    }
}

/// Re-register the webhook routes of `capabilities`, unless the reload
/// narrows a live event type (T52).
fn apply_webhook_refresh(
    hub: &Arc<EventsHub>,
    capabilities: &crate::capability::CapabilityBackend,
    registry: &Arc<parking_lot::RwLock<crate::gateway::WebhookRegistry>>,
) {
    let _gate = hub.catalogue_lock();
    match crate::events::refresh_webhooks(registry, &capabilities.list_capabilities()) {
        Ok(removed) => {
            hub.withdraw(&removed);
        }
        Err(event) => tracing::error!(
            %event,
            "capability reload not applied to webhook routes: it removes a filter or \
             mapped field of a live event type; the previous routes stay live"
        ),
    }
}

#[cfg(test)]
#[path = "events_hook_tests.rs"]
mod events_hook_tests;
