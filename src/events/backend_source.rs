// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `backend.<server>.tools_changed` (design §3.3, b1): the gateway already
//! announces every tool-set change of a backend; this source turns that
//! announcement into an event for callers who may see the backend. Several
//! changes in a burst become one event, sent when the backend has been quiet
//! for [`QUIET`]. Resource and prompt notifications (b2) are I5.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use parking_lot::Mutex;
use serde_json::{Value, json};

use super::fanout::SourceEvent;
use super::types::{EventDescriptor, RpcError, SourceKind, Visibility};
use super::upstream::{Kind, parse_name};
use super::upstream_listener::UpstreamListeners;
use super::upstream_need::{Interest, MAX_URIS};
use super::{EventSource, EventsHub};

/// How long a backend must be quiet before its burst is reported.
pub(super) const QUIET: Duration = Duration::from_millis(500);

/// Lists the backends that exist now.
pub(crate) type BackendNames = Arc<dyn Fn() -> Vec<String> + Send + Sync>;

/// The configured backends that cannot offer the upstream-notification
/// events (design §6), read from the live config at each call.
pub(crate) type Ineligible = Arc<dyn Fn() -> std::collections::BTreeSet<String> + Send + Sync>;

/// The three upstream-notification names (I5), delegated to the listeners.
pub(crate) struct Upstream {
    pub listeners: Arc<UpstreamListeners>,
    pub ineligible: Ineligible,
}

pub(crate) struct BackendSource {
    pub names: BackendNames,
    pub upstream: Option<Upstream>,
}

/// Every backend event name starts with this.
pub(super) const NAME_PREFIX: &str = "backend.";

fn event_name(backend: &str) -> String {
    format!("backend.{backend}.tools_changed")
}

#[async_trait::async_trait]
impl EventSource for BackendSource {
    fn kind(&self) -> SourceKind {
        SourceKind::BackendNotification
    }

    fn descriptors(&self) -> Vec<EventDescriptor> {
        let mut names = (self.names)();
        names.sort();
        names.dedup();
        let refused = self.upstream.as_ref().map(|u| (u.ineligible)());
        let mut out = Vec::new();
        for backend in names {
            let upstream = self
                .upstream
                .as_ref()
                .is_some_and(|u| u.listeners.knows(&backend))
                && refused.as_ref().is_some_and(|r| !r.contains(&backend));
            out.push(EventDescriptor {
                name: event_name(&backend),
                description: format!("The tool set of backend {backend} changed."),
                input_schema: json!({"type": "object", "properties": {},
                    "additionalProperties": false}),
                payload_schema: json!({"type": "object", "properties": {},
                    "additionalProperties": false}),
                scope: Visibility::Backend(backend.clone()),
                kind: SourceKind::BackendNotification,
            });
            if upstream {
                out.extend(upstream_descriptors(&backend));
            }
        }
        out
    }

    async fn authorize(
        &self,
        _principal: &str,
        name: &str,
        arguments: &Value,
    ) -> Result<(), RpcError> {
        let (Some(up), Some((backend, kind))) = (&self.upstream, parse_name(name)) else {
            return Ok(());
        };
        // Subscribe, fan-out and the worker all ask here, so a backend a
        // reload made ineligible is refused at every delivery (MIK-7894).
        // `tools_changed` stays: the gateway announces it itself.
        if kind != Kind::ToolsChanged && (up.ineligible)().contains(backend) {
            return Err(RpcError::forbidden());
        }
        if kind != Kind::ResourceUpdated {
            return Ok(());
        }
        let Some(uri) = arguments
            .get("uri")
            .and_then(Value::as_str)
            .filter(|u| u.len() <= 2048)
        else {
            return Err(RpcError::invalid("arguments.uri"));
        };
        up.listeners.authorize_uri(backend, uri).await?;
        // The lookup can wait on a catalogue read (up to 10s): a reload during
        // it counts, so eligibility, and the backend still being registered,
        // are read again once it returns.
        if (up.ineligible)().contains(backend) || !up.listeners.knows(backend) {
            return Err(RpcError::forbidden());
        }
        Ok(())
    }

    fn matches(&self, _principal: &str, arguments: &Value, event: &SourceEvent) -> bool {
        match parse_name(&event.name) {
            Some((_, Kind::ResourceUpdated)) => {
                arguments.get("uri").is_some() && arguments.get("uri") == event.data.get("uri")
            }
            _ => true,
        }
    }

    async fn on_first_subscriber(
        &self,
        _key: &str,
        _principal: &str,
        name: &str,
        arguments: &Value,
    ) -> Result<(), RpcError> {
        let (Some(up), Some((backend, interest))) = (&self.upstream, interest_of(name, arguments))
        else {
            return Ok(());
        };
        // `tools_changed` is offered on every backend (a reload announces it);
        // only a backend that can be listened to gets a listener (§6, §14).
        // The other kinds are offered only for one that can: if it was
        // removed or refused since the commit check, a start with no listener
        // would leave the subscription silent, so it is refused (MIK-7969),
        // and a replay retries it.
        let known = up.listeners.knows(backend);
        let refused = known && (up.ineligible)().contains(backend);
        if !known || refused {
            return if matches!(interest, Interest::ToolsChanged) {
                Ok(())
            } else if refused {
                Err(RpcError::forbidden())
            } else {
                Err(RpcError::not_found())
            };
        }
        up.listeners
            .add(backend, &interest)
            .map_err(|_| RpcError::exhausted("upstream_uris", Some(MAX_URIS)))
    }

    async fn on_last_subscriber(&self, key: &str) {
        let Some(up) = &self.upstream else { return };
        let Ok(Value::Array(parts)) = serde_json::from_str::<Value>(key) else {
            return;
        };
        let (Some(name), Some(arguments)) = (parts.first().and_then(Value::as_str), parts.get(1))
        else {
            return;
        };
        if let Some((backend, interest)) = interest_of(name, arguments) {
            up.listeners.remove(backend, &interest);
        }
    }
}

/// `(backend, interest)` of an upstream-notification subscription.
fn interest_of<'a>(name: &'a str, arguments: &Value) -> Option<(&'a str, Interest)> {
    let (backend, kind) = parse_name(name)?;
    let interest = match kind {
        Kind::ResourcesChanged => Interest::ResourcesChanged,
        Kind::PromptsChanged => Interest::PromptsChanged,
        Kind::ToolsChanged => Interest::ToolsChanged,
        Kind::ResourceUpdated => {
            Interest::ResourceUpdated(arguments.get("uri")?.as_str()?.to_owned())
        }
    };
    Some((backend, interest))
}

fn upstream_descriptors(backend: &str) -> Vec<EventDescriptor> {
    let none = json!({"type": "object", "properties": {}, "additionalProperties": false});
    let uri = json!({"type": "object", "properties": {"uri": {"type": "string", "maxLength": 2048}},
        "required": ["uri"], "additionalProperties": false});
    let descriptor =
        |kind: Kind, description: String, input: &Value, payload: &Value| EventDescriptor {
            name: format!("backend.{backend}.{}", kind.suffix()),
            description,
            input_schema: input.clone(),
            payload_schema: payload.clone(),
            scope: Visibility::Backend(backend.to_owned()),
            kind: SourceKind::BackendNotification,
        };
    vec![
        descriptor(
            Kind::ResourceUpdated,
            format!("A resource of backend {backend} changed (re-read it)."),
            &uri,
            &json!({"type": "object", "properties": {"uri": {"type": "string"}},
                "required": ["uri"], "additionalProperties": false}),
        ),
        descriptor(
            Kind::ResourcesChanged,
            format!("The resource list of backend {backend} changed."),
            &none,
            &none,
        ),
        descriptor(
            Kind::PromptsChanged,
            format!("The prompt list of backend {backend} changed."),
            &none,
            &none,
        ),
    ]
}

/// Per-backend change counters: a pending report fires only if no newer
/// change arrived while it waited.
#[derive(Default)]
pub(super) struct Debounce {
    latest: Mutex<HashMap<String, u64>>,
    /// Hub-wide, so an entry removed and re-inserted never reuses a pending
    /// timer's generation.
    next: std::sync::atomic::AtomicU64,
}

impl EventsHub {
    /// Offer `backend.<x>.tools_changed` for the backends `names` lists.
    #[cfg(test)]
    pub(crate) fn install_backend_source(self: &Arc<Self>, names: BackendNames) {
        self.register_source(Arc::new(BackendSource {
            names,
            upstream: None,
        }));
    }

    /// [`Self::install_backend_source`] plus the three upstream-notification
    /// names for the eligible backends of `registry` (MIK-7630 I5).
    pub(crate) fn install_backend_source_with_upstream(
        self: &Arc<Self>,
        names: BackendNames,
        registry: Arc<crate::backend::BackendRegistry>,
        ineligible: Ineligible,
    ) {
        let _ = self.runtime.backends.set(Arc::clone(&registry));
        let listeners =
            UpstreamListeners::new(registry, Arc::downgrade(self), Arc::clone(&ineligible));
        self.register_source(Arc::new(BackendSource {
            names,
            upstream: Some(Upstream {
                listeners,
                ineligible,
            }),
        }));
    }

    /// Backend `backend`'s tool set changed. Reports once, after [`QUIET`].
    pub(crate) fn backend_tools_changed(self: &Arc<Self>, backend: &str) {
        if self.source(SourceKind::BackendNotification).is_none() {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        // A removed backend takes its subscriptions with it, as a reload that
        // removes a webhook route does; re-adding the name starts clean.
        if let Some(source) = self.source(SourceKind::BackendNotification)
            && !source.offers(&event_name(backend))
        {
            // A report still waiting for its quiet period must not outlive the backend.
            self.debounce.latest.lock().remove(backend);
            self.withdraw(&[event_name(backend)]);
            self.reconcile_stops_in_background();
            return;
        }
        let generation = {
            // ponytail: an entry leaves the map when its report fires, so only
            // a backend that keeps changing stays in it.
            let mut latest = self.debounce.latest.lock();
            let generation = self
                .debounce
                .next
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            latest.insert(backend.to_owned(), generation);
            generation
        };
        let (hub, backend) = (Arc::clone(self), backend.to_owned());
        runtime.spawn(async move {
            tokio::time::sleep(QUIET).await;
            {
                let mut latest = hub.debounce.latest.lock();
                if latest.get(&backend) != Some(&generation) {
                    return;
                }
                latest.remove(&backend);
            }
            hub.emit(SourceEvent {
                kind: SourceKind::BackendNotification,
                name: event_name(&backend),
                backend: backend.clone(),
                scope: Visibility::Backend(backend),
                owner: None,
                upstream_id: uuid::Uuid::new_v4().to_string(),
                occurred_at: Utc::now(),
                data: json!({}),
                lifecycle_key: None,
            });
        });
    }
}
