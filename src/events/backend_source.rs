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

use parking_lot::Mutex;
use serde_json::{Value, json};

use super::fanout::SourceEvent;
use super::types::{EventDescriptor, RpcError, SourceKind, Visibility};
use super::upstream::{Kind, parse_name};
use super::upstream_listener::{ListenerKey, UpstreamListeners};
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

impl BackendSource {
    /// The authorization of `name` for a subscription granted at `granted`
    /// (`None` at subscribe): see [`EventSource::authorize`].
    async fn authorize_granted(
        &self,
        name: &str,
        arguments: &Value,
        granted: Option<u64>,
        observed: Option<String>,
    ) -> Result<(), RpcError> {
        let Some((backend, kind)) = parse_name(name) else {
            return Ok(());
        };
        // A backend the config no longer has is refused, not held: the
        // subscription cannot be delivered again (MIK-7907).
        if !(self.names)().iter().any(|n| n == backend) {
            return Err(RpcError::forbidden());
        }
        let Some(up) = &self.upstream else {
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
        // At subscribe on a per-user backend the subscriber has no listener
        // yet, and the catalogue is never read as the gateway for them: the
        // URI is judged by their own listener's snapshot once it reads.
        let per_user = observed.is_some()
            || up
                .listeners
                .live_config()
                .is_some_and(|config| super::observation::binding(&config, backend).is_some());
        if granted.is_none() && per_user {
            return Ok(());
        }
        let key = ListenerKey {
            backend: backend.to_owned(),
            obs: observed,
        };
        up.listeners.authorize_uri(&key, uri, granted).await?;
        // The lookup can wait on a catalogue read (up to 10s): a reload during
        // it counts, so eligibility, and the backend still being registered,
        // are read again once it returns.
        if (up.ineligible)().contains(backend) || !up.listeners.knows(backend) {
            return Err(RpcError::forbidden());
        }
        Ok(())
    }
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

    /// Read under the live config's admission gate (MIK-7907): a backend the
    /// reload removed, or made ineligible for upstream events, sends nothing.
    fn admits_now(&self, name: &str) -> bool {
        let Some((backend, kind)) = parse_name(name) else {
            return true;
        };
        if !(self.names)().iter().any(|n| n == backend) {
            return false;
        }
        kind == Kind::ToolsChanged
            || self
                .upstream
                .as_ref()
                .is_none_or(|up| !(up.ineligible)().contains(backend))
    }

    async fn authorize(
        &self,
        _principal: &str,
        name: &str,
        arguments: &Value,
    ) -> Result<(), RpcError> {
        self.authorize_granted(name, arguments, None, None).await
    }

    async fn authorize_row(&self, sub: &super::records::Subscription) -> Result<(), RpcError> {
        // A per-user row is judged by its own listener, and a row whose
        // observation can no longer be had is refused.
        let observed = match (parse_name(&sub.name), &self.upstream) {
            (Some((backend, _)), Some(up)) if sub.obs_basis.is_some() => {
                let config = up.listeners.live_config().ok_or_else(RpcError::forbidden)?;
                super::observation::observe_row(&config, backend, sub)
                    .map_err(|_| RpcError::forbidden())?
            }
            _ => None,
        };
        self.authorize_granted(&sub.name, &sub.arguments, Some(sub.incarnation), observed)
            .await
    }

    fn matches(
        &self,
        _principal: &str,
        arguments: &Value,
        event: &SourceEvent,
        _now: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        match parse_name(&event.name) {
            Some((_, Kind::ResourceUpdated)) => {
                arguments.get("uri").is_some() && arguments.get("uri") == event.data.get("uri")
            }
            _ => true,
        }
    }

    /// A per-user backend's row keys by the subscriber's observation,
    /// `[obs, name, arguments]`, re-derived from its stored identity and the
    /// live config; a shared one by `[name, arguments]` as before. A row
    /// whose observation cannot be had holds no key.
    fn key_of_row(
        &self,
        sub: &super::records::Subscription,
        _now: chrono::DateTime<chrono::Utc>,
    ) -> Option<String> {
        let shared = || backend_key(None, &sub.name, &sub.arguments);
        let Some((backend, _)) = parse_name(&sub.name) else {
            return shared();
        };
        let live = self
            .upstream
            .as_ref()
            .and_then(|up| up.listeners.live_config());
        let observed = match live {
            Some(config) => super::observation::observe_row(&config, backend, sub).ok()?,
            None if sub.obs_basis.is_some() => return None,
            None => None,
        };
        match observed {
            None => shared(),
            Some(obs) => backend_key(Some(&obs), &sub.name, &sub.arguments),
        }
    }

    async fn on_first_subscriber(
        &self,
        key: &str,
        _principal: &str,
        name: &str,
        arguments: &Value,
    ) -> Result<(), RpcError> {
        let (Some(up), Some((backend, interest))) = (&self.upstream, interest_of(name, arguments))
        else {
            return Ok(());
        };
        let listener = listener_of(key, backend);
        // A per-user A2A listener has no read of its own to poll the agent
        // card with, so its `tools_changed` would never fire: refused, never
        // a silent subscription.
        if listener.obs.is_some() && is_a2a(up, backend) {
            return Err(RpcError::unsupported_backend_events(
                name,
                super::upstream::Ineligible::A2aCapability.as_str(),
            ));
        }
        if up.listeners.over_budget(&listener) {
            return Err(RpcError::exhausted(
                "identity_slots",
                Some(super::upstream_listener::MAX_PER_USER_LISTENERS),
            ));
        }
        // `tools_changed` is offered on every backend (a reload announces it);
        // only a backend that can be listened to gets a listener (§6, §14).
        // The other kinds are offered only for one that can: if it was
        // removed or refused since the commit check, a start with no listener
        // would leave the subscription silent, so it is refused (MIK-7969),
        // and a replay retries it.
        // A passthrough subscriber with no lease is parked: counted with no
        // task until `events/lease` (E7).
        if !up.listeners.may_run(&listener) {
            return up
                .listeners
                .hold(&listener, &interest)
                .map_err(|_| RpcError::exhausted("upstream_uris", Some(MAX_URIS)));
        }
        let known = up.listeners.knows(backend);
        // `tools_changed` asks the listeners' own predicate: an A2A backend is
        // refused its other kinds but polled for this one (MIK-8835.A2A.2).
        let refused = known
            && if matches!(interest, Interest::ToolsChanged) {
                up.listeners.refuses(backend)
            } else {
                (up.ineligible)().contains(backend)
            };
        if !known || refused {
            return if matches!(interest, Interest::ToolsChanged) {
                // Counted with no task: the revive sweep starts one once the
                // backend can be listened to (MIK-7944 D6.EVENTS_MISC.6).
                // `tools_changed` has no URI budget: never refused here.
                let _ = up.listeners.hold(&listener, &interest);
                // A registration between the check and the park missed it.
                if up.listeners.knows(backend) {
                    up.listeners.revive_backend(backend);
                }
                Ok(())
            } else if refused {
                Err(RpcError::forbidden())
            } else {
                Err(RpcError::not_found())
            };
        }
        up.listeners
            .add(&listener, &interest)
            .map_err(|_| RpcError::exhausted("upstream_uris", Some(MAX_URIS)))
    }

    fn backend_changed(&self, backend: &str) {
        if let Some(up) = &self.upstream {
            up.listeners.revive_backend(backend);
        }
    }

    #[cfg(test)]
    fn upstream_listeners(&self) -> Option<Arc<UpstreamListeners>> {
        self.upstream.as_ref().map(|up| Arc::clone(&up.listeners))
    }

    #[cfg(test)]
    fn upstream_starts(&self) -> usize {
        self.upstream.as_ref().map_or(0, |up| {
            up.listeners
                .starts
                .load(std::sync::atomic::Ordering::SeqCst)
        })
    }

    async fn on_last_subscriber(&self, key: &str) {
        let Some(up) = &self.upstream else { return };
        let Ok(Value::Array(parts)) = serde_json::from_str::<Value>(key) else {
            return;
        };
        // `[name, arguments]`, or `[obs, name, arguments]` for a per-user key.
        let parts = if parts.len() == 3 {
            &parts[1..]
        } else {
            &parts[..]
        };
        let (Some(name), Some(arguments)) = (parts.first().and_then(Value::as_str), parts.get(1))
        else {
            return;
        };
        if let Some((backend, interest)) = interest_of(name, arguments) {
            let listener = listener_of(key, backend);
            up.listeners.remove(&listener, &interest);
            // L4: a subscriber's last row on the backend ends their lease.
            if let (Some(obs), Some(hub)) = (listener.obs, up.listeners.hub())
                && !up.listeners.holds(&ListenerKey {
                    backend: backend.to_owned(),
                    obs: Some(obs.clone()),
                })
            {
                let lease = super::lease::LeaseKey {
                    backend: backend.to_owned(),
                    obs,
                };
                hub.leases
                    .wipe(&lease, super::lease::WipeReason::Released)
                    .await;
            }
        }
    }
}

/// Whether `backend` is an A2A agent in the live config.
fn is_a2a(up: &Upstream, backend: &str) -> bool {
    #[cfg(feature = "a2a")]
    {
        up.listeners.live_config().is_some_and(|config| {
            config
                .backends
                .get(backend)
                .is_some_and(|b| matches!(b.transport, crate::config::TransportConfig::A2a { .. }))
        })
    }
    #[cfg(not(feature = "a2a"))]
    {
        let _ = (up, backend);
        false
    }
}

/// The lifecycle key of a backend event: `[name, arguments]`, or
/// `[obs, name, arguments]` for a per-user listener. Rows and occurrences
/// both key through this, so a listener's occurrence reaches exactly the rows
/// it was observed for.
pub(super) fn backend_key(obs: Option<&str>, name: &str, arguments: &Value) -> Option<String> {
    let parts = match obs {
        Some(obs) => json!([obs, name, arguments]),
        None => json!([name, arguments]),
    };
    String::from_utf8(super::rpc::canonical(&parts)).ok()
}

/// The listener a lifecycle key starts: `[obs, name, arguments]` names a
/// per-user listener, `[name, arguments]` the backend's shared one.
fn listener_of(lifecycle_key: &str, backend: &str) -> ListenerKey {
    let obs = match serde_json::from_str::<Value>(lifecycle_key) {
        Ok(Value::Array(parts)) if parts.len() == 3 => parts[0].as_str().map(str::to_owned),
        _ => None,
    };
    ListenerKey {
        backend: backend.to_owned(),
        obs,
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
    #[cfg(test)]
    pub(crate) fn install_backend_source_with_upstream(
        self: &Arc<Self>,
        names: BackendNames,
        registry: Arc<crate::backend::BackendRegistry>,
        ineligible: Ineligible,
    ) {
        let listener = Arc::clone(&ineligible);
        self.install_backend_source_with_listeners(names, registry, ineligible, listener);
    }

    /// [`Self::install_backend_source_with_upstream`] with the listener
    /// tasks judged by `listener_ineligible` (`upstream::listener_ineligible`),
    /// which keeps an A2A backend's tools listener (MIK-8835).
    pub(crate) fn install_backend_source_with_listeners(
        self: &Arc<Self>,
        names: BackendNames,
        registry: Arc<crate::backend::BackendRegistry>,
        ineligible: Ineligible,
        listener_ineligible: Ineligible,
    ) {
        let _ = self.runtime.backends.set(Arc::clone(&registry));
        let listeners = UpstreamListeners::new(registry, Arc::downgrade(self), listener_ineligible);
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
        // Every change reconciles the backend's rows, keys and listener
        // (MIK-7940 family): a removed backend takes every kind with it, an
        // ineligible one its upstream kinds, and a re-added one is listened
        // to at once.
        self.reconcile_backend(backend);
        if let Some(source) = self.source(SourceKind::BackendNotification)
            && !source.offers(&event_name(backend))
        {
            // A report still waiting for its quiet period must not outlive the backend.
            self.debounce.latest.lock().remove(backend);
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
            // The gateway's own view: never a per-user row's (E4).
            let key = backend_key(None, &event_name(&backend), &json!({}));
            hub.emit_dated(|occurred_at| SourceEvent {
                kind: SourceKind::BackendNotification,
                name: event_name(&backend),
                backend: backend.clone(),
                scope: Visibility::Backend(backend),
                owner: None,
                upstream_id: uuid::Uuid::new_v4().to_string(),
                occurred_at,
                data: json!({}),
                lifecycle_key: key,
            });
        });
    }
}
