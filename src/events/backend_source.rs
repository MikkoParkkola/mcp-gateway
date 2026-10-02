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
use super::types::{EventDescriptor, SourceKind, Visibility};
use super::{EventSource, EventsHub};

/// How long a backend must be quiet before its burst is reported.
pub(super) const QUIET: Duration = Duration::from_millis(500);

/// Lists the backends that exist now.
pub(crate) type BackendNames = Arc<dyn Fn() -> Vec<String> + Send + Sync>;

pub(crate) struct BackendSource {
    pub names: BackendNames,
}

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
        names
            .into_iter()
            .map(|backend| EventDescriptor {
                name: event_name(&backend),
                description: format!("The tool set of backend {backend} changed."),
                input_schema: json!({"type": "object", "properties": {},
                    "additionalProperties": false}),
                payload_schema: json!({"type": "object", "properties": {},
                    "additionalProperties": false}),
                scope: Visibility::Backend(backend),
                kind: SourceKind::BackendNotification,
            })
            .collect()
    }

    fn matches(&self, _principal: &str, _arguments: &Value, _event: &SourceEvent) -> bool {
        true
    }
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
    pub(crate) fn install_backend_source(self: &Arc<Self>, names: BackendNames) {
        self.register_source(Arc::new(BackendSource { names }));
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
            self.withdraw(&[event_name(backend)]);
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
                upstream_id: uuid::Uuid::new_v4().to_string(),
                occurred_at: Utc::now(),
                data: json!({}),
            });
        });
    }
}
