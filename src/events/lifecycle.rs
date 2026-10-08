// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Reference-counted source lifecycle (design §4): a source's upstream work
//! starts with the first live subscription for a lifecycle key and stops
//! after the last one leaves. The started set is the only state; the count
//! itself is always read from the store, so every way a subscription can end
//! (unsubscribe, expiry, revocation, withdrawal) needs no bookkeeping of its
//! own, only a call to [`EventsHub::reconcile_stops`].
//!
//! One async mutex orders every start and stop. It is held across the
//! source's `on_first_subscriber` and the store commit of the subscription
//! that needed it, so a stop triggered by another key cannot land between
//! them, and never across the verification POST.

use std::collections::HashSet;
use std::sync::Arc;

use chrono::Utc;

use super::types::{RpcError, SourceKind};
use super::{EventSource, EventsHub};

/// `(source kind, lifecycle key)` pairs whose `on_first_subscriber` ran.
pub(super) type Started = tokio::sync::Mutex<HashSet<(SourceKind, String)>>;

impl EventsHub {
    /// The source that offers event type `name`.
    pub(super) fn source_offering(&self, name: &str) -> Option<Arc<dyn EventSource>> {
        // ponytail: scans every source's descriptors per call, delivery
        // included; sources are few. Index by name if that changes.
        self.sources.read().iter().find(|s| s.offers(name)).cloned()
    }

    /// May an event of type `name` be sent now (MIK-7907)? Its source
    /// answers; a backend name no source offers any more is not admitted,
    /// as in `source_verdict`. Call it inside `LiveConfig::admit`, without
    /// awaiting, so a reload that has returned is always seen.
    pub(super) fn admits_now(&self, name: &str) -> bool {
        match self.source_offering(name) {
            Some(source) => source.admits_now(name),
            None => !name.starts_with(super::backend_source::NAME_PREFIX),
        }
    }

    /// Start `(name, arguments)` for `principal` unless it is already
    /// started. The caller holds the lifecycle lock (`started`) and commits
    /// the subscription before releasing it. `Ok(true)` when this call
    /// started it, so a failed commit can undo exactly that.
    pub(super) async fn start_key(
        &self,
        started: &mut HashSet<(SourceKind, String)>,
        principal: &str,
        name: &str,
        arguments: &serde_json::Value,
    ) -> Result<Option<(SourceKind, String)>, RpcError> {
        let Some(source) = self.source_offering(name) else {
            // An upstream-notification name no source offers any more (its
            // backend was refused or removed since the subscribe judged it)
            // would commit with no listener: refuse it (MIK-7969).
            return match super::upstream::parse_name(name) {
                Some((_, kind)) if kind != super::upstream::Kind::ToolsChanged => {
                    Err(RpcError::not_found())
                }
                _ => Ok(None),
            };
        };
        let key = (
            source.kind(),
            source.lifecycle_key(principal, name, arguments),
        );
        if started.contains(&key) {
            return Ok(None);
        }
        source
            .on_first_subscriber(&key.1, principal, name, arguments)
            .await?;
        started.insert(key.clone());
        Ok(Some(key))
    }

    /// Undo [`Self::start_key`] after the commit it preceded failed.
    pub(super) async fn undo_start(
        &self,
        started: &mut HashSet<(SourceKind, String)>,
        key: (SourceKind, String),
    ) {
        // A commit that failed after inserting its row (a durability error)
        // leaves a live holder: the key stays started.
        if self.live_keys().iter().any(|(live, ..)| *live == key) {
            return;
        }
        started.remove(&key);
        if let Some(source) = self.source_of_kind(key.0) {
            source.on_last_subscriber(&key.1).await;
        }
    }

    fn source_of_kind(&self, kind: SourceKind) -> Option<Arc<dyn EventSource>> {
        self.source(kind)
    }

    /// The lifecycle keys of every live subscription, with the principal of
    /// one subscription holding each.
    fn live_keys(&self) -> Vec<((SourceKind, String), String, String, serde_json::Value)> {
        let now = Utc::now();
        let mut keys = Vec::new();
        for sub in self
            .store
            .subscriptions()
            .into_iter()
            .filter(|s| s.live(now))
        {
            if let Some(source) = self.source_offering(&sub.name) {
                let key = (
                    source.kind(),
                    source.lifecycle_key(&sub.principal, &sub.name, &sub.arguments),
                );
                keys.push((key, sub.principal, sub.name, sub.arguments));
            }
        }
        keys
    }

    /// Stop every started key no live subscription holds any more.
    pub(crate) async fn reconcile_stops(&self) {
        let mut started = self.lifecycle.lock().await;
        let live: HashSet<(SourceKind, String)> =
            self.live_keys().into_iter().map(|(key, ..)| key).collect();
        let gone: Vec<_> = started.difference(&live).cloned().collect();
        for key in gone {
            started.remove(&key);
            if let Some(source) = self.source_of_kind(key.0) {
                source.on_last_subscriber(&key.1).await;
            }
        }
    }

    /// Start every live key not yet started: after a restart the upstream
    /// state is rebuilt from the store, and a source registered later joins
    /// the same way. A refusal leaves the key unstarted for the next replay.
    pub(crate) async fn replay_starts(&self) {
        let mut started = self.lifecycle.lock().await;
        // One attempt per key per replay, even when several rows hold it.
        let mut tried = HashSet::new();
        for (key, principal, name, arguments) in self.live_keys() {
            if started.contains(&key) || !tried.insert(key.clone()) {
                continue;
            }
            let Some(source) = self.source_of_kind(key.0) else {
                continue;
            };
            match source
                .on_first_subscriber(&key.1, &principal, &name, &arguments)
                .await
            {
                Ok(()) => {
                    started.insert(key);
                }
                Err(refusal) => {
                    tracing::warn!(code = refusal.code, %name, "events: source refused a replayed start");
                }
            }
        }
    }

    /// A source of kind `old.kind()` was replaced: stop what the old one
    /// started and start what the new one now holds.
    pub(super) async fn replace_source(&self, old: Arc<dyn EventSource>) {
        {
            let mut started = self.lifecycle.lock().await;
            let kind = old.kind();
            let keys: Vec<_> = started
                .iter()
                .filter(|(k, _)| *k == kind)
                .cloned()
                .collect();
            for key in keys {
                started.remove(&key);
                old.on_last_subscriber(&key.1).await;
            }
        }
        self.replay_starts().await;
    }

    /// Run [`Self::reconcile_stops`] from synchronous code (a reload).
    pub(super) fn reconcile_stops_in_background(self: &Arc<Self>) {
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let hub = Arc::clone(self);
            runtime.spawn(async move { hub.reconcile_stops().await });
        }
    }
}
