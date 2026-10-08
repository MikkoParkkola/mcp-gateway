// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MCP Events (MIK-7630): event types offered to clients as webhook
//! subscriptions (`events/list`, `events/subscribe`, `events/unsubscribe`).
//!
//! Design: `docs/design/2026-10-01-mik-7630-mcp-events.md`. I1 is the
//! protocol surface, the store and callback verification; I2 the delivery
//! pipeline: emission, fan-out, the outbox and the worker. Served over HTTP
//! only: webhook mode needs an authenticated principal, which a stdio
//! session does not carry.

#[cfg_attr(
    not(feature = "webui"),
    allow(
        dead_code,
        reason = "dead-letter administration is served by the web UI router"
    )
)]
mod admin;
mod backend_source;
mod client;
mod dedupe;
mod fanout;
mod governance;
mod lifecycle;
mod limiter;
mod operational_source;
mod outbox;
mod rate;
mod records;
mod reload;
mod rpc;
mod runtime;
mod schedule_source;
mod services;
mod store;
mod task_source;
mod types;
mod upstream;
mod upstream_listener;
mod upstream_need;
mod upstream_session;
pub(crate) mod watch_source;
mod webhook_source;
mod worker;

use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use parking_lot::RwLock;

#[cfg(feature = "webui")]
pub(crate) use admin::{ReplayRefusal, is_dead_reason};
pub(crate) use fanout::CatalogueScan;
#[cfg(feature = "webui")]
pub(crate) use governance::Actor;
pub(crate) use records::{ApiKeyRef, Credential, LiveBinding};
pub(crate) use rpc::Caller;
pub(crate) use services::{LiveCredentials, Services};
pub(crate) use types::CallbackFailure;
pub(crate) use types::{RpcError, Visibility};
pub(crate) use upstream::live_ineligible as upstream_live_ineligible;
pub(crate) use webhook_source::Inbound;

use crate::config::EventsConfig;
use crate::gateway::WebhookRegistry;
use types::EventDescriptor;

/// The events core: configuration, store, callback client and catalogue.
pub(crate) struct EventsHub {
    config: EventsConfig,
    store: Arc<store::Store>,
    client: client::CallbackClient,
    verify_limit: limiter::HostLimiter,
    sources: RwLock<Vec<Arc<dyn EventSource>>>,
    runtime: runtime::Runtime,
    /// Sources' started lifecycle keys; see [`lifecycle`].
    lifecycle: lifecycle::Started,
    debounce: backend_source::Debounce,
    /// Held while the catalogue changes or is read to delete from it.
    catalogue_gate: parking_lot::Mutex<()>,
    /// The webhook routes, for the payload fields a subscribe records
    /// (MIK-8076). Set once with the webhook source.
    webhook_registry: std::sync::OnceLock<Arc<parking_lot::RwLock<WebhookRegistry>>>,
    /// Held by each burial and dead-letter sweep from its store call through
    /// its last receipt, so a burial's receipt comes before any eviction of
    /// it. Taken before the store's own lock, and never with `lifecycle`.
    receipts: tokio::sync::Mutex<()>,
    /// Test-only: one subscribe pauses between its commit and its audit.
    #[cfg(test)]
    after_commit: crate::test_pause::Slot,
    /// Test-only: one subscribe pauses after its commit-time re-check, still
    /// holding the catalogue gate, before its store admit (MIK-8038).
    #[cfg(test)]
    before_admit: crate::test_pause::Slot,
    /// Test-only: one burial pauses between its store call and its receipts.
    #[cfg(test)]
    before_receipts: crate::test_pause::Slot,
}

/// One producer of events (design §4). The core knows sources only through
/// this trait; crate-private, so a source is added inside the crate and the
/// public surface does not widen (I4 build notes).
#[async_trait::async_trait]
pub(crate) trait EventSource: Send + Sync {
    /// What kind of producer this is.
    fn kind(&self) -> types::SourceKind;
    /// The event types this source offers now.
    fn descriptors(&self) -> Vec<EventDescriptor>;
    /// Whether this source offers event type `name`.
    fn offers(&self, name: &str) -> bool {
        self.descriptors().iter().any(|d| d.name == name)
    }
    /// May `principal` hold this subscription? Called at subscribe and at
    /// every fan-out. The default admits: visibility is the catalogue's.
    async fn authorize(
        &self,
        _principal: &str,
        _name: &str,
        _arguments: &serde_json::Value,
    ) -> Result<(), RpcError> {
        Ok(())
    }
    /// Whether an occurrence matches a subscription's `arguments`.
    fn matches(
        &self,
        principal: &str,
        arguments: &serde_json::Value,
        event: &fanout::SourceEvent,
    ) -> bool;
    /// What the core refcounts upstream work on: by default the event name
    /// and canonical arguments, shared across principals.
    fn lifecycle_key(&self, _principal: &str, name: &str, arguments: &serde_json::Value) -> String {
        String::from_utf8(rpc::canonical(&serde_json::json!([name, arguments]))).unwrap_or_default()
    }
    /// The lifecycle key of a stored row this source owns even while it does
    /// not offer the row's type (a held REST watch, MIK-8122): the key comes
    /// from the row, never from a catalogue read. `None` for rows it does not
    /// own; their key comes from the offering source.
    fn row_key(&self, _sub: &records::Subscription) -> Option<String> {
        None
    }
    /// The sharing class a new REST watch of type `name` is admitted under;
    /// `None` for any other source (MIK-8122).
    fn watch_class(&self, _name: &str) -> Option<records::WatchClass> {
        None
    }
    /// The first live subscription for `key` appeared. A refusal fails that
    /// subscribe with the refusal's code.
    async fn on_first_subscriber(
        &self,
        _key: &str,
        _principal: &str,
        _name: &str,
        _arguments: &serde_json::Value,
    ) -> Result<(), RpcError> {
        Ok(())
    }
    /// The last subscription for `key` went away (unsubscribe, expiry,
    /// revocation or withdrawal).
    async fn on_last_subscriber(&self, _key: &str) {}
    /// Whether a delivery of event type `name` is charged to a budget. A
    /// source reporting on budgets answers `false`, so exhausting a budget
    /// does not charge the event that reports it (event-sources design §3).
    fn charges(&self, _name: &str) -> bool {
        true
    }
}

/// Distinct callback hosts the verification limiter tracks before it sheds
/// idle ones; past it, after shedding, a new host is refused.
const MAX_TRACKED_HOSTS: usize = 10_000;

impl std::fmt::Debug for EventsHub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Opaque on purpose: the store and client hold subscriber secrets.
        f.debug_struct("EventsHub").finish_non_exhaustive()
    }
}

impl EventsHub {
    /// Open the hub on `store_dir` (already `~`-expanded).
    ///
    /// # Errors
    /// The store directory cannot be created or read, or the client fails
    /// to build.
    pub(crate) fn open(config: &EventsConfig, store_dir: &Path) -> crate::Result<Arc<Self>> {
        let client = client::CallbackClient::new(allowed_networks(config))?;
        Self::open_with(config, store_dir, client)
    }

    /// As [`Self::open`], trusting `root` for callback TLS (tests only).
    #[cfg(test)]
    pub(crate) fn open_trusting(
        config: &EventsConfig,
        store_dir: &Path,
        root: reqwest::Certificate,
    ) -> crate::Result<Arc<Self>> {
        let client = client::CallbackClient::trusting(allowed_networks(config), root)?;
        Self::open_with(config, store_dir, client)
    }

    fn open_with(
        config: &EventsConfig,
        store_dir: &Path,
        client: client::CallbackClient,
    ) -> crate::Result<Arc<Self>> {
        let store = store::Store::open(store_dir, chrono::Utc::now(), tail_policy(config))
            .map_err(|e| {
                crate::Error::Config(format!("events store {}: {e}", store_dir.display()))
            })?;
        Ok(Arc::new(Self {
            config: config.clone(),
            store: Arc::new(store),
            client,
            verify_limit: limiter::HostLimiter::new(
                config.verification_per_host_per_minute,
                MAX_TRACKED_HOSTS,
            ),
            sources: RwLock::new(Vec::new()),
            runtime: runtime::Runtime::new(config, store_dir),
            lifecycle: lifecycle::Started::default(),
            debounce: backend_source::Debounce::default(),
            catalogue_gate: parking_lot::Mutex::new(()),
            webhook_registry: std::sync::OnceLock::new(),
            receipts: tokio::sync::Mutex::new(()),
            #[cfg(test)]
            after_commit: crate::test_pause::Slot::default(),
            #[cfg(test)]
            before_admit: crate::test_pause::Slot::default(),
            #[cfg(test)]
            before_receipts: crate::test_pause::Slot::default(),
        }))
    }

    /// Register `source`, replacing any earlier source of the same kind. Its
    /// descriptors join the catalogue; lifecycle hooks follow (I4).
    pub(crate) fn register_source(self: &Arc<Self>, source: Arc<dyn EventSource>) {
        let mut sources = self.sources.write();
        let position = sources.iter().position(|s| s.kind() == source.kind());
        let replaced = position.map(|at| sources.remove(at));
        sources.push(source);
        drop(sources);
        // A source joining a running hub starts what the store already holds;
        // one it replaces first stops what it had started.
        if self.runtime.services.get().is_some()
            && let Ok(runtime) = tokio::runtime::Handle::try_current()
        {
            let hub = Arc::clone(self);
            runtime.spawn(async move {
                match replaced {
                    Some(old) => hub.replace_source(old).await,
                    None => hub.replay_starts().await,
                }
            });
        }
    }

    /// Attach the webhook registry whose `event:` routes are a source.
    pub(crate) fn set_webhook_registry(
        self: &Arc<Self>,
        registry: Arc<parking_lot::RwLock<WebhookRegistry>>,
    ) {
        let _ = self.webhook_registry.set(Arc::clone(&registry));
        self.register_source(Arc::new(webhook_source::WebhookSource { registry }));
    }

    /// Take one verification slot for `host`.
    fn host_admitted(&self, host: &str) -> bool {
        self.verify_limit.admit(host, std::time::Instant::now())
    }

    /// Every descriptor any source offers now, sorted by name.
    fn catalogue(&self) -> Vec<EventDescriptor> {
        let mut all: Vec<EventDescriptor> = self
            .sources
            .read()
            .iter()
            .flat_map(|source| source.descriptors())
            .collect();
        all.sort_by(|a, b| a.name.cmp(&b.name));
        all
    }

    /// The `capabilities.events` value, or `None` when no source offers an
    /// event type (design §6.1). `listChanged` is false: nothing pushes a
    /// catalogue change, so a client re-reads `events/list` (MIK-7803).
    pub(crate) fn capability(&self) -> Option<serde_json::Value> {
        (!self.catalogue().is_empty()).then(|| serde_json::json!({ "listChanged": false }))
    }
}

fn allowed_networks(config: &EventsConfig) -> Vec<(IpAddr, u8)> {
    config
        .callback_allow_private
        .iter()
        .filter_map(|c| crate::config::parse_cidr(c))
        .collect()
}

fn tail_policy(config: &EventsConfig) -> store::TailPolicy {
    store::TailPolicy {
        ttl: config.verified_tail_ttl,
        max: config.max_verified_tail,
        max_per_principal: config.max_verified_tail_per_principal,
    }
}

#[cfg(test)]
#[path = "lifecycle_tests.rs"]
mod lifecycle_tests;

#[cfg(test)]
#[path = "sources_tests.rs"]
mod sources_tests;
