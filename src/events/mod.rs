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
mod client;
mod dedupe;
mod fanout;
mod limiter;
mod outbox;
mod rate;
mod records;
mod reload;
mod rpc;
mod runtime;
mod services;
mod store;
mod types;
mod upstream;
mod webhook_source;
mod worker;

use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use parking_lot::RwLock;

#[cfg(feature = "webui")]
pub(crate) use admin::{ReplayRefusal, is_dead_reason};
pub(crate) use records::{ApiKeyRef, Credential, LiveBinding};
pub(crate) use reload::refresh_webhooks;
pub(crate) use rpc::Caller;
pub(crate) use services::{LiveCredentials, Services};
pub(crate) use types::{RpcError, Visibility};
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
}

/// One producer of events (design §4). The core knows sources only through
/// this trait. `authorize` and the lifecycle hooks join with I4.
pub(crate) trait EventSource: Send + Sync {
    /// What kind of producer this is.
    fn kind(&self) -> types::SourceKind;
    /// The event types this source offers now.
    fn descriptors(&self) -> Vec<EventDescriptor>;
    /// Whether an occurrence matches a subscription's `arguments`.
    fn matches(&self, arguments: &serde_json::Value, event: &fanout::SourceEvent) -> bool;
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
        let allowed: Vec<(IpAddr, u8)> = config
            .callback_allow_private
            .iter()
            .filter_map(|c| crate::config::parse_cidr(c))
            .collect();
        let store = store::Store::open(store_dir, chrono::Utc::now(), tail_policy(config))
            .map_err(|e| {
                crate::Error::Config(format!("events store {}: {e}", store_dir.display()))
            })?;
        Ok(Arc::new(Self {
            config: config.clone(),
            store: Arc::new(store),
            client: client::CallbackClient::new(allowed)?,
            verify_limit: limiter::HostLimiter::new(
                config.verification_per_host_per_minute,
                MAX_TRACKED_HOSTS,
            ),
            sources: RwLock::new(Vec::new()),
            runtime: runtime::Runtime::new(config, store_dir),
        }))
    }

    /// Attach the webhook registry whose `event:` routes are a source.
    pub(crate) fn set_webhook_registry(&self, registry: Arc<parking_lot::RwLock<WebhookRegistry>>) {
        let mut sources = self.sources.write();
        sources.retain(|source| source.kind() != types::SourceKind::Webhook);
        sources.push(Arc::new(webhook_source::WebhookSource { registry }));
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
    /// event type (design §6.1).
    pub(crate) fn capability(&self) -> Option<serde_json::Value> {
        (!self.catalogue().is_empty()).then(|| serde_json::json!({ "listChanged": true }))
    }
}

fn tail_policy(config: &EventsConfig) -> store::TailPolicy {
    store::TailPolicy {
        ttl: config.verified_tail_ttl,
        max: config.max_verified_tail,
        max_per_principal: config.max_verified_tail_per_principal,
    }
}
