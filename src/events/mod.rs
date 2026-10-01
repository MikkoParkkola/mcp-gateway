// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MCP Events (MIK-7630): event types offered to clients as webhook
//! subscriptions (`events/list`, `events/subscribe`, `events/unsubscribe`).
//!
//! Design: `docs/design/2026-10-01-mik-7630-mcp-events.md`. Increment I1 is
//! the protocol surface, the store and callback verification; nothing is
//! emitted yet. Served over HTTP only: webhook mode needs an authenticated
//! principal, which a stdio session does not carry.

mod client;
mod records;
mod rpc;
mod store;
mod types;
mod webhook_source;

use std::net::IpAddr;
use std::num::NonZeroU32;
use std::path::Path;
use std::sync::Arc;

use parking_lot::RwLock;

pub(crate) use rpc::Caller;
pub(crate) use types::RpcError;

use crate::config::EventsConfig;
use crate::gateway::WebhookRegistry;
use types::EventDescriptor;

type HostLimiter = governor::DefaultKeyedRateLimiter<String>;

/// The events core: configuration, store, callback client and catalogue.
pub(crate) struct EventsHub {
    config: EventsConfig,
    store: Arc<store::Store>,
    client: client::CallbackClient,
    verify_limit: HostLimiter,
    webhooks: RwLock<Option<Arc<parking_lot::RwLock<WebhookRegistry>>>>,
    /// Serialises subscribe and unsubscribe, so a cap check and the commit
    /// it guards cannot be raced past.
    writes: tokio::sync::Mutex<()>,
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
        let per_minute =
            NonZeroU32::new(config.verification_per_host_per_minute).unwrap_or(NonZeroU32::MIN);
        Ok(Arc::new(Self {
            config: config.clone(),
            store: Arc::new(store),
            client: client::CallbackClient::new(allowed)?,
            verify_limit: governor::RateLimiter::keyed(governor::Quota::per_minute(per_minute)),
            webhooks: RwLock::new(None),
            writes: tokio::sync::Mutex::new(()),
        }))
    }

    /// Attach the webhook registry whose `event:` routes are a source.
    pub(crate) fn set_webhook_registry(&self, registry: Arc<parking_lot::RwLock<WebhookRegistry>>) {
        *self.webhooks.write() = Some(registry);
    }

    /// Every descriptor any source offers now, sorted by name.
    fn catalogue(&self) -> Vec<EventDescriptor> {
        let mut all = Vec::new();
        if let Some(registry) = self.webhooks.read().as_ref() {
            all.extend(webhook_source::descriptors(&registry.read()));
        }
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
