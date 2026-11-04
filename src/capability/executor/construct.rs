// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! [`CapabilityExecutor`]'s constructors: the default executor, the one built
//! from the capabilities config, and one with its own OAuth token storage
//! (moved from `mod.rs`).

use std::sync::Arc;

use dashmap::DashMap;
use parking_lot::RwLock;

use super::{CAPABILITY_CACHE_MAX_ENTRIES, CapabilityExecutor, client, process};
use crate::cache::ResponseCache;
use crate::oauth::TokenStorage;
use crate::secrets::SecretResolver;

impl CapabilityExecutor {
    /// Create a new executor.
    ///
    /// # Panics
    ///
    /// Panics if the HTTP client cannot be created.
    pub fn new() -> Self {
        let token_storage = TokenStorage::default_location().ok().map(Arc::new);

        Self {
            client: client::build(None),
            refresh: client::build_refresh(None),
            cache: ResponseCache::with_max_entries(CAPABILITY_CACHE_MAX_ENTRIES),
            token_storage,
            oauth_tokens: RwLock::new(DashMap::new()),
            secret_resolver: Arc::new(SecretResolver::new()),
            health: crate::failsafe::HealthTracker::new("capabilities"),
            env: Arc::new(crate::config::LiveEnv::default()),
            policy_epoch: None,
            account_strategies: None,
            process_policy: process::ProcessPolicy::default(),
            process_slots: DashMap::new(),
            mcp_children: Arc::default(),
            multi_user: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            test_loopback_egress: false,
        }
    }

    /// A new executor whose calls go through `capabilities.egress_proxy` when
    /// it is set, and direct and pinned otherwise (#1881). A value the load
    /// check would refuse is ignored here, which only ever means direct.
    // Public for the gateway server and the egress tests under tests/; not
    // documented API.
    #[doc(hidden)]
    #[must_use]
    pub fn for_config(config: &crate::config::CapabilityConfig) -> Self {
        let mut executor = Self::new();
        executor.process_policy = process::ProcessPolicy::from_config(config);
        if let Ok(Some(proxy)) = config.egress_proxy_url() {
            tracing::warn!(
                proxy = %crate::config::CapabilityConfig::egress_proxy_for_log(&proxy),
                "capability calls go through capabilities.egress_proxy; the proxy, not the \
                 gateway, resolves their destinations"
            );
            executor.client = client::build(Some(&proxy));
            executor.refresh = client::build_refresh(Some(&proxy));
        }
        executor
    }

    /// Create an executor with a custom OAuth token storage.
    ///
    /// # Panics
    ///
    /// Panics if the HTTP client cannot be created.
    #[must_use]
    pub fn with_token_storage(token_storage: Arc<TokenStorage>) -> Self {
        Self {
            client: client::build(None),
            refresh: client::build_refresh(None),
            cache: ResponseCache::with_max_entries(CAPABILITY_CACHE_MAX_ENTRIES),
            token_storage: Some(token_storage),
            oauth_tokens: RwLock::new(DashMap::new()),
            secret_resolver: Arc::new(SecretResolver::new()),
            health: crate::failsafe::HealthTracker::new("capabilities"),
            env: Arc::new(crate::config::LiveEnv::default()),
            policy_epoch: None,
            account_strategies: None,
            process_policy: process::ProcessPolicy::default(),
            process_slots: DashMap::new(),
            mcp_children: Arc::default(),
            multi_user: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            test_loopback_egress: false,
        }
    }
}
