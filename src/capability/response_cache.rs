// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Simple response cache with TTL support
//!
//! Provides a thread-safe cache for capability REST responses,
//! keyed by capability name and parameter hash.

use std::time::{Duration, Instant};

use dashmap::DashMap;
use serde_json::Value;

use crate::security::firewall::tenant_reads::ReadAttribution;

/// Thread-safe response cache with per-entry TTL expiration
pub(crate) struct ResponseCache {
    entries: DashMap<String, CacheEntry>,
}

struct CacheEntry {
    value: Value,
    /// MIK-7116.MIN.2: the tenants the raw response named before the
    /// transform; `None` when it was stored with attribution off.
    read: Option<ReadAttribution>,
    expires_at: Instant,
}

impl ResponseCache {
    pub(crate) fn new() -> Self {
        Self {
            entries: DashMap::new(),
        }
    }

    /// The cached value and the attribution stored beside it.
    pub(crate) fn get(&self, key: &str) -> Option<(Value, Option<ReadAttribution>)> {
        if let Some(entry) = self.entries.get(key) {
            if entry.expires_at > Instant::now() {
                return Some((entry.value.clone(), entry.read.clone()));
            }
            // Entry expired, remove it
            drop(entry);
            self.entries.remove(key);
        }
        None
    }

    /// Store `value` for `ttl_seconds`, unless it is an error (`isError:
    /// true`): a 2xx body reporting a failure would otherwise be replayed for
    /// the whole TTL after the upstream recovered (F26).
    pub(crate) fn set(
        &self,
        key: &str,
        value: &Value,
        read: Option<ReadAttribution>,
        ttl_seconds: u64,
    ) {
        if crate::protocol::cacheable::is_error(value) {
            tracing::debug!(key, "Refused to cache an error result");
            return;
        }
        let entry = CacheEntry {
            value: value.clone(),
            read,
            expires_at: Instant::now() + Duration::from_secs(ttl_seconds),
        };
        self.entries.insert(key.to_string(), entry);
    }
}
