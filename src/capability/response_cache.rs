//! Simple response cache with TTL support
//!
//! Provides a thread-safe cache for capability REST responses,
//! keyed by capability name and parameter hash.

use std::time::{Duration, Instant};

use dashmap::DashMap;
use serde_json::Value;

/// Thread-safe response cache with per-entry TTL expiration
pub(crate) struct ResponseCache {
    entries: DashMap<String, CacheEntry>,
}

struct CacheEntry {
    value: Value,
    expires_at: Instant,
}

impl ResponseCache {
    pub(crate) fn new() -> Self {
        Self {
            entries: DashMap::new(),
        }
    }

    pub(crate) fn get(&self, key: &str) -> Option<Value> {
        if let Some(entry) = self.entries.get(key) {
            if entry.expires_at > Instant::now() {
                return Some(entry.value.clone());
            }
            // Entry expired, remove it
            drop(entry);
            self.entries.remove(key);
        }
        None
    }

    pub(crate) fn set(&self, key: &str, value: &Value, ttl_seconds: u64) {
        let entry = CacheEntry {
            value: value.clone(),
            expires_at: Instant::now() + Duration::from_secs(ttl_seconds),
        };
        self.entries.insert(key.to_string(), entry);
    }
}
