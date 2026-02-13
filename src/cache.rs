//! Response caching with TTL for `gateway_invoke` results
//!
//! Provides a thread-safe, TTL-based cache for tool invocation responses.
//! Cache keys are computed from `server:tool:args_hash` where `args_hash`
//! is the SHA-256 digest of the canonical JSON arguments.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Thread-safe response cache with TTL expiry
pub struct ResponseCache {
    /// Cache entries keyed by `server:tool:args_hash`
    entries: DashMap<String, CachedResponse>,
    /// Cache statistics
    stats: CacheStats,
}

/// A cached response with TTL metadata
struct CachedResponse {
    /// The cached JSON value
    value: Value,
    /// When this entry was cached
    cached_at: Instant,
    /// Time-to-live duration
    ttl: Duration,
}

impl CachedResponse {
    /// Check if this entry has expired
    fn is_expired(&self) -> bool {
        Instant::now().duration_since(self.cached_at) > self.ttl
    }
}

/// Cache statistics tracked atomically
#[derive(Debug)]
pub struct CacheStats {
    /// Total cache hits (entries served from cache)
    pub hits: AtomicU64,
    /// Total cache misses (entries not found or expired)
    pub misses: AtomicU64,
    /// Total evictions (expired entries removed)
    pub evictions: AtomicU64,
}

impl CacheStats {
    /// Create new statistics with all counters at zero
    fn new() -> Self {
        Self {
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
        }
    }

    /// Get current cache hit count
    pub fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    /// Get current cache miss count
    pub fn misses(&self) -> u64 {
        self.misses.load(Ordering::Relaxed)
    }

    /// Get current eviction count
    pub fn evictions(&self) -> u64 {
        self.evictions.load(Ordering::Relaxed)
    }

    /// Calculate hit rate as a percentage (0.0-1.0)
    #[allow(clippy::cast_precision_loss)]
    pub fn hit_rate(&self) -> f64 {
        let hits = self.hits();
        let total = hits + self.misses();
        if total == 0 {
            0.0
        } else {
            hits as f64 / total as f64
        }
    }
}

impl ResponseCache {
    /// Create a new empty cache
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
            stats: CacheStats::new(),
        }
    }

    /// Get a cached response if it exists and hasn't expired
    ///
    /// Returns `None` if the key doesn't exist or the entry has expired.
    /// Expired entries are automatically evicted.
    pub fn get(&self, key: &str) -> Option<Value> {
        if let Some(entry) = self.entries.get(key) {
            if entry.is_expired() {
                // Entry expired - evict it
                drop(entry);
                self.entries.remove(key);
                self.stats.evictions.fetch_add(1, Ordering::Relaxed);
                self.stats.misses.fetch_add(1, Ordering::Relaxed);
                None
            } else {
                // Cache hit
                self.stats.hits.fetch_add(1, Ordering::Relaxed);
                Some(entry.value.clone())
            }
        } else {
            // Cache miss
            self.stats.misses.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    /// Store a value in the cache with the given TTL
    ///
    /// # Arguments
    ///
    /// * `key` - Cache key (typically `server:tool:args_hash`)
    /// * `value` - JSON value to cache
    /// * `ttl` - Time-to-live duration
    pub fn set(&self, key: &str, value: Value, ttl: Duration) {
        let entry = CachedResponse {
            value,
            cached_at: Instant::now(),
            ttl,
        };
        self.entries.insert(key.to_string(), entry);
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStatsSnapshot {
        CacheStatsSnapshot {
            hits: self.stats.hits(),
            misses: self.stats.misses(),
            evictions: self.stats.evictions(),
            size: self.entries.len(),
            hit_rate: self.stats.hit_rate(),
        }
    }

    /// Build a cache key from server, tool name, and arguments
    ///
    /// The key format is `{server}:{tool}:{args_hash}` where `args_hash`
    /// is the SHA-256 hex digest of the canonical JSON representation.
    #[must_use]
    pub fn build_key(server: &str, tool: &str, arguments: &Value) -> String {
        let args_hash = Self::hash_arguments(arguments);
        format!("{server}:{tool}:{args_hash}")
    }

    /// Compute SHA-256 hash of arguments in canonical JSON form
    fn hash_arguments(arguments: &Value) -> String {
        // Serialize to canonical JSON (keys sorted)
        let canonical = serde_json::to_string(arguments).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        let result = hasher.finalize();
        format!("{result:x}")
    }

    /// Clear all cached entries
    pub fn clear(&self) {
        self.entries.clear();
    }

    /// Evict expired entries (background maintenance)
    pub fn evict_expired(&self) {
        let keys_to_remove: Vec<String> = self
            .entries
            .iter()
            .filter_map(|entry| {
                if entry.value().is_expired() {
                    Some(entry.key().clone())
                } else {
                    None
                }
            })
            .collect();

        let count = keys_to_remove.len();
        for key in keys_to_remove {
            self.entries.remove(&key);
        }

        if count > 0 {
            self.stats
                .evictions
                .fetch_add(count as u64, Ordering::Relaxed);
        }
    }
}

impl Default for ResponseCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Snapshot of cache statistics
#[derive(Debug, Clone, serde::Serialize)]
pub struct CacheStatsSnapshot {
    /// Total cache hits
    pub hits: u64,
    /// Total cache misses
    pub misses: u64,
    /// Total evictions
    pub evictions: u64,
    /// Current number of entries
    pub size: usize,
    /// Hit rate (0.0-1.0)
    pub hit_rate: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_cache_hit() {
        let cache = ResponseCache::new();
        let value = json!({"result": "success"});

        cache.set("test_key", value.clone(), Duration::from_secs(60));
        let retrieved = cache.get("test_key");

        assert_eq!(retrieved, Some(value));
        assert_eq!(cache.stats().hits, 1);
        assert_eq!(cache.stats().misses, 0);
    }

    #[test]
    fn test_cache_miss() {
        let cache = ResponseCache::new();
        let retrieved = cache.get("nonexistent");

        assert_eq!(retrieved, None);
        assert_eq!(cache.stats().misses, 1);
    }

    #[test]
    fn test_cache_expiry() {
        let cache = ResponseCache::new();
        let value = json!({"result": "expired"});

        // Set with 1ms TTL
        cache.set("test_key", value, Duration::from_millis(1));

        // Wait for expiry
        std::thread::sleep(Duration::from_millis(5));

        // Should be expired and evicted
        let retrieved = cache.get("test_key");
        assert_eq!(retrieved, None);
        assert_eq!(cache.stats().evictions, 1);
    }

    #[test]
    fn test_build_key() {
        let args = json!({"param": "value", "number": 42});
        let key = ResponseCache::build_key("my_server", "my_tool", &args);

        // Should have format server:tool:hash
        assert!(key.starts_with("my_server:my_tool:"));
        // Hash should be 64 hex chars (SHA-256)
        let parts: Vec<&str> = key.split(':').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[2].len(), 64);
    }

    #[test]
    fn test_hash_deterministic() {
        let args1 = json!({"a": 1, "b": 2});
        let args2 = json!({"b": 2, "a": 1}); // Same keys, different order

        let hash1 = ResponseCache::hash_arguments(&args1);
        let hash2 = ResponseCache::hash_arguments(&args2);

        // Hashes should be identical for equivalent objects
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hit_rate() {
        let cache = ResponseCache::new();
        cache.set("key1", json!(1), Duration::from_secs(60));
        cache.set("key2", json!(2), Duration::from_secs(60));

        // 2 hits
        cache.get("key1");
        cache.get("key2");
        // 1 miss
        cache.get("key3");

        let stats = cache.stats();
        assert_eq!(stats.hits, 2);
        assert_eq!(stats.misses, 1);
        assert!((stats.hit_rate - 0.666).abs() < 0.01);
    }

    #[test]
    fn test_clear() {
        let cache = ResponseCache::new();
        cache.set("key1", json!(1), Duration::from_secs(60));
        cache.set("key2", json!(2), Duration::from_secs(60));

        assert_eq!(cache.stats().size, 2);

        cache.clear();
        assert_eq!(cache.stats().size, 0);
        assert_eq!(cache.get("key1"), None);
    }

    #[test]
    fn test_evict_expired() {
        let cache = ResponseCache::new();
        cache.set("short", json!(1), Duration::from_millis(1));
        cache.set("long", json!(2), Duration::from_secs(60));

        std::thread::sleep(Duration::from_millis(5));

        cache.evict_expired();

        assert_eq!(cache.stats().size, 1);
        assert_eq!(cache.get("long"), Some(json!(2)));
        assert_eq!(cache.stats().evictions, 1);
    }

    #[test]
    fn test_default_impl() {
        let cache = ResponseCache::default();
        assert_eq!(cache.stats().hits, 0);
        assert_eq!(cache.stats().misses, 0);
    }

    #[test]
    fn test_multiple_hits_and_misses() {
        let cache = ResponseCache::new();
        cache.set("key", json!({"data": "value"}), Duration::from_secs(60));

        // Multiple hits
        for _ in 0..5 {
            assert_eq!(cache.get("key"), Some(json!({"data": "value"})));
        }

        // Multiple misses
        for _ in 0..3 {
            assert_eq!(cache.get("nonexistent"), None);
        }

        let stats = cache.stats();
        assert_eq!(stats.hits, 5);
        assert_eq!(stats.misses, 3);
        assert_eq!(stats.size, 1);
    }

    #[test]
    fn test_cache_key_with_complex_args() {
        let args = json!({
            "nested": {
                "array": [1, 2, 3],
                "object": {"key": "value"}
            },
            "string": "test"
        });

        let key1 = ResponseCache::build_key("server", "tool", &args);
        let key2 = ResponseCache::build_key("server", "tool", &args);

        assert_eq!(key1, key2);
        assert!(key1.starts_with("server:tool:"));
    }

    #[test]
    fn test_ttl_boundary() {
        let cache = ResponseCache::new();
        cache.set("key", json!(1), Duration::from_millis(10));

        // Should be valid immediately
        assert_eq!(cache.get("key"), Some(json!(1)));

        // Wait for expiry
        std::thread::sleep(Duration::from_millis(15));

        // Should be expired
        assert_eq!(cache.get("key"), None);
        assert_eq!(cache.stats().evictions, 1);
    }
}
