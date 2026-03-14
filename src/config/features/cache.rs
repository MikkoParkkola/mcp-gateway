//! Cache configuration for response caching.

use std::time::Duration;

use serde::{Deserialize, Serialize};

// ── Constants ──────────────────────────────────────────────────────────────────

const DEFAULT_TTL_SECS: u64 = 60;
const DEFAULT_MAX_ENTRIES: usize = 10_000;

// ── Cache ──────────────────────────────────────────────────────────────────────

/// Cache configuration for response caching.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CacheConfig {
    /// Enable response caching.
    pub enabled: bool,
    /// Default TTL for cached responses.
    #[serde(with = "crate::config::humantime_serde")]
    pub default_ttl: Duration,
    /// Maximum number of entries before eviction.
    pub max_entries: usize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_ttl: Duration::from_secs(DEFAULT_TTL_SECS),
            max_entries: DEFAULT_MAX_ENTRIES,
        }
    }
}
