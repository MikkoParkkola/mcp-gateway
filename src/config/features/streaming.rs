//! Streaming configuration for real-time notifications (SSE).

use std::time::Duration;

use serde::{Deserialize, Serialize};

// ── Constants ──────────────────────────────────────────────────────────────────

const DEFAULT_BUFFER_SIZE: usize = 100;
const DEFAULT_KEEP_ALIVE_SECS: u64 = 15;
const DEFAULT_SESSION_TTL_SECS: u64 = 1800;
const DEFAULT_SESSION_REAPER_INTERVAL_SECS: u64 = 60;

// ── Streaming ──────────────────────────────────────────────────────────────────

/// Streaming configuration (for real-time notifications).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StreamingConfig {
    /// Enable streaming (GET /mcp for notifications).
    pub enabled: bool,
    /// Notification buffer size per client.
    pub buffer_size: usize,
    /// Keep-alive interval for SSE streams.
    #[serde(with = "crate::config::humantime_serde")]
    pub keep_alive_interval: Duration,
    /// Backends to auto-subscribe for notifications.
    #[serde(default)]
    pub auto_subscribe: Vec<String>,
    /// Maximum session lifetime before reaping (default: 30 min).
    #[serde(with = "crate::config::humantime_serde")]
    pub session_ttl: Duration,
    /// How often the session reaper runs (default: 60 s).
    #[serde(with = "crate::config::humantime_serde")]
    pub session_reaper_interval: Duration,
}

impl Default for StreamingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            buffer_size: DEFAULT_BUFFER_SIZE,
            keep_alive_interval: Duration::from_secs(DEFAULT_KEEP_ALIVE_SECS),
            auto_subscribe: Vec::new(),
            session_ttl: Duration::from_secs(DEFAULT_SESSION_TTL_SECS),
            session_reaper_interval: Duration::from_secs(DEFAULT_SESSION_REAPER_INTERVAL_SECS),
        }
    }
}
