//! Webhook receiver configuration.

use serde::{Deserialize, Serialize};

// ── Constants ──────────────────────────────────────────────────────────────────

const DEFAULT_BASE_PATH: &str = "/webhooks";
const DEFAULT_RATE_LIMIT: u32 = 100;

// ── Webhooks ───────────────────────────────────────────────────────────────────

/// Webhook receiver configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WebhookConfig {
    /// Enable the webhook receiver.
    pub enabled: bool,
    /// Base path prefix for all webhook endpoints (e.g., "/webhooks").
    pub base_path: String,
    /// Require HMAC signature on all webhooks (can be overridden per definition).
    pub require_signature: bool,
    /// Rate limit for webhook endpoints (requests per minute, 0 = unlimited).
    pub rate_limit: u32,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            base_path: DEFAULT_BASE_PATH.to_string(),
            require_signature: true,
            rate_limit: DEFAULT_RATE_LIMIT,
        }
    }
}
