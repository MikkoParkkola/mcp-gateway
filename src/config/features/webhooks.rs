// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
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

impl WebhookConfig {
    /// Refuse a `base_path` axum would reject at startup, or one that overlaps
    /// a route the gateway listener owns (MIK-8002). A disabled receiver
    /// mounts nothing, so its path is not checked.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ConfigValidation`] naming the path and, for an
    /// overlap, the owned route.
    pub(crate) fn validate(&self) -> crate::Result<()> {
        if !self.enabled {
            return Ok(());
        }
        let path = &self.base_path;
        if !well_formed(path) {
            return Err(crate::Error::ConfigValidation(format!(
                "webhooks.base_path '{path}' must start with '/', not be '/', and have no \
                 trailing '/', no empty, '.' or '..' segment, no '{{' or '}}', and no segment \
                 starting with ':' or '*'"
            )));
        }
        if let Some(route) = crate::gateway::routes::OWNED
            .iter()
            .find(|route| overlaps(path, route))
        {
            return Err(crate::Error::ConfigValidation(format!(
                "webhooks.base_path '{path}' overlaps the gateway route '{route}'; choose a \
                 path outside the gateway's own routes"
            )));
        }
        Ok(())
    }
}

/// A path axum mounts as written: rooted, not the root itself (a root
/// catch-all would shadow the fallback), every segment a plain literal.
fn well_formed(path: &str) -> bool {
    let Some(rest) = path.strip_prefix('/') else {
        return false;
    };
    !rest.is_empty()
        && rest.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && !segment.contains(['{', '}'])
                && !segment.starts_with([':', '*'])
        })
}

/// Whether a webhook mount at `base` and the owned `route` share a path: one
/// is the other or lies under it. Both directions matter: an owned route
/// under `base` would sit beside the webhook catch-all, which axum refuses
/// at startup for a parameter route. Per segment, so `/mcpx` is not under
/// `/mcp`; a `{x}` segment in `route` matches any one segment, `{*x}` the rest.
pub(crate) fn overlaps(base: &str, route: &str) -> bool {
    for (b, r) in base.split('/').zip(route.split('/')) {
        if r.starts_with("{*") {
            return true;
        }
        if !(r.starts_with('{') || r == b) {
            return false;
        }
    }
    true
}

#[cfg(test)]
#[path = "webhooks_tests.rs"]
mod tests;
