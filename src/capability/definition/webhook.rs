// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A webhook route's opt-in MCP event (MIK-7630), and the route's redacting
//! `Debug`.

use serde::{Deserialize, Serialize};

use super::WebhookDefinition;

/// Webhook senders POST; a route that names no method accepts that.
pub(super) fn default_method() -> String {
    "POST".to_string()
}

/// The `event:` block of a webhook route: the route becomes the event
/// `webhook.<capability>.<route>.received`, projected from `transform.data`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookEvent {
    /// Description shown in `events/list`.
    #[serde(default)]
    pub description: String,
    /// `transform.data` keys a subscription may filter on by equality.
    #[serde(default)]
    pub filters: Vec<String>,
    /// Header carrying the provider's stable delivery id (dedupe key).
    #[serde(default)]
    pub delivery_id_header: Option<String>,
    /// `body` dedupes on the signed body's hash; absent = no body dedupe.
    #[serde(default)]
    pub dedupe: Option<String>,
}

// Manual `Debug` that redacts the HMAC verification secret (CWE-532, mirrors
// PR #323). A derived `Debug` would print the webhook `secret` verbatim into
// any trace or error context; only its presence is surfaced.
impl std::fmt::Debug for WebhookDefinition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redact_opt = |v: &Option<String>| if v.is_some() { "<redacted>" } else { "None" };
        f.debug_struct("WebhookDefinition")
            .field("path", &self.path)
            .field("method", &self.method)
            .field("secret", &redact_opt(&self.secret))
            .field("signature_header", &self.signature_header)
            .field("notify", &self.notify)
            .field("transform", &self.transform)
            .field("event", &self.event)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::WebhookDefinition;

    /// The documented default: a route that names no method accepts POST,
    /// the verb every webhook sender uses (MIK-7758).
    #[test]
    fn a_route_without_a_method_accepts_post() {
        let route: WebhookDefinition = serde_yaml::from_str("path: /acme/hook").unwrap();
        assert_eq!(route.method, "POST");
    }
}
