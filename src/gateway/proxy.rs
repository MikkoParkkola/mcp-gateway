//! Client-side capability proxying for MCP Gateway.
//!
//! MCP defines several **server-to-client** capabilities where a backend MCP
//! server initiates a request that must be forwarded to the connected client:
//!
//! - **Elicitation** (`elicitation/create`): Backend requests structured user
//!   input via the client.
//! - **Sampling** (`sampling/createMessage`): Backend requests an LLM completion
//!   via the client, optionally with tool use.
//! - **Roots** (`roots/list`): Backend requests the set of filesystem roots
//!   exposed by the client.
//!
//! For the initial implementation (v1), these are forwarded as fire-and-forget
//! notifications over the existing SSE stream. Full bidirectional
//! request-response proxying (where the gateway matches client responses back
//! to the originating backend) can be added later.

use std::sync::Arc;

use parking_lot::RwLock;
use serde_json::json;
use tracing::{debug, warn};

use crate::protocol::{ElicitationCreateParams, Root, SamplingCreateMessageParams};

use super::streaming::{NotificationMultiplexer, TaggedNotification};

// ============================================================================
// Proxy Manager
// ============================================================================

/// Manages client-side capability proxying (elicitation, sampling, roots).
///
/// Holds a reference to the [`NotificationMultiplexer`] used for forwarding
/// requests to connected clients via SSE.
pub struct ProxyManager {
    /// Notification multiplexer for sending to clients
    multiplexer: Arc<NotificationMultiplexer>,
    /// Cached roots from the most recent `roots/list` response
    cached_roots: RwLock<Vec<Root>>,
}

impl ProxyManager {
    /// Create a new proxy manager.
    #[must_use]
    pub fn new(multiplexer: Arc<NotificationMultiplexer>) -> Self {
        Self {
            multiplexer,
            cached_roots: RwLock::new(Vec::new()),
        }
    }

    // ========================================================================
    // Elicitation proxying
    // ========================================================================

    /// Forward an `elicitation/create` request to connected clients.
    ///
    /// In v1, this sends the elicitation request as a notification over SSE.
    /// The client is expected to POST back with the response.
    pub fn forward_elicitation(&self, session_id: &str, params: &ElicitationCreateParams) -> bool {
        let data = json!({
            "jsonrpc": "2.0",
            "method": "elicitation/create",
            "params": serde_json::to_value(params).unwrap_or(json!({}))
        });

        let notification = TaggedNotification {
            source: "gateway".to_string(),
            event_type: "proxy_request".to_string(),
            data,
            event_id: Some(self.multiplexer.next_event_id()),
        };

        let sent = self.multiplexer.send_to_session(session_id, notification);
        if sent {
            debug!(session_id = %session_id, "Forwarded elicitation/create to client");
        } else {
            warn!(session_id = %session_id, "Failed to forward elicitation/create");
        }
        sent
    }

    // ========================================================================
    // Sampling proxying
    // ========================================================================

    /// Forward a `sampling/createMessage` request to connected clients.
    ///
    /// In v1, this sends the sampling request as a notification over SSE.
    pub fn forward_sampling(&self, session_id: &str, params: &SamplingCreateMessageParams) -> bool {
        let data = json!({
            "jsonrpc": "2.0",
            "method": "sampling/createMessage",
            "params": serde_json::to_value(params).unwrap_or(json!({}))
        });

        let notification = TaggedNotification {
            source: "gateway".to_string(),
            event_type: "proxy_request".to_string(),
            data,
            event_id: Some(self.multiplexer.next_event_id()),
        };

        let sent = self.multiplexer.send_to_session(session_id, notification);
        if sent {
            debug!(session_id = %session_id, "Forwarded sampling/createMessage to client");
        } else {
            warn!(session_id = %session_id, "Failed to forward sampling/createMessage");
        }
        sent
    }

    // ========================================================================
    // Roots proxying
    // ========================================================================

    /// Forward a `roots/list` request to connected clients.
    ///
    /// In v1, this sends the roots request as a notification over SSE.
    pub fn forward_roots_list(&self, session_id: &str) -> bool {
        let data = json!({
            "jsonrpc": "2.0",
            "method": "roots/list"
        });

        let notification = TaggedNotification {
            source: "gateway".to_string(),
            event_type: "proxy_request".to_string(),
            data,
            event_id: Some(self.multiplexer.next_event_id()),
        };

        let sent = self.multiplexer.send_to_session(session_id, notification);
        if sent {
            debug!(session_id = %session_id, "Forwarded roots/list to client");
        } else {
            warn!(session_id = %session_id, "Failed to forward roots/list");
        }
        sent
    }

    /// Broadcast `notifications/roots/list_changed` to all backends
    /// when the client reports a roots change.
    pub fn broadcast_roots_changed(&self) {
        let notification = TaggedNotification {
            source: "client".to_string(),
            event_type: "notification".to_string(),
            data: json!({
                "jsonrpc": "2.0",
                "method": "notifications/roots/list_changed"
            }),
            event_id: Some(self.multiplexer.next_event_id()),
        };

        self.multiplexer.broadcast(notification);
        debug!("Broadcast roots/list_changed to all sessions");
    }

    /// Update the cached roots (e.g., from a client's roots/list response).
    pub fn update_cached_roots(&self, roots: Vec<Root>) {
        debug!(count = roots.len(), "Updated cached roots");
        *self.cached_roots.write() = roots;
    }

    /// Get the currently cached roots.
    #[must_use]
    pub fn cached_roots(&self) -> Vec<Root> {
        self.cached_roots.read().clone()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::BackendRegistry;
    use crate::config::StreamingConfig;
    use crate::protocol::{Content, ModelHint, ModelPreferences, SamplingMessage, ToolChoice};

    fn make_multiplexer() -> Arc<NotificationMultiplexer> {
        let backends = Arc::new(BackendRegistry::new());
        let config = StreamingConfig::default();
        Arc::new(NotificationMultiplexer::new(backends, config))
    }

    // ── ProxyManager construction ──────────────────────────────────────

    #[test]
    fn proxy_manager_initializes_with_empty_roots() {
        let mux = make_multiplexer();
        let proxy = ProxyManager::new(mux);
        assert!(proxy.cached_roots().is_empty());
    }

    // ── Roots caching ──────────────────────────────────────────────────

    #[test]
    fn update_and_retrieve_cached_roots() {
        let mux = make_multiplexer();
        let proxy = ProxyManager::new(mux);

        let roots = vec![
            Root {
                uri: "file:///home/user/project".to_string(),
                name: Some("project".to_string()),
            },
            Root {
                uri: "file:///tmp".to_string(),
                name: None,
            },
        ];

        proxy.update_cached_roots(roots.clone());
        let cached = proxy.cached_roots();
        assert_eq!(cached.len(), 2);
        assert_eq!(cached[0].uri, "file:///home/user/project");
        assert_eq!(cached[0].name.as_deref(), Some("project"));
        assert_eq!(cached[1].uri, "file:///tmp");
        assert!(cached[1].name.is_none());
    }

    #[test]
    fn update_cached_roots_replaces_previous() {
        let mux = make_multiplexer();
        let proxy = ProxyManager::new(mux);

        proxy.update_cached_roots(vec![Root {
            uri: "file:///old".to_string(),
            name: None,
        }]);
        assert_eq!(proxy.cached_roots().len(), 1);

        proxy.update_cached_roots(vec![
            Root {
                uri: "file:///new1".to_string(),
                name: None,
            },
            Root {
                uri: "file:///new2".to_string(),
                name: None,
            },
        ]);
        assert_eq!(proxy.cached_roots().len(), 2);
        assert_eq!(proxy.cached_roots()[0].uri, "file:///new1");
    }

    // ── Elicitation forwarding ─────────────────────────────────────────

    #[test]
    fn forward_elicitation_to_nonexistent_session_returns_false() {
        let mux = make_multiplexer();
        let proxy = ProxyManager::new(mux);

        let params = ElicitationCreateParams {
            message: "Please provide your API key".to_string(),
            requested_schema: Some(json!({
                "type": "object",
                "properties": {
                    "api_key": { "type": "string" }
                }
            })),
        };

        assert!(!proxy.forward_elicitation("nonexistent-session", &params));
    }

    #[tokio::test]
    async fn forward_elicitation_to_existing_session() {
        let mux = make_multiplexer();
        let (session_id, mut rx) = mux.get_or_create_session(Some("elicit-test"));
        let proxy = ProxyManager::new(Arc::clone(&mux));

        let params = ElicitationCreateParams {
            message: "Enter name".to_string(),
            requested_schema: None,
        };

        assert!(proxy.forward_elicitation(&session_id, &params));

        let received = rx.recv().await.unwrap();
        assert_eq!(received.event_type, "proxy_request");
        assert_eq!(received.data["method"], "elicitation/create");
        assert_eq!(received.data["params"]["message"], "Enter name");
    }

    // ── Sampling forwarding ────────────────────────────────────────────

    #[test]
    fn forward_sampling_to_nonexistent_session_returns_false() {
        let mux = make_multiplexer();
        let proxy = ProxyManager::new(mux);

        let params = SamplingCreateMessageParams {
            messages: vec![SamplingMessage {
                role: "user".to_string(),
                content: Content::Text {
                    text: "Hello".to_string(),
                    annotations: None,
                },
            }],
            tools: None,
            tool_choice: None,
            model_preferences: None,
            system_prompt: None,
            max_tokens: 100,
        };

        assert!(!proxy.forward_sampling("nonexistent-session", &params));
    }

    #[tokio::test]
    async fn forward_sampling_to_existing_session() {
        let mux = make_multiplexer();
        let (session_id, mut rx) = mux.get_or_create_session(Some("sample-test"));
        let proxy = ProxyManager::new(Arc::clone(&mux));

        let params = SamplingCreateMessageParams {
            messages: vec![SamplingMessage {
                role: "user".to_string(),
                content: Content::Text {
                    text: "Summarize this".to_string(),
                    annotations: None,
                },
            }],
            tools: None,
            tool_choice: Some(ToolChoice::Auto),
            model_preferences: Some(ModelPreferences {
                hints: vec![ModelHint {
                    name: "claude-3-opus".to_string(),
                }],
                cost_priority: Some(0.3),
                speed_priority: Some(0.5),
                intelligence_priority: Some(0.8),
            }),
            system_prompt: Some("You are a helpful assistant.".to_string()),
            max_tokens: 1024,
        };

        assert!(proxy.forward_sampling(&session_id, &params));

        let received = rx.recv().await.unwrap();
        assert_eq!(received.event_type, "proxy_request");
        assert_eq!(received.data["method"], "sampling/createMessage");
        assert_eq!(received.data["params"]["maxTokens"], 1024);
    }

    // ── Roots forwarding ───────────────────────────────────────────────

    #[test]
    fn forward_roots_list_to_nonexistent_session_returns_false() {
        let mux = make_multiplexer();
        let proxy = ProxyManager::new(mux);
        assert!(!proxy.forward_roots_list("nonexistent-session"));
    }

    #[tokio::test]
    async fn forward_roots_list_to_existing_session() {
        let mux = make_multiplexer();
        let (session_id, mut rx) = mux.get_or_create_session(Some("roots-test"));
        let proxy = ProxyManager::new(Arc::clone(&mux));

        assert!(proxy.forward_roots_list(&session_id));

        let received = rx.recv().await.unwrap();
        assert_eq!(received.event_type, "proxy_request");
        assert_eq!(received.data["method"], "roots/list");
    }

    // ── Roots changed broadcast ────────────────────────────────────────

    #[tokio::test]
    async fn broadcast_roots_changed_reaches_all_sessions() {
        let mux = make_multiplexer();
        let (_id1, mut rx1) = mux.get_or_create_session(Some("session-a"));
        let (_id2, mut rx2) = mux.get_or_create_session(Some("session-b"));
        let proxy = ProxyManager::new(Arc::clone(&mux));

        proxy.broadcast_roots_changed();

        let r1 = rx1.recv().await.unwrap();
        let r2 = rx2.recv().await.unwrap();
        assert_eq!(r1.data["method"], "notifications/roots/list_changed");
        assert_eq!(r2.data["method"], "notifications/roots/list_changed");
    }
}
