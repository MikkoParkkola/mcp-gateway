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

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use serde_json::{Value, json};
use thiserror::Error;
use tokio::sync::oneshot;
use tracing::{debug, warn};
use uuid::Uuid;

use crate::protocol::{ElicitationCreateParams, Root, SamplingCreateMessageParams};

use super::streaming::{NotificationMultiplexer, TaggedNotification};

// ============================================================================
// Sampling error types
// ============================================================================

/// Errors that can occur during a `sampling/createMessage` request-response cycle.
#[derive(Debug, Error)]
pub enum SamplingError {
    /// No sampling-capable client is connected.
    #[error("No sampling-capable client connected")]
    NoSession,
    /// The gateway failed to deliver the request to the client over SSE.
    #[error("Failed to send sampling request to client")]
    SendFailed,
    /// The client did not respond within the configured timeout.
    #[error("Sampling request timed out after {0:?}")]
    Timeout(Duration),
    /// The pending request was cancelled before it received a response.
    #[error("Sampling request was cancelled")]
    Cancelled,
}

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
    /// In-flight `sampling/createMessage` requests awaiting client responses.
    ///
    /// Key: generated request ID (e.g. `"sampling-<uuid>"`).
    /// Value: oneshot sender that delivers the client's response body.
    pending_sampling: RwLock<HashMap<String, oneshot::Sender<Value>>>,
}

impl ProxyManager {
    /// Create a new proxy manager.
    #[must_use]
    pub fn new(multiplexer: Arc<NotificationMultiplexer>) -> Self {
        Self {
            multiplexer,
            cached_roots: RwLock::new(Vec::new()),
            pending_sampling: RwLock::new(HashMap::new()),
        }
    }

    // ========================================================================
    // Pending-request map helpers
    // ========================================================================

    /// Register a pending sampling request and return its response receiver.
    ///
    /// Stores the sender side internally; the caller awaits the returned
    /// receiver to obtain the client's response when it arrives via
    /// [`Self::resolve_pending`].
    pub fn register_pending(&self, id: String) -> oneshot::Receiver<Value> {
        let (tx, rx) = oneshot::channel();
        self.pending_sampling.write().insert(id, tx);
        rx
    }

    /// Deliver a client response to the caller waiting on `id`.
    ///
    /// Returns `true` if the ID was found and the response was dispatched,
    /// `false` if no caller is waiting for this ID (already timed out or
    /// unknown).
    pub fn resolve_pending(&self, id: &str, response: Value) -> bool {
        let tx = self.pending_sampling.write().remove(id);
        match tx {
            Some(sender) => {
                // If the receiver has already been dropped (timeout), send fails silently.
                let _ = sender.send(response);
                true
            }
            None => false,
        }
    }

    /// Remove a pending sampling request without delivering a response.
    ///
    /// Called on timeout to clean up the map entry.
    pub fn cancel_pending(&self, id: &str) {
        self.pending_sampling.write().remove(id);
    }

    // ========================================================================
    // Sampling request-response flow
    // ========================================================================

    /// Return the first connected session ID, if any.
    pub fn first_session_id(&self) -> Option<String> {
        self.multiplexer.first_session_id()
    }

    /// Forward a `sampling/createMessage` request and wait for the client response.
    ///
    /// Full bidirectional flow:
    /// 1. Generates a unique request ID.
    /// 2. Registers a pending entry so the response can be correlated.
    /// 3. Sends the request as an SSE event to the named session.
    /// 4. Awaits the client's POST-back response, subject to `timeout`.
    /// 5. Returns the response on success, or a [`SamplingError`] on failure.
    ///
    /// # Errors
    ///
    /// - [`SamplingError::SendFailed`] if the SSE send fails (client disconnected).
    /// - [`SamplingError::Timeout`] if the client does not respond within `timeout`.
    /// - [`SamplingError::Cancelled`] if the oneshot channel is dropped unexpectedly.
    pub async fn forward_sampling_with_response(
        &self,
        session_id: &str,
        params: &SamplingCreateMessageParams,
        timeout: Duration,
    ) -> Result<Value, SamplingError> {
        let id = format!("sampling-{}", Uuid::new_v4());

        let rx = self.register_pending(id.clone());

        let data = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "sampling/createMessage",
            "params": serde_json::to_value(params).unwrap_or(json!({}))
        });

        let notification = TaggedNotification {
            source: "gateway".to_string(),
            event_type: "sampling_request".to_string(),
            data,
            event_id: Some(self.multiplexer.next_event_id()),
        };

        let sent = self.multiplexer.send_to_session(session_id, notification);
        if !sent {
            self.cancel_pending(&id);
            warn!(session_id = %session_id, %id, "Failed to forward sampling/createMessage");
            return Err(SamplingError::SendFailed);
        }

        debug!(session_id = %session_id, %id, "Awaiting sampling response from client");

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(response)) => {
                debug!(%id, "Received sampling response from client");
                Ok(response)
            }
            Ok(Err(_recv_err)) => {
                // Sender was dropped — should not happen in normal operation.
                self.cancel_pending(&id);
                Err(SamplingError::Cancelled)
            }
            Err(_timeout) => {
                self.cancel_pending(&id);
                warn!(%id, timeout = ?timeout, "Sampling request timed out");
                Err(SamplingError::Timeout(timeout))
            }
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

    // ── Pending sampling request map ───────────────────────────────────

    #[tokio::test]
    async fn register_and_resolve_pending_delivers_response() {
        // GIVEN: a fresh proxy manager
        let mux = make_multiplexer();
        let proxy = ProxyManager::new(mux);

        // WHEN: we register a pending request and immediately resolve it
        let rx = proxy.register_pending("sampling-abc".to_string());
        let response = json!({"result": "done"});
        let resolved = proxy.resolve_pending("sampling-abc", response.clone());

        // THEN: resolve returns true and the receiver gets the value
        assert!(resolved);
        let received = rx.await.expect("receiver should not be dropped");
        assert_eq!(received, response);
    }

    #[test]
    fn resolve_pending_unknown_id_returns_false() {
        // GIVEN: a proxy manager with no pending requests
        let mux = make_multiplexer();
        let proxy = ProxyManager::new(mux);

        // WHEN: we try to resolve an ID that was never registered
        let resolved = proxy.resolve_pending("sampling-unknown", json!({}));

        // THEN: returns false — no waiting caller
        assert!(!resolved);
    }

    #[test]
    fn cancel_pending_removes_entry() {
        // GIVEN: a registered pending request
        let mux = make_multiplexer();
        let proxy = ProxyManager::new(mux);
        let _rx = proxy.register_pending("sampling-xyz".to_string());

        // WHEN: we cancel it
        proxy.cancel_pending("sampling-xyz");

        // THEN: resolving after cancellation returns false (entry gone)
        let resolved = proxy.resolve_pending("sampling-xyz", json!({}));
        assert!(!resolved);
    }

    #[tokio::test]
    async fn resolve_pending_with_dropped_receiver_does_not_panic() {
        // GIVEN: a pending request where the receiver has been dropped
        let mux = make_multiplexer();
        let proxy = ProxyManager::new(mux);
        let rx = proxy.register_pending("sampling-dropped".to_string());
        drop(rx); // simulate timeout dropping the receiver

        // WHEN: the client posts back a response
        let resolved = proxy.resolve_pending("sampling-dropped", json!({"ok": true}));

        // THEN: returns true (entry existed) but send fails silently — no panic
        assert!(resolved);
    }

    #[test]
    fn first_session_id_none_when_no_sessions() {
        // GIVEN: a multiplexer with no sessions
        let mux = make_multiplexer();
        let proxy = ProxyManager::new(mux);

        // THEN: first_session_id returns None
        assert!(proxy.first_session_id().is_none());
    }

    #[test]
    fn first_session_id_returns_session_when_connected() {
        // GIVEN: a multiplexer with one session
        let mux = make_multiplexer();
        let (session_id, _rx) = mux.get_or_create_session(Some("my-session"));
        let proxy = ProxyManager::new(mux);

        // THEN: first_session_id returns that session
        assert_eq!(proxy.first_session_id(), Some(session_id));
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
