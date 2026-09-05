// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
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
//! These requests are forwarded over the existing SSE stream to connected
//! clients. For bidirectional methods such as `sampling/createMessage` and
//! `elicitation/create`, the gateway also tracks in-flight request IDs so the
//! client's POST-back response can be matched to the originating backend call.
//! Fire-and-forget helpers still exist for one-way notification-style flows.

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
    /// In-flight `sampling/createMessage` / `elicitation/create` requests.
    ///
    /// Key: generated request ID (e.g. `"sampling-<uuid>"`).
    /// Value: the originating session plus the oneshot that delivers its reply.
    /// The session is part of the keying so a second client that guesses or
    /// observes the request id cannot win the race (MIK-7251 / MIK.SAMPLE.2).
    pending_sampling: RwLock<HashMap<String, PendingSample>>,
}

/// A waiting sampling/elicitation call, bound to the session that was prompted.
struct PendingSample {
    session_id: String,
    tx: oneshot::Sender<Value>,
}

/// Removes a pending entry when the request future ends, however it ends.
///
/// [`ProxyManager::resolve_pending`] clears the entry on the answered path and
/// the timeout arm clears its own, but neither runs when an OUTER timeout or a
/// task abort drops the in-flight future first. The entry would then outlive
/// the caller waiting on it for the proxy's lifetime. Dropping the guard is the
/// one cleanup that happens on every exit, so it covers cancellation; where a
/// path has already removed the entry the removal is a harmless no-op.
///
/// The transport layer solves the same problem the same way — see
/// `PendingRequestGuard` in `src/transport/mod.rs`. That guard is typed to the
/// transports' `DashMap` of response senders, so it cannot be reused here.
struct PendingSampleGuard<'a> {
    proxy: &'a ProxyManager,
    id: &'a str,
}

impl Drop for PendingSampleGuard<'_> {
    fn drop(&mut self) {
        self.proxy.cancel_pending(self.id);
    }
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
    /// Stores the sender side internally, bound to `session_id`. The caller
    /// awaits the returned receiver; only a POST-back from that same session
    /// may complete it via [`Self::resolve_pending`].
    pub fn register_pending(
        &self,
        id: String,
        session_id: impl Into<String>,
    ) -> oneshot::Receiver<Value> {
        let (tx, rx) = oneshot::channel();
        self.pending_sampling.write().insert(
            id,
            PendingSample {
                session_id: session_id.into(),
                tx,
            },
        );
        rx
    }

    /// Deliver a client response to the caller waiting on `id`.
    ///
    /// Returns `true` if the ID was found, `session_id` matches the session
    /// that was prompted, and the response was dispatched. Returns `false`
    /// without consuming the pending entry when the session does not match
    /// (another client answering is refused, not raced) or when no caller is
    /// waiting (already timed out or unknown).
    pub fn resolve_pending(&self, id: &str, session_id: &str, response: Value) -> bool {
        let mut pending = self.pending_sampling.write();
        match pending.get(id) {
            None => false,
            Some(entry) if entry.session_id != session_id => {
                warn!(
                    %id,
                    attempted_session = %session_id,
                    owner_session = %entry.session_id,
                    "Refused sampling/elicitation POST-back from a session that was not prompted"
                );
                false
            }
            Some(_) => {
                let entry = pending.remove(id).expect("entry present");
                // If the receiver has already been dropped (timeout), send fails silently.
                let _ = entry.tx.send(response);
                true
            }
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
    /// 3. Sends the request to `session_id` alone.
    /// 4. Awaits that session's POST-back response, subject to `timeout`.
    /// 5. Returns the response on success, or a [`SamplingError`] on failure.
    ///
    /// Only the originating session is prompted, so no other client can see or
    /// answer a prompt addressed to it.
    ///
    /// # Errors
    ///
    /// - [`SamplingError::NoSession`] if `session_id` has no live stream.
    /// - [`SamplingError::Timeout`] if no client responds within `timeout`.
    /// - [`SamplingError::Cancelled`] if the oneshot channel is dropped unexpectedly.
    pub async fn forward_sampling_with_response(
        &self,
        session_id: &str,
        params: &SamplingCreateMessageParams,
        timeout: Duration,
    ) -> Result<Value, SamplingError> {
        let id = format!("sampling-{}", Uuid::new_v4());

        let rx = self.register_pending(id.clone(), session_id);
        // Declared after `id` so it drops first, and held across the await
        // below: an outer timeout or a task abort drops this future without
        // running any arm of the match, and the guard is the cleanup that
        // still runs. The explicit removals below stay — each sits on a path
        // that reports something too, and a second removal is a no-op.
        let _cleanup = PendingSampleGuard {
            proxy: self,
            id: &id,
        };

        let data = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "sampling/createMessage",
            "params": serde_json::to_value(params).unwrap_or(json!({}))
        });

        let notification = TaggedNotification {
            source: "gateway".to_string(),
            event_type: "message".to_string(), // MCP-standard: raw JSON-RPC for compliant clients
            data,
            event_id: Some(self.multiplexer.next_event_id()),
        };

        // To the originating session only. Broadcasting let any connected client
        // see another's prompt and answer on their behalf — including the
        // destructive-action confirmation, which made that gate a lottery
        // rather than a control on a gateway with more than one client.
        if !self.multiplexer.send_to_session(session_id, notification) {
            // The entry was registered before the send; an undeliverable
            // prompt has no responder, so nothing would ever remove it.
            self.cancel_pending(&id);
            return Err(SamplingError::NoSession);
        }
        debug!(%id, %session_id, "Sent sampling/createMessage to the originating session");

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(response)) => {
                debug!(%id, "Received sampling response from client");
                Ok(response)
            }
            Ok(Err(_recv_err)) => {
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
    // Elicitation request-response flow
    // ========================================================================

    /// Forward an `elicitation/create` request and wait for the client response.
    ///
    /// Same session-targeted pattern as [`Self::forward_sampling_with_response`].
    pub async fn forward_elicitation_with_response(
        &self,
        session_id: &str,
        params: &ElicitationCreateParams,
        timeout: Duration,
    ) -> Result<Value, SamplingError> {
        let id = format!("elicitation-{}", Uuid::new_v4());

        let rx = self.register_pending(id.clone(), session_id);
        // Declared after `id` so it drops first, and held across the await
        // below: an outer timeout or a task abort drops this future without
        // running any arm of the match, and the guard is the cleanup that
        // still runs. The explicit removals below stay — each sits on a path
        // that reports something too, and a second removal is a no-op.
        let _cleanup = PendingSampleGuard {
            proxy: self,
            id: &id,
        };

        let data = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "elicitation/create",
            "params": serde_json::to_value(params).unwrap_or(json!({}))
        });

        let notification = TaggedNotification {
            source: "gateway".to_string(),
            event_type: "message".to_string(), // MCP-standard: raw JSON-RPC for compliant clients
            data,
            event_id: Some(self.multiplexer.next_event_id()),
        };

        // To the originating session only, for the same reason as sampling: a
        // confirmation another client can answer is not a confirmation.
        if !self.multiplexer.send_to_session(session_id, notification) {
            // Same reason as sampling: registered before the send, and an
            // undeliverable prompt never reaches a responder that clears it.
            self.cancel_pending(&id);
            return Err(SamplingError::NoSession);
        }
        debug!(%id, %session_id, "Sent elicitation/create to the originating session");

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(response)) => {
                debug!(%id, "Received elicitation response from client");
                Ok(response)
            }
            Ok(Err(_recv_err)) => {
                self.cancel_pending(&id);
                Err(SamplingError::Cancelled)
            }
            Err(_timeout) => {
                self.cancel_pending(&id);
                warn!(%id, timeout = ?timeout, "Elicitation request timed out");
                Err(SamplingError::Timeout(timeout))
            }
        }
    }

    // ========================================================================
    // Elicitation proxying (fire-and-forget, kept for backward compat)
    // ========================================================================

    /// Forward an `elicitation/create` request to connected clients (fire-and-forget).
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

    /// Broadcast `notifications/tools/list_changed` to all connected clients.
    ///
    /// Call this whenever the effective tool list may have changed — e.g. on
    /// config reload, backend connect/disconnect, or surfaced-tool cache warm.
    /// Follows the same pattern as [`Self::broadcast_roots_changed`].
    pub fn broadcast_tools_list_changed(&self) {
        let notification = TaggedNotification {
            source: "gateway".to_string(),
            event_type: "notification".to_string(),
            data: json!({
                "jsonrpc": "2.0",
                "method": "notifications/tools/list_changed"
            }),
            event_id: Some(self.multiplexer.next_event_id()),
        };

        self.multiplexer.broadcast(notification);
        debug!("Broadcast notifications/tools/list_changed to all sessions");
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
        let rx = proxy.register_pending("sampling-abc".to_string(), "session-a");
        let response = json!({"result": "done"});
        let resolved = proxy.resolve_pending("sampling-abc", "session-a", response.clone());

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
        let resolved = proxy.resolve_pending("sampling-unknown", "session-a", json!({}));

        // THEN: returns false — no waiting caller
        assert!(!resolved);
    }

    #[test]
    fn cancel_pending_removes_entry() {
        // GIVEN: a registered pending request
        let mux = make_multiplexer();
        let proxy = ProxyManager::new(mux);
        let _rx = proxy.register_pending("sampling-xyz".to_string(), "session-a");

        // WHEN: we cancel it
        proxy.cancel_pending("sampling-xyz");

        // THEN: resolving after cancellation returns false (entry gone)
        let resolved = proxy.resolve_pending("sampling-xyz", "session-a", json!({}));
        assert!(!resolved);
    }

    #[tokio::test]
    async fn resolve_pending_with_dropped_receiver_does_not_panic() {
        // GIVEN: a pending request where the receiver has been dropped
        let mux = make_multiplexer();
        let proxy = ProxyManager::new(mux);
        let rx = proxy.register_pending("sampling-dropped".to_string(), "session-a");
        drop(rx); // simulate timeout dropping the receiver

        // WHEN: the client posts back a response
        let resolved = proxy.resolve_pending("sampling-dropped", "session-a", json!({"ok": true}));

        // THEN: returns true (entry existed) but send fails silently — no panic
        assert!(resolved);
    }

    #[tokio::test]
    async fn resolve_pending_from_other_session_is_refused_and_does_not_race() {
        let mux = make_multiplexer();
        let proxy = ProxyManager::new(mux);

        let rx = proxy.register_pending("sampling-owned".to_string(), "session-a");
        let interloper = json!({"result": "hijack"});
        assert!(
            !proxy.resolve_pending("sampling-owned", "session-b", interloper),
            "a POST-back from a session that was not prompted must be refused"
        );

        let genuine = json!({"result": "from-owner"});
        assert!(
            proxy.resolve_pending("sampling-owned", "session-a", genuine.clone()),
            "the originating session must still be able to answer after a refused interloper"
        );
        let received = rx.await.expect("owner reply must still be delivered");
        assert_eq!(received, genuine);
    }

    #[tokio::test]
    async fn sampling_request_reaches_only_the_originating_session() {
        let mux = make_multiplexer();
        let (session_a, mut rx_a) = mux.get_or_create_session(Some("sess-a"));
        let (_session_b, mut rx_b) = mux.get_or_create_session(Some("sess-b"));
        let proxy = Arc::new(ProxyManager::new(Arc::clone(&mux)));

        let params = SamplingCreateMessageParams {
            messages: vec![SamplingMessage {
                role: "user".to_string(),
                content: Content::Text {
                    text: "secret prompt".to_string(),
                    annotations: None,
                },
            }],
            tools: None,
            tool_choice: None,
            model_preferences: None,
            system_prompt: None,
            max_tokens: 16,
        };

        let proxy_for_task = Arc::clone(&proxy);
        let origin = session_a.clone();
        let wait = tokio::spawn(async move {
            proxy_for_task
                .forward_sampling_with_response(&origin, &params, Duration::from_secs(2))
                .await
        });

        let delivered = tokio::time::timeout(Duration::from_millis(500), rx_a.recv())
            .await
            .expect("originating session must receive the sampling request")
            .expect("channel open");
        assert_eq!(delivered.data["method"], "sampling/createMessage");
        assert_eq!(
            delivered.data["params"]["messages"][0]["content"]["text"],
            "secret prompt"
        );

        assert!(
            rx_b.try_recv().is_err(),
            "the other session must see nothing of the prompt"
        );

        let request_id = delivered.data["id"]
            .as_str()
            .expect("sampling request carries an id")
            .to_string();
        assert!(proxy.resolve_pending(
            &request_id,
            &session_a,
            json!({"result": {"role": "assistant", "content": {"type": "text", "text": "ok"}}})
        ));
        wait.await
            .expect("forward task join")
            .expect("originating session answered");
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
            mode: None,
            message: "Please provide your API key".to_string(),
            requested_schema: Some(json!({
                "type": "object",
                "properties": {
                    "api_key": { "type": "string" }
                }
            })),
            url: None,
        };

        assert!(!proxy.forward_elicitation("nonexistent-session", &params));
    }

    #[tokio::test]
    async fn forward_elicitation_to_existing_session() {
        let mux = make_multiplexer();
        let (session_id, mut rx) = mux.get_or_create_session(Some("elicit-test"));
        let proxy = ProxyManager::new(Arc::clone(&mux));

        let params = ElicitationCreateParams {
            mode: None,
            message: "Enter name".to_string(),
            requested_schema: None,
            url: None,
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

    // ── T2.8: tools/list_changed broadcast ────────────────────────────

    #[tokio::test]
    async fn broadcast_tools_list_changed_reaches_all_sessions() {
        // GIVEN: two connected sessions
        let mux = make_multiplexer();
        let (_id1, mut rx1) = mux.get_or_create_session(Some("tools-session-a"));
        let (_id2, mut rx2) = mux.get_or_create_session(Some("tools-session-b"));
        let proxy = ProxyManager::new(Arc::clone(&mux));

        // WHEN: broadcasting tools/list_changed
        proxy.broadcast_tools_list_changed();

        // THEN: both sessions receive the correct MCP notification
        let r1 = rx1.recv().await.unwrap();
        let r2 = rx2.recv().await.unwrap();
        assert_eq!(r1.data["method"], "notifications/tools/list_changed");
        assert_eq!(r2.data["method"], "notifications/tools/list_changed");
    }

    #[tokio::test]
    async fn broadcast_tools_list_changed_uses_notification_event_type() {
        // GIVEN: one session
        let mux = make_multiplexer();
        let (_id, mut rx) = mux.get_or_create_session(Some("tools-session-c"));
        let proxy = ProxyManager::new(Arc::clone(&mux));

        // WHEN: broadcasting
        proxy.broadcast_tools_list_changed();

        // THEN: event_type is "notification" (same as roots_changed)
        let received = rx.recv().await.unwrap();
        assert_eq!(received.event_type, "notification");
        assert_eq!(received.source, "gateway");
    }

    #[tokio::test]
    async fn broadcast_tools_list_changed_no_op_when_no_sessions() {
        // GIVEN: no connected sessions
        let mux = make_multiplexer();
        let proxy = ProxyManager::new(Arc::clone(&mux));

        // WHEN / THEN: no panic
        proxy.broadcast_tools_list_changed();
    }

    // ── Undeliverable prompts must not leak their pending entry ────────

    #[tokio::test]
    async fn undeliverable_sampling_leaves_no_pending_entry() {
        // GIVEN: a proxy with no connected sessions
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

        // WHEN: delivery to a session that does not exist fails
        let result = proxy
            .forward_sampling_with_response("absent", &params, Duration::from_millis(50))
            .await;

        // THEN: the caller sees NoSession and nothing is left allocated
        assert!(matches!(result, Err(SamplingError::NoSession)));
        assert_eq!(
            proxy.pending_sampling.read().len(),
            0,
            "an undeliverable prompt must not leave a pending entry behind"
        );
    }

    #[tokio::test]
    async fn undeliverable_elicitation_leaves_no_pending_entry() {
        // GIVEN: a proxy with no connected sessions
        let mux = make_multiplexer();
        let proxy = ProxyManager::new(mux);
        let params = ElicitationCreateParams {
            mode: None,
            message: "Confirm?".to_string(),
            requested_schema: Some(json!({"type": "object"})),
            url: None,
        };

        // WHEN: delivery to a session that does not exist fails
        let result = proxy
            .forward_elicitation_with_response("absent", &params, Duration::from_millis(50))
            .await;

        // THEN: the caller sees NoSession and nothing is left allocated
        assert!(matches!(result, Err(SamplingError::NoSession)));
        assert_eq!(
            proxy.pending_sampling.read().len(),
            0,
            "an undeliverable prompt must not leave a pending entry behind"
        );
    }

    /// MIK-7212.WIRE.11 — dropping an in-flight sampling call must not strand
    /// its `pending_sampling` entry.
    ///
    /// This is the HTTP mirror of the stdio contract already pinned by
    /// `cancelled_request_does_not_strand_pending_entry` in
    /// `src/transport/stdio.rs`: an outer `tokio::time::timeout` or a task
    /// abort drops the request future BEFORE the proxy's own timeout arm
    /// runs, so neither `resolve_pending` nor the timeout branch removes the
    /// entry. Only RAII cleanup on drop can. Without it every cancelled
    /// sampling call leaks a `PendingSample` for the proxy's lifetime, which
    /// is the leak MIK-7388.BRIDGE.2 requires the bridged client channel not
    /// to have.
    ///
    /// The live session is what makes the drop happen mid-await: delivery
    /// must succeed (an undeliverable prompt is already cleaned up on the
    /// `NoSession` path) and the session must never answer.
    #[tokio::test]
    async fn mik_7212_wire_11_cancelled_sampling_does_not_strand_pending_entry() {
        // GIVEN: a live session that will receive the prompt and never answer
        let mux = make_multiplexer();
        let (session, mut rx_session) = mux.get_or_create_session(Some("sess-cancel"));
        let proxy = Arc::new(ProxyManager::new(Arc::clone(&mux)));
        let params = SamplingCreateMessageParams {
            messages: vec![SamplingMessage {
                role: "user".to_string(),
                content: Content::Text {
                    text: "never answered".to_string(),
                    annotations: None,
                },
            }],
            tools: None,
            tool_choice: None,
            model_preferences: None,
            system_prompt: None,
            max_tokens: 16,
        };

        // The timeout is far beyond the abort below, so the proxy's own
        // timeout arm cannot be what cleans up — the drop must be.
        let proxy_for_task = Arc::clone(&proxy);
        let origin = session.clone();
        let wait = tokio::spawn(async move {
            proxy_for_task
                .forward_sampling_with_response(&origin, &params, Duration::from_secs(30))
                .await
        });

        // Receiving the prompt proves the entry is registered and the send
        // succeeded: the call is now parked on the response receiver.
        let delivered = tokio::time::timeout(Duration::from_millis(500), rx_session.recv())
            .await
            .expect("originating session must receive the sampling request")
            .expect("channel open");
        assert_eq!(delivered.data["method"], "sampling/createMessage");
        assert_eq!(
            proxy.pending_sampling.read().len(),
            1,
            "precondition: the in-flight call holds exactly one pending entry"
        );

        // WHEN: the call is cancelled mid-await. Joining the aborted handle
        // is what makes this deterministic — `abort()` only requests
        // cancellation, and the future is not dropped until the task is
        // reaped, so asserting before the join races the runtime.
        wait.abort();
        let _ = wait.await;

        // THEN: nothing is left allocated for a caller that no longer exists
        assert_eq!(
            proxy.pending_sampling.read().len(),
            0,
            "a cancelled in-flight sampling call must not strand its pending entry"
        );
    }
}
