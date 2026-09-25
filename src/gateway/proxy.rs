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

use super::input_bridge::{ClientChannel, DeliveryError};
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
        // Held across the await: on an outer timeout or a task abort no arm
        // of the match below runs, and dropping this guard is the only
        // cleanup left. See `PendingSampleGuard`.
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
        // Held across the await: on an outer timeout or a task abort no arm
        // of the match below runs, and dropping this guard is the only
        // cleanup left. See `PendingSampleGuard`.
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

    /// Forward a `roots/list` request and wait for the client's own reply.
    ///
    /// Registers in the SAME pending map as
    /// [`Self::forward_sampling_with_response`], so `resolve_pending`'s
    /// session-ownership check covers a roots reply too: a second connected
    /// client cannot answer on the prompted session's behalf, and refusing a
    /// forged reply leaves the real one's slot intact.
    ///
    /// The id minted here goes on the wire and is what the client must echo
    /// back. Roots has no fire-and-forget forward: a `roots/list` frame with
    /// no id is a notification a conforming client need not answer, and no
    /// answer to it could ever be routed back.
    pub async fn forward_roots_list_with_response(
        &self,
        session_id: &str,
        timeout: Duration,
    ) -> Result<Value, SamplingError> {
        let id = format!("roots-{}", Uuid::new_v4());

        let rx = self.register_pending(id.clone(), session_id);
        // Held across the await: on an outer timeout or a task abort no arm of
        // the match below runs, and dropping this guard is the only cleanup
        // left. See `PendingSampleGuard`.
        let _cleanup = PendingSampleGuard {
            proxy: self,
            id: &id,
        };

        let notification = TaggedNotification {
            source: "gateway".to_string(),
            event_type: "message".to_string(),
            data: json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "roots/list"
            }),
            event_id: Some(self.multiplexer.next_event_id()),
        };

        if !self.multiplexer.send_to_session(session_id, notification) {
            // Registered before the send; an undeliverable request has no
            // responder, so nothing would ever remove the entry.
            self.cancel_pending(&id);
            return Err(SamplingError::NoSession);
        }
        debug!(%id, %session_id, "Sent roots/list to the originating session");

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_recv_err)) => {
                self.cancel_pending(&id);
                Err(SamplingError::Cancelled)
            }
            Err(_timeout) => {
                self.cancel_pending(&id);
                warn!(%id, timeout = ?timeout, "roots/list request timed out");
                Err(SamplingError::Timeout(timeout))
            }
        }
    }

    /// Tell the sessions whose caller may access `backend` that its tools changed.
    ///
    /// The frame has no content, but its timing still tells a caller that an
    /// operator edited a backend it cannot use, so out-of-scope sessions are
    /// skipped. Scope is re-checked per session at delivery.
    pub async fn broadcast_tools_list_changed(&self, backend: &str) {
        let notification = TaggedNotification {
            source: "gateway".to_string(),
            event_type: "notification".to_string(),
            data: json!({
                "jsonrpc": "2.0",
                "method": "notifications/tools/list_changed"
            }),
            event_id: Some(self.multiplexer.next_event_id()),
        };

        let reached = self
            .multiplexer
            .broadcast_to_backend(&notification, backend)
            .await;
        debug!(backend, reached, "Sent notifications/tools/list_changed");
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

/// The gateway's own client connection, as the input bridge's channel.
///
/// The bridge owns both the id and the deadline: `id` is its pending id
/// (`input_bridge.rs:63`), and every call already runs inside its outer
/// `tokio::time::timeout` (`input_bridge.rs:451`), so this adds neither. What
/// it must add is the trait's cancellation contract, and it meets it with the
/// same [`PendingSampleGuard`] the three `forward_*_with_response` methods
/// hold: when that outer timeout drops this future part-way, no arm below
/// runs, and dropping the guard is the only cleanup left.
///
/// Reusing `ProxyManager` rather than standing up a second channel keeps one
/// pending map. A separate one would have to be reconciled with the POST-back
/// path in `router/handlers.rs:754`, which resolves against this one.
#[async_trait::async_trait]
impl ClientChannel for ProxyManager {
    async fn send_request(
        &self,
        session_id: &str,
        id: &str,
        method: &str,
        params: Option<Value>,
    ) -> Result<Value, DeliveryError> {
        let rx = self.register_pending(id.to_string(), session_id);
        // Held across the await, for the reason on `PendingSampleGuard`.
        let _cleanup = PendingSampleGuard { proxy: self, id };

        let mut data = json!({ "jsonrpc": "2.0", "id": id, "method": method });
        // Absent params stays absent: an empty object is a params member the
        // bridge did not send, and the client cannot tell the two apart.
        if let Some(params) = params {
            data["params"] = params;
        }

        let notification = TaggedNotification {
            source: "gateway".to_string(),
            event_type: "message".to_string(),
            data,
            event_id: Some(self.multiplexer.next_event_id()),
        };

        // To the originating session only, for the same reason as sampling and
        // elicitation: a prompt another client can answer is not a prompt.
        if !self.multiplexer.send_to_session(session_id, notification) {
            return Err(DeliveryError::NoSession);
        }
        debug!(%id, %session_id, %method, "Sent bridged request to the originating session");

        // A dropped sender means the entry went away without an answer, which
        // is what the bridge's own timeout arm means by `TimedOut`.
        rx.await.map_err(|_| DeliveryError::TimedOut)
    }
}

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

    // ── T2.8: tools/list_changed broadcast ────────────────────────────
    // Scoped delivery reaches nobody without an authorizer; auth off keeps
    // "every session" the meaning of these rows. Scope rows: proxy_scope_tests.

    fn auth_off_multiplexer() -> Arc<NotificationMultiplexer> {
        let mux = make_multiplexer();
        let config = crate::config::AuthConfig::default();
        mux.set_authorizer(crate::gateway::auth::AuthState {
            auth_config: Arc::new(crate::gateway::auth::ResolvedAuthConfig::from_config(
                &config,
            )),
            key_server: None,
            dashboard_bootstrap: Arc::new(crate::gateway::auth::DashboardBootstrap::new()),
            tls_enabled: false,
        });
        mux
    }

    #[tokio::test]
    async fn broadcast_tools_list_changed_reaches_all_sessions() {
        // GIVEN: two connected sessions
        let mux = auth_off_multiplexer();
        let (_id1, mut rx1) = mux.get_or_create_session(Some("tools-session-a"));
        let (_id2, mut rx2) = mux.get_or_create_session(Some("tools-session-b"));
        let proxy = ProxyManager::new(Arc::clone(&mux));

        // WHEN: broadcasting tools/list_changed
        proxy.broadcast_tools_list_changed("alpha").await;

        // THEN: both sessions receive the correct MCP notification
        let r1 = rx1.recv().await.unwrap();
        let r2 = rx2.recv().await.unwrap();
        assert_eq!(r1.data["method"], "notifications/tools/list_changed");
        assert_eq!(r2.data["method"], "notifications/tools/list_changed");
    }

    #[tokio::test]
    async fn broadcast_tools_list_changed_uses_notification_event_type() {
        // GIVEN: one session
        let mux = auth_off_multiplexer();
        let (_id, mut rx) = mux.get_or_create_session(Some("tools-session-c"));
        let proxy = ProxyManager::new(Arc::clone(&mux));

        // WHEN: broadcasting
        proxy.broadcast_tools_list_changed("alpha").await;

        // THEN: event_type is "notification"
        let received = rx.recv().await.unwrap();
        assert_eq!(received.event_type, "notification");
        assert_eq!(received.source, "gateway");
    }

    #[tokio::test]
    async fn broadcast_tools_list_changed_no_op_when_no_sessions() {
        // GIVEN: no connected sessions
        let mux = auth_off_multiplexer();
        let proxy = ProxyManager::new(Arc::clone(&mux));

        // WHEN / THEN: no panic
        proxy.broadcast_tools_list_changed("alpha").await;
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
    /// A prompt nobody will ever answer, so the call parks on its receiver.
    fn never_answered_sampling_params() -> SamplingCreateMessageParams {
        SamplingCreateMessageParams {
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
        }
    }

    /// The elicitation counterpart of [`never_answered_sampling_params`].
    fn never_answered_elicitation_params() -> ElicitationCreateParams {
        ElicitationCreateParams {
            mode: None,
            message: "never answered".to_string(),
            requested_schema: None,
            url: None,
        }
    }

    #[tokio::test]
    async fn mik_7212_wire_11_cancelled_sampling_does_not_strand_pending_entry() {
        // GIVEN: a live session that will receive the prompt and never answer
        let mux = make_multiplexer();
        let (session, mut rx_session) = mux.get_or_create_session(Some("sess-cancel"));
        let proxy = Arc::new(ProxyManager::new(Arc::clone(&mux)));
        let params = never_answered_sampling_params();

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

    /// MIK-7388.CANCEL.1 — cancelling one bridged exchange reclaims its pending
    /// state and cannot hand its answer to another exchange.
    ///
    /// The sibling above proves the map is drained. Drainage alone does not
    /// settle the criterion: the map is keyed by request id, so what it leaves
    /// open is what a late POST-back for a cancelled id does to the exchange
    /// still parked beside it. Two concurrent prompts on one session are the
    /// smallest arrangement where a mis-keyed delivery is observable — a
    /// resolve that matched on session alone, or one that took the first
    /// waiting entry, would answer the survivor with the cancelled call's
    /// reply and every single-exchange test would still pass.
    #[tokio::test]
    async fn mik_7388_cancel_1_a_cancelled_exchange_cannot_be_answered_into_another() {
        let mux = make_multiplexer();
        let (session, mut rx_session) = mux.get_or_create_session(Some("sess-cross"));
        let proxy = Arc::new(ProxyManager::new(Arc::clone(&mux)));

        // GIVEN: two exchanges in flight on one session, neither of them
        // answered. The proxy timeout is far beyond anything this test does,
        // so no timeout arm can be what cleans up.
        let prompt = |session: &str| {
            let proxy = Arc::clone(&proxy);
            let session = session.to_string();
            tokio::spawn(async move {
                proxy
                    .forward_sampling_with_response(
                        &session,
                        &never_answered_sampling_params(),
                        Duration::from_secs(30),
                    )
                    .await
            })
        };
        // Receiving each prompt proves its entry is registered and the call is
        // parked on its receiver, and yields the id the client would answer.
        macro_rules! next_id {
            () => {{
                let delivered = tokio::time::timeout(Duration::from_millis(500), rx_session.recv())
                    .await
                    .expect("the session must receive the prompt")
                    .expect("channel open");
                assert_eq!(delivered.data["method"], "sampling/createMessage");
                delivered.data["id"]
                    .as_str()
                    .expect("a prompt carries its own id")
                    .to_string()
            }};
        }

        let cancelled = prompt(&session);
        let id_cancelled = next_id!();
        let survivor = prompt(&session);
        let id_survivor = next_id!();
        assert_ne!(id_cancelled, id_survivor, "each prompt must get its own id");
        assert_eq!(
            proxy.pending_sampling.read().len(),
            2,
            "precondition: two in-flight exchanges"
        );

        // WHEN: one is cancelled mid-await and its answer arrives afterwards.
        // Joining the aborted handle is what makes this deterministic: abort()
        // only requests cancellation, and the future is not dropped until the
        // task is reaped.
        cancelled.abort();
        let _ = cancelled.await;
        let late = json!({
            "role": "assistant",
            "content": {"type": "text", "text": "for the cancelled call"},
        });
        let delivered = proxy.resolve_pending(&id_cancelled, &session, late.clone());

        // THEN: the cancelled exchange is gone, and refusing its answer is not
        // done by consuming somebody else's entry.
        assert!(
            !delivered,
            "a cancelled exchange has no caller left to deliver to"
        );
        assert_eq!(
            proxy.pending_sampling.read().len(),
            1,
            "the surviving exchange must still be pending"
        );

        // AND: the survivor answers as itself, with its own reply.
        let own = json!({
            "role": "assistant",
            "content": {"type": "text", "text": "for the surviving call"},
        });
        assert!(
            proxy.resolve_pending(&id_survivor, &session, own.clone()),
            "the surviving exchange must still be answerable"
        );
        let got = tokio::time::timeout(Duration::from_millis(500), survivor)
            .await
            .expect("the surviving call must return")
            .expect("its task must not panic")
            .expect("it must succeed");
        assert_eq!(got, own, "the survivor must receive its own answer");
        assert_ne!(got, late, "and never the cancelled exchange's");
        assert_eq!(
            proxy.pending_sampling.read().len(),
            0,
            "both entries reclaimed"
        );
    }

    /// MIK-7212 WIRE-11 (elicitation): the sibling of the sampling case above.
    ///
    /// `forward_elicitation_with_response` registers in the SAME
    /// `pending_sampling` map, so it strands an entry the same way. Covered by
    /// the same guard, but a guard nobody exercises is a guard nobody has
    /// checked — the elicitation call site is verified here on its own.
    #[tokio::test]
    async fn mik_7212_wire_11_cancelled_elicitation_does_not_strand_pending_entry() {
        let mux = make_multiplexer();
        let (session, mut rx_session) = mux.get_or_create_session(Some("sess-cancel-elicit"));
        let proxy = Arc::new(ProxyManager::new(Arc::clone(&mux)));
        let params = never_answered_elicitation_params();

        let proxy_for_task = Arc::clone(&proxy);
        let origin = session.clone();
        let wait = tokio::spawn(async move {
            proxy_for_task
                .forward_elicitation_with_response(&origin, &params, Duration::from_secs(30))
                .await
        });

        let delivered = tokio::time::timeout(Duration::from_millis(500), rx_session.recv())
            .await
            .expect("originating session must receive the elicitation request")
            .expect("channel open");
        assert_eq!(delivered.data["method"], "elicitation/create");
        assert_eq!(
            proxy.pending_sampling.read().len(),
            1,
            "precondition: the in-flight call holds exactly one pending entry"
        );

        wait.abort();
        let _ = wait.await;

        assert_eq!(
            proxy.pending_sampling.read().len(),
            0,
            "a cancelled in-flight elicitation call must not strand its pending entry"
        );
    }

    /// MIK-7212 WIRE-11 (outer timeout, sampling): a different way to be cancelled.
    ///
    /// The abort tests above cover the task-reaper shape; this is the shape a
    /// real caller hits, wrapping the call in a timeout of its own. Both end at
    /// the same `Drop`, so this is a second CALLER rather than a second
    /// mechanism. The proxy's own timeout is 30s away, so it cannot be what
    /// cleans up here either.
    #[tokio::test]
    async fn mik_7212_wire_11_outer_timeout_on_sampling_does_not_strand_pending_entry() {
        let mux = make_multiplexer();
        let (session, mut rx_session) = mux.get_or_create_session(Some("sess-outer-sampling"));
        let proxy = ProxyManager::new(Arc::clone(&mux));
        let params = never_answered_sampling_params();

        let outcome = tokio::time::timeout(
            Duration::from_millis(50),
            proxy.forward_sampling_with_response(&session, &params, Duration::from_secs(30)),
        )
        .await;
        assert!(
            outcome.is_err(),
            "the outer timeout must fire first; the proxy's own is 30s away"
        );

        // Draining afterwards proves the request really was registered and sent
        // before the outer timeout dropped the future.
        let delivered = rx_session
            .try_recv()
            .expect("the sampling request must have reached the session");
        assert_eq!(delivered.data["method"], "sampling/createMessage");

        assert_eq!(
            proxy.pending_sampling.read().len(),
            0,
            "an externally timed-out sampling call must not strand its pending entry"
        );
    }

    /// MIK-7212 WIRE-11 (outer timeout, elicitation): the fourth corner.
    #[tokio::test]
    async fn mik_7212_wire_11_outer_timeout_on_elicitation_does_not_strand_pending_entry() {
        let mux = make_multiplexer();
        let (session, mut rx_session) = mux.get_or_create_session(Some("sess-outer-elicit"));
        let proxy = ProxyManager::new(Arc::clone(&mux));
        let params = never_answered_elicitation_params();

        let outcome = tokio::time::timeout(
            Duration::from_millis(50),
            proxy.forward_elicitation_with_response(&session, &params, Duration::from_secs(30)),
        )
        .await;
        assert!(
            outcome.is_err(),
            "the outer timeout must fire first; the proxy's own is 30s away"
        );

        let delivered = rx_session
            .try_recv()
            .expect("the elicitation request must have reached the session");
        assert_eq!(delivered.data["method"], "elicitation/create");

        assert_eq!(
            proxy.pending_sampling.read().len(),
            0,
            "an externally timed-out elicitation call must not strand its pending entry"
        );
    }

    /// MIK-7212 WIRE-11 (production `ClientChannel`): the bridge's own send is
    /// held to the same cancellation contract as the proxy's three forwards.
    ///
    /// The bridge wraps every `send_request` in an outer timeout
    /// (`input_bridge.rs:451`) and abandons the future on expiry, so an
    /// implementation that registers a pending entry before awaiting and
    /// releases it only on the success or error path leaks one per expired
    /// prompt. This drives the implementor through the trait, not through
    /// `forward_elicitation_with_response`, because it is the implementor that
    /// chooses whether to hold a guard.
    #[tokio::test]
    async fn mik_7212_wire_11_cancelled_channel_send_does_not_strand_pending_entry() {
        use crate::gateway::input_bridge::ClientChannel;

        let mux = make_multiplexer();
        let (session, mut rx_session) = mux.get_or_create_session(Some("sess-channel-cancel"));
        let proxy = ProxyManager::new(Arc::clone(&mux));
        let channel: &dyn ClientChannel = &proxy;

        let outcome = tokio::time::timeout(
            Duration::from_millis(50),
            channel.send_request(
                &session,
                "elicitation-1",
                "elicitation/create",
                Some(json!({"message": "which one?", "requestedSchema": {"type": "object"}})),
            ),
        )
        .await;
        assert!(
            outcome.is_err(),
            "the outer timeout must fire first; nothing ever answers this prompt"
        );

        let delivered = rx_session
            .try_recv()
            .expect("the request must have reached the session");
        assert_eq!(delivered.data["method"], "elicitation/create");
        assert_eq!(
            delivered.data["id"], "elicitation-1",
            "the bridge's own id must go on the wire, not a freshly minted one"
        );
        // The answer has to be able to come back. `handlers.rs:754` only
        // resolves a POST-back whose id passes this gate, so an id that goes
        // out without it would strand the caller with both halves green.
        assert!(
            crate::gateway::input_bridge::is_bridge_reply_id(
                delivered.data["id"].as_str().expect("the id is a string")
            ),
            "the id on the wire must be one the POST-back path admits"
        );

        assert_eq!(
            proxy.pending_sampling.read().len(),
            0,
            "a cancelled bridge send must not strand its pending entry"
        );
    }

    /// MIK-7212 WIRE-11 (undeliverable): no session to reach is `NoSession`,
    /// and it leaves nothing behind either.
    #[tokio::test]
    async fn mik_7212_wire_11_undeliverable_channel_send_leaves_no_pending_entry() {
        use crate::gateway::input_bridge::{ClientChannel, DeliveryError};

        let mux = make_multiplexer();
        let proxy = ProxyManager::new(Arc::clone(&mux));
        let channel: &dyn ClientChannel = &proxy;

        let err = channel
            .send_request(
                "sess-nobody-home",
                "bridge-elicit-2",
                "elicitation/create",
                None,
            )
            .await
            .expect_err("there is no such session to deliver to");

        assert!(
            matches!(err, DeliveryError::NoSession),
            "an undeliverable prompt is NoSession, not a timeout: {err:?}"
        );
        assert_eq!(
            proxy.pending_sampling.read().len(),
            0,
            "an undeliverable bridge send must not strand its pending entry"
        );
    }

    // ── NFR.CONFORMANCE.1, minor 11 — removed elicitation surface ───────

    /// Minor 11, clause (a) — neither live elicitation forward path can put
    /// `elicitationId` on the wire.
    ///
    /// The 2026-07-28 changelog removes the field from URL-mode elicitation
    /// requests. A 2025-11-25 backend still sends it, and the gateway forwards
    /// elicitation to the connected client on two paths — the fire-and-forget
    /// [`ProxyManager::forward_elicitation`] and the awaited
    /// [`ProxyManager::forward_elicitation_with_response`]. Both are asserted,
    /// because a removal proven on one path and not the other is not a removal.
    ///
    /// **What actually strips it, stated so the test does not overclaim:** the
    /// typed read. Both paths re-serialise from [`ElicitationCreateParams`]
    /// (`protocol::messages`), which names four fields and carries no
    /// `#[serde(flatten)]`, so every key the gateway cannot name is gone by the
    /// time a frame is built. Neither path inspects the client's era. The field
    /// is therefore dropped for a modern client AND for a legacy one, which is
    /// stricter than the changelog requires and is the behaviour this pins. A
    /// future `flatten` added for pass-through fidelity would regain the field
    /// on both, and this test is what would notice.
    ///
    /// The router's own `parse_elicitation_params` (`router/helpers.rs`) is
    /// `pub(super)`; its entire body is the `serde_json::from_value` call made
    /// here, so the typed read under test is the one the handler performs.
    #[tokio::test]
    async fn ac_conformance_minor_11a_elicitation_id_is_dropped_on_both_forward_paths() {
        let raw = json!({
            "mode": "url",
            "message": "Authorise the deploy",
            "url": "https://example.test/authorise",
            "elicitationId": "elicit-2025-11-25-42",
        });
        let params: ElicitationCreateParams =
            serde_json::from_value(raw).expect("a 2025-11-25 URL-mode request still parses");

        let mux = make_multiplexer();
        // Held for the whole test: `send_to_session` reports failure against a
        // session whose receiver has been dropped, and a test that lost its
        // receiver would pass the assertions below on zero delivered frames.
        let (session, mut rx) = mux.get_or_create_session(Some("sess-minor-11a"));
        let proxy = ProxyManager::new(Arc::clone(&mux));

        assert!(
            proxy.forward_elicitation(&session, &params),
            "the fire-and-forget forward must reach the session"
        );

        // Nothing ever answers, so the awaited path is ended by the outer
        // timeout. The frame it sent is already in the receiver by then.
        let _ = tokio::time::timeout(
            Duration::from_millis(50),
            proxy.forward_elicitation_with_response(&session, &params, Duration::from_secs(30)),
        )
        .await;

        let mut seen = 0;
        while let Ok(frame) = rx.try_recv() {
            seen += 1;
            assert_eq!(
                frame.data["method"], "elicitation/create",
                "frame {seen} is not the elicitation request"
            );
            let sent = &frame.data["params"];
            assert!(
                sent.get("elicitationId").is_none(),
                "frame {seen} carried the removed elicitationId field: {sent}"
            );
            // The neighbour assertion: a forward that dropped everything would
            // satisfy the line above and forward no question at all.
            assert_eq!(sent["mode"], "url", "frame {seen} lost the mode");
            assert_eq!(
                sent["url"], "https://example.test/authorise",
                "frame {seen} lost the url"
            );
            assert_eq!(
                sent["message"], "Authorise the deploy",
                "frame {seen} lost the message"
            );
        }
        assert_eq!(seen, 2, "both forward paths must have been exercised");
    }
}
