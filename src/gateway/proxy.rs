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

use crate::gateway::session_id::{SessionId, session_fp};
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
///
/// There is no "first session" accessor: any session is not the caller's
/// session (F9). This compiles:
///
/// ```
/// # use std::sync::Arc;
/// # use mcp_gateway::{backend::BackendRegistry, config::StreamingConfig};
/// # use mcp_gateway::gateway::{proxy::ProxyManager, streaming::NotificationMultiplexer};
/// let m = NotificationMultiplexer::new(Arc::new(BackendRegistry::new()), StreamingConfig::default());
/// let x = ProxyManager::new(Arc::new(m));
/// assert!(x.cached_roots().is_empty());
/// ```
///
/// and this does not:
///
/// ```compile_fail
/// # use std::sync::Arc;
/// # use mcp_gateway::{backend::BackendRegistry, config::StreamingConfig};
/// # use mcp_gateway::gateway::{proxy::ProxyManager, streaming::NotificationMultiplexer};
/// let m = NotificationMultiplexer::new(Arc::new(BackendRegistry::new()), StreamingConfig::default());
/// let x = ProxyManager::new(Arc::new(m));
/// let _ = x.first_session_id();
/// ```
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
    session_id: SessionId,
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
                session_id: SessionId::new(&Into::<String>::into(session_id)),
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
            Some(entry) if entry.session_id.expose_secret() != session_id => {
                warn!(
                    %id,
                    attempted_session = %session_fp(session_id),
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
        let Some(watch) = self
            .multiplexer
            .send_request_to_session(session_id, notification, None)
        else {
            // The entry was registered before the send; an undeliverable
            // prompt has no responder, so nothing would ever remove it.
            self.cancel_pending(&id);
            return Err(SamplingError::NoSession);
        };
        debug!(%id, session_id = %session_fp(session_id), "Sent sampling/createMessage to the originating session");
        self.await_reply(&id, rx, &watch, timeout).await
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
        let Some(watch) = self
            .multiplexer
            .send_request_to_session(session_id, notification, None)
        else {
            // Same reason as sampling: registered before the send, and an
            // undeliverable prompt never reaches a responder that clears it.
            self.cancel_pending(&id);
            return Err(SamplingError::NoSession);
        };
        debug!(%id, session_id = %session_fp(session_id), "Sent elicitation/create to the originating session");
        self.await_reply(&id, rx, &watch, timeout).await
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
            debug!(session_id = %session_fp(session_id), "Forwarded elicitation/create to client");
        } else {
            warn!(session_id = %session_fp(session_id), "Failed to forward elicitation/create");
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
            debug!(session_id = %session_fp(session_id), "Forwarded sampling/createMessage to client");
        } else {
            warn!(session_id = %session_fp(session_id), "Failed to forward sampling/createMessage");
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

        let Some(watch) = self
            .multiplexer
            .send_request_to_session(session_id, notification, None)
        else {
            // Registered before the send; an undeliverable request has no
            // responder, so nothing would ever remove the entry.
            self.cancel_pending(&id);
            return Err(SamplingError::NoSession);
        };
        debug!(%id, session_id = %session_fp(session_id), "Sent roots/list to the originating session");
        self.await_reply(&id, rx, &watch, timeout).await
    }

    /// `id`'s reply, its timeout, or every queued copy withheld at write
    /// (a failed audit record), which ends the wait at once (MIK-7975 WAIT.1).
    async fn await_reply(
        &self,
        id: &str,
        rx: oneshot::Receiver<Value>,
        watch: &crate::gateway::streaming::DeliveryWatch,
        timeout: Duration,
    ) -> Result<Value, SamplingError> {
        let outcome = tokio::select! {
            replied = tokio::time::timeout(timeout, rx) => match replied {
                Ok(Ok(response)) => {
                    debug!(%id, "Received a response from the client");
                    return Ok(response);
                }
                Ok(Err(_recv_err)) => SamplingError::Cancelled,
                Err(_timeout) => {
                    warn!(%id, timeout = ?timeout, "Request to the client timed out");
                    SamplingError::Timeout(timeout)
                }
            },
            () = watch.failed() => {
                warn!(%id, "Request withheld from the client's stream");
                SamplingError::SendFailed
            }
        };
        self.cancel_pending(id);
        Err(outcome)
    }

    /// Tell the sessions whose caller may access `backend` that its tools changed.
    ///
    /// The frame has no content, but its timing still tells a caller that an
    /// operator edited a backend it cannot use, so out-of-scope sessions are
    /// skipped. Scope is re-checked per session at delivery.
    ///
    /// Sent as a `message` event, so the GET stream carries the bare JSON-RPC
    /// notification an MCP client reads, not the gateway's envelope (F24).
    pub async fn broadcast_tools_list_changed(&self, backend: &str) {
        let notification = TaggedNotification {
            source: "gateway".to_string(),
            event_type: "message".to_string(),
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
        self.send_request_committing(session_id, id, method, params, None)
            .await
    }

    async fn send_request_committing(
        &self,
        session_id: &str,
        id: &str,
        method: &str,
        params: Option<Value>,
        commit: Option<crate::gateway::input_bridge::DeliveryCommit>,
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
        // MIK-7887.RECEIPT.3, MIK-7939: the watch commits when a stream of the
        // session writes the prompt past its gates (SSE has no client
        // acknowledgement), not when it is queued; the frame owns the commit,
        // so a written prompt stays committed if the wait below is cancelled.
        let Some(watch) =
            self.multiplexer
                .send_request_to_session(session_id, notification, commit)
        else {
            return Err(DeliveryError::NoSession);
        };
        debug!(%id, session_id = %session_fp(session_id), %method, "Sent bridged request to the originating session");

        // A dropped sender means the entry went away without an answer, which
        // is what the bridge's own timeout arm means by `TimedOut`. Every copy
        // withheld at write means nothing will come back either (MIK-7975
        // WAIT.1); `NoSession` would send the legacy bridge to re-ask round one.
        tokio::select! {
            replied = rx => replied.map_err(|_| DeliveryError::TimedOut),
            () = watch.failed() => Err(DeliveryError::TimedOut),
        }
    }
}

#[cfg(test)]
#[path = "proxy_tests.rs"]
mod tests;
