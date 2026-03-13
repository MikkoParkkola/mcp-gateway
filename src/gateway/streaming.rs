//! Streaming and Notification Multiplexer for MCP Gateway
//!
//! Implements MCP Streamable HTTP spec (2025-03-26):
//! - GET /mcp → SSE stream for server→client notifications
//! - POST /mcp → JSON-RPC requests (may upgrade to SSE for streaming responses)
//! - Session management via Mcp-Session-Id header
//! - Notification multiplexing from multiple backends

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_stream::stream;
use axum::response::sse::{Event, KeepAlive, Sse};
use futures::Stream;
use parking_lot::RwLock;
use serde::Serialize;
use serde_json::{Value, json};
use tokio::sync::broadcast;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::Result;
use crate::backend::BackendRegistry;
use crate::config::StreamingConfig;

/// A tagged notification event from a backend
#[derive(Debug, Clone, Serialize)]
pub struct TaggedNotification {
    /// Source backend name
    pub source: String,
    /// Event type (e.g., "notification", "result", "error")
    pub event_type: String,
    /// The notification data (JSON-RPC notification or result)
    pub data: Value,
    /// Optional event ID for resumability
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
}

/// Client session state
#[derive(Debug)]
struct ClientSession {
    /// Session ID (used in Debug output and potential future features)
    #[allow(dead_code)]
    id: String,
    /// Notification sender
    tx: broadcast::Sender<TaggedNotification>,
    /// Last event ID received (for resumability)
    last_event_id: RwLock<Option<String>>,
    /// Subscribed backends
    subscribed_backends: RwLock<Vec<String>>,
    /// Timestamp of session creation (for TTL-based reaping)
    created_at: Instant,
}

/// Notification Multiplexer
///
/// Routes notifications from multiple streaming backends to connected clients.
/// Implements the server-side of MCP Streamable HTTP.
pub struct NotificationMultiplexer {
    /// Client sessions by session ID
    sessions: RwLock<HashMap<String, Arc<ClientSession>>>,
    /// Backend registry for subscriptions
    backends: Arc<BackendRegistry>,
    /// Configuration
    config: StreamingConfig,
    /// Event ID counter (global, for uniqueness)
    event_counter: std::sync::atomic::AtomicU64,
}

impl NotificationMultiplexer {
    /// Create a new notification multiplexer.
    ///
    /// Spawns a background session-reaper task that periodically removes
    /// sessions older than `config.session_ttl` that have no active receivers,
    /// preventing FD exhaustion from dropped SSE connections.
    #[must_use]
    pub fn new(backends: Arc<BackendRegistry>, config: StreamingConfig) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            backends,
            config,
            event_counter: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// Start the background session-reaper task.
    ///
    /// Must be called once after the multiplexer has been placed in an `Arc`.
    /// All call sites in `server.rs`, `webhooks.rs`, and `proxy.rs` do this
    /// immediately, so the reaper always runs in production.
    pub fn spawn_reaper_on(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        let ttl = self.config.session_ttl;
        let interval = self.config.session_reaper_interval;

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                ticker.tick().await;

                let Some(mux) = weak.upgrade() else {
                    // Multiplexer has been dropped — stop the reaper.
                    break;
                };

                mux.reap_expired_sessions(ttl);
            }
        });
    }

    /// Remove all sessions that are both expired and have no active receivers.
    fn reap_expired_sessions(&self, ttl: Duration) {
        let now = Instant::now();
        let mut sessions = self.sessions.write();

        let before = sessions.len();
        sessions.retain(|id, session| {
            let expired = now.duration_since(session.created_at) >= ttl;
            let abandoned = session.tx.receiver_count() == 0;

            if expired && abandoned {
                info!(session_id = %id, "Reaping expired streaming session (no active receivers)");
                false
            } else {
                true
            }
        });

        let reaped = before.saturating_sub(sessions.len());
        if reaped > 0 {
            info!(
                reaped,
                remaining = sessions.len(),
                "Session reaper completed"
            );
        }
    }

    /// Create or get a session
    pub fn get_or_create_session(
        &self,
        session_id: Option<&str>,
    ) -> (String, broadcast::Receiver<TaggedNotification>) {
        let id = session_id.map_or_else(|| format!("gw-{}", Uuid::new_v4()), String::from);

        let mut sessions = self.sessions.write();

        if let Some(session) = sessions.get(&id) {
            // Existing session - return new receiver
            return (id, session.tx.subscribe());
        }

        // New session
        let (tx, rx) = broadcast::channel(self.config.buffer_size);
        let session = Arc::new(ClientSession {
            id: id.clone(),
            tx,
            last_event_id: RwLock::new(None),
            subscribed_backends: RwLock::new(Vec::new()),
            created_at: Instant::now(),
        });

        sessions.insert(id.clone(), session);
        info!(session_id = %id, "Created new streaming session");

        (id, rx)
    }

    /// Remove a session
    pub fn remove_session(&self, session_id: &str) {
        let mut sessions = self.sessions.write();
        if sessions.remove(session_id).is_some() {
            info!(session_id = %session_id, "Removed streaming session");
        }
    }

    /// Check if a session exists
    pub fn has_session(&self, session_id: &str) -> bool {
        self.sessions.read().contains_key(session_id)
    }

    /// Get session count
    pub fn session_count(&self) -> usize {
        self.sessions.read().len()
    }

    /// Send a notification to a specific session
    pub fn send_to_session(&self, session_id: &str, notification: TaggedNotification) -> bool {
        let sessions = self.sessions.read();
        if let Some(session) = sessions.get(session_id) {
            match session.tx.send(notification) {
                Ok(_) => true,
                Err(e) => {
                    debug!(session_id = %session_id, error = %e, "Failed to send notification");
                    false
                }
            }
        } else {
            false
        }
    }

    /// Broadcast a notification to all sessions
    #[allow(clippy::needless_pass_by_value)] // public API: caller may have owned value
    pub fn broadcast(&self, notification: TaggedNotification) {
        let sessions = self.sessions.read();
        for session in sessions.values() {
            let _ = session.tx.send(notification.clone());
        }
    }

    /// Generate a unique event ID
    pub fn next_event_id(&self) -> String {
        let id = self
            .event_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        format!("evt-{id}")
    }

    /// Subscribe a session to a backend's notifications
    ///
    /// # Errors
    ///
    /// Returns an error if the backend is not found in the registry.
    #[allow(clippy::unused_async)] // async for future streaming implementation
    pub async fn subscribe_backend(&self, session_id: &str, backend_name: &str) -> Result<()> {
        // Verify backend exists
        let _backend = self
            .backends
            .get(backend_name)
            .ok_or_else(|| crate::Error::BackendNotFound(backend_name.to_string()))?;

        // Record subscription
        {
            let sessions = self.sessions.read();
            if let Some(session) = sessions.get(session_id) {
                let mut subs = session.subscribed_backends.write();
                if !subs.contains(&backend_name.to_string()) {
                    subs.push(backend_name.to_string());
                }
            }
        }

        // If backend supports streaming, start forwarding notifications
        // For now, we'll handle this via the invoke path
        debug!(session_id = %session_id, backend = %backend_name, "Subscribed to backend notifications");

        Ok(())
    }

    /// Auto-subscribe a session to configured backends
    pub async fn auto_subscribe(&self, session_id: &str) {
        for backend_name in &self.config.auto_subscribe {
            if let Err(e) = self.subscribe_backend(session_id, backend_name).await {
                warn!(
                    session_id = %session_id,
                    backend = %backend_name,
                    error = %e,
                    "Failed to auto-subscribe to backend"
                );
            }
        }
    }

    /// Return the ID of the first connected session, if any.
    ///
    /// Used by [`super::proxy::ProxyManager`] to locate a client capable of
    /// handling server-to-client requests such as `sampling/createMessage`.
    pub fn first_session_id(&self) -> Option<String> {
        self.sessions.read().keys().next().cloned()
    }
}

/// Create SSE response for GET /mcp
///
/// Takes owned data to satisfy Rust 2024 lifetime capture rules for `impl Stream`.
#[allow(clippy::needless_pass_by_value)] // owned values required for stream lifetime
pub fn create_sse_response(
    multiplexer: Arc<NotificationMultiplexer>,
    session_id: String,
    last_event_id: Option<String>,
    keep_alive_interval: Duration,
) -> Option<Sse<impl Stream<Item = std::result::Result<Event, Infallible>>>> {
    // Access session data
    let sessions = multiplexer.sessions.read();
    let session = sessions.get(&session_id)?;

    // Update last event ID if provided (for resumability)
    if let Some(ref id) = last_event_id {
        *session.last_event_id.write() = Some(id.clone());
    }

    let mut rx = session.tx.subscribe();
    let session_id_owned = session_id;

    // Create the stream with owned data
    let stream = stream! {
        // Send initial connection event
        yield Ok(Event::default()
            .event("connected")
            .data(json!({ "session_id": session_id_owned }).to_string()));

        loop {
            match rx.recv().await {
                Ok(notification) => {
                    // MCP-standard events (event_type == "message") send raw
                    // JSON-RPC as data so compliant clients (e.g. Claude Code)
                    // can parse them as server-to-client requests.
                    let event = if notification.event_type == "message" {
                        Event::default()
                            .event("message")
                            .data(notification.data.to_string())
                    } else {
                        Event::default()
                            .event(&notification.event_type)
                            .data(serde_json::to_string(&notification).unwrap_or_default())
                    };

                    // Add event ID if present
                    let event = if let Some(ref id) = notification.event_id {
                        event.id(id.clone())
                    } else {
                        event
                    };

                    yield Ok(event);
                }
                Err(broadcast::error::RecvError::Closed) => {
                    break;
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    // Client fell behind, notify them
                    yield Ok(Event::default()
                        .event("lagged")
                        .data(json!({ "missed": n }).to_string()));
                }
            }
        }
    };

    Some(Sse::new(stream).keep_alive(KeepAlive::new().interval(keep_alive_interval).text("ping")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_session_creation() {
        let backends = Arc::new(BackendRegistry::new());
        let config = StreamingConfig::default();
        let multiplexer = NotificationMultiplexer::new(backends, config);

        let (session_id, _rx) = multiplexer.get_or_create_session(None);
        assert!(session_id.starts_with("gw-"));
        assert!(multiplexer.has_session(&session_id));
        assert_eq!(multiplexer.session_count(), 1);

        multiplexer.remove_session(&session_id);
        assert!(!multiplexer.has_session(&session_id));
        assert_eq!(multiplexer.session_count(), 0);
    }

    #[tokio::test]
    async fn test_notification_send() {
        let backends = Arc::new(BackendRegistry::new());
        let config = StreamingConfig::default();
        let multiplexer = NotificationMultiplexer::new(backends, config);

        let (session_id, mut rx) = multiplexer.get_or_create_session(Some("test-session"));

        let notification = TaggedNotification {
            source: "test-backend".to_string(),
            event_type: "notification".to_string(),
            data: json!({"message": "hello"}),
            event_id: Some("evt-1".to_string()),
        };

        assert!(multiplexer.send_to_session(&session_id, notification.clone()));

        let received = rx.recv().await.unwrap();
        assert_eq!(received.source, "test-backend");
        assert_eq!(received.event_type, "notification");
    }

    #[tokio::test]
    async fn test_broadcast() {
        let backends = Arc::new(BackendRegistry::new());
        let config = StreamingConfig::default();
        let multiplexer = NotificationMultiplexer::new(backends, config);

        let (_id1, mut rx1) = multiplexer.get_or_create_session(Some("session-1"));
        let (_id2, mut rx2) = multiplexer.get_or_create_session(Some("session-2"));

        let notification = TaggedNotification {
            source: "global".to_string(),
            event_type: "broadcast".to_string(),
            data: json!({"alert": "system"}),
            event_id: None,
        };

        multiplexer.broadcast(notification);

        let r1 = rx1.recv().await.unwrap();
        let r2 = rx2.recv().await.unwrap();
        assert_eq!(r1.source, "global");
        assert_eq!(r2.source, "global");
    }

    // ── Session reaper tests ─────────────────────────────────────────────

    /// GIVEN a session with no active receivers and an elapsed TTL
    /// WHEN `reap_expired_sessions` runs
    /// THEN the session is removed
    #[test]
    fn reap_expired_sessions_removes_abandoned_sessions_past_ttl() {
        // GIVEN
        let backends = Arc::new(BackendRegistry::new());
        let multiplexer = NotificationMultiplexer::new(backends, StreamingConfig::default());

        let (id, rx) = multiplexer.get_or_create_session(Some("expired-session"));
        assert_eq!(multiplexer.session_count(), 1);

        // Drop the receiver so receiver_count() == 0
        drop(rx);

        // WHEN: reap with zero TTL (everything is expired)
        multiplexer.reap_expired_sessions(Duration::ZERO);

        // THEN
        assert_eq!(
            multiplexer.session_count(),
            0,
            "expired abandoned session must be reaped"
        );
        assert!(!multiplexer.has_session(&id));
    }

    /// GIVEN a session with an active receiver (SSE client still connected)
    /// WHEN `reap_expired_sessions` runs with zero TTL
    /// THEN the session is preserved because a client is still attached
    #[test]
    fn reap_expired_sessions_preserves_sessions_with_active_receivers() {
        // GIVEN
        let backends = Arc::new(BackendRegistry::new());
        let multiplexer = NotificationMultiplexer::new(backends, StreamingConfig::default());

        let (id, _rx) = multiplexer.get_or_create_session(Some("active-session"));
        // `_rx` is still alive → receiver_count() == 1

        // WHEN: reap with zero TTL
        multiplexer.reap_expired_sessions(Duration::ZERO);

        // THEN: session survives because client is still connected
        assert_eq!(
            multiplexer.session_count(),
            1,
            "session with active receiver must be preserved"
        );
        assert!(multiplexer.has_session(&id));
    }

    /// GIVEN two sessions — one abandoned/expired, one with an active receiver
    /// WHEN `reap_expired_sessions` runs
    /// THEN only the abandoned session is removed
    #[test]
    fn reap_expired_sessions_selectively_removes_only_abandoned_sessions() {
        // GIVEN
        let backends = Arc::new(BackendRegistry::new());
        let multiplexer = NotificationMultiplexer::new(backends, StreamingConfig::default());

        let (abandoned_id, rx_abandoned) = multiplexer.get_or_create_session(Some("abandoned"));
        let (active_id, _rx_active) = multiplexer.get_or_create_session(Some("active"));
        assert_eq!(multiplexer.session_count(), 2);

        drop(rx_abandoned); // No more receivers on abandoned session

        // WHEN
        multiplexer.reap_expired_sessions(Duration::ZERO);

        // THEN
        assert_eq!(multiplexer.session_count(), 1);
        assert!(
            !multiplexer.has_session(&abandoned_id),
            "abandoned session must be reaped"
        );
        assert!(
            multiplexer.has_session(&active_id),
            "active session must survive"
        );
    }

    /// GIVEN a session with no active receivers but within its TTL
    /// WHEN `reap_expired_sessions` runs with a long TTL
    /// THEN the session is NOT removed (TTL not yet elapsed)
    #[test]
    fn reap_expired_sessions_respects_ttl_for_recently_created_sessions() {
        // GIVEN
        let backends = Arc::new(BackendRegistry::new());
        let multiplexer = NotificationMultiplexer::new(backends, StreamingConfig::default());

        let (id, rx) = multiplexer.get_or_create_session(Some("young-session"));
        drop(rx); // No receivers, but session was just created

        // WHEN: reap with a 30-minute TTL — session is seconds old
        multiplexer.reap_expired_sessions(Duration::from_secs(1800));

        // THEN: session is preserved because it hasn't exceeded the TTL
        assert_eq!(multiplexer.session_count(), 1);
        assert!(multiplexer.has_session(&id));
    }

    /// GIVEN the multiplexer wrapped in Arc
    /// WHEN `spawn_reaper_on` is called and sufficient time passes
    /// THEN expired abandoned sessions are cleaned up automatically
    #[tokio::test]
    async fn spawn_reaper_on_reaps_sessions_automatically() {
        // GIVEN
        let backends = Arc::new(BackendRegistry::new());
        let mut config = StreamingConfig::default();
        // Very short TTL and interval for the test
        config.session_ttl = Duration::from_millis(50);
        config.session_reaper_interval = Duration::from_millis(20);

        let multiplexer = Arc::new(NotificationMultiplexer::new(backends, config));
        multiplexer.spawn_reaper_on();

        let (id, rx) = multiplexer.get_or_create_session(Some("auto-reap-session"));
        drop(rx); // Drop receiver immediately

        assert_eq!(multiplexer.session_count(), 1);

        // WHEN: wait for the reaper to fire (TTL=50ms, interval=20ms)
        tokio::time::sleep(Duration::from_millis(200)).await;

        // THEN
        assert_eq!(
            multiplexer.session_count(),
            0,
            "reaper must have cleaned up expired session"
        );
        assert!(!multiplexer.has_session(&id));
    }

    /// GIVEN the multiplexer dropped while reaper task is running
    /// WHEN the Arc is dropped
    /// THEN the reaper task exits cleanly (no panic, no leak)
    #[tokio::test]
    async fn spawn_reaper_on_exits_when_multiplexer_is_dropped() {
        // GIVEN
        let backends = Arc::new(BackendRegistry::new());
        let mut config = StreamingConfig::default();
        config.session_reaper_interval = Duration::from_millis(10);

        let multiplexer = Arc::new(NotificationMultiplexer::new(backends, config));
        multiplexer.spawn_reaper_on();

        // WHEN: drop the only strong reference
        drop(multiplexer);

        // THEN: give the task a tick to observe the weak ref is gone — no panic
        tokio::time::sleep(Duration::from_millis(50)).await;
        // If we reach here without a panic, the reaper exited cleanly.
    }
}
