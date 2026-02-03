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
use std::time::Duration;

use async_stream::stream;
use axum::response::sse::{Event, KeepAlive, Sse};
use futures::Stream;
use parking_lot::RwLock;
use serde::Serialize;
use serde_json::{Value, json};
use tokio::sync::broadcast;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::backend::BackendRegistry;
use crate::config::StreamingConfig;
use crate::Result;

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
    /// Create a new notification multiplexer
    pub fn new(backends: Arc<BackendRegistry>, config: StreamingConfig) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            backends,
            config,
            event_counter: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// Create or get a session
    pub fn get_or_create_session(&self, session_id: Option<&str>) -> (String, broadcast::Receiver<TaggedNotification>) {
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
    pub fn broadcast(&self, notification: TaggedNotification) {
        let sessions = self.sessions.read();
        for session in sessions.values() {
            let _ = session.tx.send(notification.clone());
        }
    }

    /// Generate a unique event ID
    pub fn next_event_id(&self) -> String {
        let id = self.event_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        format!("evt-{id}")
    }


    /// Subscribe a session to a backend's notifications
    pub async fn subscribe_backend(&self, session_id: &str, backend_name: &str) -> Result<()> {
        // Verify backend exists
        let _backend = self.backends.get(backend_name)
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
}

/// Create SSE response for GET /mcp
///
/// Takes owned data to satisfy Rust 2024 lifetime capture rules for `impl Stream`.
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
                    let event = Event::default()
                        .event(&notification.event_type)
                        .data(serde_json::to_string(&notification).unwrap_or_default());

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

    Some(
        Sse::new(stream)
            .keep_alive(
                KeepAlive::new()
                    .interval(keep_alive_interval)
                    .text("ping")
            )
    )
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
}
