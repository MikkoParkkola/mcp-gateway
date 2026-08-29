// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The subscriber side of `subscriptions/listen` (MCP 2026-07-28).
//!
//! One process-wide channel of change notifications, and one listener per open
//! stream holding its own filter.
//!
//! Deliberately not the [`NotificationMultiplexer`]: that structure is keyed by
//! session id, and this revision deleted sessions. A session-free path bolted
//! into a session-keyed table conflates two lifetimes, which is the defect this
//! branch already fixed once when a stateless request was minting a session per
//! call.
//!
//! A listener that goes away costs nothing: dropping the stream drops its
//! receiver and returns its permit, with no reaper, no deadline and no cleanup
//! callback. That is the point rather than a convenience — the registry that
//! would have reclaimed per-caller state is not wired to anything (MIK-7291),
//! so a design needing reclamation is a design that leaks.
//!
//! [`NotificationMultiplexer`]: crate::gateway::streaming::NotificationMultiplexer

use std::sync::Arc;

use serde_json::Value;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, broadcast};

use crate::protocol::subscriptions::{ListenRequest, NotificationKind};

/// How many notifications a listener may fall behind before it is disconnected.
///
/// A slow reader is disconnected rather than quietly starved, so this only has
/// to absorb an ordinary burst.
const CHANNEL_DEPTH: usize = 256;

/// Whether a filter asked for this notification.
///
/// The whole delivery decision, in one place. Written as a free function so the
/// filter and the notification meet exactly once: two copies of this comparison
/// would drift, and the difference between them is a client receiving something
/// it never asked for.
#[must_use]
pub fn delivers(filter: &ListenRequest, notification: &Value) -> bool {
    let Some(method) = notification.get("method").and_then(Value::as_str) else {
        return false;
    };
    // A method with no subscribable kind is request-scoped — `progress` and
    // `message` travel on the response stream of the request that caused them,
    // and delivering them here would hand them to a client that never made it.
    let Some(kind) = NotificationKind::from_method(method) else {
        return false;
    };

    if kind == NotificationKind::ResourceSubscriptions {
        // Named resources only. The opt-in is a list of URIs, so "subscribed to
        // resource updates" is never true in general — only for the ones asked
        // for by name.
        return notification
            .get("params")
            .and_then(|p| p.get("uri"))
            .and_then(Value::as_str)
            .is_some_and(|uri| filter.resource_uris().iter().any(|want| want == uri));
    }

    filter.wants(kind)
}

/// One open `subscriptions/listen` stream.
///
/// Holds its permit, so capacity returns when the stream is dropped and not a
/// moment later.
#[derive(Debug)]
pub struct Listener {
    receiver: broadcast::Receiver<Value>,
    _permit: OwnedSemaphorePermit,
}

impl Listener {
    /// Receive the next notification, or the reason the stream ends.
    ///
    /// # Errors
    ///
    /// Returns the broadcast error so the caller can distinguish a closed
    /// channel from a lagging reader; both end the stream, for different
    /// reasons the caller logs differently.
    pub async fn recv(&mut self) -> Result<Value, broadcast::error::RecvError> {
        self.receiver.recv().await
    }
}

/// The notifications this gateway publishes, and the streams listening to them.
#[derive(Debug)]
pub struct SubscriptionRegistry {
    sender: broadcast::Sender<Value>,
    permits: Arc<Semaphore>,
}

impl SubscriptionRegistry {
    /// A registry admitting at most `capacity` concurrent listeners.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(CHANNEL_DEPTH);
        Self {
            sender,
            permits: Arc::new(Semaphore::new(capacity)),
        }
    }

    /// Admit a listener, or `None` when the ceiling is reached.
    ///
    /// The permit **is** the admission: acquiring it is one atomic operation,
    /// so two concurrent requests cannot both observe room and both take it. A
    /// ceiling that can be raced is not a ceiling, and this one exists against a
    /// caller who opens streams and abandons them — which the specification
    /// says a server must not assume they will not do.
    #[must_use]
    pub fn subscribe(&self) -> Option<Listener> {
        let permit = Arc::clone(&self.permits).try_acquire_owned().ok()?;
        Some(Listener {
            receiver: self.sender.subscribe(),
            _permit: permit,
        })
    }

    /// Publish a notification to every listener.
    ///
    /// Filtering happens per listener, not here: one listener's filter must
    /// never decide what another receives.
    pub fn publish(&self, notification: Value) {
        // An error means nobody is listening, which is ordinary rather than a
        // failure — the gateway's tool surface changes whether or not a modern
        // client is watching.
        let _ = self.sender.send(notification);
    }

    /// How many more listeners may be admitted.
    #[must_use]
    pub fn available(&self) -> usize {
        self.permits.available_permits()
    }
}

/// The notification raised when the gateway's tool surface changes.
#[must_use]
pub fn tools_list_changed() -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/tools/list_changed",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn filter(value: Value) -> ListenRequest {
        ListenRequest::from_params(Some(&json!({ "notifications": value })))
            .expect("a filter the tests build must parse")
    }

    fn notification(method: &str) -> Value {
        json!({ "jsonrpc": "2.0", "method": method })
    }

    #[test]
    fn a_kind_the_client_asked_for_is_delivered() {
        let wants_tools = filter(json!({ "toolsListChanged": true }));
        assert!(delivers(
            &wants_tools,
            &notification("notifications/tools/list_changed")
        ));
    }

    #[test]
    fn a_kind_the_client_did_not_ask_for_is_never_delivered() {
        // The specification is explicit: a server MUST NOT send notification
        // types the client has not explicitly requested.
        let wants_tools = filter(json!({ "toolsListChanged": true }));
        for method in [
            "notifications/prompts/list_changed",
            "notifications/resources/list_changed",
            "notifications/resources/updated",
        ] {
            assert!(
                !delivers(&wants_tools, &notification(method)),
                "{method} was not asked for"
            );
        }
    }

    #[test]
    fn a_request_scoped_notification_never_rides_this_stream() {
        // Progress and log messages belong to the request that caused them and
        // travel on its own response stream. Delivering them here would hand
        // them to a client that never made that request.
        let wants_everything = filter(json!({
            "toolsListChanged": true,
            "promptsListChanged": true,
            "resourcesListChanged": true,
            "resourceSubscriptions": ["file:///a"]
        }));
        for method in [
            "notifications/progress",
            "notifications/message",
            "notifications/initialized",
        ] {
            assert!(
                !delivers(&wants_everything, &notification(method)),
                "{method} is request-scoped and must not be delivered here"
            );
        }
    }

    #[test]
    fn a_resource_update_is_delivered_only_for_a_named_uri() {
        // The opt-in is a list of URIs, so "subscribed to resource updates" is
        // never true in general — only for the resources named.
        let names_one = filter(json!({ "resourceSubscriptions": ["file:///wanted"] }));

        let wanted = json!({
            "jsonrpc": "2.0",
            "method": "notifications/resources/updated",
            "params": { "uri": "file:///wanted" }
        });
        assert!(delivers(&names_one, &wanted));

        let other = json!({
            "jsonrpc": "2.0",
            "method": "notifications/resources/updated",
            "params": { "uri": "file:///not-wanted" }
        });
        assert!(
            !delivers(&names_one, &other),
            "a resource the client never named must not be delivered"
        );

        let no_uri = notification("notifications/resources/updated");
        assert!(
            !delivers(&names_one, &no_uri),
            "an update naming no resource matches no subscription"
        );
    }

    #[test]
    fn an_empty_filter_receives_nothing() {
        let empty = filter(json!({}));
        for method in [
            "notifications/tools/list_changed",
            "notifications/prompts/list_changed",
            "notifications/resources/list_changed",
        ] {
            assert!(!delivers(&empty, &notification(method)));
        }
    }

    #[test]
    fn a_malformed_notification_is_not_delivered() {
        let wants_tools = filter(json!({ "toolsListChanged": true }));
        assert!(!delivers(&wants_tools, &json!({})));
        assert!(!delivers(&wants_tools, &json!({ "method": 7 })));
    }

    #[tokio::test]
    async fn a_listener_receives_what_is_published() {
        let registry = SubscriptionRegistry::new(4);
        let mut listener = registry.subscribe().expect("capacity");

        registry.publish(tools_list_changed());

        let received = listener.recv().await.expect("a published notification");
        assert_eq!(received["method"], "notifications/tools/list_changed");
    }

    #[tokio::test]
    async fn every_listener_receives_it_and_filters_for_itself() {
        // One listener's filter must never decide what another receives, so
        // publishing is unfiltered and each stream applies its own.
        let registry = SubscriptionRegistry::new(4);
        let mut first = registry.subscribe().expect("capacity");
        let mut second = registry.subscribe().expect("capacity");

        registry.publish(tools_list_changed());

        assert_eq!(
            first.recv().await.expect("first")["method"],
            "notifications/tools/list_changed"
        );
        assert_eq!(
            second.recv().await.expect("second")["method"],
            "notifications/tools/list_changed"
        );
    }

    #[test]
    fn admission_stops_at_the_ceiling() {
        // A bound against a caller who opens streams and walks away, which the
        // specification says a server must not assume they will not do.
        let registry = SubscriptionRegistry::new(2);
        let _first = registry.subscribe().expect("capacity");
        let _second = registry.subscribe().expect("capacity");

        assert!(
            registry.subscribe().is_none(),
            "a full registry must refuse a new listener"
        );
        assert_eq!(registry.available(), 0);
    }

    #[test]
    fn dropping_a_listener_returns_its_capacity() {
        // The permit is owned by the listener, so release is the drop and not a
        // deadline anything has to remember to enforce.
        let registry = SubscriptionRegistry::new(1);
        let listener = registry.subscribe().expect("capacity");
        assert!(registry.subscribe().is_none());

        drop(listener);

        assert_eq!(registry.available(), 1);
        assert!(
            registry.subscribe().is_some(),
            "capacity must come back when a stream ends"
        );
    }

    #[tokio::test]
    async fn a_listener_that_falls_behind_is_told_it_lagged() {
        // The stream closes on this rather than delivering the remainder as
        // though nothing had happened, which would leave a client holding stale
        // state with no way to learn it.
        let registry = SubscriptionRegistry::new(1);
        let mut listener = registry.subscribe().expect("capacity");

        for _ in 0..(CHANNEL_DEPTH + 10) {
            registry.publish(tools_list_changed());
        }

        assert!(
            matches!(
                listener.recv().await,
                Err(broadcast::error::RecvError::Lagged(_))
            ),
            "a reader that fell behind must be told, not silently starved"
        );
    }
}
