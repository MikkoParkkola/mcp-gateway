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

use crate::gateway::auth::AuthState;
use crate::gateway::auth::live::{Audience, Delivery, HeldCredential, delivery};
use crate::protocol::subscriptions::{ListenRequest, NotificationKind};

/// How many notifications a listener may fall behind before it is disconnected.
///
/// A slow reader is disconnected rather than quietly starved, so this only has
/// to absorb an ordinary burst.
/// How many `subscriptions/listen` streams may be open at once.
///
/// A ceiling rather than a configured value because the specification's own
/// guidance is that a server must not assume a client closes what it opens:
/// this is the bound that makes an abandoned stream cost something finite.
pub const DEFAULT_MAX_LISTENERS: usize = 256;

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

    if kind == NotificationKind::Tasks {
        // Named tasks only, matched exactly like a resource URI. The ownership
        // narrowing already emptied this list for a caller who named a task it
        // does not own, so an exact match here is what closes that rule at the
        // broadcast door.
        return notification
            .get("params")
            .and_then(|p| p.get("taskId"))
            .and_then(Value::as_str)
            .is_some_and(|id| filter.task_ids().iter().any(|want| want == id));
    }

    filter.wants(kind)
}

/// One open `subscriptions/listen` stream.
///
/// Holds its permit, so capacity returns when the stream is dropped and not a
/// moment later.
pub struct Listener {
    receiver: broadcast::Receiver<Published>,
    /// The credential the stream was opened with, re-validated at delivery.
    // ci-allow-secret-debug: HeldCredential's own Debug prints only <redacted>
    credential: Option<HeldCredential>,
    authorizer: AuthState,
    _permit: OwnedSemaphorePermit,
}

impl std::fmt::Debug for Listener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Listener").finish_non_exhaustive()
    }
}

/// A published notification and who it is for.
#[derive(Clone, Debug)]
pub(crate) struct Published {
    pub(crate) notification: Value,
    audience: OwnedAudience,
}

/// The owned twin of [`Audience`], carried through the channel.
#[derive(Clone, Debug)]
enum OwnedAudience {
    Backend(String),
    Any,
}

impl Listener {
    /// Receive the next notification, or the reason the stream ends.
    ///
    /// # Errors
    ///
    /// Returns the broadcast error so the caller can distinguish a closed
    /// channel from a lagging reader; both end the stream, for different
    /// reasons the caller logs differently.
    pub(crate) async fn recv(&mut self) -> Result<Published, broadcast::error::RecvError> {
        self.receiver.recv().await
    }

    /// What delivering `published` to this listener's caller should do now.
    pub(crate) async fn delivery(&self, published: &Published) -> Delivery {
        let audience = match &published.audience {
            OwnedAudience::Backend(backend) => Audience::Backend(backend),
            OwnedAudience::Any => Audience::Any,
        };
        delivery(&self.authorizer, self.credential.as_ref(), audience).await
    }
}

/// The notifications this gateway publishes, and the streams listening to them.
pub struct SubscriptionRegistry {
    sender: broadcast::Sender<Published>,
    permits: Arc<Semaphore>,
    /// The authorizer every listener is re-validated against. Required at
    /// construction, so a registry that delivers without one cannot exist.
    authorizer: AuthState,
}

impl std::fmt::Debug for SubscriptionRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubscriptionRegistry")
            .field("available", &self.available())
            .finish_non_exhaustive()
    }
}

impl SubscriptionRegistry {
    /// A registry admitting at most `capacity` concurrent listeners, each
    /// re-validated against `authorizer` at delivery.
    #[must_use]
    pub fn new(capacity: usize, authorizer: AuthState) -> Self {
        let (sender, _) = broadcast::channel(CHANNEL_DEPTH);
        Self {
            sender,
            permits: Arc::new(Semaphore::new(capacity)),
            authorizer,
        }
    }

    /// Admit a listener that presented no credential, or `None` when the
    /// ceiling is reached. With authentication on it is closed at its first
    /// delivery; the HTTP route refuses such a caller before this point.
    ///
    /// The permit **is** the admission: acquiring it is one atomic operation,
    /// so two concurrent requests cannot both observe room and both take it. A
    /// ceiling that can be raced is not a ceiling, and this one exists against a
    /// caller who opens streams and abandons them — which the specification
    /// says a server must not assume they will not do.
    #[must_use]
    pub fn subscribe(&self) -> Option<Listener> {
        self.admit(None)
    }

    fn admit(&self, credential: Option<HeldCredential>) -> Option<Listener> {
        let permit = Arc::clone(&self.permits).try_acquire_owned().ok()?;
        Some(Listener {
            receiver: self.sender.subscribe(),
            credential,
            authorizer: self.authorizer.clone(),
            _permit: permit,
        })
    }

    /// Admit a listener for the caller holding `credential`.
    pub(crate) async fn subscribe_as(
        &self,
        credential: Option<HeldCredential>,
    ) -> Result<Listener, ListenRefusal> {
        // Checked before the permit: a stream nothing could ever reach would
        // only hold a slot.
        if delivery(&self.authorizer, credential.as_ref(), Audience::Any).await == Delivery::Dead {
            return Err(ListenRefusal::Unauthenticated);
        }
        self.admit(credential).ok_or(ListenRefusal::Full)
    }

    /// Publish a notification to every listener.
    ///
    /// Filtering happens per listener, not here: one listener's filter must
    /// never decide what another receives.
    pub fn publish(&self, notification: Value) {
        // An error means nobody is listening, which is ordinary rather than a
        // failure — the gateway's tool surface changes whether or not a modern
        // client is watching.
        self.send(notification, OwnedAudience::Any);
    }

    fn send(&self, notification: Value, audience: OwnedAudience) {
        let _ = self.sender.send(Published {
            notification,
            audience,
        });
    }

    /// Publish a notification only for callers who may access `backend`.
    pub fn publish_for_backend(&self, notification: Value, backend: &str) {
        self.send(notification, OwnedAudience::Backend(backend.to_owned()));
    }

    /// How many more listeners may be admitted.
    #[must_use]
    pub fn available(&self) -> usize {
        self.permits.available_permits()
    }
}

/// Why a `subscriptions/listen` was not admitted.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ListenRefusal {
    /// The caller's credential does not authenticate, so nothing could ever
    /// be delivered to the stream it asked for.
    Unauthenticated,
    /// Every listener slot is taken.
    Full,
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

    fn filter(value: &Value) -> ListenRequest {
        ListenRequest::from_params(Some(&json!({ "notifications": value })))
            .expect("a filter the tests build must parse")
    }

    fn notification(method: &str) -> Value {
        json!({ "jsonrpc": "2.0", "method": method })
    }

    #[test]
    fn a_kind_the_client_asked_for_is_delivered() {
        let wants_tools = filter(&json!({ "toolsListChanged": true }));
        assert!(delivers(
            &wants_tools,
            &notification("notifications/tools/list_changed")
        ));
    }

    #[test]
    fn a_kind_the_client_did_not_ask_for_is_never_delivered() {
        // The specification is explicit: a server MUST NOT send notification
        // types the client has not explicitly requested.
        let wants_tools = filter(&json!({ "toolsListChanged": true }));
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
        let wants_everything = filter(&json!({
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
        let names_one = filter(&json!({ "resourceSubscriptions": ["file:///wanted"] }));

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
        let empty = filter(&json!({}));
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
        let wants_tools = filter(&json!({ "toolsListChanged": true }));
        assert!(!delivers(&wants_tools, &json!({})));
        assert!(!delivers(&wants_tools, &json!({ "method": 7 })));
    }

    #[tokio::test]
    async fn a_listener_receives_what_is_published() {
        let registry = SubscriptionRegistry::new(
            4,
            crate::gateway::test_helpers::auth_state(&crate::config::AuthConfig::default()),
        );
        let mut listener = registry.subscribe().expect("capacity");

        registry.publish(tools_list_changed());

        let received = listener
            .recv()
            .await
            .expect("a published notification")
            .notification;
        assert_eq!(received["method"], "notifications/tools/list_changed");
    }

    #[tokio::test]
    async fn every_listener_receives_it_and_filters_for_itself() {
        // One listener's filter must never decide what another receives, so
        // publishing is unfiltered and each stream applies its own.
        let registry = SubscriptionRegistry::new(
            4,
            crate::gateway::test_helpers::auth_state(&crate::config::AuthConfig::default()),
        );
        let mut first = registry.subscribe().expect("capacity");
        let mut second = registry.subscribe().expect("capacity");

        registry.publish(tools_list_changed());

        assert_eq!(
            first.recv().await.expect("first").notification["method"],
            "notifications/tools/list_changed"
        );
        assert_eq!(
            second.recv().await.expect("second").notification["method"],
            "notifications/tools/list_changed"
        );
    }

    #[test]
    fn admission_stops_at_the_ceiling() {
        // A bound against a caller who opens streams and walks away, which the
        // specification says a server must not assume they will not do.
        let registry = SubscriptionRegistry::new(
            2,
            crate::gateway::test_helpers::auth_state(&crate::config::AuthConfig::default()),
        );
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
        let registry = SubscriptionRegistry::new(
            1,
            crate::gateway::test_helpers::auth_state(&crate::config::AuthConfig::default()),
        );
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
        let registry = SubscriptionRegistry::new(
            1,
            crate::gateway::test_helpers::auth_state(&crate::config::AuthConfig::default()),
        );
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
