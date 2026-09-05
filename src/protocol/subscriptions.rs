// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: MIT

//! `subscriptions/listen` — server-to-client change notifications after the
//! GET stream was removed (MCP 2026-07-28).
//!
//! One long-lived POST-response stream, opted into by notification type. The
//! server acknowledges and tags what it sends with
//! `io.modelcontextprotocol/subscriptionId`, because a client may hold several
//! and the payloads do not otherwise say which is which.
//!
//! Request-scoped notifications — `notifications/progress`,
//! `notifications/message` — deliberately have no place here. They belong to
//! the request that caused them and travel on that request's own response
//! stream; putting them on the subscription stream would deliver them to a
//! client that never made the request.

use serde_json::Value;

use crate::protocol::RequestId;

/// A change a client can subscribe to.
///
/// Closed on purpose. The request-scoped notifications are absent because they
/// are not subscribable, and an `Other(String)` variant would let one in by
/// accident.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotificationKind {
    /// The tool list changed.
    ToolsListChanged,
    /// The prompt list changed.
    PromptsListChanged,
    /// The resource list changed.
    ResourcesListChanged,
    /// A subscribed resource changed.
    ResourceSubscriptions,
}

impl NotificationKind {
    /// The kind a notification method belongs to, or `None` when it is
    /// request-scoped and therefore not subscribable.
    #[must_use]
    pub fn from_method(method: &str) -> Option<Self> {
        match method {
            "notifications/tools/list_changed" => Some(Self::ToolsListChanged),
            "notifications/prompts/list_changed" => Some(Self::PromptsListChanged),
            "notifications/resources/list_changed" => Some(Self::ResourcesListChanged),
            "notifications/resources/updated" => Some(Self::ResourceSubscriptions),
            _ => None,
        }
    }

    /// The opt-in field name a client uses to ask for this kind.
    #[must_use]
    pub const fn opt_in_field(self) -> &'static str {
        match self {
            Self::ToolsListChanged => "toolsListChanged",
            Self::PromptsListChanged => "promptsListChanged",
            Self::ResourcesListChanged => "resourcesListChanged",
            Self::ResourceSubscriptions => "resourceSubscriptions",
        }
    }

    /// Every subscribable kind.
    #[must_use]
    pub const fn all() -> [Self; 4] {
        [
            Self::ToolsListChanged,
            Self::PromptsListChanged,
            Self::ResourcesListChanged,
            Self::ResourceSubscriptions,
        ]
    }
}

/// What a client asked to be told about.
///
/// The filter is `params.notifications`, not `params`. Reading the opt-ins at
/// the root looked equivalent and rejected every conforming request, because
/// nothing was ever found where it was looked for.
#[derive(Debug, Clone, Default)]
pub struct ListenRequest {
    wanted: Vec<NotificationKind>,
    resource_uris: Vec<String>,
}

impl ListenRequest {
    /// Read a `subscriptions/listen` request.
    ///
    /// `None` means the request carried no `notifications` filter at all, which
    /// is invalid params rather than an empty subscription. An **empty** filter
    /// is valid and distinct: the client asked for nothing, and the honest
    /// answer is to acknowledge it and send nothing, not to refuse it.
    ///
    /// Unrecognised keys are ignored rather than refused, because the
    /// specification tells a client to expect a server to handle unsupported
    /// types gracefully — refusing them would make every future notification
    /// type a breaking change.
    #[must_use]
    pub fn from_params(params: Option<&Value>) -> Option<Self> {
        let filter = params?.get("notifications")?.as_object()?;

        let wanted: Vec<NotificationKind> = NotificationKind::all()
            .into_iter()
            .filter(|kind| match kind {
                // Three are booleans. The fourth is not, and treating it as one
                // silently dropped every resource a client named.
                NotificationKind::ResourceSubscriptions => filter
                    .get(kind.opt_in_field())
                    .and_then(Value::as_array)
                    .is_some_and(|uris| !uris.is_empty()),
                _ => filter
                    .get(kind.opt_in_field())
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            })
            .collect();

        // `resourceSubscriptions` is a list of resource URIs, per the filter
        // table. Non-string entries are dropped rather than failing the whole
        // request: one malformed entry should not cost a client its stream.
        let resource_uris = filter
            .get(NotificationKind::ResourceSubscriptions.opt_in_field())
            .and_then(Value::as_array)
            .map(|uris| {
                uris.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();

        Some(Self {
            wanted,
            resource_uris,
        })
    }

    /// Whether the client asked for this kind.
    #[must_use]
    pub fn wants(&self, kind: NotificationKind) -> bool {
        self.wanted.contains(&kind)
    }

    /// The resource URIs the client subscribed to.
    #[must_use]
    pub fn resource_uris(&self) -> &[String] {
        &self.resource_uris
    }

    /// Whether the client asked for nothing at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.wanted.is_empty() && self.resource_uris.is_empty()
    }
}

/// Identifies one subscription on one stream.
///
/// **It is the JSON-RPC id of the `subscriptions/listen` request**, not a value
/// the server invents. The specification is explicit: *"The value is the
/// JSON-RPC ID of the `subscriptions/listen` request."* A minted id looks
/// server-authoritative and safe, and leaves the client unable to correlate a
/// notification with the subscription that asked for it — which on stdio, where
/// every message shares one channel, is the only way to correlate at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionId(RequestId);

impl SubscriptionId {
    /// The subscription identified by the request that opened it.
    #[must_use]
    pub const fn of_request(id: RequestId) -> Self {
        Self(id)
    }

    /// The wire value, string or number as the client sent it.
    #[must_use]
    pub fn as_value(&self) -> Value {
        match &self.0 {
            RequestId::String(s) => Value::String(s.clone()),
            RequestId::Number(n) => Value::Number((*n).into()),
        }
    }

    /// Tag a notification as belonging to this subscription.
    ///
    /// Into `params._meta`, which is where the specification's own example puts
    /// it. At the notification root a conforming client never looks, so the tag
    /// was present, well-formed and invisible.
    #[must_use]
    pub fn tag(&self, mut notification: Value) -> Value {
        let Some(object) = notification.as_object_mut() else {
            return notification;
        };
        let params = object
            .entry("params")
            .or_insert_with(|| serde_json::json!({}));
        if let Some(params) = params.as_object_mut() {
            let meta = params
                .entry("_meta")
                .or_insert_with(|| serde_json::json!({}));
            if let Some(meta) = meta.as_object_mut() {
                meta.insert(
                    "io.modelcontextprotocol/subscriptionId".to_string(),
                    self.as_value(),
                );
            }
        }
        notification
    }
}
