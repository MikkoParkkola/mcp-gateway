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
#[derive(Debug, Clone)]
pub struct ListenRequest {
    wanted: Vec<NotificationKind>,
}

impl ListenRequest {
    /// Read a `subscriptions/listen` request, or `None` if it names nothing.
    ///
    /// A subscription to nothing is a stream held open forever carrying no
    /// traffic — something a client can allocate by accident and never notice,
    /// and something a gateway would then hold on its behalf.
    #[must_use]
    pub fn from_params(params: Option<&Value>) -> Option<Self> {
        let params = params?;
        let wanted: Vec<NotificationKind> = NotificationKind::all()
            .into_iter()
            .filter(|kind| {
                params
                    .get(kind.opt_in_field())
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
            })
            .collect();
        if wanted.is_empty() {
            return None;
        }
        Some(Self { wanted })
    }

    /// Whether the client asked for this kind.
    #[must_use]
    pub fn wants(&self, kind: NotificationKind) -> bool {
        self.wanted.contains(&kind)
    }
}

/// Identifies one subscription on one stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionId(String);

impl SubscriptionId {
    /// Mint a new one. Server-assigned, never client-chosen: a client that
    /// named its own could name another's.
    #[must_use]
    pub fn mint() -> Self {
        Self(format!("sub-{}", uuid::Uuid::new_v4()))
    }

    /// The wire value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Tag a notification as belonging to this subscription.
    #[must_use]
    pub fn tag(&self, mut notification: Value) -> Value {
        if let Some(object) = notification.as_object_mut() {
            let meta = object
                .entry("_meta")
                .or_insert_with(|| serde_json::json!({}));
            if let Some(meta) = meta.as_object_mut() {
                meta.insert(
                    "io.modelcontextprotocol/subscriptionId".to_string(),
                    Value::String(self.0.clone()),
                );
            }
        }
        notification
    }
}
