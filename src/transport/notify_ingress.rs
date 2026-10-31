// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! One ingress for every notification bound for a caller's sink.
//!
//! A backend's answer loses its forged and misplaced members where it enters
//! (`reserved_members::strip_ingress`); a notification the same backend raises
//! during the call reaches the sink by another road. Every road ends in the
//! sink's `admitted`, so the strip runs there, on every notification, whoever
//! raised it: no path into the sink can skip it.
//!
//! Who raised it is carried only to name it in the log, and to drop a
//! notification no backend call accounts for: every known path into the sink
//! runs inside a backend's scope ([`in_backend`]) or is the gateway's own
//! `emit_log`, so a missing sender is a path nobody classified.

use std::sync::Arc;

use serde_json::Value;

use crate::protocol::JsonRpcNotification;
use crate::protocol::notifications::{self, Rule};
use crate::protocol::{member_scope, reserved_members};

tokio::task_local! {
    /// The backend whose call is in flight on this task.
    static NOTIFY_ORIGIN: Arc<str>;
}

/// Who raised a notification bound for the sink.
#[derive(Debug, Clone)]
pub(crate) enum Origin {
    /// A gateway line (`emit_log`) raised outside any backend call.
    Gateway,
    /// The backend whose call raised it.
    Backend(Arc<str>),
    /// A transport published it with no backend scope in sight.
    Missing,
}

impl Origin {
    /// A transport's notification on this task: the backend whose call is in
    /// flight, else `Missing`.
    pub(crate) fn ambient() -> Self {
        NOTIFY_ORIGIN
            .try_with(|backend| Self::Backend(Arc::clone(backend)))
            .unwrap_or(Self::Missing)
    }

    /// A gateway log line on this task: inside a backend call it is that
    /// backend's, so it is judged as backend text; outside, the gateway's.
    pub(crate) fn gateway_line() -> Self {
        NOTIFY_ORIGIN
            .try_with(|backend| Self::Backend(Arc::clone(backend)))
            .unwrap_or(Self::Gateway)
    }

    fn name(&self) -> &str {
        match self {
            Self::Gateway => "gateway",
            Self::Backend(backend) => backend,
            Self::Missing => "unknown",
        }
    }
}

/// Run `fut` as `backend`'s call: every notification it raises names it.
pub(crate) fn in_backend<F: Future>(backend: Arc<str>, fut: F) -> impl Future<Output = F::Output> {
    NOTIFY_ORIGIN.scope(backend, fut)
}

/// What ingress decided for one notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ingress {
    Deliver,
    /// Withheld, for the reason named.
    Drop(&'static str),
}

/// Strip `notification` of what its sender may not write, and decide whether
/// it is delivered. One warn per notification names the sender, the method
/// and the removed paths, never their values.
pub(crate) fn ingress_notification(
    origin: &Origin,
    notification: &mut JsonRpcNotification,
) -> Ingress {
    let method = notification.method.as_str();
    let rule = notifications::rule(method);
    if rule == Some(Rule::Drop) {
        tracing::warn!(
            backend = origin.name(),
            method,
            "withheld a task notification a backend raised"
        );
        return Ingress::Drop("task notification");
    }
    let removed = notification
        .params
        .as_mut()
        .map(|params| strip(rule, params))
        .unwrap_or_default();
    if matches!(origin, Origin::Missing) {
        tracing::warn!(
            method,
            members = ?removed,
            "withheld a notification raised outside any backend call"
        );
        return Ingress::Drop("no sender");
    }
    if !removed.is_empty() {
        tracing::warn!(
            backend = origin.name(),
            method,
            members = ?removed,
            "removed members a backend may not put in a notification"
        );
    }
    Ingress::Deliver
}

/// Remove from `params`' root every gateway-only member, the two `_meta`
/// tags no notification may carry, and, on a protocol notification, every
/// scoped protocol member. Returns the removed paths, dotted.
fn strip(rule: Option<Rule>, params: &mut Value) -> Vec<String> {
    let mut removed = Vec::new();
    if let Some(Value::Object(meta)) = params.get_mut("_meta") {
        // Nothing judges a chain on a notification, and a sink frame is not a
        // listen frame: the gateway tags its own.
        for key in [
            crate::security::signature_chain::CHAIN_META,
            super::upstream_tap::SUBSCRIPTION_ID,
        ] {
            if meta.remove(key).is_some() {
                removed.push(format!("_meta.{key}"));
            }
        }
    }
    removed.extend(reserved_members::strip_with(
        reserved_members::MEMBERS,
        params,
    ));
    if let Value::Object(map) = params {
        if removed.iter().any(|path| path.starts_with("_meta."))
            && map
                .get("_meta")
                .is_some_and(|meta| meta.as_object().is_some_and(serde_json::Map::is_empty))
        {
            map.remove("_meta");
        }
        // A vendor's method is not MCP's: its own fields of these names stay.
        if rule == Some(Rule::Strip) {
            for member in member_scope::every_scoped() {
                if map.remove(member).is_some() {
                    removed.push(member.to_owned());
                }
            }
        }
    }
    removed
}

#[cfg(test)]
#[path = "notify_ingress_tests.rs"]
mod tests;

/// Sink scopes for a test that drives a transport directly, as a backend's
/// send would: inside a backend scope, so its notifications have a sender.
#[cfg(test)]
pub(crate) mod test_support {
    use super::in_backend;
    use crate::protocol::JsonRpcNotification;
    use crate::transport::notification_sink::{self, Screen};

    /// The backend the wrapped scopes name.
    pub(crate) const BACKEND: &str = "test-backend";

    pub(crate) fn scope<F: Future>(
        screen: Screen,
        fut: F,
    ) -> (
        impl Future<Output = F::Output>,
        tokio::sync::mpsc::Receiver<JsonRpcNotification>,
    ) {
        notification_sink::scope(screen, in_backend(BACKEND.into(), fut))
    }

    pub(crate) async fn collect<F: Future>(
        screen: Screen,
        fut: F,
    ) -> (F::Output, Vec<JsonRpcNotification>) {
        notification_sink::collect(screen, in_backend(BACKEND.into(), fut)).await
    }
}
