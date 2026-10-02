// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7116.MIN.2 row 14 for the Meta-MCP response cache and the idempotency
//! store (design §4.4): a stored result carries, inside the entry itself,
//! what its own dispatch read before any transform, and a hit restores that
//! into the request's read scope. A hit with no reading counts as unread.
//!
//! The reading is the dispatch's own: what the read scope gained while this
//! call ran (its raw response, a capability's pre-transform reading), plus the
//! tenants its own arguments name. A sibling dispatch of the same request is
//! not attributed to it.

use std::borrow::Cow;

use serde_json::Value;

use crate::security::tenant_reads::{self, ReadAttribution};

/// The member a stored result carries its reading under; stripped before a
/// hit is delivered, so a client never sees it.
const READ_MEMBER: &str = "_gatewayRead";

/// What the read scope has noted before this dispatch; `None` outside one.
pub(super) fn mark() -> Option<ReadAttribution> {
    tenant_reads::in_read_scope().then(|| tenant_reads::noted().unwrap_or_default())
}

/// `result` as a store keeps it: with this dispatch's reading inside, when a
/// read scope is collecting. `before` is [`mark`]'s snapshot; `request` the
/// tenants this call's own arguments name.
pub(crate) fn stamped<'v>(
    result: &'v Value,
    before: Option<&ReadAttribution>,
    request: impl FnOnce() -> std::collections::BTreeSet<String>,
) -> Cow<'v, Value> {
    let (Some(before), Some(now), true) = (before, tenant_reads::noted(), result.is_object())
    else {
        return Cow::Borrowed(result);
    };
    let mut stored = result.clone();
    let Value::Object(map) = &mut stored else {
        return Cow::Borrowed(result);
    };
    let mut reading = ReadAttribution {
        tenants: now.tenants.difference(&before.tenants).cloned().collect(),
        uninspected: now.uninspected && !before.uninspected,
    };
    reading.extend(&ReadAttribution::of(request(), false));
    if let Ok(value) = serde_json::to_value(reading) {
        map.insert(READ_MEMBER.to_string(), value);
    }
    Cow::Owned(stored)
}

impl super::super::MetaMcp {
    /// [`stamped`] with the tenants `args`' own arguments name.
    pub(super) fn stamped<'v>(
        &self,
        result: &'v Value,
        before: Option<&ReadAttribution>,
        args: &Value,
    ) -> Cow<'v, Value> {
        stamped(result, before, || {
            let arguments = crate::gateway::meta_mcp_helpers::parse_tool_arguments(args);
            self.request_tenants(arguments.as_ref().unwrap_or(&Value::Null))
        })
    }
}

/// A hit of a stored result: restore its reading into the read scope (or
/// count it unread when it carries none) and strip it from the value.
pub(crate) fn restored(mut stored: Value) -> Value {
    let reading = stored
        .as_object_mut()
        .and_then(|map| map.remove(READ_MEMBER))
        .and_then(|value| serde_json::from_value::<ReadAttribution>(value).ok());
    tenant_reads::note_restored(reading.as_ref());
    stored
}

#[cfg(all(test, feature = "firewall"))]
mod tests {
    use std::sync::Arc;

    use serde_json::json;

    use super::*;
    use crate::security::firewall::tenant_guard::TenantGuardConfig;
    use crate::security::firewall::{Firewall, FirewallConfig};
    use crate::security::hash_argument;
    use crate::security::tenant_reads::with_read_scope;

    fn firewall() -> Arc<Firewall> {
        Arc::new(Firewall::from_config(
            FirewallConfig {
                tenant_guard: TenantGuardConfig {
                    arg_keys: vec!["customer_id".to_string()],
                    ..TenantGuardConfig::default()
                },
                ..FirewallConfig::default()
            },
            None,
        ))
    }

    fn b() -> ReadAttribution {
        ReadAttribution::of([String::from("cust-b")].into(), false)
    }

    /// Row 14: a hit restores what the stored dispatch read, and only that:
    /// a sibling dispatch's reading before it is not stored with it. An
    /// entry with no reading counts as unread; the member never reaches the
    /// client.
    #[tokio::test]
    async fn cache_hit_restores_pre_transform() {
        let fw = firewall();
        let a = ReadAttribution::of([String::from("cust-a")].into(), false);
        let (stored, _) = with_read_scope(Arc::clone(&fw), async {
            tenant_reads::note_attribution(Some(a));
            let before = mark();
            tenant_reads::note_attribution(Some(b()));
            stamped(&json!({ "note": "x" }), before.as_ref(), Default::default).into_owned()
        })
        .await;
        let (delivered, reading) =
            with_read_scope(Arc::clone(&fw), async { restored(stored) }).await;
        assert_eq!(delivered, json!({ "note": "x" }), "the member is stripped");
        assert!(
            reading.tenants.contains(&hash_argument(&json!("cust-b"))),
            "the hit restores B: {reading:?}"
        );
        assert!(
            !reading.tenants.contains(&hash_argument(&json!("cust-a"))),
            "a sibling dispatch's A is not this entry's reading: {reading:?}"
        );

        let ((), bare) = with_read_scope(fw, async {
            let _ = restored(json!({ "note": "y" }));
        })
        .await;
        assert!(bare.uninspected, "an entry without a reading is unread");
    }
}
