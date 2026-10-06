// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7116.MIN.2 row 14 for the Meta-MCP response cache and the idempotency
//! stores (design §4.4): a stored result keeps, in the same entry, what its
//! own dispatch read before any transform, and a hit restores that into the
//! request's read scope. A hit with no reading counts as unread.
//!
//! "Its own dispatch": each invocation runs in a read scope of its own
//! (`tenant_reads::with_dispatch_reads`), so the reading stored is exactly
//! what that dispatch noted, plus the tenants its own arguments name.

use std::collections::BTreeSet;

use crate::security::tenant_reads::{self, ReadAttribution};

/// The reading to store beside this dispatch's result; `None` outside a read
/// scope, so the default config stores nothing.
pub(crate) fn reading(request: impl FnOnce() -> BTreeSet<String>) -> Option<ReadAttribution> {
    if !tenant_reads::in_read_scope() {
        return None;
    }
    let mut reading = tenant_reads::noted().unwrap_or_default();
    reading.extend(&ReadAttribution::of(request(), false));
    Some(reading)
}

/// A hit of a stored result: restore its reading into the read scope, or
/// count it unread when it was stored without one.
pub(crate) fn restore(read: Option<&ReadAttribution>) {
    tenant_reads::note_restored(read);
}

impl super::super::MetaMcp {
    /// A delivered invocation's reading joins the request's: what it read in
    /// its own scope, and, when a backend answered it, the tenants its own
    /// arguments name (a playbook step the outer request does not show).
    pub(super) fn note_delivered_reading(
        &self,
        args: &serde_json::Value,
        reading: Option<ReadAttribution>,
        responded: bool,
    ) {
        if !tenant_reads::in_read_scope() {
            return;
        }
        tenant_reads::note_attribution(reading);
        if responded {
            let arguments = crate::gateway::meta_mcp_helpers::parse_tool_arguments(args);
            let tenants =
                self.request_tenants(arguments.as_ref().unwrap_or(&serde_json::Value::Null));
            tenant_reads::note_attribution(Some(ReadAttribution::of(tenants, false)));
        }
    }

    /// [`reading`] with the tenants `args`' own arguments name.
    pub(super) fn dispatch_reading(&self, args: &serde_json::Value) -> Option<ReadAttribution> {
        reading(|| {
            let arguments = crate::gateway::meta_mcp_helpers::parse_tool_arguments(args);
            self.request_tenants(arguments.as_ref().unwrap_or(&serde_json::Value::Null))
        })
    }
}

#[cfg(all(test, feature = "firewall"))]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use serde_json::json;

    use super::*;
    use crate::cache::ResponseCache;
    use crate::gateway::WriteRecord;
    use crate::security::firewall::tenant_guard::TenantGuardConfig;
    use crate::security::firewall::{Firewall, FirewallConfig};
    use crate::security::hash_argument;
    use crate::security::tenant_reads::{with_dispatch_reads, with_read_scope};

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

    fn tenant(id: &str) -> ReadAttribution {
        ReadAttribution::of([id.to_string()].into(), false)
    }

    /// Row 14: two dispatches of one request both read B, then a third reads
    /// A; each stored entry keeps its own reading. A hit restores B, the
    /// sibling's A stays out, the value is untouched; an entry stored without
    /// a reading is unread.
    #[tokio::test]
    async fn cache_hit_restores_pre_transform() {
        let (fw, cache) = (firewall(), ResponseCache::new());
        let ttl = Duration::from_secs(60);
        with_read_scope(Arc::clone(&fw), async {
            for (key, read) in [
                ("first", "cust-b"),
                ("second", "cust-b"),
                ("third", "cust-a"),
            ] {
                let ((), mine) = with_dispatch_reads(async {
                    tenant_reads::note_attribution(Some(tenant(read)));
                    let stored = reading(BTreeSet::new);
                    assert!(cache.set_read(
                        key,
                        json!({ "note": "x" }),
                        (stored, WriteRecord::default()),
                        ttl
                    ));
                })
                .await;
                tenant_reads::note_attribution(mine);
            }
        })
        .await;
        let (value, read, _) = cache.get_read("second").expect("stored");
        assert_eq!(value, json!({ "note": "x" }), "the value is untouched");
        let ((), restored) =
            with_read_scope(Arc::clone(&fw), async { restore(read.as_ref()) }).await;
        assert!(
            restored.tenants.contains(&hash_argument(&json!("cust-b"))),
            "the second dispatch's own B is restored, though the first read B too: {restored:?}"
        );
        assert!(
            !restored.tenants.contains(&hash_argument(&json!("cust-a"))),
            "the sibling's A is not this entry's reading: {restored:?}"
        );

        assert!(cache.set("bare", json!({ "note": "y" }), ttl));
        let (_, read, _) = cache.get_read("bare").expect("stored");
        let ((), bare) = with_read_scope(fw, async { restore(read.as_ref()) }).await;
        assert!(bare.uninspected, "an entry without a reading is unread");
    }
}
