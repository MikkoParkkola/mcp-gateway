// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7116.MIN.2 row 14 for the Meta-MCP response cache (design §4.4): an
//! entry keeps beside it what its dispatch read before the response gates,
//! under a sibling key with the same TTL and eviction, and a hit restores it
//! into the request's read scope. A hit with no sibling counts as unread.

use std::time::Duration;

use crate::cache::ResponseCache;
use crate::security::tenant_reads;

/// The sibling key holding `key`'s read attribution.
fn read_key(key: &str) -> String {
    format!("{key}#min2-read")
}

/// After `key` was stored: keep this request's reading beside it. Only inside
/// a read scope, so the default config stores nothing more.
pub(super) fn remember(cache: &ResponseCache, key: &str, ttl: Duration) {
    if !tenant_reads::in_read_scope() {
        return;
    }
    let read = tenant_reads::noted().unwrap_or_default();
    if let Ok(value) = serde_json::to_value(read) {
        cache.set(&read_key(key), value, ttl);
    }
}

/// On a hit of `key`: restore the reading kept beside it into this request's
/// read scope, or count the hit as unread when none is kept.
pub(super) fn restore(cache: &ResponseCache, key: &str) {
    if !tenant_reads::in_read_scope() {
        return;
    }
    let read = cache
        .get(&read_key(key))
        .and_then(|value| serde_json::from_value(value).ok());
    tenant_reads::note_restored(read.as_ref());
}

#[cfg(all(test, feature = "firewall"))]
mod tests {
    use std::sync::Arc;

    use serde_json::json;

    use super::*;
    use crate::security::firewall::tenant_guard::TenantGuardConfig;
    use crate::security::firewall::{Firewall, FirewallConfig};
    use crate::security::hash_argument;
    use crate::security::tenant_reads::{ReadAttribution, with_read_scope};

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

    /// Row 14: a hit restores what the stored dispatch read; an entry with
    /// nothing kept beside it counts as unread.
    #[tokio::test]
    async fn cache_hit_restores_pre_transform() {
        let (fw, cache) = (firewall(), ResponseCache::new());
        let ttl = Duration::from_secs(60);
        let b = ReadAttribution::of([String::from("cust-b")].into(), false);
        with_read_scope(Arc::clone(&fw), async {
            tenant_reads::note_attribution(Some(b));
            assert!(cache.set("k", json!({ "note": "x" }), ttl));
            remember(&cache, "k", ttl);
        })
        .await;
        let ((), restored) = with_read_scope(Arc::clone(&fw), async { restore(&cache, "k") }).await;
        assert!(
            restored.tenants.contains(&hash_argument(&json!("cust-b"))),
            "the hit restores B: {restored:?}"
        );

        assert!(cache.set("bare", json!({ "note": "y" }), ttl));
        let ((), restored) = with_read_scope(fw, async { restore(&cache, "bare") }).await;
        assert!(restored.uninspected, "an entry without a reading is unread");
    }
}
