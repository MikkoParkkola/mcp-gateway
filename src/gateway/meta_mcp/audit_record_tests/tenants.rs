// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7116.MIN.1: tenant attribution on the meta invocation record
//! (test plan T7-T11, T25).

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};

use super::{api_key_caller, context, meta, only_record, records};
use crate::gateway::authz::AllowAll;
use crate::gateway::meta_mcp::MetaMcp;
use crate::security::firewall::tenant_guard::TenantGuardConfig;
use crate::security::firewall::{Firewall, FirewallConfig};
use crate::security::hash_argument;

fn h(id: &str) -> String {
    hash_argument(&json!(id))
}

fn sorted(ids: &[&str]) -> Value {
    let mut hashes: Vec<String> = ids.iter().map(|id| h(id)).collect();
    hashes.sort();
    json!(hashes)
}

/// AWS's documented example access key id, which response inspection rates
/// HIGH. Assembled at runtime so secret scanners do not flag the source.
fn example_access_key() -> String {
    ["AKIA", "IOSFODNN7", "EXAMPLE"].concat()
}

/// A tool result whose text block is JSON naming `tenant`.
fn reply_naming(tenant: &str, extra_text: &str) -> Value {
    let rows = json!({"rows": [{"customer_id": tenant}], "note": extra_text});
    json!({"content": [{"type": "text", "text": rows.to_string()}], "isError": false})
}

/// Attribution on: `arg_keys` set, the guard itself off (observe-only).
fn attributing(mut meta: MetaMcp) -> MetaMcp {
    meta.set_firewall(Some(Arc::new(Firewall::from_config(
        FirewallConfig {
            tenant_guard: TenantGuardConfig {
                arg_keys: vec!["customer_id".to_string()],
                ..TenantGuardConfig::default()
            },
            ..FirewallConfig::default()
        },
        None,
    ))));
    meta
}

fn args_for(tenant: Option<&str>) -> Value {
    let arguments = tenant.map_or_else(|| json!({}), |t| json!({"customer_id": t}));
    json!({"server": "alpha", "tool": "read", "arguments": arguments})
}

fn log_text(dir: &tempfile::TempDir) -> String {
    std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap_or_default()
}

/// T7. The record names request and response tenants, hashed and sorted,
/// next to the kernel's data classes. Also proves the dispatch notes reach
/// the writer after the scope ends.
#[tokio::test]
async fn allowed_call_record_carries_tenants_and_data_classes() {
    let dir = tempfile::tempdir().unwrap();
    let meta = attributing(meta(Ok(reply_naming("cust-9", "")), &dir));
    let who = api_key_caller();
    meta.invoke_tool(&args_for(Some("cust-1")), None, &context(&AllowAll, &who))
        .await
        .expect("allowed call");
    let record = only_record(&dir);
    assert_eq!(record["tenants"], sorted(&["cust-1", "cust-9"]), "{record}");
    assert!(
        record["data_classes"]
            .as_array()
            .is_some_and(|classes| !classes.is_empty()),
        "{record}"
    );
    let text = log_text(&dir);
    assert!(
        !text.contains("cust-1") && !text.contains("cust-9"),
        "{text}"
    );
}

/// T8. A response the inspection gate refuses still records the response's
/// tenants (captured before the gates), and no data classes (never
/// classified).
#[tokio::test]
async fn gate_refused_response_keeps_response_tenants() {
    let dir = tempfile::tempdir().unwrap();
    let note = format!("AWS_ACCESS_KEY_ID={}", example_access_key());
    let mut refusing = meta(Ok(reply_naming("cust-9", &note)), &dir);
    refusing.enable_response_inspection_action_mode();
    let meta = attributing(refusing);
    let who = api_key_caller();
    let _ = meta
        .invoke_tool(&args_for(Some("cust-1")), None, &context(&AllowAll, &who))
        .await;
    let record = only_record(&dir);
    assert_ne!(record["outcome"], json!("ok"), "{record}");
    let tenants = record["tenants"].as_array().cloned().unwrap_or_default();
    assert!(tenants.contains(&json!(h("cust-9"))), "{record}");
    assert!(record.get("data_classes").is_none(), "{record}");
}

/// T9. No firewall, no attribution: the record keeps its schema.
#[tokio::test]
async fn no_firewall_means_no_attribution_fields() {
    let dir = tempfile::tempdir().unwrap();
    let meta = meta(Ok(reply_naming("cust-9", "")), &dir);
    let who = api_key_caller();
    meta.invoke_tool(&args_for(Some("cust-1")), None, &context(&AllowAll, &who))
        .await
        .expect("allowed call");
    let record = only_record(&dir);
    assert!(record.get("tenants").is_none(), "{record}");
    assert!(record.get("data_classes").is_none(), "{record}");
}

/// T10. A call touching no tenant writes neither field. `data_classes` is
/// never empty, so this catches an unconditional write.
#[tokio::test]
async fn tenantless_call_writes_no_attribution_fields() {
    let dir = tempfile::tempdir().unwrap();
    let plain = json!({"content": [{"type": "text", "text": "{\"ok\":true}"}], "isError": false});
    let meta = attributing(meta(Ok(plain), &dir));
    let who = api_key_caller();
    meta.invoke_tool(&args_for(None), None, &context(&AllowAll, &who))
        .await
        .expect("allowed call");
    let record = only_record(&dir);
    assert!(record.get("tenants").is_none(), "{record}");
    assert!(record.get("data_classes").is_none(), "{record}");
}

/// T11 (route half). The attributed meta record verifies as part of the chain.
#[tokio::test]
async fn attributed_meta_record_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let meta = attributing(meta(Ok(reply_naming("cust-9", "")), &dir));
    let who = api_key_caller();
    meta.invoke_tool(&args_for(Some("cust-1")), None, &context(&AllowAll, &who))
        .await
        .expect("allowed call");
    assert!(only_record(&dir).get("tenants").is_some());
    let verified =
        crate::security::transparency_log::verify_log(&dir.path().join("audit.jsonl")).unwrap();
    assert!(verified.ok, "{verified:?}");
}

/// T25. A response-cache hit records the delivered value's tenants, marked
/// as a cached delivery, without data classes: a post-gate value cannot be
/// re-classified as the raw response was.
#[tokio::test]
async fn cache_hit_record_carries_delivered_tenants() {
    let dir = tempfile::tempdir().unwrap();
    let mut cached = meta(Ok(reply_naming("cust-9", "")), &dir);
    cached.cache = Some(Arc::new(crate::cache::ResponseCache::new()));
    cached.default_cache_ttl = Duration::from_secs(300);
    let meta = attributing(cached);
    let who = api_key_caller();
    for _ in 0..2 {
        meta.invoke_tool(&args_for(Some("cust-1")), None, &context(&AllowAll, &who))
            .await
            .expect("allowed call");
    }
    let all = records(&dir);
    assert_eq!(all.len(), 2, "{all:?}");
    let (miss, hit) = (&all[0], &all[1]);
    assert!(miss.get("attribution").is_none(), "{miss}");
    assert_eq!(hit["attribution"], json!("cached_delivery"), "{hit}");
    assert_eq!(hit["tenants"], sorted(&["cust-1", "cust-9"]), "{hit}");
    assert!(hit.get("data_classes").is_none(), "{hit}");
}
