// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The cross-tenant read verdict runs on its own switch: with
//! `security.firewall.enabled: false` and `arg_keys` set, `block` still
//! withholds and `observe` still flags on HTTP. Pins: a change tying the
//! verdict to the firewall switch turns these red. A child of `tenant_reads`,
//! sharing its fixture.

use super::*;

/// The `response_delivery_attempt` records naming `tenant`'s hash.
fn deliveries_naming(log_dir: &tempfile::TempDir, tenant: &str) -> Vec<Value> {
    let hash = hash_argument(&json!(tenant));
    log_lines(log_dir)
        .iter()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|r| {
            record_field(r, "event") == Some("response_delivery_attempt")
                && r.to_string().contains(&hash)
        })
        .collect()
}

/// Firewall off, `block`: after A, a B answer on `POST /mcp` is the refusal
/// and its delivery record says `blocked`; a B answer on `/mcp/{name}` is
/// refused too.
#[tokio::test]
async fn block_withholds_with_the_firewall_off() {
    let who = caller();
    let (router, _store, log_dir) =
        logged_router_switched(Switch::Off, CrossTenantReads::Block).await;
    let (a, _, body) = send(&router, call_with(&who, true, None, 0, &reading(A))).await;
    assert_eq!(a, Delivered, "the first tenant is ordinary: {body}");
    let (b, _, body) = send(&router, call_with(&who, true, None, 1, &reading(B))).await;
    assert_ne!(
        b, Delivered,
        "block withholds B with the firewall off: {body}"
    );
    assert!(
        body.to_string().contains("Response withheld"),
        "the refusal is the read verdict's: {body}"
    );
    let verdict = deliveries_naming(&log_dir, B);
    assert_eq!(verdict.len(), 1, "one delivery record for B: {verdict:#?}");
    assert_eq!(
        record_field(&verdict[0], "cross_tenant_read"),
        Some("blocked"),
        "{}",
        verdict[0]
    );

    let (state, _store) =
        switched_state(Switch::Off, CrossTenantReads::Block, 3600, &["customer_id"]).await;
    let direct = create_router(state);
    let (a, _, body) = send(&direct, call_with(&who, true, None, 0, &reading(A))).await;
    assert_eq!(a, Delivered, "{body}");
    let (b, _, body) = send(&direct, direct_call_with("key-one", 1, &reading(B))).await;
    assert_ne!(
        b, Delivered,
        "block withholds B on /mcp/demo with the firewall off: {body}"
    );
}

/// Firewall off, `observe`: B is delivered and its delivery record says
/// `flagged`.
#[tokio::test]
async fn observe_flags_with_the_firewall_off() {
    let who = caller();
    let (router, _store, log_dir) =
        logged_router_switched(Switch::Off, CrossTenantReads::Observe).await;
    for (n, tenant) in [A, B].into_iter().enumerate() {
        let (got, _, body) = send(&router, call_with(&who, true, None, n, &reading(tenant))).await;
        assert_eq!(got, Delivered, "observe never withholds {tenant}: {body}");
    }
    let verdict = deliveries_naming(&log_dir, B);
    assert_eq!(verdict.len(), 1, "one delivery record for B: {verdict:#?}");
    assert_eq!(
        record_field(&verdict[0], "cross_tenant_read"),
        Some("flagged"),
        "{}",
        verdict[0]
    );
}

/// Control: firewall off, `cross_tenant_reads: off`: nothing is judged.
#[tokio::test]
async fn mode_off_judges_nothing_with_the_firewall_off() {
    let who = caller();
    let (router, _store, log_dir) =
        logged_router_switched(Switch::Off, CrossTenantReads::Off).await;
    for (n, tenant) in [A, B].into_iter().enumerate() {
        let (got, _, body) = send(&router, call_with(&who, true, None, n, &reading(tenant))).await;
        assert_eq!(got, Delivered, "off delivers {tenant}: {body}");
    }
    let lines = log_lines(&log_dir);
    assert!(
        !lines.iter().any(|l| l.contains("cross_tenant_read")),
        "mode off writes no verdict: {lines:#?}"
    );
}
