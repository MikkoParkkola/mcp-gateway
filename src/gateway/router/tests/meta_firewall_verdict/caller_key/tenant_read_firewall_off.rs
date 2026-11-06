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
/// and its delivery record says `blocked`; the same on `/mcp/{name}`.
#[tokio::test]
async fn block_withholds_with_the_firewall_off() {
    let who = caller();
    let (state, _store, log_dir) =
        logged_state_switched(Switch::Off, CrossTenantReads::Block).await;
    let router = create_router(state);
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

    let (state, _store, log_dir) =
        logged_state_switched(Switch::Off, CrossTenantReads::Block).await;
    let direct = create_router(state);
    let (a, _, body) = send(&direct, call_with(&who, true, None, 0, &reading(A))).await;
    assert_eq!(a, Delivered, "{body}");
    let (b, _, body) = send(&direct, direct_call_with("key-one", 1, &reading(B))).await;
    assert_ne!(
        b, Delivered,
        "block withholds B on /mcp/demo with the firewall off: {body}"
    );
    let verdict = deliveries_naming(&log_dir, B);
    assert_eq!(
        verdict.len(),
        1,
        "one direct-route delivery record for B: {verdict:#?}"
    );
    assert_eq!(
        record_field(&verdict[0], "cross_tenant_read"),
        Some("blocked"),
        "{}",
        verdict[0]
    );
}

/// Firewall off, `observe`: B is delivered and its delivery record says
/// `flagged`.
#[tokio::test]
async fn observe_flags_with_the_firewall_off() {
    let who = caller();
    let (state, _store, log_dir) =
        logged_state_switched(Switch::Off, CrossTenantReads::Observe).await;
    let router = create_router(state);
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
    let (state, _store, log_dir) = logged_state_switched(Switch::Off, CrossTenantReads::Off).await;
    let router = create_router(state);
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

/// One caller reads A, then B, on `POST /mcp`: whether each delivers a
/// result, and the verdicts on the delivery records, in order. The same
/// shape as the stdio driver's, for the side-by-side row.
async fn http_a_then_b(switch: Switch, mode: CrossTenantReads) -> ([bool; 2], Vec<String>) {
    let who = caller();
    let (state, _store, log_dir) = logged_state_switched(switch, mode).await;
    let router = create_router(state);
    let mut delivered = [false; 2];
    for (n, tenant) in [A, B].into_iter().enumerate() {
        let (got, _, _) = send(&router, call_with(&who, true, None, n, &reading(tenant))).await;
        delivered[n] = got == Delivered;
    }
    let verdicts = log_lines(&log_dir)
        .iter()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|r| record_field(r, "event") == Some("response_delivery_attempt"))
        .filter_map(|r| record_field(&r, "cross_tenant_read").map(str::to_owned))
        .collect();
    (delivered, verdicts)
}

/// HTTP and stdio side by side: the same config (`arg_keys: [customer_id]`,
/// one hour, the mode) and the same arguments (`customer_id` A, then B) give
/// the same deliveries and the same recorded verdicts, firewall on and off.
#[tokio::test]
async fn http_and_stdio_make_the_same_verdict() {
    use crate::gateway::server::route_matrix_driver_tests::read_verdict as stdio;
    for (switch, stdio_switch) in [
        (Switch::On, stdio::Switch::On),
        (Switch::Off, stdio::Switch::Off),
    ] {
        for mode in [
            CrossTenantReads::Off,
            CrossTenantReads::Observe,
            CrossTenantReads::Block,
        ] {
            let http = http_a_then_b(switch, mode).await;
            let stdio = stdio::a_then_b(stdio_switch, mode).await;
            assert_eq!(http, stdio, "{switch:?} {mode:?}: HTTP vs stdio");
            assert!(http.0[0], "{switch:?} {mode:?}: premise: A is delivered");
        }
    }
}
