// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8439 R1b (MIK-8361.NOVIEW.1, hosted connect offer): a bridged caller
//! whose account was never connected has no view of the per-user backend.
//! A tool other callers pushed into error-rate cooldown gets the hosted
//! connect offer a missing name gets: the same `accounts.v1` payload, the
//! same account, the same journey. Uses the parent's fixture.

use super::*;

const COOLING: &str = "list_files";
const MISSING: &str = "no_such_tool";

/// `gateway_invoke` of `tool` on the bound backend as the bridged `alice`.
async fn invoke_named(gw: &Gateway, tool: &str) -> Value {
    let args = json!({"server": BACKEND, "tool": tool, "arguments": {}});
    let params = json!({"name": "gateway_invoke", "arguments": args});
    rpc(
        gw,
        "/mcp",
        Caller::Bridged,
        "alice",
        &call("tools/call", &params),
    )
    .await
}

/// R1b (red first): both twins carry the hosted offer (`offered` checks the
/// payload's schema, account and not-connected code) and are byte-equal
/// once the names are factored out. RED at base: admission answers the
/// cooldown text, naming the tool, with no offer.
#[tokio::test]
async fn r1b_noview_cooldown_twin_gets_the_hosted_offer() {
    let gw = gateway(Shape::Bridged).await;
    let kill_switch = gw.meta.kill_switch();
    let cfg = crate::kill_switch::CapabilityErrorBudgetConfig::default();
    for _ in 0..=cfg.window_size.max(cfg.min_samples) {
        kill_switch.record_capability_failure(BACKEND, COOLING, &cfg);
    }
    assert!(
        kill_switch.is_capability_disabled(BACKEND, COOLING),
        "premise: {COOLING} is in cooldown"
    );
    let missing = invoke_named(&gw, MISSING).await;
    let missing_url = offered(&missing, "account_not_connected");
    let cooling = invoke_named(&gw, COOLING).await;
    assert!(
        !cooling.to_string().contains("temporarily disabled"),
        "R1b: the cooldown named the tool: {cooling}"
    );
    assert_eq!(
        offered(&cooling, "account_not_connected"),
        missing_url,
        "R1b: one journey for both twins"
    );
    assert_eq!(
        cooling.to_string().replace(COOLING, "<tool>"),
        missing.to_string().replace(MISSING, "<tool>"),
        "R1b: in cooldown vs missing"
    );
}
