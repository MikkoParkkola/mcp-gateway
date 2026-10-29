// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8356 test plan r3, L8: a managed caller's name-only listing judges
//! its caller-slot index entry against the CURRENT grant. The fixture is the
//! managed-account one (production compile, install and real custody); the
//! listing is `gateway_list_disabled_capabilities`, driven through
//! `handle_tools_call`, the async entry where the non-minting current-grant
//! lookup (`VaultStrategy::view_binding`) runs before the sync reader.

use serde_json::{Value, json};

use super::*;

const SERVER: &str = "mail";
const TOOL: &str = "read";
const FRESH: u64 = u64::MAX;

/// alice's managed gateway: `SERVER` bound to [`WORK`], alice's grant seeded,
/// and the shared slot holding a valid [`TOOL`].
fn managed() -> (
    crate::security::transparency_log::temp::TempLog,
    MetaMcp,
    Custody,
) {
    let custody = custody_with(&[(account_key("alice", WORK), grant(ALICE_WORK_TOKEN, FRESH))]);
    let (log, meta, _dispatches) = gateway(
        &[(SERVER, Bind::Account(WORK))],
        &Descriptors::same(&[WORK]),
        &custody.installed(),
        &slots(&[("alice", WORK)]),
    );
    meta.set_multi_user(true);
    let tool: crate::protocol::Tool = serde_json::from_value(json!({
        "name": TOOL, "inputSchema": {"type": "object", "properties": {"folder": {"type": "string"}}}
    }))
    .expect("a tool");
    meta.backends
        .for_test()
        .get(SERVER)
        .expect("the backend")
        .store_shared_tools_for_test(vec![tool]);
    (log, meta, custody)
}

/// Disable [`TOOL`] by its error budget, so the disabled list has an entry
/// to name. After this, a call of [`TOOL`] is refused.
fn disable_tool(meta: &MetaMcp) {
    let cfg = meta.capability_budget_config.read().clone();
    for _ in 0..=cfg.window_size.max(cfg.min_samples) {
        meta.kill_switch
            .record_capability_failure(SERVER, TOOL, &cfg);
    }
}

/// alice lists `SERVER` through `gateway_list_tools`: a real fill of her own
/// slot, the way it becomes warm (and indexed).
async fn warm_alice(meta: &MetaMcp) {
    let alice = identity("alice");
    meta.list_tools(
        &json!({"server": SERVER}),
        None,
        &caller_as(Some(&alice), None),
    )
    .await
    .expect("gateway_list_tools answers");
}

/// Whether alice's `gateway_list_disabled_capabilities` names [`TOOL`].
async fn disabled_names_tool(meta: &MetaMcp) -> bool {
    let alice = identity("alice");
    let response = Box::pin(meta.handle_tools_call(
        crate::protocol::RequestId::Number(1),
        "gateway_list_disabled_capabilities",
        json!({}),
        None,
        caller_as(Some(&alice), None),
    ))
    .await;
    let answer = serde_json::to_value(&response).expect("a response serialises");
    let text = answer
        .pointer("/result/content/0/text")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("premise: the disabled list answers: {answer}"));
    let listed: Value = serde_json::from_str(text).expect("the disabled list is JSON");
    listed["disabled_capabilities"]
        .as_array()
        .unwrap_or_else(|| panic!("premise: a disabled list: {listed}"))
        .iter()
        .any(|entry| entry["capability"] == TOOL)
}

/// L8a (absence): alice's warm slot is indexed under her grant's binding;
/// the grant is then revoked and reconnected under a new generation, so the
/// current-grant lookup no longer yields the indexed binding, while the old
/// slot still holds its list. The listing withholds [`TOOL`]. RED on base:
/// the disabled list judges the shared slot (valid) and names it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn managed_index_entry_checked_against_current_grant() {
    let (_log, meta, custody) = managed();
    warm_alice(&meta).await;
    disable_tool(&meta);
    assert!(
        disabled_names_tool(&meta).await,
        "L8 premise: alice's current grant is not named her own disabled tool"
    );
    let seeded = grant(ALICE_WORK_TOKEN, FRESH);
    revoke_and_reconnect(
        &custody,
        &account_key("alice", WORK),
        &seeded,
        ROTATED_TOKEN,
    )
    .await;
    let indexed = expected_identity_key("alice", WORK, SEEDED_REVISION);
    let backend = meta.backends.for_test().get(SERVER).expect("the backend");
    assert!(
        backend
            .populated_per_user_bindings_for_test()
            .contains(&indexed),
        "L8 premise: the rotation evicted the old slot, so this is not the grant check"
    );
    assert!(
        !disabled_names_tool(&meta).await,
        "L8: a rotated grant's stale index entry still names the tool"
    );
}

/// L8b (guard): a warm name-only listing mints nothing. Custody's release
/// count stands in for `VaultStrategy::prepare_held_classified` (every `prepare`
/// releases; `view_binding` only resolves), so it stays at its baseline.
/// The control runs first, while [`TOOL`] is still callable: a managed call
/// that resolves a credential moves the counter. Green on base.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn managed_listing_lookup_is_non_minting() {
    let (_log, meta, custody) = managed();
    warm_alice(&meta).await;
    let before = custody.releases();
    Box::pin(execute(&meta, SERVER, Some(&identity("alice"))))
        .await
        .expect("control: alice's managed call succeeds");
    assert_eq!(
        custody.releases(),
        before + 1,
        "L8b control: a managed call releases once"
    );
    disable_tool(&meta);
    let baseline = custody.releases();
    assert!(
        disabled_names_tool(&meta).await,
        "L8b premise: the warm listing names alice's disabled tool"
    );
    assert_eq!(
        custody.releases(),
        baseline,
        "L8b: the name-only listing released a credential"
    );
}
