// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! One rule for "is this caller's held view current for this request": a
//! listing's own account read decides it, and a publish of a superseded
//! grant's binding never becomes a listing view. Rows forced with the
//! `after_revalidate` seam and the backend's test pauses, never a sleep for
//! ordering. Seam rows run on a current-thread runtime: the seam is the
//! thread's. Uses the parent's fixture.
use super::listing::{fill_bound, is_shared_schema, surfaced_on};
use super::*;
use crate::gateway::meta_mcp::visible::seams;
use crate::identity_propagation::{CallerProof, CallerProvenance};

/// The proof an API-key request of the sole operator carries.
fn operator_proof() -> CallerProof<'static> {
    CallerProof::Operator(CallerProvenance::Credential)
}

/// The sole operator's index key on every managed backend.
fn operator_id() -> String {
    crate::personal_accounts::identity::Principal::SoleOperator.stable_actor_id()
}

/// Warm the operator's own slot under the seeded (old) grant with a real
/// `gateway_list_tools` fill, and return that old binding.
async fn fill_old(fx: &Fx, id: u64) -> String {
    let filled = rpc(
        fx,
        id,
        "tools/call",
        json!({"name": "gateway_list_tools", "arguments": {"server": BACKEND}}),
    )
    .await;
    let old = DirectAccountGateway::operator_binding();
    let backend = fx.gateway.backends().get(BACKEND).expect("the backend");
    assert_eq!(
        backend.caller_slot_binding(&operator_id()),
        Some(old.clone()),
        "premise: a real fill indexed the old grant's slot: {filled}"
    );
    old
}

/// The binding the vault reads for the operator now.
async fn current_binding(fx: &Fx) -> String {
    fx.state
        .meta_mcp
        .account_strategies()
        .managed_vault(Some("work-gmail"))
        .expect("the managed vault")
        .view_binding(crate::personal_accounts::identity::Principal::SoleOperator)
        .await
        .expect("premise: the grant has a view")
}

/// Rotate the operator's grant; returns the new binding, which differs.
async fn rotate(fx: &Fx, old: &str) -> String {
    fx.gateway.rotate_operator_grant().await;
    let new = current_binding(fx).await;
    assert_ne!(new, old, "premise: rotation selects a new slot");
    new
}

/// Register a seam hook that publishes `old` for the operator through the
/// production writer, and return the flag it sets when it fires.
fn publish_old_after_revalidate(
    fx: &Arc<Fx>,
    old: &str,
    before: impl FnOnce(&Fx) + 'static,
) -> Arc<std::sync::atomic::AtomicBool> {
    let fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (fx, old, flag) = (Arc::clone(fx), old.to_owned(), Arc::clone(&fired));
    seams::after_revalidate(move || {
        before(&fx);
        let backend = fx.gateway.backends().get(BACKEND).expect("the backend");
        fx.meta
            .remember_caller_slot(&backend, operator_proof(), Some(&old));
        flag.store(true, std::sync::atomic::Ordering::SeqCst);
    });
    fired
}

/// Every JSON value inside `value`, with JSON carried as a string (a meta
/// tool's text content) parsed and walked too.
fn walk(value: &Value, out: &mut Vec<Value>) {
    match value {
        Value::String(text) => {
            if let Ok(inner) = serde_json::from_str::<Value>(text)
                && (inner.is_object() || inner.is_array())
            {
                walk(&inner, out);
            }
        }
        Value::Array(items) => items.iter().for_each(|item| walk(item, out)),
        Value::Object(map) => {
            out.push(value.clone());
            map.values().for_each(|item| walk(item, out));
        }
        _ => {}
    }
}

/// `server`'s entry in a `gateway_list_servers` answer.
fn server_entry(answer: &Value, server: &str) -> Value {
    let mut all = Vec::new();
    walk(answer, &mut all);
    all.into_iter()
        .find(|entry| {
            entry.get("name") == Some(&json!(server)) && entry.get("tools_known").is_some()
        })
        .unwrap_or_else(|| panic!("premise: gateway_list_servers lists {server}: {answer}"))
}

async fn list_servers(fx: &Fx, id: u64) -> Value {
    rpc(
        fx,
        id,
        "tools/call",
        json!({"name": "gateway_list_servers", "arguments": {}}),
    )
    .await
}

/// R1, the falsifier: a name-only listing runs its account re-check after a
/// rotation, then a call resolved under the old grant publishes the old
/// binding before the listing reads. The listing must not present the old
/// grant's catalogue: the backend's tools are not known to this caller.
/// RED on base: with no account binding recorded in the request, the held
/// slot stands.
#[tokio::test]
async fn r1_a_publish_of_the_old_grant_after_the_listings_check_is_not_listed() {
    let fx = Arc::new(fixture().await);
    let old = fill_old(&fx, 1).await;
    rotate(&fx, &old).await;
    let fired = publish_old_after_revalidate(&fx, &old, |_| {});
    let answer = list_servers(&fx, 2).await;
    assert!(
        fired.load(std::sync::atomic::Ordering::SeqCst),
        "premise: the after_revalidate seam fired and the old publish ran"
    );
    let entry = server_entry(&answer, BACKEND);
    assert_eq!(
        entry.get("tools_known"),
        Some(&json!(false)),
        "R1: gateway_list_servers presented the old grant's catalogue after the rotation: {entry}"
    );
}

/// R2 through `remember_caller_slot`: a `gateway_list_tools` fill resolved
/// under the old grant is held mid-fetch while the grant rotates; its publish
/// of the old binding must not be indexed. The call's own answer stands.
/// RED on base: the writer publishes whatever binding its call resolved.
#[tokio::test(start_paused = true)]
async fn r2_a_direct_publish_of_the_old_grant_after_a_rotation_is_not_indexed() {
    let fx = Arc::new(fixture().await);
    let bound = fill_bound(&fx, BACKEND);
    fx.gateway.delay_lists_on(BACKEND, bound / 2);
    let call = tokio::spawn({
        let fx = Arc::clone(&fx);
        async move {
            rpc(
                &fx,
                1,
                "tools/call",
                json!({"name": "gateway_list_tools", "arguments": {"server": BACKEND}}),
            )
            .await
        }
    });
    tokio::time::sleep(bound / 4).await;
    assert_eq!(
        fx.gateway.lists_to(BACKEND),
        1,
        "premise: the old grant's fetch is running"
    );
    let old = DirectAccountGateway::operator_binding();
    rotate(&fx, &old).await;
    let answer = call.await.expect("the call");
    assert!(
        answer.get("result").is_some(),
        "premise: the call's own answer stands: {answer}"
    );
    let backend = fx.gateway.backends().get(BACKEND).expect("the backend");
    assert_ne!(
        backend.caller_slot_binding(&operator_id()),
        Some(old),
        "R2 remember_caller_slot: the old grant's binding was indexed after the rotation"
    );
}

/// R2 through `ColdFill::run`: a listing's cold fill claimed under the old
/// grant finishes after the rotation; its publish must not be indexed. No
/// listing runs in between, so no re-check forgets it. RED on base.
#[tokio::test(start_paused = true)]
async fn r2_a_cold_fill_publish_of_the_old_grant_after_a_rotation_is_not_indexed() {
    let fx = Arc::new(fixture().await);
    let bound = fill_bound(&fx, BACKEND);
    fx.gateway.delay_lists_on(BACKEND, bound / 2);
    let first = tokio::spawn({
        let fx = Arc::clone(&fx);
        async move { rpc(&fx, 1, "tools/list", json!({})).await }
    });
    tokio::time::sleep(bound / 4).await;
    assert_eq!(
        fx.gateway.lists_to(BACKEND),
        1,
        "premise: the old grant's cold fill is running"
    );
    let old = DirectAccountGateway::operator_binding();
    rotate(&fx, &old).await;
    first.await.expect("the first listing");
    let backend = fx.gateway.backends().get(BACKEND).expect("the backend");
    assert!(
        backend
            .populated_per_user_bindings_for_test()
            .contains(&old),
        "premise: the old fill stored its slot"
    );
    assert_ne!(
        backend.caller_slot_binding(&operator_id()),
        Some(old),
        "R2 ColdFill: the old grant's binding was indexed after the rotation"
    );
}

#[path = "slot_verdict_g2_managed_http_held_view_more_tests.rs"]
mod more;
