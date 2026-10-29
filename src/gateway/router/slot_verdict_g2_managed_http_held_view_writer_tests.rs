// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The writer gate's rows through both writers: the equal-binding publish
//! with no custody read, a publish while custody is busy, a publish after a
//! revoke, and the control that a current binding still publishes. Uses the
//! parent's helpers.
use super::listing::fill_bound;
use super::*;

/// R2b (`remember_caller_slot`): publishing the binding the index already
/// holds is a no-op that reads no custody. Green on base (the writer reads
/// none); the fix's gate must keep this steady state free. Mutant: the gate
/// reads on every publish.
#[tokio::test]
async fn r2b_an_equal_binding_publish_reads_no_custody() {
    let fx = fixture().await;
    let old = fill_old(&fx, 1).await;
    let backend = fx.gateway.backends().get(BACKEND).expect("the backend");
    let reads = fx.gateway.resolves();
    fx.meta
        .remember_caller_slot(&backend, operator_proof(), Some(&old));
    assert_eq!(
        fx.gateway.resolves(),
        reads,
        "R2b: an equal-binding publish read custody"
    );
    assert_eq!(
        backend.caller_slot_binding(&operator_id()),
        Some(old),
        "R2b: an equal-binding publish dropped the index entry"
    );
}

/// R2b (`ColdFill::run`): a cold fill of the grant's current binding
/// publishes. Green on base; the fix reads custody before this publish and
/// must still publish when the read agrees.
#[tokio::test(start_paused = true)]
async fn r2b_a_cold_fill_of_the_current_binding_publishes() {
    let fx = fixture().await;
    let _ = rpc(&fx, 1, "tools/list", json!({})).await;
    let backend = fx.gateway.backends().get(BACKEND).expect("the backend");
    assert_eq!(
        backend.caller_slot_binding(&operator_id()),
        Some(DirectAccountGateway::operator_binding()),
        "R2b ColdFill: a cold fill of the current binding was not indexed"
    );
}

/// R2 control (row 6): after a rotation, a fill of the new binding
/// publishes it. Green on base. Mutant: a gate that refuses every changed
/// binding.
#[tokio::test]
async fn r2_control_a_fill_of_the_rotated_binding_publishes() {
    let fx = fixture().await;
    let old = fill_old(&fx, 1).await;
    let new = rotate(&fx, &old).await;
    fx.gateway.rearm_operator_slot_at_for_test(&new);
    let filled = rpc(
        &fx,
        2,
        "tools/call",
        json!({"name": "gateway_list_tools", "arguments": {"server": BACKEND}}),
    )
    .await;
    let backend = fx.gateway.backends().get(BACKEND).expect("the backend");
    assert_eq!(
        backend.caller_slot_binding(&operator_id()),
        Some(new),
        "R2 control: the rotated grant's own fill was not indexed: {filled}"
    );
}

/// R2c (`remember_caller_slot`, row 7): a publish that changes the index
/// while custody is busy is refused, the fail-closed side. RED on base: the
/// writer publishes with no read.
#[tokio::test]
async fn r2c_a_publish_while_custody_is_busy_is_not_indexed() {
    let fx = fixture().await;
    let old = fill_old(&fx, 1).await;
    let backend = fx.gateway.backends().get(BACKEND).expect("the backend");
    backend.forget_caller_principal(&operator_id());
    fx.gateway.fail_custody_for_test(true);
    fx.meta
        .remember_caller_slot(&backend, operator_proof(), Some(&old));
    fx.gateway.fail_custody_for_test(false);
    assert_eq!(
        backend.caller_slot_binding(&operator_id()),
        None,
        "R2c remember_caller_slot: a publish was indexed while custody was busy"
    );
}

/// R2c (`ColdFill::run`): a cold fill that finishes while custody is busy
/// is not published. RED on base.
#[tokio::test(start_paused = true)]
async fn r2c_a_cold_fill_finishing_while_custody_is_busy_is_not_indexed() {
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
        "premise: the cold fill is running"
    );
    fx.gateway.fail_custody_for_test(true);
    first.await.expect("the listing");
    fx.gateway.fail_custody_for_test(false);
    let backend = fx.gateway.backends().get(BACKEND).expect("the backend");
    assert!(
        backend
            .populated_per_user_bindings_for_test()
            .contains(&DirectAccountGateway::operator_binding()),
        "premise: the fill stored its slot"
    );
    assert_eq!(
        backend.caller_slot_binding(&operator_id()),
        None,
        "R2c ColdFill: a cold fill was indexed while custody was busy"
    );
}

/// Revoke-publish: after a revoke, a publish of the revoked grant's binding
/// is refused. RED on base: the writer publishes over the revocation.
#[tokio::test]
async fn a_publish_after_a_revoke_is_not_indexed() {
    let fx = fixture().await;
    let old = fill_old(&fx, 1).await;
    fx.gateway.revoke_operator_grant().await;
    let backend = fx.gateway.backends().get(BACKEND).expect("the backend");
    backend.forget_caller_principal(&operator_id());
    fx.meta
        .remember_caller_slot(&backend, operator_proof(), Some(&old));
    assert_eq!(
        backend.caller_slot_binding(&operator_id()),
        None,
        "revoke-publish: the revoked grant's binding was indexed"
    );
}
