// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8407 design r4 C6: a capability dispatch the meta route resolved
//! (and recorded) as minting nothing per caller never mints in the executor.
//! An account bound between the two is refused before HTTP; the record would
//! otherwise name a binding the output was not produced under.

use super::*;

/// The context the meta route hands the executor after resolving no
/// per-caller account: no credential, resolved by the caller.
fn resolved_none(subject: &str) -> crate::capability::CapabilityExecutionContext {
    let mut context = context(Some(subject));
    context.account_resolution = crate::capability::AccountResolution::ByCaller(None);
    context
}

/// RB-exec-choice (mutant M-exec): the definition now names a managed
/// account, the meta route resolved none: refused, nothing reaches the peer.
/// Control: the same call resolved in the executor is served.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rb_exec_choice_an_account_bound_after_resolve_is_refused_before_http() {
    let (port, captured) = capture_endpoint().await;
    let custody = custody_with(&[(account_key("alice", WORK), grant(ALICE_WORK_TOKEN, FRESH))]);
    let installed: Arc<dyn AccountCustody> = custody.installed();
    let (_log, _meta, registry) = installed_gateway(&[(WORK, managed(WORK))], &installed);
    let backend = backend_with(
        &registry,
        capability(&base_url(port), "oauth:google", Some(WORK)),
    )
    .expect("the capability registers");

    let refused = backend
        .call_tool_with_context(TOOL, json!({}), resolved_none("alice"))
        .await
        .expect_err("RB-exec-choice: dispatched under an account resolved as none");
    assert!(
        refused.to_string().contains("different account"),
        "RB-exec-choice: not the binding refusal: {refused}"
    );
    assert!(
        captured.authorizations().is_empty(),
        "RB-exec-choice: the peer was reached"
    );

    call(&backend, Some("alice"))
        .await
        .expect("RB-exec-choice control: the executor's own resolution serves");
    assert_eq!(captured.authorizations().len(), 1, "control: one send");
}
