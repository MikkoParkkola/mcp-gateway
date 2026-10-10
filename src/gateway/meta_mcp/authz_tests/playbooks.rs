// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! AUTHZ.13e and 17-19: the playbook path and its denial semantics.

use super::*;

// ===========================================================================
// AUTHZ.13e / 17 / 18 / 19 — the playbook path. This is the shape the router
// never authorized, because a playbook step's target comes from the playbook
// definition and never appears in the request the router inspects.
// ===========================================================================

/// Register a playbook and run it through the real `gateway_run_playbook`
/// entry point, so the test exercises the production path rather than the
/// engine in isolation.
async fn run_playbook_yaml(
    meta: &MetaMcp,
    yaml: &str,
    caller: &MetaMcpCallerContext<'_>,
) -> crate::Result<Value> {
    let definition: crate::playbook::PlaybookDefinition =
        serde_yaml::from_str(yaml).expect("playbook fixture must parse");
    let name = definition.name.clone();
    // Registered through the same public entry point an operator's config uses,
    // so the test drives the production path rather than a test-only seam.
    let mut engine = crate::playbook::PlaybookEngine::new();
    engine.register(definition);
    meta.set_playbook_engine(engine);
    meta.run_playbook(&json!({ "name": name, "arguments": {} }), caller)
        .await
}

#[tokio::test]
async fn authz_13e_playbook_step_denied() {
    let (registry, calls) = counted_backend("alpha");
    let meta = MetaMcp::new(registry);

    let result = run_playbook_yaml(
        &meta,
        r"
name: one_step
description: a single step against a backend
on_error: abort
steps:
  - name: read
    server: alpha
    tool: read
",
        &ctx(&DenyAll),
    )
    .await;

    assert!(
        result.is_err(),
        "a playbook step must face the caller's authorization: {result:?}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "a refused step must never reach the backend"
    );
}

#[tokio::test]
async fn authz_13e_playbook_step_allowed() {
    let (registry, calls) = counted_backend("alpha");
    let meta = MetaMcp::new(registry);

    let result = run_playbook_yaml(
        &meta,
        r"
name: one_step_ok
description: a single step against a backend
on_error: abort
steps:
  - name: read
    server: alpha
    tool: read
",
        &ctx(&AllowAll),
    )
    .await;

    assert!(result.is_ok(), "an allowed playbook must run: {result:?}");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the allow path must reach the backend, or the refusal above proves \
         nothing about authorization"
    );
}

// ===========================================================================
// AUTHZ.17-19 — denial semantics. Every fixture sets `on_error` explicitly:
// the default is `Abort`, and an `Abort` fixture passes whether or not the
// rules below hold.
// ===========================================================================

/// A refusal is not retried, and says why.
///
/// One step, so the consultation count is unambiguous: a whole-run count is
/// satisfied by a terminal refusal, and a multi-step playbook under `DenyAll`
/// denies every step, so the total could never be one even when correct.
#[tokio::test]
async fn authz_17_denial_is_not_retried() {
    let (registry, calls) = counted_backend("alpha");
    let meta = MetaMcp::new(registry);
    let counting = CountingAuthorizer::new(DenyAll);

    let result = run_playbook_yaml(
        &meta,
        r"
name: retrying
description: retries a failing step
on_error: retry
max_retries: 3
steps:
  - name: read
    server: alpha
    tool: read
",
        &ctx(&counting),
    )
    .await;

    assert_eq!(
        counting.count_for("alpha", "read"),
        1,
        "a denial must be consulted once, not once per retry attempt"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0, "no backend call");

    let value = result.expect("retry continues past a failed step");
    let errors = value
        .get("step_errors")
        .expect("a denied step must record why it failed");
    assert!(
        errors.get("read").is_some(),
        "the refusal reason must be recorded under the step's name: {errors}"
    );
}

/// An ordinary error still retries. Without this control, an implementation
/// that stopped retrying *everything* would satisfy the case above.
///
/// The failure has to be a genuine `Err`, and that is narrower than it looks:
/// a missing backend comes back as `Ok` carrying an `isError` envelope, so the
/// engine records the step as COMPLETED and the retry loop never engages. An
/// invalid tool name is rejected after the chokepoint and does return `Err`,
/// so the authorizer is consulted once per attempt.
#[tokio::test]
async fn authz_17b_ordinary_error_still_retries() {
    let registry = Arc::new(BackendRegistry::new());
    let meta = MetaMcp::new(registry);
    let counting = CountingAuthorizer::new(AllowAll);

    let result = run_playbook_yaml(
        &meta,
        r"
name: retrying_ordinary
description: retries a step whose tool name cannot be dispatched
on_error: retry
max_retries: 3
steps:
  - name: read
    server: alpha
    tool: 'bad/name'
",
        &ctx(&counting),
    )
    .await;

    assert_eq!(
        counting.count_for("alpha", "bad/name"),
        3,
        "an ordinary failure must still be retried max_retries times; only a \
         denial short-circuits"
    );
    let value = result.expect("retry continues past a failed step");
    assert!(
        value
            .get("step_errors")
            .and_then(|e| e.get("read"))
            .is_some(),
        "an ordinary failure must be explained too, not only a refusal: {value}"
    );
}

/// Under `continue`, a denied step is recorded and the run carries on to a
/// step it IS allowed to take.
///
/// The authorizer is selective on purpose. `DenyAll` would deny the successor
/// too, so the case could show only that the run did not abort — never that a
/// permitted step afterwards actually executed, which is the whole promise of
/// `continue`. The backend counter is what proves it.
#[tokio::test]
async fn authz_18_continue_records_and_runs_the_permitted_successor() {
    let (registry, calls) = counted_backend("alpha");
    let meta = MetaMcp::new(registry);

    let value = run_playbook_yaml(
        &meta,
        r"
name: continuing
description: a denied step, then one the caller is allowed to take
on_error: continue
steps:
  - name: denied
    server: alpha
    tool: blocked
  - name: allowed
    server: alpha
    tool: read
",
        &ctx(&DenyOne { tool: "blocked" }),
    )
    .await
    .expect("continue must not abort the run");

    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the permitted successor must actually have run — without this the \
         case shows only that the run did not abort"
    );

    let failed = value
        .get("steps_failed")
        .and_then(Value::as_array)
        .expect("steps_failed must be present");
    assert_eq!(failed.len(), 1, "only the denied step failed: {value}");
    assert!(
        failed.iter().any(|s| s == "denied"),
        "and it is the one that was denied: {value}"
    );

    let completed = value
        .get("steps_completed")
        .and_then(Value::as_array)
        .expect("steps_completed must be present");
    assert!(
        completed.iter().any(|s| s == "allowed"),
        "the successor must be recorded as completed: {value}"
    );

    let errors = value.get("step_errors").expect("reasons must be recorded");
    assert!(
        errors.get("denied").is_some(),
        "a partial run must explain itself, or it reads as a success: {errors}"
    );
    assert!(
        errors.get("allowed").is_none(),
        "and must not blame a step that succeeded: {errors}"
    );
}

/// A run that fails nothing serialises exactly as it did before this change.
#[tokio::test]
async fn authz_24_successful_run_omits_step_errors() {
    let (registry, _calls) = counted_backend("alpha");
    let meta = MetaMcp::new(registry);

    let value = run_playbook_yaml(
        &meta,
        r"
name: clean
description: nothing fails
on_error: abort
steps:
  - name: read
    server: alpha
    tool: read
",
        &ctx(&AllowAll),
    )
    .await
    .expect("a clean run must succeed");

    assert!(
        value.get("step_errors").is_none(),
        "a run that denies nothing must produce the JSON it produced before \
         this field existed: {value}"
    );
}

/// AUTHZ.19 — under `abort`, the run returns the denial's own code, and no
/// later step runs.
///
/// Asserting only "the run aborted" would pass for any error; the code is what
/// pins it to a refusal.
#[tokio::test]
async fn authz_19_abort_returns_the_denial_itself() {
    let (registry, calls) = counted_backend("alpha");
    let meta = MetaMcp::new(registry);

    let result = run_playbook_yaml(
        &meta,
        r"
name: aborting
description: a denied step followed by one that must not run
on_error: abort
steps:
  - name: denied
    server: alpha
    tool: read
  - name: never_runs
    server: alpha
    tool: write
",
        &ctx(&DenyAll),
    )
    .await;

    let err = result.expect_err("abort must surface the failure");
    assert!(
        matches!(err, crate::Error::Forbidden { .. }),
        "the run must return the denial, not a generic failure: {err:?}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "neither the denied step nor the one after it may dispatch"
    );
}

/// AUTHZ.18a — an ordinary failure is explained too, not only a refusal.
///
/// A fix that recorded refusals alone would leave a `continue` caller with an
/// unexplained null for every other kind of failure, which is the defect
/// `step_errors` exists to close.
#[tokio::test]
async fn authz_18a_ordinary_failure_is_also_recorded() {
    let registry = Arc::new(BackendRegistry::new());
    let meta = MetaMcp::new(registry);

    let value = run_playbook_yaml(
        &meta,
        r"
name: continuing_ordinary
description: an ordinary failure under continue
on_error: continue
steps:
  - name: bad
    server: alpha
    tool: 'bad/name'
",
        &ctx(&AllowAll),
    )
    .await
    .expect("continue must not abort the run");

    let errors = value
        .get("step_errors")
        .expect("an ordinary failure must be explained");
    assert!(
        errors.get("bad").is_some(),
        "and recorded under the step's own name: {errors}"
    );
}

/// AUTHZ.6 / 6a — a step skipped by its condition is never authorized.
///
/// The counting authorizer carries both halves: zero consultations for the
/// skipped step AND exactly one for the step that runs. A zero on its own is
/// satisfied by an authorizer that is never called at all.
#[tokio::test]
async fn authz_6a_skipped_step_is_never_authorized() {
    let (registry, _calls) = counted_backend("alpha");
    let meta = MetaMcp::new(registry);
    let counting = CountingAuthorizer::new(AllowAll);

    let value = run_playbook_yaml(
        &meta,
        r"
name: conditional
description: one skipped step and one that runs
on_error: continue
steps:
  - name: skipped
    server: forbidden_backend
    tool: never
    condition: 'false'
  - name: runs
    server: alpha
    tool: read
",
        &ctx(&counting),
    )
    .await
    .expect("the run must complete");

    assert_eq!(
        counting.count_for("forbidden_backend", "never"),
        0,
        "a step whose condition excluded it must never be authorized — \
         refusing a playbook for a step that would not have run is a \
         regression invented by the fix"
    );
    assert_eq!(
        counting.count_for("alpha", "read"),
        2,
        "and the step that does run is authorized at its invocation and \
         re-checked once at the dispatch chokepoint (MIK-8137 b1)"
    );

    let skipped = value
        .get("steps_skipped")
        .and_then(Value::as_array)
        .expect("steps_skipped must be present");
    assert!(
        skipped.iter().any(|s| s == "skipped"),
        "the step must actually have been skipped, not merely absent: {value}"
    );
}

/// MIK-8341 INV (mutant m6): a playbook step never inherits the run's retry
/// fields. `gateway_run_playbook` refuses them at the dispatcher (D3), so this
/// drives `run_playbook` directly with a caller carrying a `requestState` and
/// an `inputResponses`: a step that inherited either would be dispatched as a
/// continuation retry and refused; a step with its own empty retry runs.
/// Red on base: the step inherits the outer caller's retry fields.
#[tokio::test]
async fn mik_8341_a_step_never_inherits_the_runs_retry_fields() {
    for (field, retry) in [
        (
            "requestState",
            crate::protocol::mrtr::RetryFields {
                request_state: Some("not-a-continuation-of-ours".into()),
                ..Default::default()
            },
        ),
        (
            "inputResponses",
            crate::protocol::mrtr::RetryFields {
                input_responses: Some(json!({"k1": {"action": "accept"}})),
                ..Default::default()
            },
        ),
    ] {
        let (registry, calls) = counted_backend("alpha");
        let meta = MetaMcp::new(registry);
        let allowed = ctx(&AllowAll);
        let result = run_playbook_yaml(
            &meta,
            r"
name: inherits
description: one plain step
on_error: abort
steps:
  - name: read
    server: alpha
    tool: read
",
            &allowed.with_retry(&retry),
        )
        .await;
        assert!(
            result.is_ok(),
            "{field}: the step inherited the run's retry field: {result:?}"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "{field}: the step did not run"
        );
    }
}

/// MIK-8341 D3 site (b) (mutant m9): synchronous admission refuses a playbook
/// run carrying retry fields BEFORE it reserves anything. HTTP and stdio admit
/// before the dispatcher's own check, so without this a refused retry could
/// reserve a round or meet a capacity error first. Red on base: admitted.
#[test]
fn mik_8341_admission_refuses_a_playbook_retry_before_reserving() {
    let (registry, _calls) = counted_backend("alpha");
    let meta = MetaMcp::new(registry);
    let mut engine = crate::playbook::PlaybookEngine::new();
    engine.register(
        serde_yaml::from_str(
            "name: any\ndescription: d\nsteps:\n  - {name: read, server: alpha, tool: read}\n",
        )
        .expect("playbook fixture must parse"),
    );
    meta.set_playbook_engine(engine);
    let retry = crate::protocol::mrtr::RetryFields {
        idempotency_key: Some("pk-admit".into()),
        input_responses: Some(json!({})),
        ..Default::default()
    };
    // The refused call has NO execution owner, so a refusal placed after
    // `admit_operation` would surface as its -32003 instead (grok c2).
    let allowed = ctx(&AllowAll);
    let caller = allowed.with_retry(&retry);
    let admitted = meta.admit_meta_sync(
        crate::gateway::meta_mcp::AdmissionOwner::for_test(caller.owner_principal()),
        &caller,
        "gateway_run_playbook",
        &json!({"name": "any"}),
        None,
        &crate::protocol::RequestId::Number(1),
    );
    match admitted {
        Err(crate::Error::JsonRpc { code, message, .. }) => {
            assert_eq!(code, -32602, "{message}");
            assert!(message.contains("no continuation to resume"), "{message}");
        }
        Err(other) => panic!("admission refused for another reason: {other}"),
        Ok(_) => panic!("admission admitted the playbook retry before refusing it"),
    }
    assert_eq!(
        meta.execution_admission().snapshot().entries,
        0,
        "the refused retry reserved a round"
    );
    // grok c1: nothing was reserved. The honest call under the same key is
    // admitted as the key's first owner, not met as a round in flight.
    let honest = crate::protocol::mrtr::RetryFields {
        idempotency_key: Some("pk-admit".into()),
        ..Default::default()
    };
    let mut owned = ctx(&AllowAll);
    owned.credential_principal = Some("cred:mik-8341");
    let caller = owned.with_retry(&honest);
    let admitted = meta.admit_meta_sync(
        crate::gateway::meta_mcp::AdmissionOwner::for_test(caller.owner_principal()),
        &caller,
        "gateway_run_playbook",
        &json!({"name": "any"}),
        None,
        &crate::protocol::RequestId::Number(2),
    );
    match admitted {
        Ok(crate::gateway::meta_mcp::admission::SyncAdmission::Owned(_)) => {}
        Ok(crate::gateway::meta_mcp::admission::SyncAdmission::Unprotected) => {
            panic!("setup: the honest call is unprotected")
        }
        Ok(crate::gateway::meta_mcp::admission::SyncAdmission::Replay(..)) => {
            panic!("the refused retry left a stored round")
        }
        Err(error) => panic!("the refused retry left the key reserved: {error}"),
    }
}
