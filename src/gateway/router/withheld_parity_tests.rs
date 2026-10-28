// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8340 rows on `/mcp` (test plan r2.1): a surfaced tool withheld from
//! the caller answers exactly as the same name does where it is absent.
//! Every expected answer is computed live from the absent twin
//! (`withheld_twin_tests`); a failed premise panics "premise".

use serde_json::{Value, json};

use super::withheld_twin_tests::{
    Absence, Answered, Reason, Side, Spec, assert_call_premise, twin,
};

/// The reasons a call row runs on `/mcp`. Grant has its own fixture (row 7).
const REASONS: [Reason; 3] = [Reason::Policy, Reason::Schema, Reason::Descriptor];

/// Assert `withheld` answered exactly as `absent`: HTTP status and the whole
/// body (code, message, `data`).
fn assert_same(row: &str, reason: Reason, withheld: &Answered, absent: &Answered) {
    if let Some(mismatch) = mismatch(row, reason, withheld, absent) {
        panic!("{mismatch}");
    }
}

/// The cell's mismatch, when `withheld` did not answer exactly as `absent`.
fn mismatch(row: &str, reason: Reason, withheld: &Answered, absent: &Answered) -> Option<String> {
    ((withheld.status, &withheld.body) != (absent.status, &absent.body)).then(|| {
        format!(
            "{row} ({reason:?}): withheld {} {} vs absent {} {}",
            withheld.status, withheld.body, absent.status, absent.body
        )
    })
}

/// Fail with every collected cell, so a red run publishes each cell's answer.
fn assert_cells(row: &str, cells: &[String]) {
    assert!(cells.is_empty(), "{row}:\n{}", cells.join("\n"));
}

/// Send `extra` on a modern call of the spec's tool to the withheld fixture
/// and its `NotSurfaced` twin, after the call premise. Returns both answers
/// and the withheld twin's request audit rows naming the tool.
async fn modern_pair(spec: Spec, extra: &Value) -> (Answered, Answered, Vec<Value>) {
    assert_call_premise(spec).await;
    let withheld = twin(spec.with_side(Side::Withheld)).await;
    let absent = twin(spec.with_side(Side::Absent(Absence::NotSurfaced))).await;
    let w = withheld.call_modern(spec.tool, extra).await;
    let a = absent.call_modern(spec.tool, extra).await;
    let rows = withheld
        .audit_rows("request")
        .into_iter()
        .filter(|row| row["tool"] == spec.tool)
        .collect();
    (w, a, rows)
}

/// Row 1 (ORACLE.1): a bogus `requestState` on a withheld name answers as on
/// an absent one, and the withheld call leaves no request audit row (the
/// route targets never resolved it). RED on base.
#[tokio::test]
async fn row1_bogus_request_state_answers_as_absent() {
    let mut cells = Vec::new();
    for reason in REASONS {
        let spec = Spec::of(reason, Side::Withheld);
        let extra = json!({"requestState": "not-an-envelope"});
        let (withheld, absent, requests) = Box::pin(modern_pair(spec, &extra)).await;
        cells.extend(mismatch("row 1", reason, &withheld, &absent));
        if !requests.is_empty() {
            cells.push(format!(
                "row 1 ({reason:?}): request audit rows {requests:?}"
            ));
        }
        assert_eq!(withheld.calls, 0, "row 1 ({reason:?}): {}", withheld.body);
    }
    assert_cells("row 1", &cells);
}

/// Row 3 (ORACLE.1): `inputResponses` with no `requestState` on a withheld
/// name answers as on an absent one. RED on base (P3's route stage answers
/// -32601 before the unsolicited-answer check).
#[tokio::test]
async fn row3_unsolicited_answers_answer_as_absent() {
    let spec = Spec::of(Reason::Policy, Side::Withheld);
    let extra = json!({"inputResponses": {"k1": {"action": "accept", "content": {}}}});
    let (withheld, absent, _) = Box::pin(modern_pair(spec, &extra)).await;
    assert_same("row 3", Reason::Policy, &withheld, &absent);
}

/// Row 2 (ORACLE.1): a well-formed envelope this caller was minted for
/// another call (the asking tool's question) answers on a withheld name as
/// on an absent one. RED on base.
/// The envelope names its server, so the absent twin reaches the policy check
/// and answers 403 "blocked by client policy"; after the fix the withheld name
/// answers that same 403.
#[tokio::test]
async fn row2_envelope_for_another_call_answers_as_absent() {
    use super::withheld_twin_tests::ASKING;
    let spec = Spec::of(Reason::Policy, Side::Withheld);
    assert_call_premise(spec).await;
    let mut answers = Vec::new();
    for side in [Side::Withheld, Side::Absent(Absence::NotSurfaced)] {
        let fx = twin(spec.with_side(side)).await;
        let asked = fx.call_modern(ASKING, &json!({})).await;
        let envelope = asked.body["result"]["requestState"].clone();
        assert!(
            envelope.is_string(),
            "premise: the asking tool minted no envelope: {}",
            asked.body
        );
        let extra = json!({
            "requestState": envelope,
            "inputResponses": {"k1": {"action": "accept", "content": {}}}
        });
        answers.push(fx.call_modern(spec.tool, &extra).await);
    }
    assert_same("row 2", Reason::Policy, &answers[0], &answers[1]);
}

/// Row 4 (ORACLE.1): a task member beside a bogus `requestState`; the
/// continuation comparison only (a state skips task intent). RED on base.
#[tokio::test]
async fn row4_task_with_bogus_state_answers_as_absent() {
    let spec = Spec::of(Reason::Policy, Side::Withheld);
    let extra = json!({"task": {}, "requestState": "not-an-envelope"});
    let (withheld, absent, _) = Box::pin(modern_pair(spec, &extra)).await;
    assert_same("row 4", Reason::Policy, &withheld, &absent);
}

/// Row 4b: a plain modern task call (no `requestState`) of a destructive
/// withheld tool answers as the absent name, with no `taskId`. GREEN for
/// policy (WH.1), RED for schema and descriptor.
#[tokio::test]
async fn row4b_plain_task_answers_as_absent() {
    let mut cells = Vec::new();
    for reason in REASONS {
        let spec = Spec {
            destructive: true,
            ..Spec::of(reason, Side::Withheld)
        };
        let extra = json!({"task": {}, "_meta": {
            crate::protocol::mrtr::IDEMPOTENCY_KEY_META: "wh-4b"
        }});
        let (withheld, absent, _) = Box::pin(modern_pair(spec, &extra)).await;
        if withheld.body.pointer("/result/taskId").is_some() {
            cells.push(format!(
                "row 4b ({reason:?}): a task was made: {}",
                withheld.body
            ));
        }
        cells.extend(mismatch("row 4b", reason, &withheld, &absent));
    }
    assert_cells("row 4b", &cells);
}

/// Row 5 (ORACLE.2): `gateway_invok`, one edit from `gateway_invoke`. The
/// withheld name answers the absent one's whole message, suggestion
/// included. RED on base.
#[tokio::test]
async fn row5_near_meta_name_keeps_the_suggestion() {
    let mut cells = Vec::new();
    for reason in [Reason::Policy, Reason::Schema] {
        let spec = Spec {
            tool: "gateway_invok",
            ..Spec::of(reason, Side::Withheld)
        };
        assert_call_premise(spec).await;
        let withheld = twin(spec).await.call_plain(spec.tool).await;
        let absent = twin(spec.with_side(Side::Absent(Absence::NotSurfaced)))
            .await
            .call_plain(spec.tool)
            .await;
        assert!(
            absent.body.to_string().contains("gateway_invoke"),
            "premise ({reason:?}): the absent answer suggests nothing: {}",
            absent.body
        );
        cells.extend(mismatch("row 5", reason, &withheld, &absent));
    }
    assert_cells("row 5", &cells);
}

/// The operator records a withheld call of `tool` wrote: WARN lines naming
/// it as refused or withheld.
pub(super) fn operator_records(warnings: &str, tool: &str) -> Vec<String> {
    warnings
        .lines()
        .filter(|line| line.contains(tool))
        .filter(|line| {
            let lower = line.to_lowercase();
            lower.contains("refus") || lower.contains("withh")
        })
        .map(str::to_string)
        .collect()
}

/// Row 6 (ORACLE.3): exactly one operator record per withheld call on `/mcp`,
/// for every reason. The fixture is built and warmed outside the capture, so
/// only the call's own records are counted. GREEN or RED as observed.
#[test]
fn row6_one_operator_record_per_withheld_call() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let mut cells = Vec::new();
    for reason in REASONS {
        let spec = Spec::of(reason, Side::Withheld);
        let fx = runtime.block_on(twin(spec));
        let (answered, warnings) = crate::test_log_capture::capture_warnings(|| {
            runtime.block_on(fx.call_plain(spec.tool))
        });
        assert_eq!(answered.calls, 0, "premise ({reason:?}): {}", answered.body);
        let records = operator_records(&warnings, spec.tool);
        if records.len() != 1 {
            cells.push(format!(
                "row 6 ({reason:?}): {} operator records:\n{warnings}",
                records.len()
            ));
        }
    }
    assert_cells("row 6", &cells);
}

/// Backend reader row (mutant pairing for `is_blocked_tool`): a
/// descriptor-blocked name is dropped by `get_cached_tool`,
/// `get_cached_tool_names` and the snapshot (`without_blocked`), read
/// directly, before any visibility filter. GREEN on base.
#[tokio::test]
async fn backend_readers_drop_a_blocked_name() {
    use super::withheld_twin_tests::{SIBLING, TOOL};
    let fx = twin(Spec::of(Reason::Descriptor, Side::Withheld)).await;
    let backend = fx.fx.state.backends.get("alpha").expect("alpha");
    let names = backend.get_cached_tool_names();
    assert!(
        names.iter().any(|n| n == SIBLING),
        "premise: no sibling: {names:?}"
    );
    assert!(backend.get_cached_tool(TOOL).is_none(), "get_cached_tool");
    assert!(!names.iter().any(|n| n == TOOL), "names: {names:?}");
    assert!(
        !backend
            .get_cached_tools_snapshot()
            .iter()
            .any(|t| t.name == TOOL),
        "snapshot"
    );
}

/// Row 12 (X14 classify, WH.4 extended): a destructive tool withheld for its
/// schema or descriptor gets no X14 challenge on a modern task call; the
/// repaired or unblocked control is challenged. RED on base.
#[tokio::test]
async fn row12_x14_never_challenges_a_withheld_destructive_tool() {
    // X14 engaged: it asked, or (a shared key on `/mcp`) refused because it
    // cannot name the caller its question would bind to.
    let challenged = |body: &Value| {
        body.pointer("/result/resultType") == Some(&json!("input_required"))
            || body.pointer("/error/code") == Some(&json!(-32003))
    };
    let mut cells = Vec::new();
    for reason in [Reason::Schema, Reason::Descriptor] {
        let spec = Spec {
            destructive: true,
            ..Spec::of(reason, Side::Withheld)
        };
        let extra = json!({"task": {}, "_meta": {
            crate::protocol::mrtr::IDEMPOTENCY_KEY_META: "wh-12"
        }});
        let control = twin(spec.with_side(Side::Control))
            .await
            .call_modern(spec.tool, &extra)
            .await;
        assert!(
            challenged(&control.body),
            "premise ({reason:?}): the control is not challenged: {}",
            control.body
        );
        let withheld = twin(spec).await.call_modern(spec.tool, &extra).await;
        if challenged(&withheld.body) {
            cells.push(format!(
                "row 12 ({reason:?}): X14 engaged: {}",
                withheld.body
            ));
        }
    }
    assert_cells("row 12", &cells);
}

/// Row 8 (ORACLE.3): a withheld call and an absent-name call under one
/// idempotency key spend nothing: the same key on an allowed call (the
/// sibling) then dispatches, answering as the same probe on an untouched
/// fixture. GREEN on base.
#[tokio::test]
async fn row8_withheld_call_parks_no_idempotency_key() {
    use super::withheld_twin_tests::SIBLING;
    let spec = Spec::of(Reason::Policy, Side::Withheld);
    let keyed = json!({"_meta": {crate::protocol::mrtr::IDEMPOTENCY_KEY_META: "wh-8"}});
    let fx = twin(spec).await;
    let withheld = fx.call_modern(spec.tool, &keyed).await;
    assert!(
        withheld.body.get("error").is_some(),
        "premise: {}",
        withheld.body
    );
    let absent = fx.call_modern("no_such_tool", &keyed).await;
    assert!(
        absent.body.get("error").is_some(),
        "premise: {}",
        absent.body
    );
    let reuse = fx.call_modern(SIBLING, &keyed).await;
    let probe = twin(spec).await.call_modern(SIBLING, &keyed).await;
    assert_eq!(
        reuse.calls, 1,
        "row 8: the reused key did not dispatch: {}",
        reuse.body
    );
    // A trace id is minted per call; nothing else may differ.
    let untraced = |mut body: Value| {
        if let Some(result) = body["result"].as_object_mut() {
            result.remove("_trace_id");
        }
        body
    };
    assert_eq!(
        (reuse.status, untraced(reuse.body.clone())),
        (probe.status, untraced(probe.body.clone())),
        "row 8: reuse {} vs untouched {}",
        reuse.body,
        probe.body
    );
}

/// Row 8, nonce half: on the signed fixture, a refusal of `first` under
/// signing nonce N, then the sibling under N, on a fresh fixture. `None` when
/// that reuse dispatched as the sibling's probe under N on an untouched
/// fixture; otherwise the mismatch.
async fn nonce_reuse_after(first: &str) -> Option<String> {
    use super::withheld_twin_tests::{Kind, SIBLING, twin_of};
    use crate::gateway::meta_mcp::signing::NONCE_META;
    let spec = Spec::of(Reason::Policy, Side::Withheld);
    let signed = json!({"_meta": {NONCE_META: "wh-8-nonce"}});
    // A trace id is minted per call, and the signature covers it.
    let untraced = |mut body: Value| {
        if let Some(result) = body["result"].as_object_mut() {
            result.remove("_trace_id");
        }
        if let Some(signature) = body["result"]["_signature"].as_object_mut() {
            signature.remove("sig");
            signature.remove("ts");
        }
        body
    };
    let probe = twin_of(Kind::Signed, spec, |meta| meta)
        .await
        .call_modern(SIBLING, &signed)
        .await;
    assert_eq!(
        probe.calls, 1,
        "premise: the probe did not dispatch: {}",
        probe.body
    );
    let fx = twin_of(Kind::Signed, spec, |meta| meta).await;
    let refused = fx.call_modern(first, &signed).await;
    assert!(
        refused.body.get("error").is_some(),
        "premise: {}",
        refused.body
    );
    let reuse = fx.call_modern(SIBLING, &signed).await;
    ((reuse.status, untraced(reuse.body.clone())) != (probe.status, untraced(probe.body.clone())))
        .then(|| {
            format!(
                "reuse {} {} vs untouched {}",
                reuse.status, reuse.body, probe.body
            )
        })
}

/// Row 8, nonce half (ORACLE.3): a withheld call spends no signing nonce.
/// GREEN on base; must stay green once withheld takes the absent path.
#[tokio::test]
async fn row8_withheld_call_spends_no_signing_nonce() {
    if let Some(mismatch) = nonce_reuse_after(super::withheld_twin_tests::TOOL).await {
        panic!("row 8 nonce (withheld first): {mismatch}");
    }
}

/// Row 8b, design addendum A4 (lead ruling, MIK-8150 rule): an absent-name
/// refusal is refused before dispatch, so it gives its signing nonce back.
/// RED on base ("Nonce replay detected"). Paired mutant: no refund on the
/// absent-name refusal.
#[tokio::test]
async fn row8b_absent_name_refusal_refunds_the_signing_nonce() {
    if let Some(mismatch) = nonce_reuse_after("no_such_tool").await {
        panic!("row 8b (absent first): {mismatch}");
    }
}

/// The scope a row-11 caller asks with: refused for the policy reason,
/// allowed otherwise (schema and descriptor withhold for every caller).
fn row11_scope(reason: Reason) -> crate::gateway::meta_mcp::InvokeScope<'static> {
    static ALLOW: crate::gateway::authz::AllowAll = crate::gateway::authz::AllowAll;
    static DENY: crate::gateway::authz::DenyAll = crate::gateway::authz::DenyAll;
    crate::gateway::meta_mcp::InvokeScope {
        authorizer: if reason == Reason::Policy {
            &DENY
        } else {
            &ALLOW
        },
        is_admin: false,
        api_key_name: None,
        grant_key: None,
        agent_id: None,
        grant_subject: None,
        caller: crate::identity_propagation::CallerProof::Anonymous,
    }
}

/// Row 11 (unit, lead ruling): the route-target builder resolves a surfaced
/// name withheld from the caller to no target, exactly as the absent name,
/// and the visible control to its one target. RED before the caller-taking
/// builder (MIK-8340).
#[tokio::test]
async fn row11_route_targets_resolve_a_withheld_name_as_absent() {
    use super::withheld_twin_tests::TOOL;
    use crate::gateway::meta_mcp::visible::TargetView;
    let arguments = json!({});
    let targets = |fx: &super::withheld_twin_tests::Twin, scope| {
        super::backend_tool_targets_for_call(
            &fx.fx.state.meta_mcp,
            TOOL,
            &arguments,
            TargetView::Caller(scope, None),
        )
        .len()
    };
    let mut cells = Vec::new();
    for reason in REASONS {
        let spec = Spec::of(reason, Side::Withheld);
        let withheld = targets(&twin(spec).await, row11_scope(reason));
        let absent = targets(
            &twin(spec.with_side(Side::Absent(Absence::NotSurfaced))).await,
            row11_scope(reason),
        );
        let visible = targets(
            &twin(spec.with_side(Side::Control)).await,
            row11_scope(Reason::Schema),
        );
        assert_eq!(
            visible, 1,
            "premise ({reason:?}): the visible control has its target"
        );
        if (withheld, absent) != (0, 0) {
            cells.push(format!(
                "row 11 ({reason:?}): withheld {withheld} vs absent {absent} targets"
            ));
        }
    }
    assert_cells("row 11", &cells);
}

/// MIK-8154 NP3 (design r3 D1, r3.1 F3): with sanitizing on, `/mcp` intake
/// judges a surfaced name's visibility for the sanitize exemption, through
/// the request's memo. A repair right after that judgement does not reach the
/// route stage or the dispatch: the call answers exactly as unrepaired
/// (-32601), with no dispatch. RED if intake's judgement is not the memo's:
/// the route stage then judges afresh, after the repair, and dispatches.
#[tokio::test]
async fn np3_intakes_judgement_is_the_requests_one() {
    let spec = Spec::of(Reason::Schema, Side::Withheld);
    let sanitizing = super::direct_guards_fixture::sanitizing;
    let unrepaired = Box::pin(sanitizing(true, twin(spec)))
        .await
        .call_plain(spec.tool)
        .await;
    assert_eq!(
        unrepaired.body.pointer("/error/code"),
        Some(&json!(-32601)),
        "premise: the withheld name is not answered as absent: {}",
        unrepaired.body
    );
    let raced = Box::pin(sanitizing(true, twin(spec))).await;
    let backend = raced
        .fx
        .state
        .backends
        .get("alpha")
        .expect("the twin serves alpha");
    let repaired: Vec<crate::protocol::Tool> = serde_json::from_value(
        super::withheld_twin_tests::catalogue(spec.with_side(Side::Control)),
    )
    .expect("the control catalogue parses");
    crate::gateway::meta_mcp::visible::seams::after_intake(move || {
        backend.store_shared_tools_for_test(repaired);
    });
    let answered = raced.call_plain(spec.tool).await;
    assert_eq!(
        (answered.status, &answered.body["error"], answered.calls),
        (unrepaired.status, &unrepaired.body["error"], 0),
        "np3: the repaired name dispatched or answered differently: {}",
        answered.body
    );
}

/// Row 14 (MIK-8340, perflane R3.1, one judgement per request): a surfaced
/// tool withheld for its shared schema at the route stage stays withheld for
/// the rest of the request. The catalogue is repaired between the route
/// stage and the dispatch, and the call still answers exactly as without the
/// repair, with no dispatch. RED without the per-request memo: the dispatch
/// re-judges, finds the tool valid, and calls it past the route-stage checks.
#[tokio::test]
async fn row14_a_repair_between_route_and_dispatch_keeps_the_name_absent() {
    let spec = Spec::of(Reason::Schema, Side::Withheld);
    let unrepaired = twin(spec).await.call_plain(spec.tool).await;
    assert_eq!(
        unrepaired.body.pointer("/error/code"),
        Some(&json!(-32601)),
        "premise: the withheld name is not answered as absent: {}",
        unrepaired.body
    );
    let raced = twin(spec).await;
    let backend = raced
        .fx
        .state
        .backends
        .get("alpha")
        .expect("the twin serves alpha");
    let repaired: Vec<crate::protocol::Tool> = serde_json::from_value(
        super::withheld_twin_tests::catalogue(spec.with_side(Side::Control)),
    )
    .expect("the control catalogue parses");
    crate::gateway::meta_mcp::visible::seams::after_route_stage(move || {
        backend.store_shared_tools_for_test(repaired);
    });
    let answered = raced.call_plain(spec.tool).await;
    assert_eq!(
        (answered.status, &answered.body["error"], answered.calls),
        (unrepaired.status, &unrepaired.body["error"], 0),
        "row 14: the repaired name dispatched or answered differently: {}",
        answered.body
    );
    // The repair did happen: the next request judges afresh and dispatches.
    let after = raced.call_plain(spec.tool).await;
    assert_eq!(
        after.calls, 1,
        "premise: the repair did not reach the next request: {}",
        after.body
    );
}
