// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MRTR.7a: what reaches the client.

use super::*;

// ── MRTR.7a — what reaches the client ────────────────────────────────────────

/// Row 308 — a backend's elicitation params reach the client whole.
///
/// Asserted as one object equal to what the backend sent, not field by field:
/// a per-field assertion passes an implementation that also adds fields the
/// backend never wrote, and the client cannot tell the gateway's inventions
/// from the backend's request.
#[tokio::test]
async fn ac_mrtr_7a_elicitation_params_reach_the_client_whole() {
    let params = json!({
        "mode": "url",
        "message": "Authorise the deploy",
        "requestedSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}},
        "url": "https://example.test/authorise",
    });
    let client = FakeClient::new(vec![accepted(&json!({"ok": true}))]);
    let backend = FakeBackend::new(vec![completed()]);
    let records = Records::default();

    let outcome = bridge(
        &client,
        &backend,
        &records,
        declared_all(),
        None,
        &interim(&[("k1", entry("elicitation/create", &params))]),
    )
    .await;
    assert!(outcome.is_ok(), "bridged call failed: {outcome:?}");

    let frames = client.frames();
    assert_eq!(frames.len(), 1, "one entry, one frame");
    assert_eq!(frames[0].method, "elicitation/create");
    assert_eq!(
        frames[0].session, SESSION,
        "asked on the caller's own session"
    );
    assert!(
        is_bridge_reply_id(&frames[0].id),
        "id {:?} must be one the ingress gate admits",
        frames[0].id
    );
    assert_eq!(
        frames[0].params.as_ref(),
        Some(&params),
        "params must equal the backend's, with nothing dropped and nothing invented"
    );
}

/// Row 309 — an entry naming a method outside the closed set is refused, and
/// nothing is sent.
///
/// Driven through the bridge rather than through `InputRequired::undeclared`,
/// which already answers `UnrecognisedMethod` today: a test calling that
/// directly is green before the bridge exists and proves nothing about what
/// reaches the client. The zero-frames half is the half that fails against a
/// bridge that forwards by method name.
#[tokio::test]
async fn ac_mrtr_7a_a_method_outside_the_closed_set_is_refused_unsent() {
    let client = FakeClient::mute();
    let backend = FakeBackend::never();
    let records = Records::default();

    let outcome = bridge(
        &client,
        &backend,
        &records,
        declared_all(),
        None,
        &interim(&[("k1", entry("tools/call", &json!({"name": "rm"})))]),
    )
    .await;

    assert_eq!(
        outcome,
        Err(BridgeError::Refused {
            key: "k1".to_string(),
            reason: Refusal::UnrecognisedMethod,
        }),
    );
    assert!(
        client.frames().is_empty(),
        "nothing may be sent: {:?}",
        client.methods()
    );
    assert!(backend.calls().is_empty(), "backend must not be retried");
}

/// The bounds the bridge ships with, against the numbers written here.
///
/// Against literals rather than against the constant, because every bound row
/// below drives `DEFAULT` and would follow it silently wherever it moved. The
/// per-prompt value is the one worth pinning: it is deliberately not the
/// 120-second elicitation timeout, and a "simplification" back onto that
/// constant makes the aggregate unreachable while every other row still passes.
#[test]
fn ac_mrtr_7b_the_shipped_bounds_are_the_documented_ones() {
    assert_eq!(
        BridgeBounds::DEFAULT.rounds,
        3,
        "retries after the first call"
    );
    assert_eq!(
        BridgeBounds::DEFAULT.requests,
        8,
        "requests across the call"
    );
    assert_eq!(
        BridgeBounds::DEFAULT.aggregate,
        Duration::from_secs(120),
        "aggregate wall-clock budget"
    );
    assert_eq!(
        BridgeBounds::DEFAULT.per_prompt,
        Duration::from_secs(30),
        "per-prompt ceiling, which must stay below the aggregate"
    );
    assert!(
        BridgeBounds::DEFAULT.per_prompt < BridgeBounds::DEFAULT.aggregate,
        "a per-prompt ceiling equal to the aggregate makes the aggregate unreachable"
    );
}

/// Row 311 — a client that declared only `elicitation` is not asked for
/// `sampling`, even when the per-request slice is empty.
///
/// Two halves, because the row's own assertion cannot fail on its own: a bridge
/// that sends nothing at all satisfies "sampling was not sent". The neighbour
/// runs the same client, the same empty slice and the same elicitation entry
/// alone, and must reach the client — so the second half's silence is the
/// capability gate and not a fixture that never speaks.
///
/// `Some(&[])` and `None` are different states and the row's word "empty"
/// reaches both, so each is pinned separately. `None` is the request saying
/// nothing and leaves `declared` standing — row 325 drives that direction.
/// `Some(&[])` is the request declaring an empty set, and it narrows to
/// nothing: reading an explicit empty declaration as "no narrowing requested"
/// is the fail-open direction, and it is the one an implementer reaches for
/// because it keeps the neighbour speaking. The neighbour therefore runs on a
/// slice that names `elicitation`, which proves the bridge speaks without
/// deciding the empty case, and the empty case is asserted on its own at the
/// end.
#[tokio::test]
async fn ac_mrtr_7a_an_undeclared_variant_is_not_asked_under_an_empty_slice() {
    let elicitation_only = declared(&json!({"elicitation": {"form": {}}}));
    let empty: [String; 0] = [];
    let naming = ["elicitation".to_string()];
    let slice = Some(&naming[..]);

    // The neighbour: what the client declared, and the slice names, is asked.
    let client = FakeClient::new(vec![accepted(&json!({"ok": true}))]);
    let backend = FakeBackend::new(vec![completed()]);
    let records = Records::default();
    let outcome = bridge(
        &client,
        &backend,
        &records,
        elicitation_only,
        slice,
        &interim(&[(
            "k1",
            entry(
                "elicitation/create",
                &json!({"mode": "form", "message": "Which branch?"}),
            ),
        )]),
    )
    .await;
    assert!(
        outcome.is_ok(),
        "declared variant must still be asked: {outcome:?}"
    );
    assert_eq!(
        client.methods(),
        vec!["elicitation/create".to_string()],
        "a slice naming the declared capability must not narrow it away"
    );

    // The row: the same batch plus a variant the client never declared.
    let client = FakeClient::mute();
    let backend = FakeBackend::never();
    let records = Records::default();
    let outcome = bridge(
        &client,
        &backend,
        &records,
        elicitation_only,
        slice,
        &interim(&[
            (
                "k1",
                entry(
                    "elicitation/create",
                    &json!({"mode": "form", "message": "Which branch?"}),
                ),
            ),
            (
                "k2",
                entry(
                    "sampling/createMessage",
                    &json!({"messages": [], "maxTokens": 1}),
                ),
            ),
        ]),
    )
    .await;

    assert_eq!(
        outcome,
        Err(BridgeError::Refused {
            key: "k2".to_string(),
            reason: Refusal::Capability("sampling"),
        }),
        "the undeclared entry must name itself and its capability"
    );
    assert!(
        client.frames().is_empty(),
        "a refused batch asks nothing at all, not even its declared half: {:?}",
        client.methods()
    );
    assert!(backend.calls().is_empty(), "backend must not be retried");

    // The empty case on its own: an explicitly empty slice declares an empty
    // set, so even the capability the session declared is not asked. Only the
    // silence is asserted, not which error names it — the row is about what
    // reaches the client, and pinning a variant here would invent a contract
    // the design does not state.
    let client = FakeClient::mute();
    let backend = FakeBackend::never();
    let records = Records::default();
    let outcome = bridge(
        &client,
        &backend,
        &records,
        elicitation_only,
        Some(&empty[..]),
        &interim(&[(
            "k1",
            entry(
                "elicitation/create",
                &json!({"mode": "form", "message": "Which branch?"}),
            ),
        )]),
    )
    .await;

    assert!(
        outcome.is_err(),
        "an empty slice declares an empty set, so the round cannot complete: {outcome:?}"
    );
    assert!(
        client.frames().is_empty(),
        "an empty slice narrows to nothing, so nothing is asked: {:?}",
        client.methods()
    );
}

/// A state-only interim result carries `requestState` and no questions. The
/// bridge must ask the client nothing at all: inventing a round trip here
/// would put a question to a person that no server ever posed.
///
/// `mik_7212_acs.rs` pins the same property against `Bridge::to_legacy_client`,
/// a projection that skips the capability slice. This one runs against the live
/// run loop, which is the only thing that can dispatch.
#[tokio::test]
async fn ac_mrtr_7a_a_state_only_interim_asks_the_client_nothing() {
    let client = FakeClient::mute();
    let backend = FakeBackend::new(vec![completed()]);
    let records = Records::default();

    let outcome = bridge(
        &client,
        &backend,
        &records,
        declared(&json!({"elicitation": {"form": {}}})),
        None,
        &interim(&[]),
    )
    .await;

    assert!(
        outcome.is_ok(),
        "a state-only interim must complete, not fail: {outcome:?}"
    );
    assert!(
        client.methods().is_empty(),
        "nothing was asked, so nothing may be put to the client: {:?}",
        client.methods()
    );
}

/// Row 325 — a capability declared in the session is asked for when the
/// per-request slice is absent.
///
/// The only direction that can fail. Under a slice-authoritative bridge an
/// absent slice and an undeclared capability both come out as "do not ask", so
/// the narrowing row above passes either way; only the permitted path shows the
/// session store is the authority.
#[tokio::test]
async fn ac_mrtr_7a_a_session_declared_capability_is_asked_with_no_slice() {
    let answer = json!({"role": "assistant", "content": {"type": "text", "text": "ok"}});
    let client = FakeClient::new(vec![result(&answer)]);
    let backend = FakeBackend::new(vec![completed()]);
    let records = Records::default();

    let outcome = bridge(
        &client,
        &backend,
        &records,
        declared(&json!({"sampling": {}})),
        None,
        &interim(&[(
            "k1",
            entry(
                "sampling/createMessage",
                &json!({"messages": [], "maxTokens": 8}),
            ),
        )]),
    )
    .await;

    assert!(
        outcome.is_ok(),
        "an absent slice must not narrow: {outcome:?}"
    );
    assert_eq!(
        client.methods(),
        vec!["sampling/createMessage".to_string()],
        "the session's own declaration is what permits the ask"
    );
}

/// Row 326 — `sampling` and `roots` each complete an accepted round, not only
/// a refused one.
///
/// Every other accepted row is elicitation, so a bridge wired for elicitation
/// and stubbed for the other two passes all of them. Each variant is driven to
/// a retry here, and the answer is asserted where the backend would read it.
#[tokio::test]
async fn ac_mrtr_7a_sampling_and_roots_each_complete_an_accepted_round() {
    let sampled = json!({"role": "assistant", "content": {"type": "text", "text": "hello"}});
    let listed = json!({"roots": [{"uri": "file:///work", "name": "work"}]});

    for (method, params, answer) in [
        (
            "sampling/createMessage",
            json!({"messages": [], "maxTokens": 8}),
            sampled,
        ),
        ("roots/list", json!({}), listed),
    ] {
        let client = FakeClient::new(vec![result(&answer)]);
        let backend = FakeBackend::new(vec![completed()]);
        let records = Records::default();

        let outcome = bridge(
            &client,
            &backend,
            &records,
            declared_all(),
            None,
            &interim(&[("k1", entry(method, &params))]),
        )
        .await;

        assert!(outcome.is_ok(), "{method} round failed: {outcome:?}");
        assert_eq!(client.methods(), vec![method.to_string()]);
        let calls = backend.calls();
        assert_eq!(calls.len(), 1, "{method} must retry the backend once");
        assert_eq!(
            calls[0].pointer("/inputResponses/k1"),
            Some(&answer),
            "{method} answer must reach the backend under its own key"
        );
    }
}
