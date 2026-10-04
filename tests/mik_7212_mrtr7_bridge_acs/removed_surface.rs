// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! NFR.CONFORMANCE.1 minor 11: the removed elicitation surface.

use super::*;

// ── NFR.CONFORMANCE.1, minor 11 — removed elicitation surface ────────────────

/// Minor 11, clause (b) — `notifications/elicitation/complete` is refused
/// before a frame leaves, on the one path where a backend names the method.
///
/// The 2026-07-28 changelog removes the notification. The concern the matrix
/// recorded was the outbound fan-out: a backend notification tagged and posted
/// to a session's subscribers without the method being inspected. Enumerating
/// the client-delivery sites says otherwise — `proxy.rs` builds every frame
/// with a literal method string (`elicitation/create`, `sampling/createMessage`,
/// `roots/list`, `notifications/roots/list_changed`,
/// `notifications/tools/list_changed`) and `webhooks/mod.rs` broadcasts a
/// transformed payload that carries no JSON-RPC method at all. The single site
/// whose method comes from a caller is `ClientChannel::send_request`, and its
/// only production caller is `InputBridge::ask`, which passes
/// `ServerRequestKind::method()` — three variants, no fourth spelling.
///
/// So the method a backend supplies is gated here, at `InputBridge::plan`, and
/// this is where the statement is assertable. The zero-frames half is the half
/// that matters: a refusal that still sent the frame would satisfy the error
/// assertion alone.
///
/// `ac_mrtr_7a_a_method_outside_the_closed_set_is_refused_unsent` proves the
/// same gate with `tools/call`. Named separately here because the statement
/// names this method, and a row citing a test that happens to cover it through
/// a different input is the citation drift `tests/mik_7272_conformance.rs`
/// exists to catch.
#[tokio::test]
async fn ac_conformance_minor_11b_elicitation_complete_is_refused_unsent() {
    let client = FakeClient::mute();
    let backend = FakeBackend::never();
    let records = Records::default();

    let outcome = bridge(
        &client,
        &backend,
        &records,
        // The most permissive declaration there is. A client that declared
        // everything is the one a leak would reach, so refusing under
        // `declared_all` is the strong form; refusing under `Declared::NONE`
        // would be the capability gate answering, not the method gate.
        declared_all(),
        None,
        &interim(&[(
            "k1",
            entry(
                "notifications/elicitation/complete",
                &json!({"elicitationId": "elicit-2025-11-25-42"}),
            ),
        )]),
    )
    .await;

    assert_eq!(
        outcome,
        Err(BridgeError::Refused {
            key: "k1".to_string(),
            reason: Refusal::UnrecognisedMethod,
        }),
        "the removed notification must be refused as an unrecognised method"
    );
    assert!(
        client.frames().is_empty(),
        "nothing may reach the client: {:?}",
        client.methods()
    );
    assert!(backend.calls().is_empty(), "backend must not be retried");
}

/// Minor 11, clause (a), legacy half — the bridge relays a URL-mode request's
/// params verbatim, `elicitationId` included.
///
/// The changelog removes the field from 2026-07-28. It does not remove it from
/// `2025-11-25`, and this bridge exists to ask a client that never negotiated
/// 2026-07-28, in the shape that client understands — so dropping the field
/// here would be the gateway editing a legacy exchange on the strength of a
/// revision neither end is speaking.
///
/// **Two qualifiers, so the test does not claim more than it proves.** First,
/// nothing on this path reads the client's era: the params survive because
/// `InputBridge::prompt` clones `request["params"]` whole, not because the
/// client is legacy. What makes this the legacy half is that the bridge only
/// runs for a client that must be asked directly. Second, `InputBridge` has no
/// production construction site in `src/` as of this commit — the caller
/// context carries a real channel (`router/handlers.rs`,
/// `channel: state.proxy_manager.as_ref()`) and nothing yet builds the bridge
/// over it. This pins the library contract, and the live forward path is pinned
/// by `gateway::proxy::tests::cancellation::ac_conformance_minor_11a_elicitation_id_is_dropped_on_both_forward_paths`,
/// which strips the field because it re-serialises from a typed struct.
///
/// Asserted as one object equal to what the backend sent, for the reason
/// `ac_mrtr_7a_elicitation_params_reach_the_client_whole` gives: a per-field
/// check passes an implementation that also invents fields.
#[tokio::test]
async fn ac_conformance_minor_11a_a_legacy_bridge_relay_retains_elicitation_id() {
    let params = json!({
        "mode": "url",
        "message": "Authorise the deploy",
        "url": "https://example.test/authorise",
        "elicitationId": "elicit-2025-11-25-42",
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
        frames[0].params.as_ref(),
        Some(&params),
        "a legacy relay must carry the request whole, elicitationId included"
    );
}
