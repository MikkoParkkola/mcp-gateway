// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Acceptance-criterion tests for the MRTR.7 `roots/list` repair
//! (MIK-7212.ROOTS.3 / .4 / .5).
//!
//! Plan: `docs/requirements/RELEASE-4.0.0-test-plan.md`, the rows added after
//! the D-A ruling. Design: `docs/design/2026-09-05-mrtr7-bridge-wiring.md`.
//!
//! These live at the integration level because the criteria are about a ROUND
//! TRIP — a frame leaving the gateway, a reply arriving from a named session,
//! and the caller that was awaiting it — which is the crate's outside edge, not
//! an internal detail. They are written before the repair exists, so their
//! first failure is the free and real one §P2 asks for.

use std::sync::Arc;
use std::time::Duration;

use mcp_gateway::backend::BackendRegistry;
use mcp_gateway::config::StreamingConfig;
use mcp_gateway::gateway::proxy::ProxyManager;
use mcp_gateway::gateway::streaming::NotificationMultiplexer;
use serde_json::{Value, json};

/// A proxy over its own multiplexer, as the gateway wires them in production.
fn make_proxy() -> (Arc<NotificationMultiplexer>, Arc<ProxyManager>) {
    let mux = Arc::new(NotificationMultiplexer::new(
        Arc::new(BackendRegistry::new()),
        StreamingConfig::default(),
    ));
    let proxy = Arc::new(ProxyManager::new(Arc::clone(&mux)));
    (mux, proxy)
}

/// The request id the gateway minted, read back off the frame it emitted.
///
/// Taken FROM THE FRAME on purpose. A fixture constant would let every test
/// below pass over a forward that mints a different id — which is the exact
/// break they exist to catch.
fn minted_id(frame: &Value) -> String {
    frame
        .get("id")
        .and_then(Value::as_str)
        .expect("the forwarded roots/list frame must carry a JSON-RPC id")
        .to_string()
}

/// MIK-7212.ROOTS.3 — a client reply to that id reaches the awaiting caller.
#[tokio::test]
async fn roots_3_a_client_reply_reaches_the_awaiting_caller() {
    // GIVEN a session listening, and a caller awaiting its roots
    let (mux, proxy) = make_proxy();
    let (session_id, mut rx) = mux.get_or_create_session(Some("roots-roundtrip"));
    let caller = tokio::spawn({
        let proxy = Arc::clone(&proxy);
        let session_id = session_id.clone();
        async move {
            proxy
                .forward_roots_list_with_response(&session_id, Duration::from_secs(5))
                .await
        }
    });

    // WHEN the client answers the id the gateway actually put on the wire
    let frame = rx.recv().await.expect("a frame must reach the session");
    let id = minted_id(&frame.data);
    let answer = json!({"roots": [{"uri": "file:///w", "name": "w"}]});
    assert!(
        proxy.resolve_pending(&id, &session_id, answer.clone()),
        "the prompted session's reply must be accepted (MIK-7212.ROOTS.3)"
    );

    // THEN the awaiting caller receives that answer
    let received = caller
        .await
        .expect("the caller task must not panic")
        .expect("an answered roots/list must resolve, not time out");
    assert_eq!(
        received, answer,
        "the caller must receive the client's own reply, unaltered (MIK-7212.ROOTS.3)"
    );
}

/// MIK-7212.ROOTS.4 — a reply from a session that was not prompted is refused,
/// and refusing it does not consume the real one's slot.
#[tokio::test]
async fn roots_4_an_unprompted_session_cannot_answer_and_the_entry_survives() {
    // GIVEN a caller awaiting roots from one session, and a second session
    let (mux, proxy) = make_proxy();
    let (session_id, mut rx) = mux.get_or_create_session(Some("roots-owner"));
    let (intruder_id, _intruder_rx) = mux.get_or_create_session(Some("roots-intruder"));
    let caller = tokio::spawn({
        let proxy = Arc::clone(&proxy);
        let session_id = session_id.clone();
        async move {
            proxy
                .forward_roots_list_with_response(&session_id, Duration::from_secs(5))
                .await
        }
    });
    let frame = rx.recv().await.expect("a frame must reach the session");
    let id = minted_id(&frame.data);

    // WHEN the session that was never prompted answers
    let forged = json!({"roots": [{"uri": "file:///attacker", "name": "attacker"}]});
    assert!(
        !proxy.resolve_pending(&id, &intruder_id, forged),
        "a session that was not prompted must not answer for one that was \
         (MIK-7212.ROOTS.4)"
    );

    // THEN the prompted session can still answer — refusal did not consume the
    // entry, which a `remove`-then-check matcher would have done silently
    let answer = json!({"roots": [{"uri": "file:///w", "name": "w"}]});
    assert!(
        proxy.resolve_pending(&id, &session_id, answer.clone()),
        "the refused reply must leave the pending entry intact (MIK-7212.ROOTS.4)"
    );
    let received = caller
        .await
        .expect("the caller task must not panic")
        .expect("the owner's answer must still resolve the call");
    assert_eq!(received, answer, "(MIK-7212.ROOTS.4)");
}

/// MIK-7212.ROOTS.5 — an abandoned roots request strands no pending entry.
#[tokio::test]
async fn roots_5_an_abandoned_request_strands_no_pending_entry() {
    // GIVEN a caller awaiting roots, which is then dropped before any reply
    let (mux, proxy) = make_proxy();
    let (session_id, mut rx) = mux.get_or_create_session(Some("roots-abandoned"));
    let caller = tokio::spawn({
        let proxy = Arc::clone(&proxy);
        let session_id = session_id.clone();
        async move {
            proxy
                .forward_roots_list_with_response(&session_id, Duration::from_secs(60))
                .await
        }
    });
    let frame = rx.recv().await.expect("a frame must reach the session");
    let id = minted_id(&frame.data);

    // WHEN the in-flight future is dropped without a reply or a timeout
    caller.abort();
    let _ = caller.await;

    // THEN nothing is left for a later reply to resolve. Observed through the
    // public matcher rather than the private map: a surviving entry would
    // answer `true` here and would never be removed for the proxy's lifetime.
    assert!(
        !proxy.resolve_pending(&id, &session_id, json!({"roots": []})),
        "dropping the caller must remove the pending entry; a late reply has \
         nothing to resolve (MIK-7212.ROOTS.5)"
    );
}
