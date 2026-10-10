// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::*;

/// MIK-7212.WIRE.11 — dropping an in-flight sampling call must not strand
/// its `pending_sampling` entry.
///
/// This is the HTTP mirror of the stdio contract already pinned by
/// `cancelled_request_does_not_strand_pending_entry` in
/// `src/transport/stdio.rs`: an outer `tokio::time::timeout` or a task
/// abort drops the request future BEFORE the proxy's own timeout arm
/// runs, so neither `resolve_pending` nor the timeout branch removes the
/// entry. Only RAII cleanup on drop can. Without it every cancelled
/// sampling call leaks a `PendingSample` for the proxy's lifetime, which
/// is the leak MIK-7388.BRIDGE.2 requires the bridged client channel not
/// to have.
///
/// The live session is what makes the drop happen mid-await: delivery
/// must succeed (an undeliverable prompt is already cleaned up on the
/// `NoSession` path) and the session must never answer.
/// A prompt nobody will ever answer, so the call parks on its receiver.
fn never_answered_sampling_params() -> SamplingCreateMessageParams {
    SamplingCreateMessageParams {
        messages: vec![SamplingMessage {
            role: "user".to_string(),
            content: Content::Text {
                text: "never answered".to_string(),
                annotations: None,
            },
        }],
        tools: None,
        tool_choice: None,
        model_preferences: None,
        system_prompt: None,
        max_tokens: 16,
    }
}

/// The elicitation counterpart of [`never_answered_sampling_params`].
fn never_answered_elicitation_params() -> ElicitationCreateParams {
    ElicitationCreateParams {
        mode: None,
        message: "never answered".to_string(),
        requested_schema: None,
        url: None,
    }
}

#[tokio::test]
async fn mik_7212_wire_11_cancelled_sampling_does_not_strand_pending_entry() {
    // GIVEN: a live session that will receive the prompt and never answer
    let mux = make_multiplexer();
    let (session, mut rx_session) = mux.get_or_create_session(Some("sess-cancel"));
    let proxy = Arc::new(ProxyManager::new(Arc::clone(&mux)));
    let params = never_answered_sampling_params();

    // The timeout is far beyond the abort below, so the proxy's own
    // timeout arm cannot be what cleans up — the drop must be.
    let proxy_for_task = Arc::clone(&proxy);
    let origin = session.clone();
    let wait = tokio::spawn(async move {
        proxy_for_task
            .forward_sampling_with_response(&origin, &params, Duration::from_secs(30))
            .await
    });

    // Receiving the prompt proves the entry is registered and the send
    // succeeded: the call is now parked on the response receiver.
    let delivered = tokio::time::timeout(Duration::from_secs(10), rx_session.recv())
        .await
        .expect("originating session must receive the sampling request")
        .expect("channel open");
    assert_eq!(delivered.data["method"], "sampling/createMessage");
    assert_eq!(
        proxy.pending_sampling.read().len(),
        1,
        "precondition: the in-flight call holds exactly one pending entry"
    );

    // WHEN: the call is cancelled mid-await. Joining the aborted handle
    // is what makes this deterministic — `abort()` only requests
    // cancellation, and the future is not dropped until the task is
    // reaped, so asserting before the join races the runtime.
    wait.abort();
    let _ = wait.await;

    // THEN: nothing is left allocated for a caller that no longer exists
    assert_eq!(
        proxy.pending_sampling.read().len(),
        0,
        "a cancelled in-flight sampling call must not strand its pending entry"
    );
}

/// MIK-7388.CANCEL.1 — cancelling one bridged exchange reclaims its pending
/// state and cannot hand its answer to another exchange.
///
/// The sibling above proves the map is drained. Drainage alone does not
/// settle the criterion: the map is keyed by request id, so what it leaves
/// open is what a late POST-back for a cancelled id does to the exchange
/// still parked beside it. Two concurrent prompts on one session are the
/// smallest arrangement where a mis-keyed delivery is observable — a
/// resolve that matched on session alone, or one that took the first
/// waiting entry, would answer the survivor with the cancelled call's
/// reply and every single-exchange test would still pass.
#[tokio::test]
async fn mik_7388_cancel_1_a_cancelled_exchange_cannot_be_answered_into_another() {
    let mux = make_multiplexer();
    let (session, mut rx_session) = mux.get_or_create_session(Some("sess-cross"));
    let proxy = Arc::new(ProxyManager::new(Arc::clone(&mux)));

    // GIVEN: two exchanges in flight on one session, neither of them
    // answered. The proxy timeout is far beyond anything this test does,
    // so no timeout arm can be what cleans up.
    let prompt = |session: &str| {
        let proxy = Arc::clone(&proxy);
        let session = session.to_string();
        tokio::spawn(async move {
            proxy
                .forward_sampling_with_response(
                    &session,
                    &never_answered_sampling_params(),
                    Duration::from_secs(30),
                )
                .await
        })
    };
    // Receiving each prompt proves its entry is registered and the call is
    // parked on its receiver, and yields the id the client would answer.
    macro_rules! next_id {
        () => {{
            let delivered = tokio::time::timeout(Duration::from_secs(10), rx_session.recv())
                .await
                .expect("the session must receive the prompt")
                .expect("channel open");
            assert_eq!(delivered.data["method"], "sampling/createMessage");
            delivered.data["id"]
                .as_str()
                .expect("a prompt carries its own id")
                .to_string()
        }};
    }

    let cancelled = prompt(&session);
    let id_cancelled = next_id!();
    let survivor = prompt(&session);
    let id_survivor = next_id!();
    assert_ne!(id_cancelled, id_survivor, "each prompt must get its own id");
    assert_eq!(
        proxy.pending_sampling.read().len(),
        2,
        "precondition: two in-flight exchanges"
    );

    // WHEN: one is cancelled mid-await and its answer arrives afterwards.
    // Joining the aborted handle is what makes this deterministic: abort()
    // only requests cancellation, and the future is not dropped until the
    // task is reaped.
    cancelled.abort();
    let _ = cancelled.await;
    let late = json!({
        "role": "assistant",
        "content": {"type": "text", "text": "for the cancelled call"},
    });
    let delivered = proxy.resolve_pending(&id_cancelled, &session, late.clone());

    // THEN: the cancelled exchange is gone, and refusing its answer is not
    // done by consuming somebody else's entry.
    assert!(
        !delivered,
        "a cancelled exchange has no caller left to deliver to"
    );
    assert_eq!(
        proxy.pending_sampling.read().len(),
        1,
        "the surviving exchange must still be pending"
    );

    // AND: the survivor answers as itself, with its own reply.
    let own = json!({
        "role": "assistant",
        "content": {"type": "text", "text": "for the surviving call"},
    });
    assert!(
        proxy.resolve_pending(&id_survivor, &session, own.clone()),
        "the surviving exchange must still be answerable"
    );
    let got = tokio::time::timeout(Duration::from_secs(10), survivor)
        .await
        .expect("the surviving call must return")
        .expect("its task must not panic")
        .expect("it must succeed");
    assert_eq!(got, own, "the survivor must receive its own answer");
    assert_ne!(got, late, "and never the cancelled exchange's");
    assert_eq!(
        proxy.pending_sampling.read().len(),
        0,
        "both entries reclaimed"
    );
}

/// MIK-7212 WIRE-11 (elicitation): the sibling of the sampling case above.
///
/// `forward_elicitation_with_response` registers in the SAME
/// `pending_sampling` map, so it strands an entry the same way. Covered by
/// the same guard, but a guard nobody exercises is a guard nobody has
/// checked — the elicitation call site is verified here on its own.
#[tokio::test]
async fn mik_7212_wire_11_cancelled_elicitation_does_not_strand_pending_entry() {
    let mux = make_multiplexer();
    let (session, mut rx_session) = mux.get_or_create_session(Some("sess-cancel-elicit"));
    let proxy = Arc::new(ProxyManager::new(Arc::clone(&mux)));
    let params = never_answered_elicitation_params();

    let proxy_for_task = Arc::clone(&proxy);
    let origin = session.clone();
    let wait = tokio::spawn(async move {
        proxy_for_task
            .forward_elicitation_with_response(&origin, &params, Duration::from_secs(30))
            .await
    });

    let delivered = tokio::time::timeout(Duration::from_secs(10), rx_session.recv())
        .await
        .expect("originating session must receive the elicitation request")
        .expect("channel open");
    assert_eq!(delivered.data["method"], "elicitation/create");
    assert_eq!(
        proxy.pending_sampling.read().len(),
        1,
        "precondition: the in-flight call holds exactly one pending entry"
    );

    wait.abort();
    let _ = wait.await;

    assert_eq!(
        proxy.pending_sampling.read().len(),
        0,
        "a cancelled in-flight elicitation call must not strand its pending entry"
    );
}

/// MIK-7212 WIRE-11 (outer timeout, sampling): a different way to be cancelled.
///
/// The abort tests above cover the task-reaper shape; this is the shape a
/// real caller hits, wrapping the call in a timeout of its own. Both end at
/// the same `Drop`, so this is a second CALLER rather than a second
/// mechanism. The proxy's own timeout is 30s away, so it cannot be what
/// cleans up here either.
#[tokio::test]
async fn mik_7212_wire_11_outer_timeout_on_sampling_does_not_strand_pending_entry() {
    let mux = make_multiplexer();
    let (session, mut rx_session) = mux.get_or_create_session(Some("sess-outer-sampling"));
    let proxy = ProxyManager::new(Arc::clone(&mux));
    let params = never_answered_sampling_params();

    let outcome = tokio::time::timeout(
        Duration::from_millis(50),
        proxy.forward_sampling_with_response(&session, &params, Duration::from_secs(30)),
    )
    .await;
    assert!(
        outcome.is_err(),
        "the outer timeout must fire first; the proxy's own is 30s away"
    );

    // Draining afterwards proves the request really was registered and sent
    // before the outer timeout dropped the future.
    let delivered = rx_session
        .try_recv()
        .expect("the sampling request must have reached the session");
    assert_eq!(delivered.data["method"], "sampling/createMessage");

    assert_eq!(
        proxy.pending_sampling.read().len(),
        0,
        "an externally timed-out sampling call must not strand its pending entry"
    );
}

/// MIK-7212 WIRE-11 (outer timeout, elicitation): the fourth corner.
#[tokio::test]
async fn mik_7212_wire_11_outer_timeout_on_elicitation_does_not_strand_pending_entry() {
    let mux = make_multiplexer();
    let (session, mut rx_session) = mux.get_or_create_session(Some("sess-outer-elicit"));
    let proxy = ProxyManager::new(Arc::clone(&mux));
    let params = never_answered_elicitation_params();

    let outcome = tokio::time::timeout(
        Duration::from_millis(50),
        proxy.forward_elicitation_with_response(&session, &params, Duration::from_secs(30)),
    )
    .await;
    assert!(
        outcome.is_err(),
        "the outer timeout must fire first; the proxy's own is 30s away"
    );

    let delivered = rx_session
        .try_recv()
        .expect("the elicitation request must have reached the session");
    assert_eq!(delivered.data["method"], "elicitation/create");

    assert_eq!(
        proxy.pending_sampling.read().len(),
        0,
        "an externally timed-out elicitation call must not strand its pending entry"
    );
}

/// MIK-7212 WIRE-11 (production `ClientChannel`): the bridge's own send is
/// held to the same cancellation contract as the proxy's three forwards.
///
/// The bridge wraps every `send_request` in an outer timeout
/// (`input_bridge.rs:451`) and abandons the future on expiry, so an
/// implementation that registers a pending entry before awaiting and
/// releases it only on the success or error path leaks one per expired
/// prompt. This drives the implementor through the trait, not through
/// `forward_elicitation_with_response`, because it is the implementor that
/// chooses whether to hold a guard.
#[tokio::test]
async fn mik_7212_wire_11_cancelled_channel_send_does_not_strand_pending_entry() {
    use crate::gateway::input_bridge::ClientChannel;

    let mux = make_multiplexer();
    let (session, mut rx_session) = mux.get_or_create_session(Some("sess-channel-cancel"));
    let proxy = ProxyManager::new(Arc::clone(&mux));
    let channel: &dyn ClientChannel = &proxy;

    let outcome = tokio::time::timeout(
        Duration::from_millis(50),
        channel.send_request(
            &session,
            "elicitation-1",
            "elicitation/create",
            Some(json!({"message": "which one?", "requestedSchema": {"type": "object"}})),
        ),
    )
    .await;
    assert!(
        outcome.is_err(),
        "the outer timeout must fire first; nothing ever answers this prompt"
    );

    let delivered = rx_session
        .try_recv()
        .expect("the request must have reached the session");
    assert_eq!(delivered.data["method"], "elicitation/create");
    assert_eq!(
        delivered.data["id"], "elicitation-1",
        "the bridge's own id must go on the wire, not a freshly minted one"
    );
    // The answer has to be able to come back. `handlers.rs:754` only
    // resolves a POST-back whose id passes this gate, so an id that goes
    // out without it would strand the caller with both halves green.
    assert!(
        crate::gateway::input_bridge::is_bridge_reply_id(
            delivered.data["id"].as_str().expect("the id is a string")
        ),
        "the id on the wire must be one the POST-back path admits"
    );

    assert_eq!(
        proxy.pending_sampling.read().len(),
        0,
        "a cancelled bridge send must not strand its pending entry"
    );
}

/// MIK-7212 WIRE-11 (undeliverable): no session to reach is `NoSession`,
/// and it leaves nothing behind either.
#[tokio::test]
async fn mik_7212_wire_11_undeliverable_channel_send_leaves_no_pending_entry() {
    use crate::gateway::input_bridge::{ClientChannel, DeliveryError};

    let mux = make_multiplexer();
    let proxy = ProxyManager::new(Arc::clone(&mux));
    let channel: &dyn ClientChannel = &proxy;

    let err = channel
        .send_request(
            "sess-nobody-home",
            "bridge-elicit-2",
            "elicitation/create",
            None,
        )
        .await
        .expect_err("there is no such session to deliver to");

    assert!(
        matches!(err, DeliveryError::NoSession),
        "an undeliverable prompt is NoSession, not a timeout: {err:?}"
    );
    assert_eq!(
        proxy.pending_sampling.read().len(),
        0,
        "an undeliverable bridge send must not strand its pending entry"
    );
}

// ── NFR.CONFORMANCE.1, minor 11 — removed elicitation surface ───────

/// Minor 11, clause (a) — neither live elicitation forward path can put
/// `elicitationId` on the wire.
///
/// The 2026-07-28 changelog removes the field from URL-mode elicitation
/// requests. A 2025-11-25 backend still sends it, and the gateway forwards
/// elicitation to the connected client on two paths — the fire-and-forget
/// [`ProxyManager::forward_elicitation`] and the awaited
/// [`ProxyManager::forward_elicitation_with_response`]. Both are asserted,
/// because a removal proven on one path and not the other is not a removal.
///
/// **What actually strips it, stated so the test does not overclaim:** the
/// typed read. Both paths re-serialise from [`ElicitationCreateParams`]
/// (`protocol::messages`), which names four fields and carries no
/// `#[serde(flatten)]`, so every key the gateway cannot name is gone by the
/// time a frame is built. Neither path inspects the client's era. The field
/// is therefore dropped for a modern client AND for a legacy one, which is
/// stricter than the changelog requires and is the behaviour this pins. A
/// future `flatten` added for pass-through fidelity would regain the field
/// on both, and this test is what would notice.
///
/// The router's own `parse_elicitation_params` (`router/helpers.rs`) is
/// `pub(super)`; its entire body is the `serde_json::from_value` call made
/// here, so the typed read under test is the one the handler performs.
#[tokio::test]
async fn ac_conformance_minor_11a_elicitation_id_is_dropped_on_both_forward_paths() {
    let raw = json!({
        "mode": "url",
        "message": "Authorise the deploy",
        "url": "https://example.test/authorise",
        "elicitationId": "elicit-2025-11-25-42",
    });
    let params: ElicitationCreateParams =
        serde_json::from_value(raw).expect("a 2025-11-25 URL-mode request still parses");

    let mux = make_multiplexer();
    // Held for the whole test: `send_to_session` reports failure against a
    // session whose receiver has been dropped, and a test that lost its
    // receiver would pass the assertions below on zero delivered frames.
    let (session, mut rx) = mux.get_or_create_session(Some("sess-minor-11a"));
    let proxy = ProxyManager::new(Arc::clone(&mux));

    assert!(
        proxy.forward_elicitation(&session, &params),
        "the fire-and-forget forward must reach the session"
    );

    // Nothing ever answers, so the awaited path is ended by the outer
    // timeout. The frame it sent is already in the receiver by then.
    let _ = tokio::time::timeout(
        Duration::from_millis(50),
        proxy.forward_elicitation_with_response(&session, &params, Duration::from_secs(30)),
    )
    .await;

    let mut seen = 0;
    while let Ok(frame) = rx.try_recv() {
        seen += 1;
        assert_eq!(
            frame.data["method"], "elicitation/create",
            "frame {seen} is not the elicitation request"
        );
        let sent = &frame.data["params"];
        assert!(
            sent.get("elicitationId").is_none(),
            "frame {seen} carried the removed elicitationId field: {sent}"
        );
        // The neighbour assertion: a forward that dropped everything would
        // satisfy the line above and forward no question at all.
        assert_eq!(sent["mode"], "url", "frame {seen} lost the mode");
        assert_eq!(
            sent["url"], "https://example.test/authorise",
            "frame {seen} lost the url"
        );
        assert_eq!(
            sent["message"], "Authorise the deploy",
            "frame {seen} lost the message"
        );
    }
    assert_eq!(seen, 2, "both forward paths must have been exercised");
}
