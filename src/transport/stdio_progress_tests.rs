// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Request-scoped progress notifications over stdio: which call a
//! notification reaches. Split out of `stdio_tests.rs` to keep it under the
//! file-size ceiling; the streaming row and its line helper stay there.

use super::*;

/// MIK-7324.COV.3 (C6 stdio 4): only `notifications/progress` rides the
/// progress route. A `notifications/message` stamped with a registered
/// `progressToken` is not delivered; the progress frame sent after it is, so
/// the first frame the caller sees shows which one got through.
#[tokio::test]
async fn a_message_stamped_with_a_registered_progress_token_is_not_delivered() {
    let transport = make_transport("cat");
    let stamped = r#"{"jsonrpc":"2.0","method":"notifications/message","params":{"progressToken":"tok-a","level":"debug","data":"x"}}"#;
    let (call, mut rx) = crate::transport::notification_sink::scope(None, async {
        let _ = transport.register_progress_token("tok-a");
        transport
            .handle_response(stamped)
            .expect("a notification must not fail the read loop");
        transport
            .handle_response(&progress_line("tok-a", 1))
            .expect("a notification must not fail the read loop");
    });
    call.await;
    let first = rx.try_recv().expect("the progress frame must be delivered");
    assert_eq!(
        first.method, "notifications/progress",
        "a token-stamped notifications/message reached the progress caller"
    );
    assert!(rx.try_recv().is_err(), "exactly one frame is delivered");
}

/// S-03 over stdio: two calls in flight on the one stdout. The notification
/// reaches the call that provoked it and no other.
///
/// Routing is now a property of which destination the token resolves to,
/// so the unregistered side is asserted by a sink that stays empty rather
/// than by an empty accumulation.
#[tokio::test]
async fn stdio_routes_a_progress_notification_to_only_the_call_that_supplied_the_token() {
    let transport = std::sync::Arc::new(make_transport("cat"));
    let reader = std::sync::Arc::clone(&transport);

    let (call, mut tok_b_rx) = crate::transport::notification_sink::scope(None, async {
        // tok-a's caller gets its own scope, so a misroute is visible. Both
        // registrations in one scope share a sender, and a frame delivered
        // to the wrong destination then arrives on the right receiver --
        // the isolation this row exists to prove would be unfalsifiable.
        // The sender is cloned into the map at registration, so it outlives
        // the scope that supplied it.
        let (tok_a_call, tok_a_rx) = crate::transport::notification_sink::scope(None, async {
            let _ = transport.register_progress_token("tok-a");
        });
        tok_a_call.await;

        let _ = transport.register_progress_token("tok-b");
        tokio::spawn(async move {
            reader
                .handle_response(&progress_line("tok-b", 7))
                .expect("handling a progress frame must succeed");
        })
        .await
        .expect("the reader task must not panic");
        tok_a_rx
    });
    let mut tok_a_rx = call.await;

    let first = tok_b_rx
        .recv()
        .await
        .expect("tok-b's caller must be reached");
    assert_eq!(
        first.params.as_ref().and_then(|p| p.get("progress")),
        Some(&serde_json::json!(7)),
        "the frame delivered must be the one tok-b provoked"
    );
    assert!(
        tok_b_rx.try_recv().is_err(),
        "tok-b's caller must see exactly the one frame it provoked"
    );
    assert!(
        tok_a_rx.try_recv().is_err(),
        "the other call in flight must see nothing at all"
    );
}

/// A second registration of a live token is refused, not honoured.
///
/// Overwriting would point the incumbent's token at the newcomer's
/// channel, so one call's progress would surface inside another call's
/// response stream -- a cross-caller leak, and worse than losing the
/// frame. ADR-014 §2 names it as one of the three defects that sank
/// registering the caller's own token.
#[tokio::test]
async fn stdio_refuses_to_reroute_a_progress_token_that_is_already_live() {
    let transport = std::sync::Arc::new(make_transport("cat"));
    let reader = std::sync::Arc::clone(&transport);

    // Two notification scopes, so the incumbent's sink and the newcomer's
    // are distinguishable. Registering twice inside one scope cannot tell
    // a refused insert from an overwriting one -- both would deliver to
    // the same receiver.
    let (incumbent_call, mut incumbent_rx) =
        crate::transport::notification_sink::scope(None, async {
            let _owner = ProgressRegistrationGuard::register(&transport, "tok-a");

            let (newcomer_call, mut newcomer_rx) =
                crate::transport::notification_sink::scope(None, async {
                    let refused = ProgressRegistrationGuard::register(&transport, "tok-a");
                    assert!(
                        !refused.owns_registration,
                        "a token already registered to a live call must be refused"
                    );
                });
            newcomer_call.await;

            // The refused guard has dropped by here. Its cleanup must not
            // have retired the incumbent's route -- that would silence a
            // call that is still open, the exact damage the refusal exists
            // to prevent.
            assert!(
                newcomer_rx.try_recv().is_err(),
                "the refused call must have been routed nothing"
            );
            assert_eq!(
                transport.progress_destinations.len(),
                1,
                "the refused guard must leave the incumbent's entry in place"
            );

            // Delivery runs off-scope on purpose: the sender has to travel
            // in the map, not be read from the ambient task-local.
            tokio::spawn(async move {
                reader
                    .handle_response(&progress_line("tok-a", 3))
                    .expect("handling a progress frame must succeed");
            })
            .await
            .expect("the reader task must not panic");
        });
    incumbent_call.await;

    let got = incumbent_rx
        .recv()
        .await
        .expect("the incumbent must still be reached after the refusal");
    assert_eq!(
        got.params.as_ref().and_then(|p| p.get("progress")),
        Some(&serde_json::json!(3)),
        "the frame must carry the incumbent's progress value"
    );
}

/// The production request path reads the token from `params._meta`, which
/// is where a caller puts it. Pinned separately from the capture side
/// because the two shapes differ and a mismatch fails quietly.
#[test]
fn stdio_reads_the_callers_progress_token_from_request_meta() {
    let params = serde_json::json!({
        "name": "t",
        "_meta": { "progressToken": "tok-live" }
    });
    assert_eq!(
        request_progress_token(Some(&params)).as_deref(),
        Some("tok-live")
    );
    // A numeric token is the same token.
    let numeric = serde_json::json!({ "_meta": { "progressToken": 7 } });
    assert_eq!(request_progress_token(Some(&numeric)).as_deref(), Some("7"));
    // No token offered, none invented.
    assert!(request_progress_token(Some(&serde_json::json!({ "name": "t" }))).is_none());
    assert!(request_progress_token(None).is_none());
}

/// S-02 over stdio, end to end through the sink: register as the request
/// path does, deliver as the reader task does -- and the caller's sink
/// holds the notification with no flush of any kind in between.
#[tokio::test]
async fn stdio_delivers_a_notification_into_the_callers_sink() {
    let t = make_transport("cat");
    let params = serde_json::json!({ "_meta": { "progressToken": "tok-live" } });

    let ((), drained) = crate::transport::notification_sink::collect(None, async {
        let token = request_progress_token(Some(&params)).expect("token");
        let _ = t.register_progress_token(&token);
        t.handle_response(&progress_line("tok-live", 3)).unwrap();
    })
    .await;

    assert_eq!(drained.len(), 1);
    assert_eq!(drained[0].method, "notifications/progress");
}

/// Negative control for stdio: a notification whose token nobody registered
/// reaches no sink, even with a call in flight that has one.
#[tokio::test]
async fn stdio_never_attributes_a_stray_token_to_an_open_call() {
    let t = make_transport("cat");

    let ((), drained) = crate::transport::notification_sink::collect(None, async {
        let _ = t.register_progress_token("tok-mine");
        t.handle_response(&progress_line("tok-stray", 1)).unwrap();
    })
    .await;

    assert!(
        drained.is_empty(),
        "a stray token must not be attributed to whichever call is open"
    );
}

/// `register_progress_token` inserts and only the drain removes, so an
/// error return that skipped the drain would strand the entry for the
/// transport's lifetime. The request path drains on every exit.
#[tokio::test]
async fn stdio_request_retires_its_registration_even_when_the_write_fails() {
    let t = make_transport("cat"); // never connected: the write fails
    let params = serde_json::json!({ "_meta": { "progressToken": "tok-leak" } });

    let (result, drained) = crate::transport::notification_sink::collect(None, async {
        t.request("tools/call", Some(params)).await
    })
    .await;

    assert!(result.is_err(), "precondition: the write must fail");
    assert!(drained.is_empty());
    assert!(
        !t.progress_destinations.contains_key("tok-leak"),
        "the registration must not outlive the failed request"
    );
}

/// The fourth exit path, and the one a drain written after the await
/// cannot reach: the request future is DROPPED while still parked on its
/// response (an outer timeout, a task abort). Nothing after the await runs,
/// so retiring the registration has to happen in `Drop`.
///
/// The guard is tested directly rather than through a cancelled
/// `request()`: reaching a parked await needs a live child that completes
/// `start()`'s handshake, and `cat` cannot. What ties the guard to the
/// request path is that it is now the ONLY drain there —
/// `stdio_request_retires_its_registration_even_when_the_write_fails` goes
/// red the moment `request` stops holding one.
#[tokio::test]
async fn a_dropped_progress_registration_retires_its_destination() {
    // GIVEN a registration holding one captured notification.
    let t = make_transport("cat");
    let ((), drained) = crate::transport::notification_sink::collect(None, async {
        let guard = ProgressRegistrationGuard::register(&t, "tok-cancel");
        t.handle_response(&progress_line("tok-cancel", 1)).unwrap();

        // WHEN the guard drops without anyone draining explicitly, which is
        // what a dropped request future leaves behind.
        drop(guard);
    })
    .await;

    // THEN what was captured still reaches the sink, and the entry is gone.
    assert_eq!(
        drained.len(),
        1,
        "a retired registration must route nothing"
    );
    assert!(
        !t.progress_destinations.contains_key("tok-cancel"),
        "a cancelled request must not strand its registration for the transport's lifetime"
    );
}

/// Condition 2 of the correlation rule: an unregistered token is never
/// forwarded. A backend's token is passed through only on a match.
#[tokio::test]
async fn stdio_drops_a_progress_notification_no_caller_asked_for() {
    let t = make_transport("cat");

    let ((), drained) = crate::transport::notification_sink::collect(None, async {
        let _ = t.register_progress_token("tok-a");
        t.handle_response(&progress_line("tok-stray", 3)).unwrap();
    })
    .await;

    assert!(
        drained.is_empty(),
        "an unregistered token reaches no caller, registered neighbour or not"
    );
    assert!(
        !t.progress_destinations.contains_key("tok-stray"),
        "and it must not register itself on the way through"
    );
}
