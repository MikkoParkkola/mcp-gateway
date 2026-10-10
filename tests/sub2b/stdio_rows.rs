// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// `S-02` and `S-03` over stdio, and why `S-03`'s message half has no stdio row.

// ── S-02 over stdio ─────────────────────────────────────────────────────────

/// `S-02`, progress half, stdio: a backend's `notifications/progress` during a
/// `tools/call` reaches that call before its result, carrying the client's own
/// token.
///
/// GIVEN a fixture that emits a progress notification and then blocks,
/// WHEN the client releases it through the fixture's own gate, and only after
/// the notification has been read off stdout,
/// THEN the notification line precedes the response line and carries the
/// client's token byte-identically.
///
/// The ORDER of those two steps is what makes this liveness rather than
/// ordering: the release is withheld until the notification has actually been
/// read, so a gateway that buffered notifications and flushed them with the
/// response would never reach the release and this row would time out —
/// ADR-014 row 4's *"deadlocks here instead of passing"*.
///
/// The release is a semaphore permit rather than a second JSON-RPC call
/// because `Gateway::run_stdio` awaits each dispatch inline: a release sent as
/// id 3 is not read until the call it releases has already returned.
#[tokio::test]
async fn s02_stdio_progress_reaches_its_own_call_before_the_result() {
    // GIVEN
    let (backend_url, received, gate) = spawn_fixture_backend().await;
    let home = tempfile::tempdir().expect("temp home");
    write_config(home.path(), &backend_url);
    let mut session = stdio_session(home.path()).await;

    // WHEN
    let client_token = "client-token-A";
    session
        .send(&invoke(
            2,
            SLOW_TOOL,
            &json!({}),
            &json!({"progressToken": client_token}),
        ))
        .await;
    let (before_notification, notification) = session
        .read_until(|frame| is_method(frame, "notifications/progress"))
        .await;
    assert!(
        notification.is_some(),
        "no notifications/progress reached the client before the read bound. \
         Frames seen instead: {before_notification:?}"
    );
    // Only now — the fixture cannot return until this lands, so reaching the
    // result at all proves the notification preceded it.
    // Released through the fixture's own gate, not as a second JSON-RPC call:
    // `Gateway::run_stdio` awaits each dispatch inline, so an id-3 release
    // would not be read until the call it is meant to release had returned.
    gate.add_permits(1);
    let (_, result) = session.read_until(|frame| has_id(frame, 2)).await;

    // THEN
    assert!(
        !before_notification.iter().any(|frame| has_id(frame, 2)),
        "the response for the call arrived before its own notification: {before_notification:?}"
    );
    assert!(
        result.is_some(),
        "the released call never returned a result"
    );
    let notification = notification.expect("checked above");
    assert_eq!(
        progress_token_of(&notification),
        Some(&json!(client_token)),
        "the client must get its own token back byte-identically, not the \
         gateway's minted one"
    );
    let minted = received
        .lock()
        .expect("fixture sink poisoned")
        .iter()
        .filter(|request| tool_name(request).as_deref() == Some(SLOW_TOOL))
        .map(minted_token)
        .next()
        .expect("the fixture must have seen the slow call");
    assert_ne!(
        minted,
        json!(client_token),
        "the token sent to the backend must be gateway-minted, not the \
         client's own (ADR-014 §2)"
    );
    session.shutdown().await;
}

/// `S-02`, message half, stdio: a backend's `notifications/message` during a
/// `tools/call` reaches that call before its result.
///
/// One call is in flight, so attribution is unambiguous even without a
/// linkage field. That is exactly why this row exists over stdio and its
/// `S-03` counterpart does not.
///
/// The row steps over the gateway's OWN audit line to find the backend's, then
/// asserts that line was delivered too. Without that second assertion a stdio
/// setter that never classified the request would still pass here, and the
/// classify-and-set seam would be proven on HTTP only.
#[tokio::test]
async fn s02_stdio_message_reaches_its_own_call_before_the_result() {
    // GIVEN
    let (backend_url, _received, gate) = spawn_fixture_backend().await;
    let home = tempfile::tempdir().expect("temp home");
    write_config(home.path(), &backend_url);
    let mut session = stdio_session(home.path()).await;

    // WHEN
    let marker = "sub2b-stdio-message";
    session
        .send(&invoke(
            2,
            SLOW_TOOL,
            &json!({"message_marker": marker}),
            &json!({"io.modelcontextprotocol/logLevel": "info"}),
        ))
        .await;
    let (before_notification, notification) = session
        .read_until(|frame| is_method(frame, "notifications/message") && !is_gateway_own(frame))
        .await;
    assert!(
        notification.is_some(),
        "no notifications/message reached the client before the read bound. \
         Frames seen instead: {before_notification:?}"
    );
    // Released through the fixture's own gate, not as a second JSON-RPC call:
    // `Gateway::run_stdio` awaits each dispatch inline, so an id-3 release
    // would not be read until the call it is meant to release had returned.
    gate.add_permits(1);
    let (after_notification, result) = session.read_until(|frame| has_id(frame, 2)).await;

    // THEN
    assert!(
        !before_notification.iter().any(|frame| has_id(frame, 2)),
        "the response arrived before its own notification: {before_notification:?}"
    );
    assert!(
        before_notification
            .iter()
            .chain(after_notification.iter())
            .any(|frame| is_method(frame, "notifications/message") && is_gateway_own(frame)),
        "the gateway's own audit line never reached the stdio client, so the \
         declaration was never classified on this transport; both sides are \
         checked because the audit line may land before or after the \
         backend's own notification"
    );
    assert!(
        result.is_some(),
        "the released call never returned a result"
    );
    assert_eq!(
        notification
            .as_ref()
            .and_then(|frame| frame.pointer("/params/data")),
        Some(&json!(marker)),
        "the delivered notification must be the backend's own, not one the \
         gateway invented"
    );
    session.shutdown().await;
}

/// `S-02` precondition, stdio: with nothing request-scoped declared, the
/// response is what it is today and no notification is delivered.
///
/// This is ADR-014 row 2's control. It passes vacuously against the current
/// tree and is only meaningful once the rows above are green; it is here so
/// that "deliver everything to everyone" cannot satisfy them.
#[tokio::test]
async fn stdio_without_request_scoped_meta_delivers_no_notification() {
    // GIVEN
    let (backend_url, _received, _gate) = spawn_fixture_backend().await;
    let home = tempfile::tempdir().expect("temp home");
    write_config(home.path(), &backend_url);
    let mut session = stdio_session(home.path()).await;

    // WHEN — no progressToken and no logLevel.
    session
        .send(&invoke(2, RELEASE_TOOL, &json!({}), &json!({})))
        .await;
    let (seen, result) = session.read_until(|frame| has_id(frame, 2)).await;

    // THEN
    assert!(result.is_some(), "the plain call must still answer");
    assert!(
        !seen
            .iter()
            .any(|frame| is_method(frame, "notifications/message")
                || is_method(frame, "notifications/progress")),
        "a request that declared nothing request-scoped received a \
         notification: {seen:?}"
    );
    session.shutdown().await;
}

// ── S-03 over stdio: the progress half only ─────────────────────────────────

/// `S-03`, progress half, stdio: two calls in flight, each notification
/// carrying its own call's token and no other's.
///
/// Both calls are provably in flight: neither can return until the third call
/// releases them, and the third call cannot be dispatched at all unless the
/// loop reads a new line while two are outstanding.
///
/// That last sentence is also why this row is parked. `Gateway::run_stdio`
/// awaits each dispatch inline inside `reader.next_line()`
/// (`src/gateway/server/mod.rs:1648`, from `513647be`, 2026-03-24, #109), so
/// call B is never read while call A is parked and the fixture sees only
/// `token-A`. Unlike the `s02` stdio rows above, no fixture change rescues
/// this one: the criterion IS per-call isolation, and isolation cannot be
/// demonstrated with a single call in flight. It is a transport limitation,
/// not a defect in the notification path -- the HTTP half of this same row
/// passes, and `s02_stdio_progress` proves delivery and token translation
/// work over stdio for the one call stdio can have in flight.
#[tokio::test]
#[ignore = "blocked by the serialized stdio serve loop (server/mod.rs:1648, \
            513647be): call B is never dispatched while call A is parked, so \
            per-call isolation cannot be observed. Un-ignore with a \
            concurrent stdio serve loop."]
async fn s03_progress_stdio_each_call_sees_only_its_own_token() {
    // GIVEN
    let (backend_url, _received, _gate) = spawn_fixture_backend().await;
    let home = tempfile::tempdir().expect("temp home");
    write_config(home.path(), &backend_url);
    let mut session = stdio_session(home.path()).await;

    // WHEN
    session
        .send(&invoke(
            2,
            SLOW_TOOL,
            &json!({}),
            &json!({"progressToken": "token-A"}),
        ))
        .await;
    session
        .send(&invoke(
            3,
            SLOW_TOOL,
            &json!({}),
            &json!({"progressToken": "token-B"}),
        ))
        .await;
    let (mut seen, first) = session
        .read_until(|frame| is_method(frame, "notifications/progress"))
        .await;
    assert!(first.is_some(), "no notification reached the client");
    seen.extend(first);
    session
        .send(&invoke(4, RELEASE_TOOL, &json!({}), &json!({})))
        .await;
    let (tail, _) = session.read_until(|frame| has_id(frame, 3)).await;
    seen.extend(tail);
    // No duplicate token after id 3's answer.
    // timing: absence
    seen.extend(session.collect_for_absence(COLLECT_WINDOW).await);

    // THEN
    let tokens: Vec<&Value> = seen
        .iter()
        .filter(|frame| is_method(frame, "notifications/progress"))
        .filter_map(progress_token_of)
        .collect();
    assert_eq!(
        tokens
            .iter()
            .filter(|token| **token == &json!("token-A"))
            .count(),
        1,
        "call A's token must appear exactly once: {tokens:?}"
    );
    assert_eq!(
        tokens
            .iter()
            .filter(|token| **token == &json!("token-B"))
            .count(),
        1,
        "call B's token must appear exactly once: {tokens:?}"
    );
    assert!(
        tokens
            .iter()
            .all(|token| **token == json!("token-A") || **token == json!("token-B")),
        "a notification carried a token no caller supplied — the gateway's \
         minted token leaked to the client: {tokens:?}"
    );
    session.shutdown().await;
}

// ── S-03, message half: why there is no stdio row here ──────────────────────
//
// `S-03` asks that a notification "reaches the provoking call's stream and no
// other". Over HTTP the response body *is* the per-request stream, so the
// question has an answer. Over client-facing stdio there is one client and one
// stdout: there is no other caller to leak to, and the failure that can
// actually occur — misattribution between two in-flight calls of the *same*
// client — is undetectable for `notifications/message`, because MCP defines no
// per-request relation on a logging notification and this repository has none
// (no `relatedRequestId`, no `progressToken` in `src/protocol/`).
//
// So a stdio row for the message half could assert only that *a* message
// notification arrived — which `s02_stdio_message_reaches_its_own_call_before_
// the_result` already asserts, and which no misrouting could fail. It is
// omitted deliberately. A test that cannot fail is worse than a missing one,
// because the criteria ledger counts it.
//
// This is recorded as UNMET, not as covered: see ADR-014 Amendment 1 and the
// `MIK-7272.SUB.2b` row of `docs/requirements/RELEASE-4.0.0-criteria-status.md`.
// The `notifications/progress` half has a real stdio row above, because the
// client's own token gives it a discriminator.

// ── S-02 and S-03 over HTTP ─────────────────────────────────────────────────
//
// Four rows belong here: the progress and message halves of `S-02`, and both
// halves of `S-03`. Both halves of `S-03` are written below, on the harness
// that follows.
//
// The two `S-02` rows assert liveness: the fixture releases a result only once
// the client has read the notification (ADR-014 Acceptance row 4). They
// therefore cannot use `post_sse`, which reads a body to its end — a client
// that waits for the whole body waits for a result the fixture is withholding
// from it, and the four-step deadlock that follows is a property of the
// consumer and not of any harness. `SseReader` below is the incremental
// consumer they need instead.
//
// `S-03` is unaffected either way: which stream carried which notification is
// fully observable in a buffered body. Batching breaks liveness, not
// isolation, which is why the two `S-03` rows keep reading to the end.
