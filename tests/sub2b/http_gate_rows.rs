// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// `S-02` over HTTP: the per-event flush rows and their discriminator.
//
// Included into `mik_7272_sub2b_acs.rs`, not compiled as a test binary of its
// own -- these rows need that file's fixture backend and stdio harness. The
// pair travels together: the second row is only meaningful as the
// discriminator for the first. Split out so the parent stays under the
// file-size ceiling `scripts/dev/check-file-size.py` gates.

/// `S-02`, HTTP: each notification reaches the caller as it decodes, not
/// batched into one write at the end.
///
/// GIVEN a backend that emits its second notification only after a release,
/// WHEN the client reads the first notification and releases,
/// THEN the second notification arrives before the result.
///
/// One gate proves a flush happened; two prove the flushing is per-event. The
/// frame that prompts the second release does not exist until the first has
/// been read and acted on, so a consumer that drains one buffer at the end
/// never reaches it. The PROBE labels localise a failure: which one fires says
/// whether the release was serviced, whether the frame followed it, and
/// whether the result ever came.
#[tokio::test]
#[ignore = "reproduction for the open client-leg defect; un-ignore with the fix"]
async fn s02_http_flushes_each_notification_rather_than_one_buffer() {
    // GIVEN
    let (backend_url, received, _gate) = spawn_fixture_backend().await;
    let home = tempfile::tempdir().expect("temp home");
    let session = HttpSession::spawn(home.path(), &backend_url).await;

    // WHEN
    let (first, second, result) = timeout(READ_TIMEOUT * 10, async {
        let (status, content_type, mut reader) = SseReader::post(
            &session.client,
            &session.url,
            &session.session,
            invoke(
                2,
                SLOW_TOOL,
                &json!({"gates": 2}),
                &json!({"progressToken": "client-token"}),
            ),
        )
        .await;
        assert_eq!(
            status, 200,
            "the two-gate call was refused before it streamed"
        );
        assert!(
            content_type.contains("text/event-stream"),
            "the gateway answered {content_type}, so it never committed to a \
             stream and nothing below can arrive early"
        );

        let first = reader
            .next_frame()
            .await
            .expect("the body ended before the first notification");
        assert!(
            parked_slow_calls(&received, 1).await,
            "the frame arrived but the call is not parked, so it proves no \
             liveness: {first}"
        );

        timeout(READ_TIMEOUT, release(&session, 3))
            .await
            .expect("PROBE-A: the release call never returned while the first call streamed");
        let second = timeout(READ_TIMEOUT, reader.next_frame())
            .await
            .expect("PROBE-B: the release landed but no second frame followed")
            .expect("the body ended before the second notification");

        timeout(READ_TIMEOUT, release(&session, 4))
            .await
            .expect("PROBE-C: the second release call never returned");
        let mut result = timeout(READ_TIMEOUT, reader.next_frame())
            .await
            .expect("PROBE-D: no frame followed the second release");
        while result.as_ref().is_some_and(|frame| !has_id(frame, 2)) {
            result = timeout(READ_TIMEOUT, reader.next_frame())
                .await
                .expect("PROBE-E: the stream stalled before the result frame");
        }
        (
            first,
            second,
            result.expect("the body ended before the result frame"),
        )
    })
    .await
    .expect("the row deadlocked, which is one buffered flush answering");

    // THEN
    assert_eq!(
        first.pointer("/params/progress"),
        Some(&json!(1)),
        "the first frame is not the first notification: {first}"
    );
    assert!(
        is_method(&second, "notifications/progress"),
        "the second gated frame is not a notification: {second}"
    );
    assert_eq!(
        second.pointer("/params/progress"),
        Some(&json!(2)),
        "the second frame repeats the first, so no second flush is proven: {second}"
    );
    assert_eq!(
        progress_token_of(&second),
        Some(&json!("client-token")),
        "the client must see its own token back on every frame: {second}"
    );
    assert!(
        has_id(&result, 2),
        "the last frame is not this call's result: {result}"
    );
    session.shutdown().await;
}

/// The discriminator: identical to the two-gate row except the second
/// notification is emitted on a timer, with no client call in between. It
/// separates "the client leg forwards only one notification" from "the second
/// notification is never produced while a stream is open".
#[tokio::test]
#[ignore = "discriminator for the row above; runs with it"]
async fn s02_http_forwards_a_second_notification_with_no_call_between() {
    let (backend_url, _received, _gate) = spawn_fixture_backend().await;
    let home = tempfile::tempdir().expect("temp home");
    let session = HttpSession::spawn(home.path(), &backend_url).await;

    let (_status, _ct, mut reader) = SseReader::post(
        &session.client,
        &session.url,
        &session.session,
        invoke(
            2,
            SLOW_TOOL,
            &json!({"gates": 3}),
            &json!({"progressToken": "client-token"}),
        ),
    )
    .await;
    let first = reader.next_frame().await.expect("first frame");
    assert_eq!(first.pointer("/params/progress"), Some(&json!(1)));
    let second = timeout(READ_TIMEOUT, reader.next_frame())
        .await
        .expect("no second frame followed the timer")
        .expect("the body ended before the second notification");
    assert_eq!(
        second.pointer("/params/progress"),
        Some(&json!(2)),
        "the timed second notification did not reach the client: {second}"
    );
    session.shutdown().await;
}
