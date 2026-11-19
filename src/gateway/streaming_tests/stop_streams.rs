// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! D3: the stop's trigger ends session streams, so a streaming client
//! no longer holds the listener for its grace. An open stream settles what it
//! still holds, unwritten, and ends; one opened after the trigger writes its
//! connected event and ends.

use std::sync::atomic::{AtomicUsize, Ordering};

use super::credential_at_write::{
    key_server_with_token, multiplexer, note, read_until, until_it_ends,
};
use super::*;
use futures::StreamExt as _;

/// A session that presented no credential, as a public caller's does.
fn session(multiplexer: &NotificationMultiplexer) -> String {
    multiplexer
        .get_or_create_session_id_scoped(
            None,
            &crate::gateway::session_id::SessionOwner::Anonymous,
            None,
        )
        .expose_secret()
        .to_owned()
}

/// The body of the session's GET stream, resumed from `last_event_id`.
fn body(
    multiplexer: &Arc<NotificationMultiplexer>,
    id: &str,
    last_event_id: Option<&str>,
) -> axum::body::BodyDataStream {
    use axum::response::IntoResponse as _;
    create_sse_response(
        Arc::clone(multiplexer),
        id.to_owned(),
        last_event_id.map(str::to_owned),
        Duration::from_secs(3600),
    )
    .expect("the session exists")
    .into_response()
    .into_body()
    .into_data_stream()
}

/// S-late: a stream opened after the stop writes its connected event and ends.
#[tokio::test]
async fn s_late_a_stream_opened_after_the_stop_ends_after_connecting() {
    let (key_server, _, _) = key_server_with_token().await;
    let multiplexer = multiplexer(&key_server);
    let id = session(&multiplexer);
    multiplexer.stop_streams();
    let mut body = body(&multiplexer, &id, None);
    let (seen, ended) = read_until(&mut body, until_it_ends).await;
    assert!(ended, "a stream opened after the stop stayed open: {seen}");
    assert!(
        seen.contains("connected"),
        "the stream ended before its connected event: {seen}"
    );
}

/// S-resume: a resumed stream holding a frame and a bridged prompt, queued and
/// unread when the stop comes, ends without writing either. The prompt's waiter
/// fails at once, no relay receipt commits, and the provisional-session counts
/// are where they were before the stream.
#[tokio::test]
async fn s_resume_the_stop_settles_what_a_resumed_stream_holds() {
    use crate::gateway::input_bridge::{ClientChannel as _, DeliveryCommit, DeliveryError};
    let (key_server, _, _) = key_server_with_token().await;
    let multiplexer = multiplexer(&key_server);
    let provisional = || {
        (
            multiplexer.provisional_live.load(Ordering::SeqCst),
            multiplexer.provisional_stream_live.load(Ordering::SeqCst),
        )
    };
    let before = provisional();
    let id = session(&multiplexer);
    let mut body = body(&multiplexer, &id, Some("1"));
    let first = tokio::time::timeout(Duration::from_secs(5), body.next())
        .await
        .expect("the connected event arrives")
        .expect("the stream is open")
        .expect("the body reads");
    assert!(String::from_utf8_lossy(&first).contains("connected"));
    assert!(multiplexer.send_to_session(&id, note("rows://s-resume")));
    let proxy = crate::gateway::proxy::ProxyManager::new(Arc::clone(&multiplexer));
    let commits = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&commits);
    let commit = DeliveryCommit::new(move || {
        counted.fetch_add(1, Ordering::SeqCst);
    });
    let asked = proxy.send_request_committing(
        &id,
        "s-resume-prompt",
        "elicitation/create",
        Some(json!({ "message": "Proceed?" })),
        Some(commit),
    );
    tokio::pin!(asked);
    assert!(
        futures::poll!(&mut asked).is_pending(),
        "premise: the prompt is queued and waits"
    );
    multiplexer.stop_streams();
    let (seen, ended) = read_until(&mut body, until_it_ends).await;
    assert!(ended, "the stream stayed open after the stop: {seen}");
    assert!(
        !seen.contains("rows://s-resume") && !seen.contains("s-resume-prompt"),
        "the stop wrote what was queued: {seen}"
    );
    let answer = tokio::time::timeout(Duration::from_secs(2), &mut asked)
        .await
        .ok();
    assert!(
        matches!(answer, Some(Err(DeliveryError::TimedOut))),
        "the queued prompt's waiter must fail at once: {answer:?}"
    );
    assert_eq!(
        commits.load(Ordering::SeqCst),
        0,
        "an unwritten prompt committed its receipt"
    );
    drop(body);
    assert_eq!(
        provisional(),
        before,
        "the stream left a provisional session counted"
    );
}
