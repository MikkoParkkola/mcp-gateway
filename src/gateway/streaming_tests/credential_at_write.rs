// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7798 G6/H2: the legacy session stream checks the session's credential
//! when it writes a copy, not only when the copy is queued. A credential that
//! died in between is written nothing, its stream ends, and a server-to-client
//! request queued behind it fails its waiter at once with no relay receipt.
//!
//! The body is not polled between the queueing and the revocation, so every
//! copy waits unwritten in the session's buffer.

use super::listen_graceful::{authorizer, bearer, temporary_token};
use super::*;
use crate::test_wait::HANG_BOUND;
use futures::StreamExt as _;

/// A key server holding one live temporary token; its credential and `jti`.
async fn key_server_with_token() -> (
    Arc<crate::key_server::KeyServer>,
    Option<HeldCredential>,
    String,
) {
    let key_server = Arc::new(crate::key_server::KeyServer::new(
        crate::config::KeyServerConfig::default(),
    ));
    let token = temporary_token();
    let (credential, jti) = (bearer(&token.token), token.jti.clone());
    key_server.store.insert(token).await;
    (key_server, credential, jti)
}

/// A session holding `credential`, with its SSE body open past `connected`.
async fn open(
    multiplexer: &Arc<NotificationMultiplexer>,
    credential: Option<HeldCredential>,
) -> (String, axum::body::BodyDataStream) {
    use axum::response::IntoResponse as _;
    let id = multiplexer
        .get_or_create_session_id_scoped(
            None,
            &crate::gateway::session_id::SessionOwner::Anonymous,
            credential,
        )
        // The raw id the session map is keyed on, as the GET /mcp handler
        // passes it; `Display` prints only the fingerprint.
        .expose_secret()
        .to_owned();
    let sse = create_sse_response(
        Arc::clone(multiplexer),
        id.clone(),
        None,
        Duration::from_secs(3600),
    )
    .expect("the session exists");
    let mut body = sse.into_response().into_body().into_data_stream();
    let first = tokio::time::timeout(Duration::from_secs(5), body.next())
        .await
        .expect("the connected event arrives")
        .expect("the stream is open")
        .expect("the body reads");
    assert!(String::from_utf8_lossy(&first).contains("connected"));
    (id, body)
}

/// How long a row watches for a write or an end that must not happen.
const SETTLE: Duration = Duration::from_millis(500);

/// What the stream writes within `within`, and whether it ended. For a check
/// that something is NOT written: a positive assert on this result races the
/// window (MIK-8295), so use [`read_until`] for that.
async fn read_for_absence(
    body: &mut axum::body::BodyDataStream,
    within: Duration,
) -> (String, bool) {
    let deadline = tokio::time::Instant::now() + within;
    let mut seen = String::new();
    loop {
        match tokio::time::timeout_at(deadline, body.next()).await {
            Err(_) => return (seen, false),
            Ok(None) => return (seen, true),
            Ok(Some(Ok(chunk))) => seen.push_str(&String::from_utf8_lossy(&chunk)),
            Ok(Some(Err(error))) => panic!("the session body failed: {error}"),
        }
    }
}

/// What the stream writes until `until` holds for it, the stream ends, or
/// `HANG_BOUND` passes (the caller's assert then says what was missing), and
/// whether it ended. Once `until` holds, it keeps reading for `SETTLE`, where
/// an extra write or an end that must not happen would show.
async fn read_until(
    body: &mut axum::body::BodyDataStream,
    until: impl Fn(&str) -> bool,
) -> (String, bool) {
    let deadline = tokio::time::Instant::now() + HANG_BOUND;
    let mut seen = String::new();
    while !until(&seen) {
        match tokio::time::timeout_at(deadline, body.next()).await {
            Err(_) => return (seen, false),
            Ok(None) => return (seen, true),
            Ok(Some(Ok(chunk))) => seen.push_str(&String::from_utf8_lossy(&chunk)),
            Ok(Some(Err(error))) => panic!("the session body failed: {error}"),
        }
    }
    // timing: absence
    let (more, ended) = read_for_absence(body, SETTLE).await;
    (seen + &more, ended)
}

/// Read until the stream ends: the event a revoked token's stream must reach.
fn until_it_ends(_: &str) -> bool {
    false
}

fn note(uri: &str) -> TaggedNotification {
    TaggedNotification {
        source: "alpha".to_string(),
        event_type: "message".to_string(),
        data: json!({
            "jsonrpc": "2.0",
            "method": "notifications/resources/updated",
            "params": { "uri": uri },
        }),
        event_id: None,
    }
}

fn multiplexer(key_server: &Arc<crate::key_server::KeyServer>) -> Arc<NotificationMultiplexer> {
    let multiplexer = Arc::new(NotificationMultiplexer::new(
        Arc::new(BackendRegistry::new()),
        StreamingConfig::default(),
    ));
    multiplexer.set_authorizer(authorizer(Arc::clone(key_server)));
    multiplexer
}

/// R9: two sessions on one backend; one session's token is revoked after both
/// copies are queued. The live one reads its copy; the revoked one is written
/// nothing and its stream ends.
#[tokio::test]
async fn a_token_revoked_after_its_copy_is_queued_is_written_nothing() {
    let (key_server, revoked_credential, jti) = key_server_with_token().await;
    let kept_token = temporary_token();
    let kept_credential = bearer(&kept_token.token);
    key_server.store.insert(kept_token).await;
    let multiplexer = multiplexer(&key_server);
    let (_, mut kept) = open(&multiplexer, kept_credential).await;
    let (_, mut revoked) = open(&multiplexer, revoked_credential).await;

    let reached = multiplexer
        .broadcast_to_backend(&note("rows://r9"), "alpha")
        .await;
    assert_eq!(
        reached, 2,
        "both tokens are live when the copies are queued"
    );
    assert!(key_server.store.revoke_by_jti(&jti).await);

    let (seen, _) = read_until(&mut kept, |s| s.contains("rows://r9")).await;
    assert!(seen.contains("rows://r9"), "the live twin reads it: {seen}");
    let (seen, ended) = read_until(&mut revoked, until_it_ends).await;
    assert!(
        !seen.contains("rows://r9"),
        "a revoked token's queued copy was written: {seen}"
    );
    assert!(ended, "the revoked token's stream ends at the write");
}

/// The credential a session holds when its stream writes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Held {
    /// A token that stays live.
    Live,
    /// A token revoked after the copies are queued.
    Revoked,
    /// No credential at all: a public caller.
    Nothing,
}

/// A frame, then a bridged prompt, queued on one session holding `held`; the
/// stream then read. Returns the prompt's wait (`None` while it still waits),
/// its receipt count, and what the stream wrote.
async fn prompt_behind_a_frame(
    held: Held,
) -> (
    Option<std::result::Result<serde_json::Value, crate::gateway::input_bridge::DeliveryError>>,
    usize,
    String,
) {
    use crate::gateway::input_bridge::{ClientChannel as _, DeliveryCommit};
    use std::sync::atomic::{AtomicUsize, Ordering};

    let (key_server, credential, jti) = key_server_with_token().await;
    let multiplexer = multiplexer(&key_server);
    let credential = if held == Held::Nothing {
        None
    } else {
        credential
    };
    let (id, mut body) = open(&multiplexer, credential).await;
    assert!(multiplexer.send_to_session(&id, note("rows://r11")));
    let proxy = crate::gateway::proxy::ProxyManager::new(Arc::clone(&multiplexer));
    let commits = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&commits);
    let commit = DeliveryCommit::new(move || {
        counted.fetch_add(1, Ordering::SeqCst);
    });
    let asked = proxy.send_request_committing(
        &id,
        "r11-prompt",
        "elicitation/create",
        Some(json!({ "message": "Proceed?" })),
        Some(commit),
    );
    tokio::pin!(asked);
    assert!(
        futures::poll!(&mut asked).is_pending(),
        "the prompt is queued and waits"
    );
    if held == Held::Revoked {
        assert!(key_server.store.revoke_by_jti(&jti).await);
    }
    let (seen, _) = if held == Held::Revoked {
        read_until(&mut body, until_it_ends).await
    } else {
        read_until(&mut body, |s| {
            s.contains("rows://r11") && s.contains("r11-prompt")
        })
        .await
    };
    let answer = tokio::time::timeout(Duration::from_secs(2), &mut asked)
        .await
        .ok();
    (answer, commits.load(Ordering::SeqCst), seen)
}

/// R11 (H2): the frame ahead of a bridged prompt finds the token revoked. The
/// prompt is never written, its waiter fails at once rather than waiting for a
/// reply that cannot come, and no relay receipt commits. Twin: a live token's
/// stream writes both and commits the receipt once.
#[tokio::test]
async fn a_prompt_queued_behind_a_dead_credential_fails_its_waiter_at_once() {
    let (answer, commits, seen) = prompt_behind_a_frame(Held::Live).await;
    assert!(
        seen.contains("rows://r11") && seen.contains("r11-prompt"),
        "{seen}"
    );
    assert_eq!(commits, 1, "a written prompt commits its receipt once");
    assert!(
        answer.is_none(),
        "a written prompt waits for its reply: {answer:?}"
    );

    let (answer, commits, seen) = prompt_behind_a_frame(Held::Revoked).await;
    assert!(
        !seen.contains("rows://r11") && !seen.contains("r11-prompt"),
        "a revoked token was written to: {seen}"
    );
    assert!(
        matches!(
            answer,
            Some(Err(crate::gateway::input_bridge::DeliveryError::TimedOut))
        ),
        "the stranded prompt's waiter must fail at once: {answer:?}"
    );
    assert_eq!(commits, 0, "an unwritten prompt committed its receipt");
}

/// Seat finding on the write-time check: a session that presented no
/// credential (a public `/mcp` caller under gateway authentication) has nothing
/// to re-validate, so a real bridged prompt is still written to it and its
/// receipt commits once.
#[tokio::test]
async fn a_credentialless_public_session_still_receives_its_prompts() {
    let (answer, commits, seen) = prompt_behind_a_frame(Held::Nothing).await;
    assert!(
        seen.contains("rows://r11") && seen.contains("r11-prompt"),
        "the public session was not written to: {seen}"
    );
    assert_eq!(commits, 1, "a written prompt commits its receipt once");
    assert!(
        answer.is_none(),
        "a written prompt waits for its reply: {answer:?}"
    );
}

/// A session with a one-slot buffer, holding `held`, sent three copies so it
/// lags; returns what its stream writes and whether it ended.
async fn lagging_stream(held: Held) -> (String, bool) {
    let (key_server, credential, jti) = key_server_with_token().await;
    let multiplexer = Arc::new(NotificationMultiplexer::new(
        Arc::new(BackendRegistry::new()),
        StreamingConfig {
            buffer_size: 1,
            ..StreamingConfig::default()
        },
    ));
    multiplexer.set_authorizer(authorizer(Arc::clone(&key_server)));
    let credential = if held == Held::Nothing {
        None
    } else {
        credential
    };
    let (id, mut body) = open(&multiplexer, credential).await;
    for uri in ["rows://lag-1", "rows://lag-2", "rows://lag-3"] {
        assert!(multiplexer.send_to_session(&id, note(uri)));
    }
    if held == Held::Revoked {
        assert!(key_server.store.revoke_by_jti(&jti).await);
    }
    if held == Held::Revoked {
        read_until(&mut body, until_it_ends).await
    } else {
        read_until(&mut body, |s| {
            s.contains("lagged") && s.contains("rows://lag-3")
        })
        .await
    }
}

/// Seat finding: the `lagged` notice is a frame like any other, so a stream
/// whose token was revoked while it fell behind gets no notice and ends.
/// Controls: a live token and a credentialless session both get the notice
/// and the newest copy, and stay open.
#[tokio::test]
async fn a_lagging_stream_whose_token_died_gets_no_lagged_notice() {
    for held in [Held::Live, Held::Nothing] {
        let (seen, ended) = lagging_stream(held).await;
        assert!(
            seen.contains("lagged") && seen.contains("rows://lag-3"),
            "a lagging live stream is told and keeps reading: {seen}"
        );
        assert!(!ended, "a lagging live stream stays open");
    }

    let (seen, ended) = lagging_stream(Held::Revoked).await;
    assert!(
        !seen.contains("lagged") && !seen.contains("rows://lag"),
        "a revoked token was written to: {seen}"
    );
    assert!(ended, "the revoked token's stream ends");
}
