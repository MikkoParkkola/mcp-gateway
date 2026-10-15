// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! L1: complete GET refusal precedes native session effects.

use axum::body::Body;
use axum::http::StatusCode;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::super::audience_ear::{Ear, EventOutcome};
use super::super::audience_fixture::{World, adapter_assertion, asserted};
use crate::gateway::streaming::TaggedNotification;

fn get(
    authorization: Option<&str>,
    session: Option<&str>,
    assertion: Option<&str>,
    last_event: Option<&str>,
) -> axum::http::Request<Body> {
    let mut builder = axum::http::Request::builder()
        .method("GET")
        .uri("/mcp")
        .header("accept", "text/event-stream");
    if let Some(value) = authorization {
        builder = builder.header("authorization", value);
    }
    if let Some(value) = session {
        builder = builder.header("mcp-session-id", value);
    }
    if let Some(value) = last_event {
        builder = builder.header("last-event-id", value);
    }
    let mut request = builder.body(Body::empty()).expect("VOID: request builds");
    asserted(&mut request, assertion);
    request
}

async fn refusal(response: axum::response::Response) -> Vec<u8> {
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "VOID: native dead-attach401 premise"
    );
    assert!(
        response.headers().get("mcp-session-id").is_none(),
        "VOID: refusal has no session header"
    );
    let bytes = crate::test_pause::within(
        "finite refusal body",
        axum::body::to_bytes(response.into_body(), usize::MAX),
    )
    .await
    .expect("VOID: refusal body reads");
    let actual: Value = serde_json::from_slice(&bytes).expect("VOID: canonical refusal JSON");
    assert_eq!(
        actual,
        json!({"jsonrpc":"2.0","id":null,"error":{"code":-32000,"message":"Invalid token"}}),
        "VOID: full native dead-attach wire premise"
    );
    bytes.to_vec()
}

async fn next(ear: &mut Ear) -> Value {
    match ear {
        Ear::Sse { relay, .. } => crate::test_pause::within("actual GET relay event", relay.recv())
            .await
            .expect_event("VOID: an actual event, not EOF/error/timeout"),
        _ => panic!("VOID: real GET required"),
    }
}

async fn marker(world: &World, ear: &mut Ear, value: &str) {
    let data = json!({"jsonrpc":"2.0","method":"notifications/l1_probe","params":{"marker":value}});
    assert!(
        world.state.multiplexer.send_to_session(
            ear.session_id(),
            TaggedNotification {
                source: "l1-control".into(),
                event_type: "message".into(),
                data: data.clone(),
                event_id: None,
            }
        ),
        "VOID: native marker send reached an actual receiver"
    );
    let outcome = match ear {
        Ear::Sse { relay, .. } => {
            crate::test_pause::within("owned marker read", relay.recv()).await
        }
        _ => panic!("VOID: real GET marker reader required"),
    };
    assert_eq!(
        outcome,
        EventOutcome::Event(data),
        "L1_ORIGINAL_BODY_MARKER: exact actual delivery, never EOF/error"
    );
}

async fn resume_controls(world: &World, id: &str, assertion: &str) {
    let resumed = world
        .router
        .clone()
        .oneshot(get(
            Some("Bearer k-std"),
            Some(id),
            Some(assertion),
            Some("valid-resume"),
        ))
        .await
        .expect("VOID: resume serves");
    assert!(
        resumed.status().is_success(),
        "VOID: same live owner resume succeeds"
    );
    assert_eq!(resumed.headers()["mcp-session-id"].to_str().unwrap(), id);
    assert_eq!(
        world.state.multiplexer.last_event_id(id).as_deref(),
        Some("valid-resume")
    );
    let outsider = adapter_assertion("bob");
    let other = world
        .router
        .clone()
        .oneshot(get(Some("Bearer k-std"), Some(id), Some(&outsider), None))
        .await
        .expect("VOID: other owner serves");
    assert!(
        other.status().is_success(),
        "VOID: different owner may open own session"
    );
    assert_ne!(
        other.headers()["mcp-session-id"].to_str().unwrap(),
        id,
        "different owner never joins original"
    );
}

#[tokio::test]
async fn l1_refused_new_get_creates_no_session() {
    let world = World::start_public().await;
    let (status, anonymous) = world.anonymous_sse().await;
    assert!(status.is_success(), "VOID: anonymous control opens");
    let mut anonymous = anonymous.expect("VOID: real anonymous body");
    assert_eq!(
        next(&mut anonymous).await["session_id"],
        anonymous.session_id()
    );
    let mut valid = world.sse("k-std").await;
    assert_eq!(next(&mut valid).await["session_id"], valid.session_id());
    let before = world.state.multiplexer.session_count();
    let mut twin = None;
    for authorization in ["Bearer wrong", "Basic abc"] {
        let response = crate::test_pause::within(
            "refused GET",
            world
                .router
                .clone()
                .oneshot(get(Some(authorization), None, None, None)),
        )
        .await
        .expect("VOID: route serves");
        let body = refusal(response).await;
        if let Some(expected) = &twin {
            assert_eq!(&body, expected, "VOID: full canonical refusal twin");
        }
        twin = Some(body);
        assert_eq!(
            world.state.multiplexer.session_count(),
            before,
            "L1_REFUSAL_COUNT: no session effect"
        );
    }
    marker(&world, &mut anonymous, "anonymous-healthy").await;
    marker(&world, &mut valid, "valid-healthy").await;
}

#[tokio::test]
async fn l1_refused_known_anonymous_get_preserves_native_history_and_body() {
    let world = World::start_public().await;
    let (status, anonymous) = world.anonymous_sse().await;
    assert!(status.is_success(), "VOID: anonymous control opens");
    let mut ear = anonymous.expect("VOID: actual anonymous body");
    assert_eq!(next(&mut ear).await["session_id"], ear.session_id());
    marker(&world, &mut ear, "before-refusal").await;
    let id = ear.session_id().to_owned();
    let before = world
        .state
        .multiplexer
        .get_session_facts(&id)
        .expect("VOID: session exists");
    let count = world.state.multiplexer.session_count();
    for authorization in ["Bearer wrong", "Basic abc"] {
        let response = crate::test_pause::within(
            "known-id refused GET",
            world.router.clone().oneshot(get(
                Some(authorization),
                Some(&id),
                None,
                Some("untrusted-overwrite"),
            )),
        )
        .await
        .expect("VOID: route serves");
        let _body = refusal(response).await;
        assert_eq!(
            world.state.multiplexer.session_count(),
            count,
            "L1_SAME_ID_COUNT"
        );
        assert_eq!(
            world.state.multiplexer.get_session_facts(&id).as_ref(),
            Some(&before),
            "L1_NATIVE_FACTS: held/reader/epoch/told/history/active unchanged"
        );
        marker(&world, &mut ear, authorization).await;
    }
}

#[tokio::test]
async fn l1_same_owner_adapter_dies_after_owner_resolution_without_session_mutation() {
    let world = World::start_adapter(|meta| meta).await;
    let issued = crate::clock::unix_secs().expect("VOID: native clock readable");
    let first_clock = crate::clock::test_clock::at_secs(issued);
    let old_assertion = adapter_assertion("alice");
    drop(first_clock);
    let seed_clock = crate::clock::test_clock::at_secs(issued + 90);
    let assertion = adapter_assertion("alice");
    let mut ear = world.sse_as("k-std", Some(&assertion)).await;
    assert_eq!(next(&mut ear).await["session_id"], ear.session_id());
    marker(&world, &mut ear, "adapter-before").await;
    let id = ear.session_id().to_owned();
    let before = world
        .state
        .multiplexer
        .get_session_facts(&id)
        .expect("VOID: session exists");
    assert!(
        before.4.len() == 1,
        "VOID: original native baselined view history exists"
    );
    let count = world.state.multiplexer.session_count();
    let (reached, release) = world.state.multiplexer.before_get_resolve.arm();
    let mut request = get(
        Some("Bearer k-std"),
        Some(&id),
        Some(&old_assertion),
        Some("must-not-overwrite"),
    );
    *request.uri_mut() = "/mcp?codemode=search_and_execute"
        .parse()
        .expect("VOID: query builds");
    let mut pending = Box::pin(world.router.clone().oneshot(request));
    tokio::select! {
        biased;
        () = crate::test_pause::within("after-owner GET resolve pause", reached.notified()) => {}
        response = &mut pending => panic!("VOID: request returned before the native pause: {:?}", response.map(|r| r.status())),
    }
    assert_eq!(
        world.state.multiplexer.get_session_facts(&id).as_ref(),
        Some(&before),
        "VOID: pause is genuinely before native session effects"
    );
    // Native owner/admission and signed adapter were accepted at live time;
    // only this existing thread-local clock moves for the pending full resolve.
    drop(seed_clock);
    let past = crate::clock::test_clock::at_secs(issued + 151);
    release.notify_one();
    let response = crate::test_pause::within("expired prepared GET", pending)
        .await
        .expect("VOID: route serves");
    let _body = refusal(response).await;
    // Keep time151: original fresh assertion lives until240; no rollback.
    let _held_past = past;
    assert_eq!(
        world.state.multiplexer.session_count(),
        count,
        "L1_MATCHING_OWNER_COUNT"
    );
    let after = world
        .state
        .multiplexer
        .get_session_facts(&id)
        .expect("VOID: original remains");
    assert_eq!(
        after.4, before.4,
        "L1_MATCHING_OWNER_RECORDS: native count/key/history unchanged"
    );
    assert_eq!(
        after, before,
        "L1_MATCHING_OWNER_FACTS: held/reader/event/touch unchanged"
    );
    marker(&world, &mut ear, "adapter-after-refusal").await;
    resume_controls(&world, &id, &assertion).await;
}

#[tokio::test]
async fn l1_cancel_pending_full_get_admission_has_zero_session_effects() {
    let world = World::start_public().await;
    let (status, anonymous) = world.anonymous_sse().await;
    assert!(status.is_success(), "VOID: control opens");
    let mut ear = anonymous.expect("VOID: original real body");
    let _connected = next(&mut ear).await;
    marker(&world, &mut ear, "cancel-before").await;
    let id = ear.session_id().to_owned();
    let count = world.state.multiplexer.session_count();
    let facts = world
        .state
        .multiplexer
        .get_session_facts(&id)
        .expect("VOID: original exists");
    let (reached, release) = world.state.multiplexer.before_get_resolve.arm();
    let mut pending = Box::pin(world.router.clone().oneshot(get(
        Some("Bearer k-std"),
        None,
        None,
        None,
    )));
    tokio::select! {
        biased;
        () = crate::test_pause::within("pending native full admission", reached.notified()) => {}
        response = &mut pending => panic!("VOID: request returned before pause: {:?}", response.map(|r| r.status())),
    }
    drop(pending);
    release.notify_one();
    assert_eq!(
        world.state.multiplexer.session_count(),
        count,
        "L1_CANCELED_COUNT"
    );
    assert_eq!(
        world.state.multiplexer.get_session_facts(&id).as_ref(),
        Some(&facts),
        "L1_CANCELED_HISTORY"
    );
    marker(&world, &mut ear, "cancel-after").await;
}
