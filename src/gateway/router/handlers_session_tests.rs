// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! F9: session ids are minted by the gateway, never adopted, never empty.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;
use tower::ServiceExt;

use super::session_owner;
use crate::gateway::auth::{AuthenticatedClient, anonymous_client};
use crate::gateway::router::create_router;
use crate::gateway::router::tests::test_router_app_state;
use crate::gateway::session_id::log_capture::{assert_fingerprinted, capture_debug};

fn unauthenticated(name: &str) -> AuthenticatedClient {
    AuthenticatedClient {
        name: name.to_string(),
        ..anonymous_client()
    }
}

fn credential(principal: &str) -> AuthenticatedClient {
    AuthenticatedClient {
        name: "key".to_string(),
        principal: principal.to_string(),
        authenticated: true,
        ..anonymous_client()
    }
}

fn legacy_post(session: Option<&str>, body: serde_json::Value) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json");
    if let Some(id) = session {
        builder = builder.header("mcp-session-id", id);
    }
    builder.body(Body::from(body.to_string())).unwrap()
}

fn ping() -> serde_json::Value {
    json!({"jsonrpc": "2.0", "id": 1, "method": "ping"})
}

fn session_header(response: &axum::response::Response) -> Option<String> {
    response
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
}

// F9-T1
#[tokio::test]
async fn an_empty_or_blank_session_id_is_never_a_session() {
    for blank in ["", "   "] {
        let (state, _store) = test_router_app_state().await;
        let router = create_router(Arc::clone(&state));
        let response = router.oneshot(legacy_post(Some(blank), ping())).await.unwrap();
        assert!(
            !state.multiplexer.has_session(blank),
            "{blank:?} must not become a session"
        );
        let minted = session_header(&response).expect("a minted id comes back");
        assert!(minted.starts_with("gw-"), "minted, not adopted: {minted:?}");
    }
}

// F9-T3b
#[tokio::test]
async fn a_client_chosen_id_is_replaced_on_get_and_post() {
    let chosen = "chosen-by-client";
    let (state, _store) = test_router_app_state().await;
    let get = Request::builder()
        .method("GET")
        .uri("/mcp")
        .header("accept", "text/event-stream")
        .header("mcp-session-id", chosen)
        .body(Body::empty())
        .unwrap();
    let post = legacy_post(Some(chosen), ping());
    for request in [get, post] {
        let router = create_router(Arc::clone(&state));
        let response = router.oneshot(request).await.unwrap();
        let returned = session_header(&response).expect("a session id comes back");
        assert_ne!(returned, chosen, "the chosen id must not be echoed");
        assert!(returned.starts_with("gw-"), "minted: {returned:?}");
        assert!(!state.multiplexer.has_session(chosen));
    }
}

// F9-T3
#[tokio::test]
async fn a_presented_id_that_names_no_session_is_not_adopted() {
    let (state, _store) = test_router_app_state().await;
    let (id, _rx) = state
        .multiplexer
        .get_or_create_session_for(Some("chosen"), &session_owner(None));
    assert_ne!(id, "chosen");
    assert!(id.starts_with("gw-"), "minted: {id:?}");
    assert!(!state.multiplexer.has_session("chosen"));
}

// F9-T4
#[tokio::test]
async fn anonymous_sessions_are_kept_apart_by_their_minted_ids() {
    let (state, _store) = test_router_app_state().await;
    let m = &state.multiplexer;
    let anon = session_owner(None);
    let (a, _ra) = m.get_or_create_session_for(None, &anon);
    let (b, _rb) = m.get_or_create_session_for(None, &anon);
    assert_ne!(a, b);
    assert_eq!(m.get_or_create_session_for(Some(&a), &anon).0, a);
    assert_eq!(m.get_or_create_session_for(Some(&b), &anon).0, b);
    let (c, _rc) = m.get_or_create_session_for(Some("gw-not-live"), &anon);
    assert!(c != a && c != b && c != "gw-not-live", "a third, minted id: {c}");
}

// F9-T4b
#[tokio::test]
async fn every_unauthenticated_caller_is_one_owner_class() {
    let public = unauthenticated("public");
    assert_eq!(session_owner(Some(&public)), session_owner(None));
    let (state, _store) = test_router_app_state().await;
    let m = &state.multiplexer;
    let (id, _rx) = m.get_or_create_session_for(None, &session_owner(Some(&public)));
    let (again, _rx2) = m.get_or_create_session_for(Some(&id), &session_owner(None));
    assert_eq!(again, id, "the holder of the minted id resumes it");
}

// F9-T6
#[tokio::test]
async fn credential_and_anonymous_sessions_never_resume_each_other() {
    let (state, _store) = test_router_app_state().await;
    let m = &state.multiplexer;
    let anon = session_owner(None);
    let cred = session_owner(Some(&credential("p1")));
    let (anon_id, _ra) = m.get_or_create_session_for(None, &anon);
    let (cred_id, _rc) = m.get_or_create_session_for(None, &cred);
    assert_ne!(m.get_or_create_session_for(Some(&anon_id), &cred).0, anon_id);
    assert_ne!(m.get_or_create_session_for(Some(&cred_id), &anon).0, cred_id);
}

fn delete(session: &str) -> Request<Body> {
    Request::builder()
        .method("DELETE")
        .uri("/mcp")
        .header("mcp-session-id", session)
        .body(Body::empty())
        .unwrap()
}

// F9-T5b
#[tokio::test]
async fn delete_treats_a_blank_id_as_absent() {
    let (state, _store) = test_router_app_state().await;
    for blank in ["", "  "] {
        let response = create_router(Arc::clone(&state))
            .oneshot(delete(blank))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{blank:?}");
    }
    let response = create_router(Arc::clone(&state))
        .oneshot(delete("gw-owned-by-nobody"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

fn elicit() -> serde_json::Value {
    json!({
        "jsonrpc": "2.0",
        "id": "confirm-1",
        "method": "elicitation/create",
        "params": {"message": "Delete everything?", "requestedSchema": {"type": "object"}}
    })
}

// F9-T2 (+ the legitimate round trip, which must keep working)
#[tokio::test]
async fn a_prompt_reaches_only_its_holder_and_only_its_holder_answers_it() {
    // GIVEN: auth off; anonymous B opens a stream presenting an id it chose,
    // and anonymous A opens its own stream presenting the same id
    let (state, _store) = test_router_app_state().await;
    let anon = session_owner(None);
    let m = &state.multiplexer;
    let (b_id, mut b_rx) = m.get_or_create_session_scoped(Some("gw-shared"), &anon, None);
    let (a_id, mut a_rx) = m.get_or_create_session_scoped(Some("gw-shared"), &anon, None);
    assert_ne!(a_id, b_id, "two callers never share one session");
    // WHEN: A asks for a prompt on the id it was handed
    let router = create_router(Arc::clone(&state));
    let a_for_call = a_id.clone();
    let call = tokio::spawn(async move {
        router
            .oneshot(legacy_post(Some(&a_for_call), elicit()))
            .await
            .unwrap()
    });
    let prompt = tokio::time::timeout(Duration::from_secs(2), a_rx.recv())
        .await
        .expect("the prompt reaches the session that asked")
        .unwrap();
    let prompt_id = prompt.data["id"].as_str().unwrap().to_string();
    // THEN: B's stream never carries it
    let leaked = tokio::time::timeout(Duration::from_millis(300), b_rx.recv()).await;
    assert!(leaked.is_err(), "B received A's prompt: {leaked:?}");
    // AND: B's POST-back, on B's id or on the id both presented, approves nothing
    let accept = json!({"jsonrpc": "2.0", "id": prompt_id, "result": {"action": "accept"}});
    for forged in [b_id.as_str(), "gw-shared"] {
        create_router(Arc::clone(&state))
            .oneshot(legacy_post(Some(forged), accept.clone()))
            .await
            .unwrap();
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!call.is_finished(), "a POST-back from B must not complete A's prompt");
    // AND: A's own POST-back on its minted id completes it
    create_router(Arc::clone(&state))
        .oneshot(legacy_post(Some(&a_id), accept))
        .await
        .unwrap();
    let response = tokio::time::timeout(Duration::from_secs(5), call)
        .await
        .expect("A's own answer completes A's prompt")
        .unwrap();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["result"]["action"], "accept", "{json}");
}

// F9-T7: the session-creating and prompt-delivering flow logs fingerprints only
#[tokio::test]
async fn the_prompt_flow_logs_session_fingerprints_only() {
    let (state, _store) = test_router_app_state().await;
    let (captured, _guard) = capture_debug();
    // A fresh legacy POST mints a session (streaming.rs, handlers.rs "Meta-MCP request")
    let response = create_router(Arc::clone(&state))
        .oneshot(legacy_post(None, ping()))
        .await
        .unwrap();
    let minted = session_header(&response).expect("minted id");
    // A live session asks for a prompt (proxy.rs "Sent elicitation/create")
    let (own, mut rx) = state
        .multiplexer
        .get_or_create_session_for(None, &session_owner(None));
    let router = create_router(Arc::clone(&state));
    let own_for_call = own.clone();
    let call = tokio::spawn(async move {
        router
            .oneshot(legacy_post(Some(&own_for_call), elicit()))
            .await
            .unwrap()
    });
    tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("the prompt reaches the asking session")
        .unwrap();
    call.abort();
    let text = captured.text();
    assert_fingerprinted(&text, "Created new streaming session", &minted);
    assert_fingerprinted(&text, "Meta-MCP request", &minted);
    assert_fingerprinted(&text, "Sent elicitation/create", &own);
}

// F9-T7 (GET) and F9-T7c (DELETE, handlers.rs owned and unowned arms)
#[tokio::test]
async fn get_and_delete_log_session_fingerprints_only() {
    let (state, _store) = test_router_app_state().await;
    let (captured, _guard) = capture_debug();
    let get = Request::builder()
        .method("GET")
        .uri("/mcp")
        .header("accept", "text/event-stream")
        .body(Body::empty())
        .unwrap();
    let response = create_router(Arc::clone(&state)).oneshot(get).await.unwrap();
    let streamed = session_header(&response).expect("minted id");
    drop(response);
    let (owned, _rx) = state
        .multiplexer
        .get_or_create_session_for(None, &session_owner(None));
    let unowned = "gw-7c1e0000-unowned-session";
    for id in [owned.as_str(), unowned] {
        create_router(Arc::clone(&state))
            .oneshot(delete(id))
            .await
            .unwrap();
    }
    let text = captured.text();
    assert_fingerprinted(&text, "Client connected to SSE stream", &streamed);
    assert_fingerprinted(&text, "Session terminated by client", &owned);
    assert_fingerprinted(&text, "No owned session for DELETE", unowned);
}

// F9-T1 (non-UTF-8 arm of the header rule; green today, kept as a regression row)
#[tokio::test]
async fn a_non_utf8_session_id_is_treated_as_absent() {
    let (state, _store) = test_router_app_state().await;
    let mut request = legacy_post(None, ping());
    request.headers_mut().insert(
        "mcp-session-id",
        axum::http::HeaderValue::from_bytes(b"\xff\xfe").unwrap(),
    );
    let response = create_router(Arc::clone(&state)).oneshot(request).await.unwrap();
    let minted = session_header(&response).expect("a minted id comes back");
    assert!(minted.starts_with("gw-"), "minted: {minted:?}");
}

// F9 amendment: the dashboard displays sessions by fingerprint, while the
// admin API that inspects a session by id keeps the raw id, its input.
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn the_dashboard_shows_session_fingerprints_and_the_admin_api_takes_raw_ids() {
    use crate::gateway::router::tests::{scoped_auth_config, test_router_app_state_with_auth_and_config};
    let (state, _store) =
        test_router_app_state_with_auth_and_config(&scoped_auth_config(true), crate::config::Config::default())
            .await;
    let raw = "gw-c057000-costed-session";
    state
        .meta_mcp
        .cost_tracker()
        .record(raw, None, "srv", "tool", 0, 1.0);
    let get = |uri: &str| {
        Request::builder()
            .method("GET")
            .uri(uri)
            .header("authorization", "Bearer scoped-key")
            .body(Body::empty())
            .unwrap()
    };
    let read = |response: axum::response::Response| async move {
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        String::from_utf8(body.to_vec()).unwrap()
    };
    let dashboard = read(
        create_router(Arc::clone(&state)).oneshot(get("/ui/api/costs")).await.unwrap(),
    )
    .await;
    let fp = crate::gateway::session_id::session_fp(raw);
    assert!(dashboard.contains(&fp), "{dashboard}");
    assert!(!dashboard.contains(raw), "the dashboard shows a raw session id: {dashboard}");
    let inspected = read(
        create_router(Arc::clone(&state))
            .oneshot(get(&format!("/api/costs?session={raw}")))
            .await
            .unwrap(),
    )
    .await;
    assert!(inspected.contains(raw), "inspect-by-id finds the session: {inspected}");
    // The admin API's own listing stays raw: it is where an admin gets the id to inspect.
    let listing = read(create_router(Arc::clone(&state)).oneshot(get("/api/costs")).await.unwrap()).await;
    assert!(listing.contains(raw), "the admin listing keeps raw ids: {listing}");
}
