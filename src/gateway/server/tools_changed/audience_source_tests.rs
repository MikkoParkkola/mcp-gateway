// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! C0 live twins for the identity-source rows (T3) and the Basic-only
//! credential row (T5), plus the T2 trusted-proxy mode-live control. The
//! T2 live source oracle itself is NOTTESTED at C0: the accepted map
//! records that no current fixture can present a `ConnectInfo` peer to an
//! anonymous GET stream and read its `told()`.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::ConnectInfo;
use axum::http::{HeaderValue, StatusCode};
use serde_json::json;
use tower::ServiceExt;

use super::audience_ear::Attach;
use super::audience_fixture::{World, tool};
use crate::key_server::oidc_test_harness::{Harness, ISS_A, config_yaml};
use crate::security::caller_identity::{CallerIdentityConfig, CallerIdentityMode};

const CF_HEADER: &str = "cf-access-jwt-assertion";
const CF_EMAIL_HEADER: &str = "cf-access-authenticated-user-email";
const GATEWAY_SUBJECT_HEADER: &str = "x-gateway-identity-subject";
/// The exact refusal body for `access_assertion`, as pinned by the attach
/// rows.
const CF_REFUSAL: &str = "{\"error\":{\"code\":-32600,\"message\":\"caller identity header refused: access_assertion\"},\"id\":null,\"jsonrpc\":\"2.0\"}";

fn alpha(read: &str) -> Vec<crate::protocol::Tool> {
    vec![
        tool("read", read),
        tool("write", "w"),
        tool("scan", "s"),
        tool("fetch", "f"),
    ]
}

/// Exactly the presented CF header bytes, padding or blank included.
fn cf_value(value: &str) -> HeaderValue {
    HeaderValue::from_bytes(value.as_bytes())
        .expect("premise: the presented CF header value constructs")
}

/// C0 T2 mode-live control only: in `trusted_proxy` mode trusting
/// `10.0.0.7` under `corp-sso` (the one C0 T2 configuration), a gateway
/// subject header arriving from an untrusted direct peer is a 403 naming
/// `untrusted_peer`. This pins the mode live in the world; it is not the
/// admitted-only source oracle, which is NOTTESTED at C0.
#[tokio::test]
async fn t2_live_trusted_proxy_mode_refuses_an_untrusted_peer() {
    let config = CallerIdentityConfig {
        mode: CallerIdentityMode::TrustedProxy,
        trusted_proxies: vec![
            "10.0.0.7"
                .parse()
                .expect("premise: the trusted peer parses"),
        ],
        authority: "corp-sso".to_string(),
        ..CallerIdentityConfig::default()
    };
    let key_server = Arc::new(crate::key_server::KeyServer::new(
        crate::config::KeyServerConfig::default(),
    ));
    let world = World::start_on(
        key_server,
        None,
        move |meta| meta.with_caller_identity(config),
        super::audience_access::McpAccess::PublicPath,
    )
    .await;
    let outsider = SocketAddr::from(([203, 0, 113, 9], 40_000));
    let (status, body) = world
        .attach_raw(Attach::Get, "k-std", move |request| {
            request.extensions_mut().insert(ConnectInfo(outsider));
            request
                .headers_mut()
                .insert(GATEWAY_SUBJECT_HEADER, HeaderValue::from_static("alice"));
        })
        .await;
    assert_eq!(
        status.as_u16(),
        403,
        "control T2-live: a gateway subject header from an untrusted peer is forbidden"
    );
    assert!(
        String::from_utf8_lossy(&body).contains("untrusted_peer"),
        "control T2-live: the refusal names untrusted_peer"
    );
}

/// C0 T3 live: a blank CF assertion header holds nothing, so a stream
/// admitted under it (on its API-key credential) is told of a change,
/// exactly as the no-CF-header control stream is. The blank header
/// beside a CF user header keeps its attach refusal on both routes.
#[tokio::test]
async fn t3_live_blank_cf_assertion_is_not_held() {
    let harness = Harness::start(&config_yaml("[]", "")).await;
    let world = super::audience_cf_tests::cf_world_on(&harness).await;

    // Control: a listen with no CF header is told once.
    let mut plain = world.listen_with("k-std", |_| {}).await;
    world.store_shared("alpha", alpha("r2"));
    assert_eq!(
        plain.told(&world).await,
        1,
        "control: a no-CF-header listen is told"
    );

    // Controls: blank assertion plus a CF user header is refused at
    // attach, 401 with the exact body, on GET and framed on listen.
    let blank = cf_value("   ");
    let (status, body) = world
        .attach_raw(Attach::Get, "k-std", {
            let blank = blank.clone();
            move |request| {
                request.headers_mut().insert(CF_HEADER, blank);
                request
                    .headers_mut()
                    .insert(CF_EMAIL_HEADER, HeaderValue::from_static("u@corp.example"));
            }
        })
        .await;
    assert_eq!(
        (status.as_u16(), String::from_utf8_lossy(&body).into_owned()),
        (401, CF_REFUSAL.to_string()),
        "control: a blank assertion with a CF user header is refused on GET"
    );
    let (status, body) = world
        .attach_raw(Attach::Listen, "k-std", {
            let blank = blank.clone();
            move |request| {
                request.headers_mut().insert(CF_HEADER, blank);
                request
                    .headers_mut()
                    .insert(CF_EMAIL_HEADER, HeaderValue::from_static("u@corp.example"));
            }
        })
        .await;
    assert_eq!(
        (status.as_u16(), String::from_utf8_lossy(&body).into_owned()),
        (401, format!("event: message\ndata: {CF_REFUSAL}\n\n")),
        "control: a blank assertion with a CF user header is refused on listen"
    );

    // Own: a blank assertion alone holds nothing to re-verify dead.
    let mut blank_ear = world
        .listen_with("k-std", move |request| {
            request.headers_mut().insert(CF_HEADER, blank);
        })
        .await;
    world.store_shared("alpha", alpha("r3"));
    assert_eq!(
        blank_ear.told(&world).await,
        1,
        "own T3: a blank CF assertion header is held as no assertion"
    );
    let (status, _body) = world
        .attach_raw(Attach::Get, "k-std", |request| {
            request.headers_mut().insert(CF_HEADER, cf_value("   "));
        })
        .await;
    assert!(
        status.is_success(),
        "own T3: a blank CF assertion header leaves a GET stream open: {status}"
    );
}

/// C0 T3 live: a padded genuine assertion is held trimmed, so the stream
/// it admitted still re-verifies good and is told of a change, exactly
/// as the unpadded control stream is.
#[tokio::test]
async fn t3_live_padded_cf_assertion_is_held_trimmed() {
    let harness = Harness::start(&config_yaml("[]", "")).await;
    let world = super::audience_cf_tests::cf_world_on(&harness).await;
    let token = harness.mint(ISS_A, "alice", &json!({}));

    // Control: the unpadded assertion admits a stream that is told.
    let plain_value = cf_value(&token);
    let mut plain = world
        .listen_with("k-std", move |request| {
            request.headers_mut().insert(CF_HEADER, plain_value);
        })
        .await;
    world.store_shared("alpha", alpha("r2"));
    assert_eq!(
        plain.told(&world).await,
        1,
        "control: an unpadded CF assertion listen is told"
    );

    // Own: the padded presentation of the same token is held trimmed.
    let padded_value = cf_value(&format!("  {token}  "));
    let mut padded = world
        .listen_with("k-std", move |request| {
            request.headers_mut().insert(CF_HEADER, padded_value);
        })
        .await;
    world.store_shared("alpha", alpha("r3"));
    assert_eq!(
        padded.told(&world).await,
        1,
        "own T3: a padded genuine CF assertion is held as the trimmed token"
    );
}

/// A T5 attach answer: an opened stream, observed by status only, or a
/// finite refusal, observed by status and its complete body.
#[derive(Debug, PartialEq, Eq)]
enum AttachAnswer {
    Open(StatusCode),
    Finite(StatusCode, Bytes),
}

/// The same GET `/mcp` attach as `attach_raw`, observed without ever
/// collecting an opened stream body.
async fn attach_answer(
    world: &World,
    bearer: &str,
    extend: impl FnOnce(&mut axum::http::Request<Body>),
) -> AttachAnswer {
    let mut request = axum::http::Request::builder()
        .uri("/mcp")
        .header("authorization", format!("Bearer {bearer}"))
        .method("GET")
        .header("accept", "text/event-stream")
        .body(Body::empty())
        .expect("a request");
    extend(&mut request);
    let response = world.router.clone().oneshot(request).await.expect("served");
    let status = response.status();
    if status.is_success() {
        return AttachAnswer::Open(status);
    }
    match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        axum::body::to_bytes(response.into_body(), usize::MAX),
    )
    .await
    {
        Ok(Ok(bytes)) => AttachAnswer::Finite(status, bytes),
        Ok(Err(_)) | Err(_) => {
            panic!("VOID T5 premise: finite refusal body did not complete: {status}")
        }
    }
}

/// C0 T5 live: on a public path, a GET presenting only a Basic
/// `Authorization` header is answered exactly as a wrong-Bearer GET on
/// the same world — byte for byte — never opened as an anonymous stream.
/// The anonymous public stream itself stays open (premise control).
#[tokio::test]
async fn t5_live_basic_only_get_matches_the_wrong_bearer_twin() {
    let world = World::start_public().await;

    let (status, anonymous) = world.anonymous_sse().await;
    assert!(
        status.is_success() && anonymous.is_some(),
        "premise: the anonymous public stream opens: {status}"
    );

    let wrong_bearer = attach_answer(&world, "wrong", |_| {}).await;
    let basic_only = attach_answer(&world, "k-std", |request| {
        request
            .headers_mut()
            .remove(axum::http::header::AUTHORIZATION);
        request.headers_mut().insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Basic abc"),
        );
    })
    .await;
    if let AttachAnswer::Open(status) = &wrong_bearer {
        panic!("VOID T5 premise: the wrong-Bearer twin opened a stream: {status}");
    }
    let basic_status = match &basic_only {
        AttachAnswer::Open(status) | AttachAnswer::Finite(status, _) => *status,
    };
    let wrong_status = match &wrong_bearer {
        AttachAnswer::Open(status) | AttachAnswer::Finite(status, _) => *status,
    };
    assert_eq!(
        basic_status, wrong_status,
        "own T5: a Basic-only GET status matches its wrong-Bearer twin"
    );
    if let (AttachAnswer::Finite(_, _), AttachAnswer::Finite(_, _)) = (&basic_only, &wrong_bearer) {
        assert_eq!(
            basic_only, wrong_bearer,
            "own T5: a Basic-only GET is answered exactly as its wrong-Bearer twin"
        );
    }
}
