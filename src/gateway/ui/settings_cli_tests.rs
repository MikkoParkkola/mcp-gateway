// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Credential settings cannot escape a CLI key's approval binding.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use axum::response::Response;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::super::keys_create_fixture_tests::{ROOT, Setup, item, root_item, yaml_of};
use super::SettingsStoreForTest;
use super::route_secret_tests::{Recording, recording};
use super::test_support::{Route, decode, secret, set};
use crate::gateway::auth::ResolvedAuthConfig;
use crate::gateway::{router::create_router, routes};

const CHILD: &str = "settings-cli-child";
const SAVED_SECRET: &str = "settings-static-successor";

async fn fixture() -> (Route, Arc<Recording>) {
    let auth = ResolvedAuthConfig::from_config(
        &Setup::default().running,
        crate::gateway::record_principal::TEST_RECORD_KEY,
    );
    let root = auth.validate_token(ROOT).expect("root validates");
    let quota = root.quota_principal.expect("root quota principal");
    let child = item(
        "cli:laptop:settings",
        CHILD,
        &format!(
            "      admin: true\n      cli_host: laptop\n      approved_by:\n        quota_principal: \"{}\"\n        digest_tag: \"{}\"\n",
            quota.limit_store_key(),
            crate::gateway::auth::secret_tag(ROOT),
        ),
    );
    let text = format!(
        "{}security:\n  ssrf_protection: true\n",
        yaml_of(&[root_item(), child]),
    );
    let mut route = Route::new(&text).await;
    // Authentication and the settings writer must share the same live table.
    Arc::get_mut(&mut route.state)
        .expect("unique state")
        .live_config = Arc::clone(&route.ctx.live_config);
    route.audit();
    let store = recording(&route, None);
    route.store = Some(SettingsStoreForTest::Store(store.clone()));
    let generation = route.state.live_config.generation();
    let child = generation
        .auth()
        .validate_token(CHILD)
        .expect("CLI validates");
    assert!(child.is_gateway_admin());
    assert!(
        generation
            .auth()
            .is_cli_key_quota(child.quota_principal.as_ref().expect("CLI quota principal"))
    );
    (route, store)
}

fn request(method: &str, uri: &str, bearer: Option<&str>, cookie: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 52_344))));
    if let Some(bearer) = bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {bearer}"));
    }
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    builder.body(Body::empty()).expect("request")
}

async fn send(route: &Route, mut request: Request<Body>) -> Response {
    request
        .extensions_mut()
        .insert(route.store.clone().expect("recording store"));
    create_router(Arc::clone(&route.state))
        .oneshot(request)
        .await
        .expect("router response")
}

async fn save(
    route: &Route,
    fields: &Value,
    bearer: Option<&str>,
    cookie: Option<&str>,
) -> (StatusCode, Value) {
    let mut request = request("POST", routes::UI_SETTINGS, bearer, cookie);
    request.headers_mut().insert(
        header::CONTENT_TYPE,
        "application/json".parse().expect("content type"),
    );
    *request.body_mut() = Body::from(route.saved_body(fields).to_string());
    decode(send(route, request).await).await
}

/// As [`save`], but with the given `base_revision` in place of the current one.
async fn save_with_revision(
    route: &Route,
    revision: &str,
    fields: &Value,
    bearer: &str,
) -> (StatusCode, Value) {
    let mut request = request("POST", routes::UI_SETTINGS, Some(bearer), None);
    request.headers_mut().insert(
        header::CONTENT_TYPE,
        "application/json".parse().expect("content type"),
    );
    *request.body_mut() =
        Body::from(json!({"base_revision": revision, "fields": fields}).to_string());
    decode(send(route, request).await).await
}

async fn cli_session(route: &Route) -> String {
    let (status, body) = decode(
        send(
            route,
            request("POST", "/ui/api/dashboard-link", Some(CHILD), None),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let link = body["link"].as_str().expect("dashboard link");
    let (_, bootstrap) = link.split_once("/dashboard?bootstrap=").expect("bootstrap");
    let response = send(
        route,
        request(
            "GET",
            &format!("/dashboard?bootstrap={bootstrap}"),
            None,
            None,
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let cookie = response.headers()[header::SET_COOKIE]
        .to_str()
        .expect("session cookie")
        .split(';')
        .next()
        .expect("cookie pair")
        .to_owned();
    let status = send(route, request("GET", "/ui/api/status", None, Some(&cookie))).await;
    assert_eq!(status.status(), StatusCode::OK, "session authenticates");
    cookie
}

fn auth_edits() -> [Value; 3] {
    [
        secret(SAVED_SECRET),
        set("auth.enabled", &json!(false)),
        set("auth.single_user", &json!(true)),
    ]
}

async fn assert_refused(route: &Route, store: &Recording, cookie: Option<&str>) {
    let before = std::fs::read(route.path()).expect("config bytes");
    for edit in auth_edits() {
        // A permitted edit ahead of the auth edit must not be partially saved.
        let fields = json!([set("security.ssrf_protection", &json!(false)), edit]);
        let bearer = cookie.is_none().then_some(CHILD);
        let (status, body) = save(route, &fields, bearer, cookie).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(body, json!({"error": "Authentication required"}));
        assert_eq!(std::fs::read(route.path()).expect("config bytes"), before);
        assert_eq!(store.calls(), 0, "no secret entry may be created");
    }
}

#[tokio::test]
async fn a_cli_key_cannot_save_an_auth_setting() {
    let (route, store) = fixture().await;
    assert_refused(&route, &store, None).await;
}

#[tokio::test]
async fn a_cli_keys_session_cannot_save_an_auth_setting() {
    let (route, store) = fixture().await;
    let cookie = cli_session(&route).await;
    assert_refused(&route, &store, Some(&cookie)).await;
}

/// The refusal comes before the revision is judged: a malformed or a stale
/// `base_revision` with an auth edit from a CLI key is refused as forbidden, not
/// processed, and nothing is written or stored.
#[tokio::test]
async fn a_cli_keys_auth_save_is_refused_before_its_revision_is_judged() {
    let (route, store) = fixture().await;
    let before = std::fs::read(route.path()).expect("config bytes");
    let fields = json!([secret(SAVED_SECRET)]);
    let current = route.saved_body(&fields)["base_revision"]
        .as_str()
        .expect("revision text")
        .to_owned();
    let mut stale = current.clone();
    let last = stale.pop().expect("a revision has characters");
    stale.push(if last == '0' { '1' } else { '0' });
    for revision in ["not-a-revision", stale.as_str()] {
        let (status, body) = save_with_revision(&route, revision, &fields, CHILD).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{revision}: {body}");
        assert_eq!(std::fs::read(route.path()).expect("config bytes"), before);
        assert_eq!(store.calls(), 0, "no secret entry may be created");
    }
}

#[tokio::test]
async fn a_cli_key_can_still_save_a_non_auth_setting() {
    for bearer in [ROOT, CHILD] {
        let (route, store) = fixture().await;
        let before = route.text();
        let fields = json!([set("security.ssrf_protection", &json!(false))]);
        let (status, body) = save(&route, &fields, Some(bearer), None).await;
        assert_eq!(status, StatusCode::OK, "{bearer}: {body}");
        assert_eq!(body["changed"], true);
        assert_eq!(
            route.text(),
            before.replace("ssrf_protection: true", "ssrf_protection: false")
        );
        assert_eq!(store.calls(), 0);
    }
}

#[tokio::test]
async fn an_ordinary_admin_key_can_still_save_an_auth_setting() {
    for edit in auth_edits() {
        let (route, store) = fixture().await;
        let before = route.text();
        // Mirror the refused request, including its first non-auth edit.
        let fields = json!([set("security.ssrf_protection", &json!(false)), edit]);
        let (status, body) = save(&route, &fields, Some(ROOT), None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["changed"], true);
        assert_ne!(route.text(), before);
        let written = crate::config::Config::load_literal(Some(&route.path())).expect("config");
        assert!(!written.security.ssrf_protection);
        match edit["field"].as_str().expect("field") {
            "auth.bearer_token" => {
                let reference = written.auth.bearer_token.expect("stored secret reference");
                let path = reference.strip_prefix("file:").expect("file store");
                assert_eq!(
                    std::fs::read(path).expect("secret bytes"),
                    format!("{SAVED_SECRET}\n").as_bytes()
                );
                assert!(store.calls() > 0);
            }
            "auth.enabled" => assert!(!written.auth.enabled),
            "auth.single_user" => assert!(written.auth.single_user),
            _ => unreachable!("auth edit"),
        }
    }
}
