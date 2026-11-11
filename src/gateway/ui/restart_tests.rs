// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! PR1: restart refuses honestly through the real router, guard and audit layer.

use crate::security::{TransparencyLogConfig, TransparencyLogger};
use crate::{
    config::AuthConfig,
    gateway::router::{create_router, tests::audience_state},
};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::Request,
};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

const URI: &str = "/ui/api/gateway/restart";
const ADMIN: &str = "restart-admin";
const CONFIRM: &str = "confirm-8867-must-never-escape";
#[cfg(not(windows))]
const REASON: &str = "restart_not_available";
#[cfg(windows)]
const REASON: &str = "windows_manual_restart";

struct Fixture {
    router: Router,
    audit: Arc<tempfile::TempDir>,
    _store: crate::gateway::router::tests::FixtureDir,
    who: Value,
}
async fn fixture() -> Fixture {
    let keys: Vec<_> = [
        (ADMIN, true, "*"),
        ("user", false, "*"),
        ("scoped", true, "alpha"),
    ]
    .into_iter()
    .map(|(name, admin, backend)| {
        json!({
            "key_sha256": crate::config::api_key_digest_spec(name.as_bytes()),
            "name": name, "admin": admin, "backends": [backend]
        })
    })
    .collect();
    let auth: AuthConfig =
        serde_json::from_value(json!({"enabled": true, "api_keys": keys})).unwrap();
    let audit = crate::test_dir_keep::kept_tempdir();
    let file = audit.path().join("audit.jsonl");
    let path = file.display().to_string();
    let config = TransparencyLogConfig {
        enabled: true,
        path,
        ..Default::default()
    };
    let log = Arc::new(TransparencyLogger::open(Arc::new(config)).expect("audit log"));
    log.keep_test_dir(Arc::clone(&audit));
    let (mut state, store) = audience_state(&auth, (None, None), |meta| meta).await;
    Arc::get_mut(&mut state)
        .expect("unique state")
        .transparency_log = Some(log);
    let generation = state.live_config.generation();
    let client = generation.auth().validate_token(ADMIN).unwrap();
    let who = serde_json::to_value(crate::security::audit::AuditWho::from_request(
        Some(&client),
        None,
        generation.auth().record_key(),
    ))
    .expect("who");
    Fixture {
        router: create_router(state),
        audit,
        _store: store,
        who,
    }
}
fn request(method: &str, uri: &str, key: Option<&str>, body: Option<&str>) -> Request<Body> {
    let mut req = Request::builder().method(method).uri(uri);
    if let Some(key) = key {
        req = req.header("authorization", format!("Bearer {key}"));
    }
    if body.is_some() {
        req = req.header("content-type", "application/json");
    }
    req.body(body.map_or_else(Body::empty, |b| Body::from(b.to_owned())))
        .expect("request")
}
async fn send(fx: &Fixture, req: Request<Body>, want: u16) -> Value {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let response = fx.router.clone().oneshot(req).await.expect("response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1 << 20).await.expect("body");
        assert_eq!(status.as_u16(), want, "{}", String::from_utf8_lossy(&bytes));
        let body: Value = serde_json::from_slice(&bytes).expect("handler JSON");
        assert!(!body.to_string().contains(CONFIRM));
        body
    })
    .await
    .expect("router responds within 10 seconds")
}
fn valid() -> String {
    json!({"confirm": CONFIRM}).to_string()
}
fn audit(fx: &Fixture) -> String {
    std::fs::read_to_string(fx.audit.path().join("audit.jsonl")).expect("read audit")
}
fn refusal(body: &Value, available: bool) {
    assert_eq!(body["reason"], REASON);
    let recovery = body["recovery"].as_str().expect("recovery sentence");
    #[cfg(not(windows))]
    {
        for phrase in [
            "process",
            "cannot tell which supervisor runs it",
            "example",
            "systemctl",
            "brew services",
            "docker restart",
        ] {
            assert!(recovery.contains(phrase), "{body}");
        }
        let sentences = recovery
            .split(['.', '!', '?'])
            .filter(|s| !s.trim().is_empty());
        assert_eq!(sentences.count(), 1, "one recovery sentence: {body}");
    }
    #[cfg(windows)]
    for phrase in ["service", "process", "manager"] {
        assert!(recovery.contains(phrase), "{body}");
    }
    let expected = if available {
        json!({"available": false, "reason": REASON, "recovery": recovery})
    } else {
        json!({"reason": REASON, "recovery": recovery})
    };
    assert_eq!(*body, expected, "no token, success flag or extra promise");
    for promise in
        "success|succeeded|restarting|restarted|will restart|restart scheduled".split('|')
    {
        assert!(!body.to_string().to_lowercase().contains(promise), "{body}");
    }
}
#[tokio::test]
async fn admin_get_is_unavailable_without_a_token_in_gateway_actions() {
    let fx = fixture().await;
    let body = send(&fx, request("GET", URI, Some(ADMIN), None), 200).await;
    refusal(&body, true);
    use super::access_table::{AdminShape, Need, Page, ROWS, Tab, Verb};
    for method in [Verb::Get, Verb::Post] {
        let row = ROWS
            .iter()
            .find(|r| r.path == URI && r.method == method)
            .expect("guard row");
        assert!(matches!(row.need, Need::Admin(AdminShape::AdminRequired)));
        assert_eq!(row.tabs, &[(Page::Gateway, Tab::Actions)]);
    }
}
#[tokio::test]
async fn anonymous_non_admin_and_backend_scoped_get_and_post_are_refused() {
    let fx = fixture().await;
    for (key, want) in [(None, 401), (Some("user"), 403), (Some("scoped"), 403)] {
        for method in ["GET", "POST"] {
            // Malformed POST also pins admit-before-body, as with create-key.
            for body in [valid(), "{}".into()] {
                let payload = (method == "POST").then_some(body.as_str());
                let value = send(&fx, request(method, URI, key, payload), want).await;
                if want == 403 {
                    assert_eq!(value, json!({"error": "Admin authentication required"}));
                }
            }
        }
    }
}
async fn invalid(body: Option<&str>) {
    let fx = fixture().await;
    let value = send(&fx, request("POST", URI, Some(ADMIN), body), 422).await;
    assert_eq!(value, json!({"error": "invalid_body"}));
    assert!(!audit(&fx).contains(CONFIRM));
}
#[tokio::test]
async fn no_body_is_fixed_422_json() {
    invalid(None).await;
}
#[tokio::test]
async fn non_json_is_fixed_422_json() {
    invalid(Some(CONFIRM)).await;
}
#[tokio::test]
async fn extra_field_is_fixed_422_json() {
    let body = json!({"confirm": CONFIRM, "extra": CONFIRM}).to_string();
    invalid(Some(&body)).await;
}
#[tokio::test]
async fn non_string_confirm_is_fixed_422_json() {
    invalid(Some(&json!({"confirm": [CONFIRM]}).to_string())).await;
}
#[tokio::test]
async fn empty_object_is_fixed_422_json() {
    invalid(Some("{}")).await;
}
#[tokio::test]
async fn well_formed_post_is_409_and_keeps_status_and_tools_call_serving() {
    let fx = fixture().await;
    let body = send(&fx, request("POST", URI, Some(ADMIN), Some(&valid())), 409).await;
    refusal(&body, false);
    let status = request("GET", "/ui/api/status", Some(ADMIN), None);
    send(&fx, status, 200).await;
    let call = json!({"jsonrpc":"2.0", "id":7, "method":"tools/call",
        "params":{"name":"gateway_list_servers", "arguments":{}}})
    .to_string();
    let body = send(&fx, request("POST", "/mcp", Some(ADMIN), Some(&call)), 200).await;
    assert_eq!(body["id"], 7);
    assert!(
        body.get("error").is_none() && body["result"]["content"].is_array(),
        "{body}"
    );
    assert_ne!(body["result"]["isError"], true, "{body}");
}
#[tokio::test]
async fn refused_post_is_attributed_without_confirm_or_success_wording() {
    let fx = fixture().await;
    let body = send(&fx, request("POST", URI, Some(ADMIN), Some(&valid())), 409).await;
    refusal(&body, false);
    let text = audit(&fx); // append_admin_action completes before the response; no sleep.
    assert!(!text.contains(CONFIRM));
    let actions: Vec<Value> = text
        .lines()
        .map(|s| serde_json::from_str::<Value>(s).expect("record"))
        .filter(|r| r["event"] == "admin_action" && r["route"] == URI)
        .collect();
    assert_eq!(actions.len(), 1, "must audit restart: {text}");
    let r = &actions[0];
    assert_eq!(r["who"], fx.who);
    for (field, value) in [
        ("action", "restart"),
        ("stage", "refused"),
        ("reason", REASON),
        ("method", "POST"),
        ("outcome", "error"),
    ] {
        assert_eq!(r[field], value, "{r}");
    }
    assert_eq!(r["http_status"], 409);
    assert_eq!(r["error_code"], -32603);
}
#[tokio::test]
async fn cross_origin_valid_post_is_refused_before_auth_and_audit() {
    let fx = fixture().await;
    let before = audit(&fx);
    for key in [None, Some("invalid-credential"), Some(ADMIN)] {
        let mut req = request("POST", URI, key, Some(&valid()));
        req.headers_mut()
            .insert("origin", "https://foreign.example".parse().unwrap());
        let body = send(&fx, req, 403).await;
        assert!(body.to_string().contains("Origin not allowed"), "{body}");
        assert_eq!(audit(&fx), before, "origin gate precedes audit");
    }
    // A missing route must not pass merely because the outer origin gate works.
    send(&fx, request("POST", URI, Some(ADMIN), Some(&valid())), 409).await;
}
