// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7630 increment I1: the events protocol surface, rows that need no
//! callback to answer (design §10: T1-T5, T11-T13, T42, T53).
//!
//! Every row drives the shipped binary over `/mcp`, or the public capability
//! parser. With no events code the methods answer `-32601`, so each row goes
//! red at its own assertion.

#[path = "mik_7630_events/gateway.rs"]
#[allow(dead_code, reason = "shared harness; each binary uses a subset")]
mod gateway;
#[path = "mik_7630_events/receiver.rs"]
#[allow(dead_code, reason = "this binary uses only the connection counter")]
mod receiver;

use std::sync::{Arc, Mutex};

use gateway::{ALICE, BOB, EVENT, Gateway, config, error};
use receiver::{ConnCounter, whsec};
use serde_json::{Value, json};

fn subscribe_params(url: &str, secret: &str) -> Value {
    json!({
        "name": EVENT,
        "arguments": {},
        "delivery": {"mode": "webhook", "url": url, "secret": secret},
    })
}

/// T1 (EVENTS.1): the capability appears only with events on and a source.
#[tokio::test]
async fn discover_advertises_events_only_when_enabled() {
    let advertised = |enabled: bool, with_route: bool| async move {
        let root = tempfile::tempdir().expect("root");
        let mut cfg = config(
            root.path(),
            &json!({"enabled": enabled,
                    "sources": {"backend_notifications": false, "task_settled": false}}),
        );
        if !with_route {
            cfg["capabilities"]["directories"] = json!([]);
        }
        let gw = Gateway::start(root.path(), cfg).await;
        if with_route {
            gw.event_names(Some(ALICE), Some(EVENT)).await;
        }
        let answer = gw.rpc(Some(ALICE), "server/discover", json!({})).await;
        answer["result"]["capabilities"].get("events").cloned()
    };
    assert_eq!(
        advertised(true, true).await,
        Some(json!({"listChanged": false})),
        "events on with a webhook event route advertise events; nothing pushes \
         catalogue changes, so listChanged is false"
    );
    assert_eq!(advertised(false, true).await, None, "events off: no key");
    assert_eq!(
        advertised(true, false).await,
        None,
        "events on but no source configured: no key"
    );
}

/// A backend that itself answers `events/list` and records every method.
async fn events_speaking_backend() -> (String, Arc<Mutex<Vec<String>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(move |axum::Json(req): axum::Json<Value>| {
            let log = Arc::clone(&log);
            async move {
                let method = req["method"].as_str().unwrap_or_default().to_owned();
                log.lock().expect("log").push(method.clone());
                let id = req.get("id").cloned().unwrap_or(Value::Null);
                axum::Json(match method.as_str() {
                    "initialize" => json!({"jsonrpc": "2.0", "id": id, "result": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {"tools": {}, "events": {"listChanged": true}},
                        "serverInfo": {"name": "mock", "version": "1"}}}),
                    "tools/list" => json!({"jsonrpc": "2.0", "id": id, "result": {"tools": []}}),
                    "events/list" => json!({"jsonrpc": "2.0", "id": id, "result": {
                        "events": [{"name": "backend.native.thing", "delivery": ["webhook"]}]}}),
                    _ => json!({"jsonrpc": "2.0", "id": id, "result": {}}),
                })
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind backend");
    let url = format!("http://{}/", listener.local_addr().expect("addr"));
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (url, seen)
}

/// `cfg` with the events-speaking backend at `url` attached as `mock`.
fn with_mock(mut cfg: Value, url: &str) -> Value {
    cfg["backends"] = json!({"mock": {"http_url": url, "streamable_http": true}});
    cfg["security"]["trust_configured_backends"] = json!(true);
    cfg["auth"]["api_keys"][0]["backends"] = json!(["hooks", "mock"]);
    cfg
}

/// T2 (EVENTS.1): off means -32601; on means gateway-derived names only, and
/// no `events/*` request ever reaches a backend.
#[tokio::test]
async fn events_methods_are_not_found_when_disabled_and_never_proxied() {
    // Events off, with an events-speaking backend attached: the methods are
    // not found, and the backend, which the gateway does reach, sees none.
    let root = tempfile::tempdir().expect("root");
    let (backend, seen_off) = events_speaking_backend().await;
    let off = Gateway::start(
        root.path(),
        with_mock(config(root.path(), &json!({"enabled": false})), &backend),
    )
    .await;
    for method in ["events/list", "events/subscribe", "events/unsubscribe"] {
        let answer = off.rpc(Some(ALICE), method, json!({})).await;
        assert_eq!(error(&answer)["code"], -32601, "{method} with events off");
    }
    let _ = off
        .tool_call(ALICE, "gateway_list_tools", json!({"server": "mock"}))
        .await;
    let methods = seen_off.lock().expect("log").clone();
    assert!(
        methods.iter().any(|m| m == "tools/list"),
        "premise: the gateway reached the backend: {methods:?}"
    );
    assert!(
        !methods.iter().any(|m| m.starts_with("events/")),
        "events/* reached the backend with events off: {methods:?}"
    );
    drop(off);

    let root = tempfile::tempdir().expect("root");
    let (backend, seen) = events_speaking_backend().await;
    let on = Gateway::start(
        root.path(),
        with_mock(config(root.path(), &json!({})), &backend),
    )
    .await;
    let answer = on.rpc(Some(ALICE), "events/list", json!({})).await;
    let events = answer["result"]["events"]
        .as_array()
        .unwrap_or_else(|| panic!("events/list must answer a result with events on: {answer}"));
    for event in events {
        let name = event["name"].as_str().unwrap_or_default();
        assert!(
            name.starts_with("webhook.")
                || name.starts_with("backend.mock.")
                || name.starts_with("backend.hooks.")
                || name == "task.settled",
            "a gateway-derived name only, got {name}"
        );
        assert_ne!(
            name, "backend.native.thing",
            "a backend's own catalogue leaked"
        );
    }
    let _ = on.rpc(Some(ALICE), "tools/list", json!({})).await;
    let proxied: Vec<String> = seen
        .lock()
        .expect("log")
        .iter()
        .filter(|m| m.starts_with("events/"))
        .cloned()
        .collect();
    assert!(
        proxied.is_empty(),
        "events/* reached the backend: {proxied:?}"
    );
}

/// A callback host that never resolves; rows using it must refuse first.
const NOWHERE: &str = "https://receiver.invalid/h";

/// T3 (EVENTS.2), webhook clause: a caller who may not reach the capability
/// backend sees none of its events.
#[tokio::test]
async fn events_list_is_filtered_by_backend_visibility() {
    let root = tempfile::tempdir().expect("root");
    let gw = Gateway::start(root.path(), config(root.path(), &json!({}))).await;
    let alice = gw.event_names(Some(ALICE), Some(EVENT)).await;
    assert!(
        alice.iter().any(|n| n == EVENT),
        "alice sees {EVENT}: {alice:?}"
    );
    let answer = gw.rpc(Some(BOB), "events/list", json!({})).await;
    let bob = answer["result"]["events"]
        .as_array()
        .unwrap_or_else(|| panic!("bob gets a result too: {answer}"));
    assert!(
        bob.iter().all(|e| !e["name"]
            .as_str()
            .unwrap_or_default()
            .starts_with("webhook.")),
        "bob may not reach backend hooks, so no webhook event: {bob:?}"
    );
    let full = gw.rpc(Some(ALICE), "events/list", json!({})).await;
    let push = full["result"]["events"]
        .as_array()
        .and_then(|events| events.iter().find(|e| e["name"] == EVENT))
        .cloned()
        .unwrap_or_default();
    assert_eq!(push["delivery"], json!(["webhook"]));
    assert!(push["inputSchema"].is_object() && push["payloadSchema"].is_object());
}

/// T4 (EVENTS.2): an invisible event and a missing one answer the same -32011.
#[tokio::test]
async fn subscribe_to_an_invisible_event_is_not_found() {
    let root = tempfile::tempdir().expect("root");
    let gw = Gateway::start(root.path(), config(root.path(), &json!({}))).await;
    gw.event_names(Some(ALICE), Some(EVENT)).await;
    let secret = whsec(32);
    let hidden = gw
        .rpc(
            Some(BOB),
            "events/subscribe",
            subscribe_params(NOWHERE, &secret),
        )
        .await;
    let mut missing_params = subscribe_params(NOWHERE, &secret);
    missing_params["name"] = json!("webhook.github.nothing.received");
    let missing = gw.rpc(Some(BOB), "events/subscribe", missing_params).await;
    assert_eq!(error(&hidden)["code"], -32011, "{hidden}");
    assert_eq!(error(&hidden)["data"]["kind"], "event");
    assert_eq!(
        error(&hidden),
        error(&missing),
        "an invisible event must be indistinguishable from a missing one"
    );
}

/// T5 (EVENTS.3): only an absolute https URL with a host is accepted, and a
/// refused URL causes no outbound request.
#[tokio::test]
async fn subscribe_rejects_non_https_and_malformed_urls() {
    let counter = ConnCounter::start().await;
    let root = tempfile::tempdir().expect("root");
    let gw = Gateway::start(
        root.path(),
        config(
            root.path(),
            &json!({"callback_allow_private": ["127.0.0.0/8"]}),
        ),
    )
    .await;
    gw.event_names(Some(ALICE), Some(EVENT)).await;
    let port = counter.port;
    for url in [
        format!("http://127.0.0.1:{port}/hook"),
        format!("ftp://127.0.0.1:{port}/hook"),
        "https://".to_string(),
        "not a url".to_string(),
    ] {
        let answer = gw
            .rpc(
                Some(ALICE),
                "events/subscribe",
                subscribe_params(&url, &whsec(32)),
            )
            .await;
        assert_eq!(error(&answer)["code"], -32602, "{url}: {answer}");
        assert_eq!(error(&answer)["data"]["field"], "delivery.url", "{url}");
    }
    assert_eq!(
        counter.connections(),
        0,
        "a refused URL must not be contacted"
    );
}

/// T11 (EVENTS.3, EVENTS.7): webhook mode needs an authenticated principal.
#[tokio::test]
async fn webhook_methods_require_an_authenticated_principal() {
    let unsub = json!({"name": EVENT, "arguments": {}, "delivery": {"url": NOWHERE}});
    // Auth on, `/mcp` public, no credential presented.
    let root = tempfile::tempdir().expect("root");
    let mut cfg = config(root.path(), &json!({}));
    cfg["auth"]["public_paths"] = json!(["/health", "/mcp"]);
    let gw = Gateway::start(root.path(), cfg).await;
    gw.event_names(Some(ALICE), Some(EVENT)).await;
    let sub = gw
        .rpc(
            None,
            "events/subscribe",
            subscribe_params(NOWHERE, &whsec(32)),
        )
        .await;
    assert_eq!(error(&sub)["code"], -32012, "no credential: {sub}");
    let un = gw.rpc(None, "events/unsubscribe", unsub.clone()).await;
    assert_eq!(error(&un)["code"], -32012, "no credential: {un}");
    drop(gw);

    // Auth off: no principal exists at all.
    let root = tempfile::tempdir().expect("root");
    let mut cfg = config(root.path(), &json!({}));
    cfg["auth"] = json!({"enabled": false});
    let gw = Gateway::start(root.path(), cfg).await;
    gw.event_names(None, Some(EVENT)).await;
    let sub = gw
        .rpc(
            None,
            "events/subscribe",
            subscribe_params(NOWHERE, &whsec(32)),
        )
        .await;
    assert_eq!(error(&sub)["code"], -32012, "auth disabled: {sub}");
    let un = gw.rpc(None, "events/unsubscribe", unsub).await;
    assert_eq!(error(&un)["code"], -32012, "auth disabled: {un}");
}

/// Every property `old` names still exists in `new` with the same type, and
/// `new` requires nothing `old` did not. Recurses into object properties.
fn assert_additive(path: &str, old: &Value, new: &Value) {
    assert_eq!(old.get("type"), new.get("type"), "{path}: type changed");
    let old_required: Vec<&Value> = old["required"]
        .as_array()
        .map_or(vec![], |r| r.iter().collect());
    for required in new["required"].as_array().into_iter().flatten() {
        assert!(
            old_required.contains(&required),
            "{path}: newly required {required}"
        );
    }
    for (name, schema) in old["properties"].as_object().into_iter().flatten() {
        let current = new["properties"]
            .get(name)
            .unwrap_or_else(|| panic!("{path}.{name}: property removed or renamed"));
        assert_additive(&format!("{path}.{name}"), schema, current);
    }
}

/// T12 (EVENTS.2): built-in descriptors evolve additively only.
#[tokio::test]
async fn event_schemas_change_only_additively() {
    let snapshot: Value =
        serde_json::from_str(include_str!("snapshots/mik_7630_event_schemas.json"))
            .expect("snapshot parses");
    let root = tempfile::tempdir().expect("root");
    let gw = Gateway::start(root.path(), config(root.path(), &json!({}))).await;
    gw.event_names(Some(ALICE), Some(EVENT)).await;
    let answer = gw.rpc(Some(ALICE), "events/list", json!({})).await;
    let events = answer["result"]["events"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    for (name, old) in snapshot.as_object().expect("snapshot object") {
        let current = events
            .iter()
            .find(|e| e["name"] == *name)
            .unwrap_or_else(|| panic!("descriptor {name} is missing from events/list: {answer}"));
        for schema in ["inputSchema", "payloadSchema"] {
            assert_additive(&format!("{name}.{schema}"), &old[schema], &current[schema]);
        }
    }
}

/// T13 (EVENTS.5): private callback addresses are refused before any
/// connection, both as IP literals and as names that resolve privately.
#[tokio::test]
async fn delivery_refuses_private_addresses() {
    let counter = ConnCounter::start().await;
    let root = tempfile::tempdir().expect("root");
    let gw = Gateway::start(root.path(), config(root.path(), &json!({}))).await;
    gw.event_names(Some(ALICE), Some(EVENT)).await;
    let port = counter.port;
    for url in [
        format!("https://127.0.0.1:{port}/hook"),
        format!("https://localhost:{port}/hook"),
        "https://10.0.0.1/hook".to_string(),
        "https://169.254.169.254/latest".to_string(),
        format!("https://[::1]:{port}/hook"),
        "https://[fc00::1]/hook".to_string(),
    ] {
        let answer = gw
            .rpc(
                Some(ALICE),
                "events/subscribe",
                subscribe_params(&url, &whsec(32)),
            )
            .await;
        assert_eq!(error(&answer)["code"], -32015, "{url}: {answer}");
        assert_eq!(
            error(&answer)["data"]["reason"],
            "connection_refused",
            "{url}"
        );
    }
    assert_eq!(
        counter.connections(),
        0,
        "nothing may reach a private address"
    );
}

/// T42 (EVENTS.2): an `event:` block needs a field mapping to project from.
#[test]
fn webhook_routes_without_a_mapping_cannot_become_events() {
    let yaml = r#"
name: bare
description: a route with no mapping
providers: {}
webhooks:
  ping:
    path: /bare/ping
    event:
      description: "would have to fall back to the raw body"
"#;
    let capability = mcp_gateway::capability::parse_capability(yaml).expect("parses");
    let refusal = mcp_gateway::capability::validate_capability(&capability)
        .expect_err("an event block on a route without transform.data must be refused");
    assert!(
        refusal.to_string().contains("ping"),
        "names the route: {refusal}"
    );
}

/// T53 (EVENTS.3): the challenge compare uses the constant-time primitive.
#[test]
fn challenge_comparison_uses_the_constant_time_primitive() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/events");
    let mut sources = String::new();
    for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
        sources.push_str(&std::fs::read_to_string(entry.path()).unwrap_or_default());
    }
    assert!(
        sources.contains("ct_eq(") || sources.contains("ConstantTimeEq"),
        "src/events must compare the challenge with subtle::ConstantTimeEq"
    );
    assert!(
        !sources.contains("challenge ==") && !sources.contains("== challenge"),
        "no plain equality on the challenge"
    );
}
