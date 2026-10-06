// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7630 increment I4: event sources on existing producers (design §10:
//! T3 backend and task clauses, T38, T40). T41 and the debounce row are
//! in-crate (`src/events/lifecycle_tests.rs`): the trait is crate-private.
//! Receiver rows need `SSL_CERT_FILE` (Unix other than Apple).
#![cfg(all(unix, not(target_vendor = "apple")))]

#[path = "mik_7630_events/delivery.rs"]
#[allow(dead_code, reason = "shared helpers; each binary uses a subset")]
mod delivery;
#[path = "mik_7630_events/gateway.rs"]
#[allow(dead_code, reason = "shared harness; each binary uses a subset")]
mod gateway;
#[path = "task_upstream_recovery_sdk/issuer.rs"]
#[allow(dead_code, reason = "shared issuer; this target mints two tokens")]
mod issuer;
#[path = "task_upstream_recovery_sdk/pins.rs"]
#[allow(dead_code, reason = "the issuer reads only its bounds")]
mod pins;
#[path = "mik_7630_events/receiver.rs"]
#[allow(dead_code, reason = "shared receiver; each binary uses a subset")]
mod receiver;

use std::sync::Arc;
use std::time::Duration;

use delivery::{DEADLINE, delivery_config, wait_until};
use gateway::{ADMIN, ALICE, BOB, Gateway, config, error};
use receiver::{Received, Receiver, whsec};
use serde_json::{Value, json};
use tokio::sync::Semaphore;

const EMAIL_A: &str = "events-a@events.test";
const EMAIL_B: &str = "events-b@events.test";
const MARKER: &str = "i4-task-backend-answered";
const TASKS_EXT: &str = "io.modelcontextprotocol/tasks";
const IDEMPOTENCY_META: &str = "io.mcp-gateway/idempotency-key";

/// A backend whose `tools/call` waits for a permit, so a task stays
/// `working` until the row releases it.
struct Mock {
    url: String,
    permits: Arc<Semaphore>,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for Mock {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl Mock {
    fn release(&self) {
        self.permits.add_permits(1);
    }

    async fn start() -> Self {
        let permits = Arc::new(Semaphore::new(0));
        let held = Arc::clone(&permits);
        let app = axum::Router::new().route(
            "/mcp",
            axum::routing::post(move |axum::Json(req): axum::Json<Value>| {
                let held = Arc::clone(&held);
                async move {
                    let method = req["method"].as_str().unwrap_or_default().to_owned();
                    let Some(id) = req.get("id").filter(|i| !i.is_null()).cloned() else {
                        return axum::response::IntoResponse::into_response(
                            axum::http::StatusCode::ACCEPTED,
                        );
                    };
                    let result = match method.as_str() {
                        "initialize" => json!({
                            "protocolVersion": "2025-06-18",
                            "capabilities": {"tools": {}},
                            "serverInfo": {"name": "mock", "version": "0"}}),
                        "tools/list" => json!({"tools": [{
                            "name": "echo", "description": "fixed marker",
                            "inputSchema": {"type": "object", "properties": {}},
                            "annotations": {"title": "Echo", "readOnlyHint": true,
                                "destructiveHint": false, "idempotentHint": true,
                                "openWorldHint": false}}]}),
                        "tools/call" => {
                            let wait =
                                tokio::time::timeout(Duration::from_secs(30), held.acquire()).await;
                            if let Ok(Ok(permit)) = wait {
                                permit.forget();
                            }
                            json!({"content": [{"type": "text", "text": MARKER}]})
                        }
                        _ => json!({}),
                    };
                    axum::response::IntoResponse::into_response(axum::Json(
                        json!({"jsonrpc": "2.0", "id": id, "result": result}),
                    ))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock");
        let url = format!("http://{}/mcp", listener.local_addr().expect("addr"));
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self {
            url,
            permits,
            server,
        }
    }
}

/// The fixture config with backend `mock` granted to every key and the
/// loopback receiver allowed.
fn config_with_mock(root: &std::path::Path, mock: &Mock) -> Value {
    let mut cfg = delivery_config(root, &json!({}));
    cfg["backends"] = json!({"mock": {"http_url": mock.url, "streamable_http": true}});
    for key in cfg["auth"]["api_keys"].as_array_mut().expect("keys") {
        key["backends"]
            .as_array_mut()
            .expect("backends")
            .push(json!("mock"));
    }
    cfg
}

async fn start(root: &std::path::Path, rx: &Receiver, cfg: Value) -> Gateway {
    let (k, v) = rx.trust_env();
    let gw = Gateway::start_with_env(root, cfg, &[(k, &v)]).await;
    gw.event_names(Some(ALICE), Some("task.settled")).await;
    gw
}

fn sub_params(name: &str, url: &str, arguments: Value) -> Value {
    let mut params = json!({"name": name,
        "delivery": {"mode": "webhook", "url": url, "secret": whsec(32)}});
    params["arguments"] = arguments;
    params
}

async fn subscribe(gw: &Gateway, key: &str, name: &str, url: &str, args: Value) -> Value {
    gw.rpc(Some(key), "events/subscribe", sub_params(name, url, args))
        .await
}

fn sub_id(answer: &Value) -> String {
    answer["result"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("subscribe answers an id: {answer}"))
        .to_owned()
}

/// Deliveries the receiver got for subscription `id`.
fn for_sub(rx: &Receiver, id: &str) -> Vec<Received> {
    rx.events()
        .into_iter()
        .filter(|r| r.header("x-mcp-subscription-id").as_deref() == Some(id))
        .collect()
}

/// T3 (EVENTS.2), backend and task clauses: `backend.<x>.*` follows backend
/// visibility; `task.settled` is listed to any authenticated principal.
#[tokio::test]
async fn events_list_carries_backend_and_task_events_per_visibility() {
    let root = tempfile::tempdir().expect("root");
    let gw = Gateway::start(root.path(), gateway::config(root.path(), &json!({}))).await;
    let alice = gw
        .event_names(Some(ALICE), Some("backend.hooks.tools_changed"))
        .await;
    assert!(
        alice.iter().any(|n| n == "backend.hooks.tools_changed"),
        "{alice:?}"
    );
    assert!(alice.iter().any(|n| n == "task.settled"), "{alice:?}");
    let bob = gw.event_names(Some(BOB), Some("task.settled")).await;
    assert!(bob.iter().any(|n| n == "task.settled"), "{bob:?}");
    assert!(
        bob.iter().all(|n| !n.starts_with("backend.hooks.")),
        "bob may not reach backend hooks: {bob:?}"
    );
}

/// T38 (SOURCE.1): a backend whose tool set changes (config reload of the
/// backend) becomes exactly one `backend.<x>.tools_changed` event. The burst
/// clause is the in-crate debounce row: the config watcher already merges
/// writes, so a black-box burst could not fail.
#[tokio::test]
async fn backend_tool_changes_become_events() {
    let root = tempfile::tempdir().expect("root");
    let rx = Receiver::start(root.path()).await;
    let mock = Mock::start().await;
    let cfg = config_with_mock(root.path(), &mock);
    let mut gw = start(root.path(), &rx, cfg.clone()).await;
    let name = "backend.mock.tools_changed";
    gw.event_names(Some(ALICE), Some(name)).await;
    let id = sub_id(&subscribe(&gw, ALICE, name, &rx.url, json!({})).await);
    // Startup announces too: take the baseline once the count is quiet.
    let mut last = usize::MAX;
    let mut stable = 0;
    while stable < 4 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let now = for_sub(&rx, &id).len();
        stable = if now == last { stable + 1 } else { 0 };
        last = now;
    }
    let baseline = last;
    let mut changed = cfg;
    changed["backends"]["mock"]["description"] = json!("changed tool set");
    gw.rewrite_config(changed);
    let arrived = wait_until(DEADLINE, || for_sub(&rx, &id).len() > baseline).await;
    assert!(arrived, "no tools_changed event after the backend changed");
    tokio::time::sleep(Duration::from_secs(4)).await;
    let posts = for_sub(&rx, &id);
    assert_eq!(
        posts.len(),
        baseline + 1,
        "exactly one event for one change"
    );
    let body = posts[baseline].json();
    assert_eq!(body["name"], name);
    assert_eq!(body["data"], json!({}));
}

async fn start_task(gw: &Gateway, key: &str, idem: &str) -> String {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
        "name": "gateway_invoke",
        "arguments": {"server": "mock", "tool": "echo", "arguments": {}},
        "task": {},
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {"extensions": {TASKS_EXT: {}}},
            "io.modelcontextprotocol/clientInfo": {"name": "events-test", "version": "1"},
            IDEMPOTENCY_META: idem}}});
    let answer: Value = gw
        .client
        .post(format!("{}/mcp", gw.url))
        .bearer_auth(key)
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", "gateway_invoke")
        .json(&body)
        .send()
        .await
        .expect("task call")
        .json()
        .await
        .expect("task answer");
    answer
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("task handle expected: {answer}"))
        .to_owned()
}

/// A gateway whose two task owners are delegated OIDC bearers, so each owner
/// is a verified identity. Returns the gateway, receiver, mock backend and the
/// two tokens.
async fn two_owner_gateway(
    root: &std::path::Path,
) -> (Gateway, Receiver, Mock, String, String, issuer::Issuer) {
    let issuer = issuer::Issuer::start(root).await;
    let rx = Receiver::start(root).await;
    let mock = Mock::start().await;
    let (alice, bob) = (
        issuer.mint("events-subject-a", EMAIL_A),
        issuer.mint("events-subject-b", EMAIL_B),
    );
    let mut cfg = config_with_mock(root, &mock);
    let policies: Vec<Value> = [EMAIL_A, EMAIL_B]
        .iter()
        .map(|email| {
            json!({"match": {"email": email, "issuer": issuer.url},
                "scopes": {"backends": ["mock"], "tools": ["*"], "rate_limit": 0}})
        })
        .collect();
    cfg["key_server"] = json!({
        "enabled": true, "delegated_bearer": true, "max_oidc_token_age_secs": 3600,
        "oidc": [{"issuer": issuer.url, "auto_discover": true,
            "audiences": [issuer::AUDIENCE]}],
        "policies": policies,
    });
    // One trust file for both TLS peers the child talks to.
    let bundle = root.join("ca-bundle.pem");
    let pem = |p: &std::path::Path| std::fs::read_to_string(p).expect("CA pem");
    std::fs::write(
        &bundle,
        format!("{}\n{}", pem(&rx.ca_file), pem(&issuer.ca_file)),
    )
    .expect("bundle");
    let bundle_path = bundle.to_string_lossy().into_owned();
    let gw = Gateway::start_with_env(root, cfg, &[("SSL_CERT_FILE", &bundle_path)]).await;
    gw.event_names(Some(ALICE), Some("task.settled")).await;
    (gw, rx, mock, alice, bob, issuer)
}

/// T40 (SOURCE.2): settlement is an owner-only event carrying no result.
#[tokio::test]
async fn settled_tasks_become_events_for_their_owner_only() {
    let root = tempfile::tempdir().expect("root");
    let (gw, rx, mock, alice, bob, _issuer) = two_owner_gateway(root.path()).await;
    let (a_tok, b_tok) = (alice.as_str(), bob.as_str());
    let task_a = start_task(&gw, a_tok, "i4-a").await;
    let alice_all = sub_id(&subscribe(&gw, a_tok, "task.settled", &rx.url, json!({})).await);
    let alice_one = sub_id(
        &subscribe(
            &gw,
            a_tok,
            "task.settled",
            &format!("{}2", rx.url),
            json!({"taskId": task_a}),
        )
        .await,
    );
    let bob_all = sub_id(&subscribe(&gw, b_tok, "task.settled", &rx.url, json!({})).await);
    let foreign = subscribe(
        &gw,
        b_tok,
        "task.settled",
        &rx.url,
        json!({"taskId": task_a}),
    )
    .await;
    assert_eq!(
        error(&foreign)["code"],
        -32012,
        "another owner's taskId: {foreign}"
    );
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(
        rx.events().is_empty(),
        "a non-terminal transition emits nothing"
    );
    mock.release();
    assert!(
        wait_until(DEADLINE, || !for_sub(&rx, &alice_all).is_empty()
            && !for_sub(&rx, &alice_one).is_empty())
        .await,
        "alice's subscribers hear her task settle"
    );
    let body = for_sub(&rx, &alice_all)[0].json();
    assert_eq!(body["name"], "task.settled");
    assert_eq!(body["data"]["taskId"], task_a);
    assert_eq!(body["data"]["status"], "completed");
    assert!(body["data"]["settledAt"].is_string());
    assert!(
        !body.to_string().contains(MARKER),
        "no result content: {body}"
    );
    let task_b = start_task(&gw, b_tok, "i4-b").await;
    mock.release();
    assert!(wait_until(DEADLINE, || !for_sub(&rx, &bob_all).is_empty()).await);
    assert_eq!(for_sub(&rx, &bob_all)[0].json()["data"]["taskId"], task_b);
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(for_sub(&rx, &bob_all).len(), 1, "bob hears only his own");
    assert_eq!(for_sub(&rx, &alice_all).len(), 1, "alice hears only hers");
    assert_eq!(for_sub(&rx, &alice_one).len(), 1);
    // A second task of alice's: her all-tasks subscriber hears it, the one
    // pinned to the first task does not.
    let task_a2 = start_task(&gw, a_tok, "i4-a2").await;
    mock.release();
    assert!(wait_until(DEADLINE, || for_sub(&rx, &alice_all).len() == 2).await);
    assert_eq!(
        for_sub(&rx, &alice_all)[1].json()["data"]["taskId"],
        task_a2
    );
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(for_sub(&rx, &alice_one).len(), 1, "the taskId filter holds");
    assert_eq!(for_sub(&rx, &bob_all).len(), 1);
}

/// MIK-7720 U5 over `/mcp`: health and kill-switch types are listed to an
/// admin key only (standing set by the transport from the authenticated
/// key), while every API-key holder sees the budget types.
#[tokio::test]
async fn operational_types_are_listed_to_admins_only() {
    let root = tempfile::tempdir().expect("root");
    let cfg = config(
        root.path(),
        &json!({"enabled": true, "sources": {
            "operational": true, "backend_notifications": false, "task_settled": false}}),
    );
    let gw = Gateway::start(root.path(), cfg).await;
    let operator = [
        "gateway.backend.health_changed",
        "gateway.kill_switch.changed",
    ];
    let admin = gw.event_names(Some(ADMIN), Some(operator[1])).await;
    for name in operator {
        assert!(
            admin.iter().any(|n| n == name),
            "admin lists {name}: {admin:?}"
        );
    }
    let alice = gw
        .event_names(Some(ALICE), Some("gateway.budget.threshold"))
        .await;
    assert!(
        alice.iter().any(|n| n == "gateway.budget.threshold"),
        "{alice:?}"
    );
    for name in operator {
        assert!(
            !alice.iter().any(|n| n == name),
            "non-admin lists {name}: {alice:?}"
        );
    }
}
