// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Adding a URL server with headers, and the plain-http credential refusal
//! answered before anything is written. Uses the parent's panel fixture.

use serde_json::json;

use super::*;

/// The add's answer and the detail its admin action record would carry
/// (`AuditDetail` on the response; `None` when the handler attached none).
async fn add_with_detail(panel: &Panel, body: Value) -> (StatusCode, Value, Option<String>) {
    add_through(panel, body, None).await
}

/// [`add_with_detail`] through `store` when given: a counting store, so a
/// row can say whether the add opened the secret store at all.
async fn add_through(
    panel: &Panel,
    body: Value,
    store: Option<&Arc<Limited>>,
) -> (StatusCode, Value, Option<String>) {
    let req: AddBackendRequest = serde_json::from_value(body).expect("add body");
    let guard = Panel::guard(routes::UI_BACKENDS, &axum::http::Method::POST);
    let seam = store.map(|store| {
        axum::Extension(BackendStoreForTest {
            store: Some(Arc::clone(store) as Arc<dyn SecretStore + Send + Sync>),
            after_precheck: None,
        })
    });
    let response = add_backend(State(Arc::clone(&panel.state)), seam, guard, Json(req))
        .await
        .into_response();
    let detail = response
        .extensions()
        .get::<crate::gateway::ui::admin_audit::AuditDetail>()
        .map(|detail| Value::Object(detail.0.clone()).to_string());
    let (status, answer) = read(response).await;
    (status, answer, detail)
}

/// The refusal list as `GET /ui/api/refusals` shows it.
fn refusal_list(panel: &Panel) -> Vec<Value> {
    let context = panel
        .state
        .meta_mcp
        .reload_context()
        .expect("a reload context");
    let list = serde_json::to_value(context.refusals().list()).expect("refusals serialize");
    list.as_array().cloned().unwrap_or_default()
}

/// The add body's one by-field refusal, exactly.
fn refused(reason: &str, field: &str) -> Value {
    json!({"error": "literal_in_value", "refusals": [{"reason": reason, "field": field}]})
}

/// Every log record `body` emits, run on a current-thread runtime inside a
/// real subscriber.
fn logged(body: impl std::future::Future<Output = ()>) -> Vec<Value> {
    crate::test_log_capture::records(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime")
            .block_on(body);
    })
}

/// H1: a URL add with a key header: the secret header value goes to the
/// store and gateway.yaml holds its reference; a plain header is written as
/// typed; the literal is in no answer, file, log record or audit detail.
#[test]
fn h1_a_url_add_stores_a_secret_header_and_answers_its_reference() {
    let bearer = format!("Bearer {TOKEN}");
    let mut checked = false;
    let logs = crate::test_log_capture::records(|| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime");
        runtime.block_on(async {
            let panel = Panel::new().await;
            let body = json!({
                "name": "h",
                "url": "https://host.example/mcp",
                "headers": {"Authorization": bearer, "X-Team": "ops"},
            });
            let (status, answer, detail) = add_with_detail(&panel, body).await;
            assert_eq!(status, StatusCode::CREATED, "{answer}");
            no_value(&answer, TOKEN);
            let stored = answer["secrets_stored"].as_array().expect("secrets_stored");
            assert_eq!(stored.len(), 1, "{answer}");
            assert_eq!(stored[0]["field"], "headers.Authorization", "{answer}");
            let reference = stored[0]["reference"].as_str().expect("a reference");
            let text = panel.text();
            assert!(
                !text.contains(TOKEN),
                "the literal reached gateway.yaml:\n{text}"
            );
            let written = panel.written("h");
            assert_eq!(
                written.headers.get("Authorization").map(String::as_str),
                Some(reference),
                "{text}"
            );
            assert_eq!(
                written.headers.get("X-Team").map(String::as_str),
                Some("ops"),
                "{text}"
            );
            assert!(
                !detail.as_deref().unwrap_or_default().contains(TOKEN),
                "the literal reached the audit detail: {detail:?}"
            );
            checked = true;
        });
    });
    assert!(checked, "the add's assertions did not run");
    let shown = logs
        .iter()
        .filter(|r| r.to_string().contains(TOKEN))
        .count();
    assert_eq!(shown, 0, "the literal reached the log: {logs:#?}");
}

/// C2: a plain-http URL with an ordinary query is credential-bearing by the
/// config's own rule; the add refuses it as the operator's mistake (422),
/// where it used to fail inside the writer with a 500.
#[tokio::test]
async fn c2_a_plain_http_url_with_a_plain_query_no_longer_answers_500() {
    let panel = Panel::new().await;
    let (status, answer) = panel
        .add(json!({"name": "q", "url": "http://host.example/mcp?x=1"}))
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{answer}");
    assert_eq!(answer["error"], "cleartext_credentials", "{answer}");
}

/// A URL that carries a credential as userinfo, split so no source line
/// holds one whole (the credential rows beside this file do the same).
fn userinfo_url() -> String {
    ["http://svc:", "pw-0123456789", "@host.example/mcp"].concat()
}

/// H2: headers on a command add, on a command add that also names a URL,
/// and on a registry add are refused by field; nothing written or stored.
#[tokio::test]
async fn h2_headers_without_a_url_are_refused_by_field() {
    let panel = Panel::new().await;
    let before = panel.text();
    let headers = json!({"X-Team": "ops"});
    for body in [
        json!({"name": "c", "command": "npx tool", "headers": headers}),
        json!({"name": "c", "command": "npx tool", "url": "https://host.example/mcp", "headers": headers}),
        json!({"name": "github", "headers": headers}),
    ] {
        let store = Arc::new(Limited::new(panel.dir.path()));
        let (status, answer, _) = add_through(&panel, body, Some(&store)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{answer}");
        assert_eq!(answer, refused("headers_need_url", "headers"));
        assert_eq!(store.calls(), 0, "the store was opened for a refused add");
    }
    assert_eq!(panel.text(), before, "a refused add wrote");
}

/// H3: a header name the HTTP parser refuses is answered by field, and the
/// answer is exactly that refusal; the bad name is shown nowhere.
#[test]
fn h3_a_bad_header_name_is_refused_and_never_echoed() {
    let names = ["bad name", "bad:name", "bad\nname", "bad\u{1}name", ""];
    let mut checked = 0;
    let logs = logged(async {
        let panel = Panel::new().await;
        let before = panel.text();
        for name in names {
            let store = Arc::new(Limited::new(panel.dir.path()));
            let body = json!({"name": "h", "url": "https://host.example/mcp",
                "headers": {name: "v", "Authorization": format!("Bearer {TOKEN}")}});
            let (status, answer, detail) = add_through(&panel, body, Some(&store)).await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{answer}");
            assert_eq!(answer, refused("header_name", "headers"), "{name:?}");
            assert_eq!(store.calls(), 0, "{name:?}: the store was opened");
            if !name.is_empty() {
                let shown = format!("{answer} {detail:?} {:?}", refusal_list(&panel));
                assert!(!shown.contains(name), "{name:?} was echoed: {shown}");
            }
            checked += 1;
        }
        assert_eq!(panel.text(), before, "a refused add wrote");
    });
    assert_eq!(checked, names.len(), "the rows did not all run");
    for name in names.iter().filter(|n| !n.is_empty()) {
        assert!(
            !logs.iter().any(|r| r.to_string().contains(name)),
            "{name:?} reached the log"
        );
    }
}

/// H4: a bad header value, two names that are one header, a URL that does
/// not parse, and the override without a URL are each refused by field
/// before the store; each case also carries a value the store would take.
/// Neither that value nor a bad header value reaches the answer or the log.
#[test]
fn h4_header_values_duplicate_names_a_bad_url_and_a_stray_override_are_refused_before_the_store() {
    let bearer = format!("Bearer {TOKEN}");
    let url = "https://host.example/mcp";
    let mut checked = 0;
    let logs = logged(async {
        let panel = Panel::new().await;
        let before = panel.text();
        let bad_line = json!({"X-A": "a\nb", "Authorization": bearer});
        let bad_nul = json!({"X-A": "a\u{0}b", "Authorization": bearer});
        let twice = json!({"Authorization": bearer, "authorization": "x"});
        for (body, reason, field) in [
            (
                json!({"name": "h", "url": url, "headers": bad_line}),
                "header_value",
                "headers",
            ),
            (
                json!({"name": "h", "url": url, "headers": bad_nul}),
                "header_value",
                "headers",
            ),
            (
                json!({"name": "h", "url": url, "headers": twice}),
                "header_name",
                "headers",
            ),
            (
                json!({"name": "h", "url": "http://", "headers": {"Authorization": bearer}}),
                "url_invalid",
                "url",
            ),
            (
                json!({"name": "c", "command": "npx tool", "env": {"API_KEY": TOKEN},
                    "allow_cleartext_credentials": true}),
                "override_needs_url",
                "allow_cleartext_credentials",
            ),
            (
                json!({"name": "github", "env": {"GITHUB_TOKEN": TOKEN},
                    "allow_cleartext_credentials": true}),
                "override_needs_url",
                "allow_cleartext_credentials",
            ),
            (
                json!({"name": "c", "command": "npx tool", "url": url, "env": {"API_KEY": TOKEN},
                    "allow_cleartext_credentials": true}),
                "override_needs_url",
                "allow_cleartext_credentials",
            ),
            (
                json!({"name": "h", "url": userinfo_url(),
                    "headers": {"bad name": "v", "Authorization": bearer}}),
                "header_name",
                "headers",
            ),
        ] {
            let store = Arc::new(Limited::new(panel.dir.path()));
            let (status, answer, _) = add_through(&panel, body.clone(), Some(&store)).await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}: {answer}");
            assert_eq!(answer, refused(reason, field), "{body}");
            no_value(&answer, TOKEN);
            assert_eq!(store.calls(), 0, "{body}: the store was opened");
            assert_eq!(panel.text(), before, "{body}: a refused add wrote");
            checked += 1;
        }
    });
    assert_eq!(checked, 8, "the cases did not all run");
    for value in [TOKEN, "a\nb", "a\u{0}b"] {
        assert!(
            !logs.iter().any(|r| r.to_string().contains(value)),
            "{value:?} reached the log"
        );
    }
}

/// The names of the files beside gateway.yaml, the secret store's folder
/// excluded: a lock sidecar left by a refused add would show here.
fn beside_config(panel: &Panel) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(panel.dir.path())
        .expect("the config folder")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n != "secrets")
        .collect();
    names.sort();
    names
}

/// C1: a plain-http (and ws) add with a header the gateway would store is
/// refused 422 with the refusal list's own cause and fix, before any write,
/// lock or store; the list holds one active `add` entry; the header's value
/// is shown nowhere.
#[test]
fn c1_a_plain_http_add_with_a_header_answers_422_before_any_write() {
    let bearer = format!("Bearer {TOKEN}");
    let mut checked = 0;
    let logs = logged(async {
        let panel = Panel::new().await;
        // The control: the same header over https opens the store, so the
        // refused cases' "not opened" means something.
        let store = Arc::new(Limited::new(panel.dir.path()));
        let body = json!({"name": "ctl", "url": "https://host.example/mcp",
            "headers": {"Authorization": bearer}});
        let (status, answer, _) = add_through(&panel, body, Some(&store)).await;
        assert_eq!(status, StatusCode::CREATED, "control: {answer}");
        assert!(store.calls() > 0, "control: the store was not opened");
        for (name, url) in [
            ("p", "http://host.example/mcp"),
            ("w", "ws://host.example/mcp"),
        ] {
            let (text, files) = (panel.text(), beside_config(&panel));
            let store = Arc::new(Limited::new(panel.dir.path()));
            let body = json!({"name": name, "url": url, "headers": {"Authorization": bearer}});
            let (status, answer, detail) = add_through(&panel, body, Some(&store)).await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{name}: {answer}");
            assert_eq!(panel.text(), text, "{name}: gateway.yaml changed");
            assert_eq!(beside_config(&panel), files, "{name}: a file was left");
            assert_eq!(store.calls(), 0, "{name}: the store was opened");
            let entries: Vec<Value> = refusal_list(&panel)
                .into_iter()
                .filter(|e| e["backend"] == name && e["active"] == true)
                .collect();
            let [entry] = entries.as_slice() else {
                panic!("{name}: one active refusal entry: {entries:?}");
            };
            assert_eq!(
                (&entry["kind"], &entry["code"]),
                (&json!("add"), &json!("cleartext_credentials"))
            );
            // The answer's words are the list's own cause and fix for this
            // name, the one source both read (`explain`, refusals.rs).
            assert_eq!(
                answer,
                json!({"error": "cleartext_credentials", "message": entry["cause"], "fix": entry["fix"]})
            );
            let shown = format!("{answer} {entry} {detail:?}");
            assert!(
                !shown.contains(TOKEN),
                "{name}: the value was shown: {shown}"
            );
            checked += 1;
        }
    });
    assert_eq!(checked, 2, "the cases did not all run");
    assert!(
        !logs.iter().any(|r| r.to_string().contains(TOKEN)),
        "the value reached the log"
    );
}

/// C3: the override writes the key, is named on the add's one audit
/// detail (beside a tool selection, never a header), and is in effect by the
/// rule the override auditor applies (`Config::cleartext_override_in_effect`,
/// the predicate its sync reads). `false` or absent sets nothing.
#[tokio::test]
async fn c3_the_override_writes_the_key_and_is_recorded() {
    let panel = Panel::new().await;
    let bearer = format!("Bearer {TOKEN}");
    for (name, url) in [
        ("o", "http://host.example/mcp"),
        ("ow", "ws://host.example/mcp"),
    ] {
        let body = json!({"name": name, "url": url, "headers": {"Authorization": bearer},
            "allow_cleartext_credentials": true});
        let (status, answer, detail) = add_with_detail(&panel, body).await;
        assert_eq!(status, StatusCode::CREATED, "{name}: {answer}");
        let written = panel.written(name);
        assert!(
            written.allow_cleartext_credentials,
            "{name}: the key was not written"
        );
        assert!(
            Config::cleartext_override_in_effect(name, &written),
            "{name}: not in effect"
        );
        let detail: Value = serde_json::from_str(&detail.expect("an audit detail")).expect("json");
        assert_eq!(detail["cleartext_override"], true, "{detail}");
        assert_eq!(detail["backend"], name, "{detail}");
        let shown = detail.to_string();
        assert!(
            !shown.contains("Authorization") && !shown.contains(TOKEN),
            "{shown}"
        );
    }
    let body = json!({"name": "ot", "url": "http://host.example/mcp", "headers": {"Authorization": bearer},
        "allow_cleartext_credentials": true, "allowed_tools": ["t1"]});
    let (status, answer, detail) = add_with_detail(&panel, body).await;
    assert_eq!(status, StatusCode::CREATED, "{answer}");
    let detail: Value = serde_json::from_str(&detail.expect("an audit detail")).expect("json");
    assert_eq!(detail["cleartext_override"], true, "{detail}");
    assert_eq!(detail["allowed_tools"]["backend"], "ot", "{detail}");
    // Not `a`: the panel's starting config already holds a backend `a`.
    for (name, flag) in [("f", json!(false)), ("absent", Value::Null)] {
        let mut body = json!({"name": name, "url": "https://host.example/mcp"});
        if !flag.is_null() {
            body["allow_cleartext_credentials"] = flag;
        }
        let (status, answer, _) = add_with_detail(&panel, body).await;
        assert_eq!(status, StatusCode::CREATED, "{name}: {answer}");
        assert!(
            !panel.written(name).allow_cleartext_credentials,
            "{name}: the override was set"
        );
    }
}

/// C4: the override never lifts a credential written into the URL: the
/// answer is exactly the one the same request gets without it.
#[tokio::test]
async fn c4_the_override_never_lifts_a_credential_in_the_url() {
    let panel = Panel::new().await;
    let before = panel.text();
    for url in [
        userinfo_url(),
        ["http://host.example/mcp?api_key=", "k-0123456789"].concat(),
    ] {
        let plain = json!({"name": "b", "url": url});
        let mut with = plain.clone();
        with["allow_cleartext_credentials"] = json!(true);
        let (status, answer) = panel.add(with).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{answer}");
        assert_eq!(answer, refused("secret_in_url", "url"));
        let (_, without) = panel.add(plain).await;
        assert_eq!(answer, without, "the override changed the answer");
    }
    assert_eq!(panel.text(), before, "a refused add wrote");
}

/// C5: loopback http, https and wss need no override, and a plain-http URL
/// that carries nothing credential-bearing is written as before.
#[tokio::test]
async fn c5_loopback_and_https_need_no_override() {
    let panel = Panel::new().await;
    let header = json!({"X-Team": "ops"});
    for (name, url, headers) in [
        ("l4", "http://127.0.0.1:9/mcp", header.clone()),
        ("l6", "http://[::1]:9/mcp", header.clone()),
        ("hs", "https://host.example/mcp", header.clone()),
        ("ws", "wss://host.example/mcp", header.clone()),
        ("pl", "http://host.example/mcp", json!({})),
    ] {
        let (status, answer) = panel
            .add(json!({"name": name, "url": url, "headers": headers}))
            .await;
        assert_eq!(status, StatusCode::CREATED, "{name}: {answer}");
        assert!(!panel.written(name).allow_cleartext_credentials, "{name}");
        assert!(
            !refusal_list(&panel).iter().any(|e| e["backend"] == name),
            "{name}: a refusal was recorded"
        );
    }
}

/// C6: after C1's refusal, the same add over https lands and the refusal
/// entry is no longer active (the ledger's rule for a committed write).
#[tokio::test]
async fn c6_the_refused_add_resolves_when_the_fixed_add_lands() {
    let panel = Panel::new().await;
    let headers = json!({"Authorization": format!("Bearer {TOKEN}")});
    let (status, answer) = panel
        .add(json!({"name": "p", "url": "http://host.example/mcp", "headers": headers}))
        .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "premise: {answer}"
    );
    let active = |panel: &Panel| {
        refusal_list(panel)
            .iter()
            .any(|e| e["backend"] == "p" && e["active"] == true)
    };
    assert!(active(&panel), "premise: the refusal is listed");
    let (status, answer) = panel
        .add(json!({"name": "p", "url": "https://host.example/mcp", "headers": headers}))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{answer}");
    assert!(!active(&panel), "the refusal is still active");
}

/// Every request a loopback MCP server saw, each as its body plus each
/// header as ` name=value`.
type Seen = Arc<parking_lot::Mutex<Vec<String>>>;

/// A legacy MCP server on loopback that records what it receives and
/// answers initialize and tools/list.
async fn recording_server(seen: Seen) -> String {
    let app = axum::Router::new().route(
        "/mcp",
        axum::routing::post(
            move |headers: axum::http::HeaderMap, body: axum::body::Bytes| {
                let seen = Arc::clone(&seen);
                async move {
                    let mut line = String::from_utf8_lossy(&body).into_owned();
                    for (name, value) in &headers {
                        let value = value.to_str().unwrap_or("");
                        let _ =
                            std::fmt::Write::write_fmt(&mut line, format_args!(" {name}={value}"));
                    }
                    seen.lock().push(line);
                    let request: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                    let id = request["id"].clone();
                    if id.is_null() {
                        return StatusCode::ACCEPTED.into_response();
                    }
                    let mut answer = match request["method"].as_str() {
                        Some("initialize") => json!({"result": {
                            "protocolVersion": "2025-06-18",
                            "capabilities": {"tools": {}},
                            "serverInfo": {"name": "previewed", "version": "0"}}}),
                        Some("tools/list") => json!({"result": {"tools": [
                            {"name": "echo", "inputSchema": {"type": "object"}}]}}),
                        _ => json!({"error": {"code": -32601, "message": "not found"}}),
                    };
                    answer["jsonrpc"] = json!("2.0");
                    answer["id"] = id;
                    Json(answer).into_response()
                }
            },
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let address = listener.local_addr().expect("address");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{address}/mcp")
}

/// One call of the preview route with `body` (an add body, plus `confirm`
/// when confirming), under a generation that lets it reach loopback.
async fn preview(panel: &Panel, body: Value) -> (StatusCode, Value) {
    let request = serde_json::from_value(body).expect("preview body");
    let mut config = Config::default();
    config.security.ssrf_protection = false;
    let generation = crate::config_reload::LiveConfig::new(config).generation();
    let guard = Panel::guard(routes::UI_PREVIEWS, &axum::http::Method::POST);
    read(
        crate::gateway::ui::preview::preview_backend(
            State(Arc::clone(&panel.state)),
            axum::Extension(generation),
            guard,
            Json(request),
        )
        .await,
    )
    .await
}

/// P1: the preview takes the add's header rules (the same refusals at the
/// same place), names each typed header as withheld, and sends none of
/// them, also when its confirm carries other headers than its describe.
/// No preview opens the store, writes gateway.yaml, or refuses for cleartext.
#[test]
fn p1_the_preview_route_applies_the_same_header_rules_and_sends_no_header() {
    let mut checked = false;
    let logs = logged(async {
        let panel = Panel::new().await;
        let (text, stored) = (panel.text(), panel.entries());
        let seen = Seen::default();
        let url = recording_server(Arc::clone(&seen)).await;
        let headers = json!({"Authorization": format!("Bearer {TOKEN}"), "X-Team": "ops"});
        let body = json!({"name": "pv", "url": url, "headers": headers});
        let (status, described) = preview(&panel, body.clone()).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{described}");
        assert_eq!(
            described["preview"]["withheld"]["headers"],
            json!(["Authorization", "X-Team"])
        );
        no_value(&described, TOKEN);
        let mut confirm = body.clone();
        confirm["confirm"] = described["confirm"].clone();
        let (status, ran) = preview(&panel, confirm).await;
        assert_eq!(status, StatusCode::OK, "{ran}");
        no_value(&ran, TOKEN);
        // A confirm whose headers differ from its describe's still matches
        // (the token's digest is taken after the scrub) and still sends none.
        let (_, described) = preview(&panel, body.clone()).await;
        let mut other = json!({"name": "pv", "url": url,
            "headers": {"Authorization": "Bearer other-value", "X-Other": "x"}});
        other["confirm"] = described["confirm"].clone();
        let (status, ran) = preview(&panel, other).await;
        assert_eq!(status, StatusCode::OK, "{ran}");
        let seen = seen.lock().clone();
        assert!(
            seen.iter().any(|line| line.contains("tools/list")),
            "premise: the preview reached the server: {seen:?}"
        );
        for line in &seen {
            let lower = line.to_ascii_lowercase();
            assert!(
                !lower.contains(" authorization=")
                    && !lower.contains(" x-team=")
                    && !lower.contains(" x-other="),
                "a typed header was sent: {line}"
            );
        }
        for (body, reason) in [
            (
                json!({"name": "pv", "url": url, "headers": {"bad name": "v"}}),
                "header_name",
            ),
            (
                json!({"name": "pv", "command": "npx tool", "headers": {"X-Team": "ops"}}),
                "headers_need_url",
            ),
            (
                json!({"name": "pv", "url": url, "headers": {"X-Team": "a\nb"}}),
                "header_value",
            ),
        ] {
            let (status, answer) = preview(&panel, body).await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{answer}");
            assert_eq!(answer, refused(reason, "headers"));
        }
        let plain = json!({"name": "pc", "url": "http://host.example/mcp"});
        let mut with_header = plain.clone();
        with_header["headers"] = json!({"Authorization": format!("Bearer {TOKEN}")});
        let (status, answer) = preview(&panel, with_header).await;
        let (plain_status, _) = preview(&panel, plain).await;
        assert_ne!(answer["error"], "cleartext_credentials", "{answer}");
        assert_eq!(
            status, plain_status,
            "the header changed the preview's answer"
        );
        assert_eq!(panel.text(), text, "a preview wrote gateway.yaml");
        assert_eq!(panel.entries(), stored, "a preview stored a value");
        checked = true;
    });
    assert!(checked, "the row's assertions did not all run");
    assert!(
        !logs.iter().any(|r| r.to_string().contains(TOKEN)),
        "the sentinel reached the log"
    );
}
