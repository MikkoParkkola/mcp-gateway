// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The egress matrix on HTTP (design `2026-10-08-one-egress-scan.md`, the
//! MIK-8139 family: MIK-8139, MIK-8146, MIK-8155, MIK-8161, MIK-8112): a
//! credential a backend plants in any part of any method's answer never
//! reaches a `POST /mcp` or `POST /mcp/{name}` client. One cell per
//! method x route x part; every failing cell is reported, not the first.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use axum::body::to_bytes;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::direct_guards_fixture::{
    Fx, fixture_audited_on, fixture_firewalled_on, fixture_inspecting_on, meta_firewall,
};
use crate::gateway::egress_fixture::{BACKEND_METHODS, NAME, Part, Planted, URI, secret};
use crate::protocol::mrtr::IDEMPOTENCY_KEY_META;
use crate::security::firewall::FirewallAction;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Route {
    /// `POST /mcp`: `tools/call` through `gateway_invoke`, the rest native.
    Meta,
    /// `POST /mcp/alpha`.
    Direct,
}

const ROUTES: [Route; 2] = [Route::Meta, Route::Direct];

/// The request `route` sends to reach `method`'s answer: the URI, the method
/// sent and its params. On `/mcp` a backend's tool descriptions reach the
/// client through `gateway_list_tools`, not `tools/list` (which lists the
/// gateway's own tools).
fn request(route: Route, method: &'static str, part: Part) -> (&'static str, &'static str, Value) {
    let (sent, mut params) = match (route, method) {
        (Route::Meta, "tools/call") => (
            "tools/call",
            json!({"name": "gateway_invoke",
            "arguments": {"server": "alpha", "tool": NAME, "arguments": {}}}),
        ),
        (Route::Meta, "tools/list") => (
            "tools/call",
            json!({"name": "gateway_list_tools",
            "arguments": {"server": "alpha"}}),
        ),
        (Route::Direct, "tools/call") => (method, json!({"name": NAME, "arguments": {}})),
        (Route::Meta, "prompts/get") => (method, json!({"name": format!("alpha/{NAME}")})),
        (Route::Direct, "prompts/get") => (method, json!({"name": NAME})),
        (_, "resources/read") => (method, json!({"uri": URI})),
        _ => (method, json!({})),
    };
    if part.is_notification() {
        params["_meta"] = json!({"progressToken": "p1"});
    }
    if matches!(part, Part::InterimQuestion | Part::InterimState) {
        params["_meta"] = answering_client();
    }
    let uri = match route {
        Route::Meta => "/mcp",
        Route::Direct => "/mcp/alpha",
    };
    (uri, sent, params)
}

/// POST one request accepting a streamed answer; the whole body as text, so
/// a notification frame is read as surely as the answer.
async fn post(fx: &Fx, uri: &str, method: &str, params: &Value) -> String {
    post_as(fx, (uri, method), params, None).await
}

/// [`post`] carrying `subject`'s verified identity, the caller a sealed
/// question is bound to.
async fn post_as(
    fx: &Fx,
    (uri, method): (&str, &str),
    params: &Value,
    subject: Option<&str>,
) -> String {
    let mut builder = axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("authorization", "Bearer k-std")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream");
    // A modern request mirrors its method and name in headers.
    if params
        .pointer("/_meta/io.modelcontextprotocol~1protocolVersion")
        .is_some()
    {
        builder = builder
            .header("mcp-protocol-version", "2026-07-28")
            .header("mcp-method", method);
        if let Some(name) = params.get("name").and_then(Value::as_str) {
            builder = builder.header("mcp-name", name);
        }
    }
    let mut request = builder
        .body(axum::body::Body::from(
            json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string(),
        ))
        .unwrap();
    if let Some(subject) = subject {
        request
            .extensions_mut()
            .insert(crate::key_server::oidc::VerifiedIdentity {
                subject: subject.to_string(),
                email: format!("{subject}@example.invalid"),
                name: None,
                groups: vec![],
                issuer: "https://a.example.invalid".to_string(),
            });
    }
    let response = fx.router.clone().oneshot(request).await.unwrap();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    String::from_utf8_lossy(&body).into_owned()
}

/// How a cell's gateway screens what it delivers.
#[derive(Clone, Copy, Debug)]
enum Setup {
    /// The firewall with no rule: a credential is high severity, so blocked.
    Default,
    /// The firewall with a Warn rule on `read`: a credential is redacted and
    /// delivered, except where a rewrite is not allowed.
    Warn,
    /// No firewall; response inspection in action mode is the only screen.
    InspectionOnly,
}

/// What one cell observed.
struct Seen {
    body: String,
    calls: usize,
    /// Firewall inspections, router and Meta-MCP instances together.
    inspections: usize,
}

/// One cell: `text` planted at `part` of `method`'s answer, sent on `route`.
async fn cell(setup: Setup, route: Route, method: &'static str, part: Part, text: String) -> Seen {
    let backend = Arc::new(Planted::with_text(method, part, text));
    let calls = Arc::clone(&backend.calls);
    let fx = match setup {
        Setup::Default => fixture_firewalled_on(backend, None).await,
        Setup::Warn => fixture_firewalled_on(backend, Some(FirewallAction::Warn)).await,
        Setup::InspectionOnly => fixture_inspecting_on(backend).await,
    };
    let firewalls = [fx.state.firewall.clone(), meta_firewall()];
    let count = || -> usize {
        let counts = firewalls.iter().flatten();
        counts
            .map(|f| f.response_inspection_counts().inspections)
            .sum()
    };
    let before = count();
    let (uri, sent, params) = request(route, method, part);
    let body = post(&fx, uri, sent, &params).await;
    Seen {
        body,
        calls: calls.load(Ordering::SeqCst),
        inspections: count() - before,
    }
}

/// A 2026-07-28 request's `_meta` declaring `elicitation`: an interim
/// question reaches the egress only for a client that said it can answer it
/// (otherwise the capability gate refuses it first, -32021).
fn answering_client() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {"elicitation": {}},
        "io.modelcontextprotocol/clientInfo": {"name": "EgressMatrix", "version": "1.0.0"}
    })
}

/// Whether a question reached the client rewritten: MIK-8155 forbids it on
/// every route (refused, or never asked, are both whole-question outcomes).
fn rewritten(body: &str) -> bool {
    body.contains("[REDACTED")
}

/// Whether the client was refused delivery, as the firewall refuses.
fn refused(body: &str) -> bool {
    body.contains("Response blocked by security firewall") || body.contains("\"code\":-32600")
}

fn report(failures: &[String]) {
    assert!(
        failures.is_empty(),
        "{} cells failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// The matrix: the credential never arrives, an interim question carrying
/// one is refused rather than rewritten, and every cell reached its backend
/// (a cell that never dispatched proves nothing).
#[tokio::test]
async fn egress_no_planted_credential_reaches_an_http_client() {
    let leak = secret();
    let mut failures = Vec::new();
    for method in BACKEND_METHODS {
        for part in Part::ALL.into_iter().filter(|p| p.applies_to(method)) {
            for route in ROUTES {
                let at = format!("{route:?} {method} {part:?}");
                let seen = cell(Setup::Default, route, method, part, leak.clone()).await;
                if seen.calls == 0 {
                    failures.push(format!("{at}: never reached the backend: {}", seen.body));
                }
                if seen.body.contains(&leak) {
                    failures.push(format!("{at}: credential delivered: {}", seen.body));
                }
                if part == Part::InterimQuestion && rewritten(&seen.body) {
                    failures.push(format!("{at}: question rewritten: {}", seen.body));
                }
            }
        }
    }
    report(&failures);
}

/// MIK-8155: under a Warn rule a completed answer is redacted and delivered,
/// while an interim question carrying a credential is still refused, never
/// rewritten, on every route: one policy per frame part.
#[tokio::test]
async fn egress_warn_redacts_an_answer_and_refuses_a_question() {
    let leak = secret();
    let mut failures = Vec::new();
    for route in ROUTES {
        let seen = cell(
            Setup::Warn,
            route,
            "tools/call",
            Part::ResultText,
            leak.clone(),
        )
        .await;
        if seen.body.contains(&leak) || !seen.body.contains("[REDACTED:credential]") {
            failures.push(format!(
                "{route:?} answer not redacted and delivered: {}",
                seen.body
            ));
        }
        // An identified caller: the gateway seals a question only for a caller
        // it can bind the continuation to, so only then does it reach delivery.
        let part = Part::InterimQuestion;
        let backend = Arc::new(Planted::new("tools/call", part));
        let fx = fixture_firewalled_on(backend, Some(FirewallAction::Warn)).await;
        let (uri, sent, params) = request(route, "tools/call", part);
        let body = post_as(&fx, (uri, sent), &params, Some("alice")).await;
        if body.contains(&leak) || rewritten(&body) || !refused(&body) {
            failures.push(format!("{route:?} question not refused whole: {body}"));
        }
    }
    report(&failures);
}

/// MIK-8146 CATSCAN.1, MIK-8139: the content inspection screens every
/// method's answer and error, not only a tool result. No firewall here, so
/// only the inspection can withhold the planted credential.
#[tokio::test]
async fn egress_content_inspection_screens_every_answer() {
    let leak = secret();
    let mut failures = Vec::new();
    for method in BACKEND_METHODS {
        for part in [Part::ResultText, Part::ErrorMessage, Part::ErrorData] {
            for route in ROUTES {
                let at = format!("{route:?} {method} {part:?}");
                let seen = cell(Setup::InspectionOnly, route, method, part, leak.clone()).await;
                if seen.calls == 0 {
                    failures.push(format!("{at}: never reached the backend: {}", seen.body));
                }
                if seen.body.contains(&leak) {
                    failures.push(format!("{at}: credential delivered: {}", seen.body));
                }
            }
        }
    }
    report(&failures);
}

/// `NFR.WORKLOAD.1`: every answer is inspected by the firewall exactly once,
/// whichever method and route delivers it.
#[tokio::test]
async fn egress_every_answer_is_inspected_once() {
    let mut failures = Vec::new();
    for method in BACKEND_METHODS {
        for route in ROUTES {
            let text = "harmless".to_string();
            let seen = cell(Setup::Default, route, method, Part::ResultText, text).await;
            if seen.inspections != 1 {
                failures.push(format!(
                    "{route:?} {method}: {} inspections",
                    seen.inspections
                ));
            }
        }
    }
    report(&failures);
}

/// Controls: harmless text at the same places is delivered, so the matrix
/// above reads frames that do reach the client. Notifications are not relayed
/// on the direct route (`backend_handlers.rs`), so their controls are meta's.
#[tokio::test]
async fn egress_harmless_text_is_delivered_unchanged() {
    let mut failures = Vec::new();
    for method in BACKEND_METHODS {
        for part in [Part::ResultText, Part::Progress, Part::CustomNote] {
            for route in ROUTES {
                if part.is_notification() && (route == Route::Direct || method != "tools/call") {
                    continue;
                }
                let text = format!("harmless-{}", method.replace('/', "-"));
                let seen = cell(Setup::Default, route, method, part, text.clone()).await;
                if !seen.body.contains(&text) {
                    failures.push(format!(
                        "{route:?} {method} {part:?}: not delivered: {}",
                        seen.body
                    ));
                }
            }
        }
    }
    report(&failures);
}

/// A meta-route answer cached under an idempotency key and replayed to the
/// direct route is scanned there too: the cache proves no provenance.
#[tokio::test]
async fn egress_a_cross_route_replay_is_scanned() {
    let leak = secret();
    let mut failures = Vec::new();
    for part in [Part::ResultText, Part::ErrorMessage] {
        let backend = Arc::new(Planted::new("tools/call", part));
        let fx = fixture_firewalled_on(backend.clone(), Some(FirewallAction::Warn)).await;
        let idem = json!({ IDEMPOTENCY_KEY_META: "egress-replay" });
        for route in [Route::Meta, Route::Direct] {
            let (uri, sent, mut params) = request(route, "tools/call", part);
            params["_meta"] = idem.clone();
            let body = post(&fx, uri, sent, &params).await;
            if body.contains(&leak) {
                failures.push(format!("{part:?} {route:?}: credential delivered: {body}"));
            }
        }
        // Else the direct call met a fresh, scanned answer, not the replay.
        let calls = backend.calls.load(std::sync::atomic::Ordering::SeqCst);
        if calls != 1 {
            failures.push(format!("{part:?}: {calls} dispatches, so nothing replayed"));
        }
    }
    report(&failures);
}

/// Completeness of the method axis: every method the `POST /mcp` dispatcher
/// serves is either a backend's answer (a matrix row) or the gateway's own.
/// A new arm in neither list fails here, so it cannot skip the matrix.
#[test]
fn egress_every_dispatched_method_is_a_matrix_row_or_gateway_own() {
    // `sampling/createMessage` relays a client's own request to a session.
    const GATEWAY_OWN: [&str; 13] = [
        "sampling/createMessage",
        "initialize",
        "server/discover",
        "ping",
        "subscriptions/listen",
        "resources/subscribe",
        "resources/unsubscribe",
        "elicitation/create",
        "tools/resolve",
        "tasks/get",
        "tasks/update",
        "tasks/cancel",
        "logging/setLevel",
    ];
    let source = include_str!("handlers.rs");
    let mut missing = Vec::new();
    for line in source.lines() {
        let arm = line.trim_start();
        if !arm.starts_with('"') || !arm.contains("=>") {
            continue;
        }
        let head = arm.split("=>").next().unwrap_or_default();
        for name in head.split('|').map(|m| m.trim().trim_matches('"')) {
            // JSON keys in audit macros (`"method" => ...`) are not methods;
            // the two slash-less methods are.
            if !name.contains('/') && !matches!(name, "initialize" | "ping") {
                continue;
            }
            if !BACKEND_METHODS.contains(&name) && !GATEWAY_OWN.contains(&name) {
                missing.push(name.to_owned());
            }
        }
    }
    assert!(
        missing.is_empty(),
        "dispatched methods outside the matrix: {missing:?}"
    );
}

/// MIK-8161: a notification verdict names the authenticated caller, bound by
/// the dispatch once it knows it, not a transport label.
#[tokio::test]
async fn egress_a_notification_verdict_names_the_authenticated_caller() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("firewall.ndjson");
    let backend = Arc::new(Planted::new("tools/call", Part::CustomNote));
    let fx = fixture_audited_on(backend, path.clone()).await;
    let (uri, sent, params) = request(Route::Meta, "tools/call", Part::CustomNote);
    let body = post(&fx, uri, sent, &params).await;
    let log = std::fs::read_to_string(&path).unwrap_or_default();
    let verdicts: Vec<Value> = log
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|entry| entry["artifact_kind"] == "notification")
        .collect();
    assert!(
        !verdicts.is_empty(),
        "no notification verdict: {log} / {body}"
    );
    for verdict in verdicts {
        assert_eq!(verdict["caller"], "k-std", "{verdict}");
    }
}

/// MIK-8131 FW.1, FW.3: a sealed question the delivery refuses gives its
/// in-flight slot back, on both routes, and only its own: an unrelated
/// exchange opened first keeps its slot.
#[tokio::test]
async fn egress_a_refused_question_frees_only_its_own_slot() {
    let mut failures = Vec::new();
    for route in ROUTES {
        let backend = Arc::new(Planted::new("tools/call", Part::InterimQuestion));
        let fx = fixture_firewalled_on(backend, None).await;
        let continuation = fx.state.meta_mcp.continuation();
        let now = crate::protocol::continuation::now_unix_secs();
        let other = continuation
            .begin_exchange(
                "other".into(),
                None,
                "fp".into(),
                &crate::protocol::continuation::QuotaKey::for_test("fp"),
                "digest".into(),
                now,
            )
            .await;
        let other = other.expect("an unrelated exchange holds a slot");
        let (uri, sent, params) = request(route, "tools/call", Part::InterimQuestion);
        let body = post_as(&fx, (uri, sent), &params, Some("alice")).await;
        if !refused(&body) {
            failures.push(format!("{route:?}: question not refused: {body}"));
        }
        let held = continuation.in_flight().len(now).await;
        if held != 1 {
            failures.push(format!(
                "{route:?}: {held} slots held, want the unrelated one"
            ));
        }
        let routing = continuation.in_flight().route(&other.hold_key, now).await;
        if routing != crate::protocol::continuation::Routing::Here {
            failures.push(format!("{route:?}: the unrelated exchange lost its slot"));
        }
    }
    report(&failures);
}

/// A key refusal lists the backend's own parameter names, which no dispatch
/// gate read: with no firewall, the content checks alone keep a
/// credential-shaped name out of it, on both routes. The harmless name is the
/// control that the refusal does list the backend's names.
#[tokio::test]
async fn egress_a_key_refusal_meets_the_content_checks() {
    let leak = secret();
    let mut failures = Vec::new();
    for route in ROUTES {
        for (name, planted) in [
            ("credential", leak.clone()),
            ("control", "harmless_key".into()),
        ] {
            let backend = Arc::new(Planted::with_text(
                "tools/call",
                Part::SchemaKey,
                planted.clone(),
            ));
            let fx = fixture_inspecting_on(backend).await;
            let (uri, sent, mut params) = request(route, "tools/call", Part::SchemaKey);
            let undeclared = json!({"undeclared_key": 1});
            match route {
                Route::Meta => params["arguments"]["arguments"] = undeclared,
                Route::Direct => params["arguments"] = undeclared,
            }
            let body = post(&fx, uri, sent, &params).await;
            let at = format!("{route:?} {name}");
            if !body.contains("undeclared_key") && !refused(&body) {
                failures.push(format!("{at}: no key refusal: {body}"));
            }
            if name == "control" && !body.contains("harmless_key") {
                failures.push(format!("{at}: refusal does not list the names: {body}"));
            }
            if name == "credential" && body.contains(&leak) {
                failures.push(format!("{at}: credential-shaped name delivered: {body}"));
            }
        }
    }
    report(&failures);
}

/// #3527 final review (a backend replaying another exchange's envelope): a
/// valid envelope stolen from another exchange, returned as an interim
/// `tools/call` answer's state, frees no slot when the answer is refused. The
/// gateway writes its own envelope over an interim answer's state, so the
/// release only ever reads the one it minted for this call.
#[tokio::test]
async fn egress_a_stolen_envelope_frees_no_other_slot() {
    let backend = Arc::new(Planted::with_text(
        "tools/call",
        Part::InterimStolenState,
        String::new(),
    ));
    let fx = fixture_firewalled_on(Arc::clone(&backend) as _, None).await;
    let continuation = fx.state.meta_mcp.continuation();
    let now = crate::protocol::continuation::now_unix_secs();
    let other = continuation
        .begin_exchange(
            "other".into(),
            None,
            "fp".into(),
            &crate::protocol::continuation::QuotaKey::for_test("fp"),
            "digest".into(),
            now,
        )
        .await
        .expect("an unrelated exchange holds a slot");
    let stolen = continuation.keyring().mint(&other).expect("its envelope");
    backend.set_text(stolen);
    let (uri, sent, params) = request(Route::Meta, "tools/call", Part::InterimQuestion);
    let body = post_as(&fx, (uri, sent), &params, Some("alice")).await;
    assert!(!body.contains(&secret()), "{body}");
    let routing = continuation.in_flight().route(&other.hold_key, now).await;
    assert_eq!(
        routing,
        crate::protocol::continuation::Routing::Here,
        "the other exchange lost its slot: {body}"
    );
}

/// The continuation-slot release matrix (MIK-8176 family).
#[path = "egress_matrix_tests/slot_release.rs"]
mod slot_release;
