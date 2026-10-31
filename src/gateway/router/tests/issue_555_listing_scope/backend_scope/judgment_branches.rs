// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Branches of the hiding judgment the request rows do not reach on their
//! own: a profile that leaves a backend out, agent auth with no agent on a
//! held catalogue, and a grant that refuses the backend first.

use std::collections::HashMap;

use super::*;
use crate::gateway::auth::{AuthenticatedClient, anonymous_client};
use crate::gateway::meta_mcp::hiding::ListedCatalogue;
use crate::gateway::record_principal::InternalPrincipal;
use crate::gateway::router::OwnedRouterAuthorizer;
use crate::gateway::router::caller_hiding::RouterHiding;
use crate::routing_profile::{ProfileRegistry, RoutingProfileConfig};

/// A session profile that leaves `alpha` out hides it from a caller whose
/// policy admits its tools, and the listing leaves it out too.
#[tokio::test]
async fn a_backend_the_profile_leaves_out_is_hidden() {
    let profiles = HashMap::from([(
        "narrow".to_string(),
        RoutingProfileConfig {
            deny_backends: Some(vec!["alpha".to_string()]),
            ..Default::default()
        },
    )]);
    let (router, state) = with_mtls_tuned(
        Auth::Off,
        move |meta| meta.with_profile_registry(ProfileRegistry::from_config(&profiles, "narrow")),
        (&["*"], &["*"]),
        (&[], &[]),
    )
    .await;
    let hiding = judgment(&state, None, Some(&agent_cert()));
    assert!(hiding.hides("alpha"), "the profile's left-out backend");
    assert!(!hiding.hides("beta"), "a backend the profile keeps");
    let (_, body) = post_as_agent_cert(
        &router,
        "/mcp",
        json!({ "name": "gateway_list_servers", "arguments": {} }),
    )
    .await;
    let listed = server_names(&serde_json::from_str(&body).expect("json"));
    assert!(
        !listed.iter().any(|n| n == "alpha") && listed.iter().any(|n| n == "beta"),
        "listed and not hidden disagree: {listed:?}"
    );
}

/// Agent auth with no validated agent admits no backend, so a held
/// catalogue's backend is hidden; an unregistered name is a miss already.
#[tokio::test]
async fn agent_auth_with_no_agent_hides_a_held_backend() {
    let f = with_agent_auth(Arc::new(crate::gateway::oauth::AgentRegistry::new())).await;
    assert!(
        matches!(
            f.state.meta_mcp.listed_catalogue("alpha"),
            ListedCatalogue::Tools { .. }
        ),
        "premise: alpha's catalogue is held"
    );
    let hiding = judgment(&f.state, None, None);
    assert!(hiding.hides("alpha"), "a held backend with no agent");
    assert!(!hiding.hides("no-such-backend"), "an unregistered name");
}

/// A grant that refuses the backend answers first, so the judgment does not
/// hide it: the grant's own refusal stands. With a grant on it, the same
/// certificate's rule hides it.
#[tokio::test]
async fn a_grant_refusal_is_the_grants_answer_not_a_hiding() {
    let (_, state) = with_mtls_state((&["*"], &["*"]), (&["beta"], &[])).await;
    let hides_beta = |backends: &str| {
        // An anonymous caller limited by its grant: it presented no secret.
        let client = AuthenticatedClient {
            principal: InternalPrincipal::new(String::new()),
            backends: vec![backends.to_string()],
            ..anonymous_client()
        };
        RouterHiding::caller(
            Arc::clone(&state),
            OwnedRouterAuthorizer::capture(Some(&client), None, Some(&agent_cert())),
            None,
            None,
        )
        .hides("beta")
    };
    assert!(!hides_beta("alpha"), "a grant without beta");
    assert!(hides_beta("*"), "control: a grant on beta");
}

/// Profiles `open` (admits all) and `narrow` (leaves `alpha` out), the
/// default being `default`.
fn session_profiles(default: &str) -> ProfileRegistry {
    let profiles = HashMap::from([
        ("open".to_string(), RoutingProfileConfig::default()),
        (
            "narrow".to_string(),
            RoutingProfileConfig {
                deny_backends: Some(vec!["alpha".to_string()]),
                ..Default::default()
            },
        ),
    ]);
    ProfileRegistry::from_config(&profiles, default)
}

/// The per-backend route, the default profile `default`, a session `u1`
/// owns running `session_profile`: the router and the session's id.
async fn direct_under_session(default: &str, session_profile: &str) -> (axum::Router, String) {
    let registry = session_profiles(default);
    let (router, state) = with_mtls_tuned(
        Auth::Keys,
        move |meta| meta.with_profile_registry(registry),
        (&["*"], &["*"]),
        (&[], &[]),
    )
    .await;
    // The session a legacy request from this same caller (key and
    // certificate) is given, so the route counts it as the caller's own.
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("authorization", "Bearer u1")
        .body(axum::body::Body::from(
            json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" }).to_string(),
        ))
        .expect("request");
    request.extensions_mut().insert(agent_cert());
    let response = router.clone().oneshot(request).await.expect("answers");
    let session = response
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .expect("a legacy request is given a session")
        .to_owned();
    state
        .meta_mcp
        .session_profiles()
        .set_profile(&session, session_profile);
    (router, session)
}

/// A per-backend call judges hiding under the caller's own session profile,
/// as it routes: a backend the session admits is served though the default
/// profile leaves it out, and one the session leaves out answers as an
/// unregistered name though the default admits it.
#[tokio::test]
async fn a_direct_call_hides_by_its_session_profile() {
    let call = json!({ "name": "alpha_read", "arguments": {} });
    let (router, session) = direct_under_session("narrow", "open").await;
    let headers = [("mcp-session-id", session.as_str())];
    let (status, body) =
        post_cert_headers(&router, "/mcp/alpha", Some("u1"), call.clone(), &headers).await;
    assert!(
        status == 200 && !body.contains("Backend not found"),
        "a backend the session admits was refused: {status} {body}"
    );

    let (router, session) = direct_under_session("open", "narrow").await;
    let headers = [("mcp-session-id", session.as_str())];
    let hidden = post_cert_headers(&router, "/mcp/alpha", Some("u1"), call.clone(), &headers).await;
    let unregistered = post_cert_headers(
        &router,
        &format!("/mcp/{UNREGISTERED}"),
        Some("u1"),
        call,
        &headers,
    )
    .await;
    assert_alike(
        "per-backend route, session profile",
        "alpha",
        &hidden,
        &unregistered,
    );
}

/// The provider `caps` with `cap_open` and `cap_callback`, an admin-only
/// capability (it registers a caller-addressed callback).
async fn caps_with_callback() -> (Arc<crate::capability::CapabilityBackend>, tempfile::TempDir) {
    let dir = tempfile::TempDir::new().expect("capability dir");
    let files = [
        ("cap_open", ""),
        ("cap_callback", "  registers_external_callback: true\n"),
    ];
    for (name, extra) in files {
        std::fs::write(
            dir.path().join(format!("{name}.yaml")),
            super::super::capability_yaml(name, extra),
        )
        .expect("write capability");
    }
    let backend = Arc::new(crate::capability::CapabilityBackend::new(
        "caps",
        Arc::new(crate::capability::CapabilityExecutor::new()),
    ));
    let loaded = backend
        .load_from_directory(dir.path().to_str().expect("utf-8 path"))
        .await
        .expect("load capabilities");
    assert_eq!(loaded, 2, "both capabilities load");
    (backend, dir)
}

/// A provider the default profile leaves out, for a certificate whose rule
/// admits everything: hidden, with nothing refusing it before the route
/// stage. `tool` on it must answer as on an unregistered name.
async fn assert_profile_hidden_provider_alike(tool: &str) {
    let profiles = HashMap::from([(
        "nocaps".to_string(),
        RoutingProfileConfig {
            deny_backends: Some(vec!["caps".to_string()]),
            ..Default::default()
        },
    )]);
    let (router, state) = with_mtls_tuned(
        Auth::Off,
        move |meta| meta.with_profile_registry(ProfileRegistry::from_config(&profiles, "nocaps")),
        (&["*"], &["*"]),
        (&[], &[]),
    )
    .await;
    let (caps, _dir) = caps_with_callback().await;
    state.meta_mcp.set_capabilities(caps);
    assert!(
        judgment(&state, None, Some(&agent_cert())).hides("caps"),
        "premise: the profile hides the provider"
    );
    let hidden = post_as_agent_cert(&router, "/mcp", invoke("caps", tool)).await;
    let unregistered = post_as_agent_cert(&router, "/mcp", invoke(UNREGISTERED, tool)).await;
    assert_alike(tool, "caps", &hidden, &unregistered);
}

/// The profile-withheld capability answer reads the caller's view: a hidden
/// provider's capability is not "defined" for this caller.
#[tokio::test]
async fn a_profile_hidden_providers_capability_answers_as_an_unregistered_name() {
    assert_profile_hidden_provider_alike("cap_open").await;
}

/// The admin-only capability rule reads the caller's view: a hidden
/// provider's admin-only capability is not refused as one.
#[tokio::test]
async fn a_profile_hidden_providers_admin_capability_answers_as_an_unregistered_name() {
    assert_profile_hidden_provider_alike("cap_callback").await;
}

/// A profile's backend deny refuses every tool by name, so it hides a warm
/// and a cold backend alike: the call answers as an unregistered name, not with the
/// profile's refusal.
#[tokio::test]
async fn a_cold_backend_the_profile_leaves_out_answers_as_an_unregistered_name() {
    let profiles = HashMap::from([(
        "nobeta".to_string(),
        RoutingProfileConfig {
            deny_backends: Some(vec!["beta".to_string()]),
            ..Default::default()
        },
    )]);
    let (router, state) = with_mtls_tuned(
        Auth::Off,
        move |meta| meta.with_profile_registry(ProfileRegistry::from_config(&profiles, "nobeta")),
        (&["*"], &["*"]),
        (&[], &[]),
    )
    .await;
    // Warm first: the profile's deny hides a held catalogue as before.
    for (stage, cold) in [("warm, profile deny", false), ("cold, profile deny", true)] {
        if cold {
            go_cold(&state, "beta");
        }
        assert!(
            judgment(&state, None, Some(&agent_cert())).hides("beta"),
            "{stage}: not hidden"
        );
        let hidden = post_as_agent_cert(&router, "/mcp", invoke("beta", "beta_tool")).await;
        let unregistered =
            post_as_agent_cert(&router, "/mcp", invoke(UNREGISTERED, "beta_tool")).await;
        assert_alike(stage, "beta", &hidden, &unregistered);
    }
}

/// Profiles with the default `nobeta`, which leaves `beta` out, and `open`.
fn nobeta_profiles() -> ProfileRegistry {
    let profiles = HashMap::from([
        ("open".to_string(), RoutingProfileConfig::default()),
        (
            "nobeta".to_string(),
            RoutingProfileConfig {
                deny_backends: Some(vec!["beta".to_string()]),
                ..Default::default()
            },
        ),
    ]);
    ProfileRegistry::from_config(&profiles, "nobeta")
}

/// Control: a caller hiding does not apply to (no mTLS policy, no agent
/// auth) keeps today's answer for a backend its profile leaves out.
#[tokio::test]
async fn outside_hiding_the_profile_refusal_stands() {
    let f = super::super::fixture_with(Auth::Off, |meta| {
        meta.with_profile_registry(nobeta_profiles())
    })
    .await;
    let (status, body) = post(
        &f.router,
        "/mcp",
        None,
        "tools/call",
        invoke("beta", "beta_tool"),
    )
    .await;
    // Today's answer: a profile-withheld name answers as a tool the backend
    // does not list, naming the tool, never the profile.
    let inner = serde_json::to_string_pretty(&json!({
        "content": [{ "text": "the backend does not list a tool named `beta_tool`", "type": "text" }],
        "isError": true,
    }))
    .expect("json");
    assert_eq!(
        (status.as_u16(), body),
        (
            200,
            json!({ "id": 5, "jsonrpc": "2.0",
                    "result": { "content": [{ "text": inner, "type": "text" }], "isError": true } })
        )
    );
}

/// Control: under mTLS, a backend the profile admits answers exactly as with
/// no routing profile at all, warm and cold.
#[tokio::test]
async fn a_backend_the_profile_admits_answers_as_without_a_profile() {
    let allowing = || {
        HashMap::from([(
            "open".to_string(),
            RoutingProfileConfig {
                deny_backends: Some(vec!["beta".to_string()]),
                ..Default::default()
            },
        )])
    };
    let (with_profile, profiled) = with_mtls_tuned(
        Auth::Off,
        move |meta| meta.with_profile_registry(ProfileRegistry::from_config(&allowing(), "open")),
        (&["*"], &["*"]),
        (&[], &[]),
    )
    .await;
    let (without_profile, plain) = with_mtls_state((&["*"], &["*"]), (&[], &[])).await;
    let trace = regex::Regex::new(r"gw-[0-9a-f-]{36}").expect("pattern");
    for cold in [false, true] {
        if cold {
            go_cold(&profiled, "alpha");
            go_cold(&plain, "alpha");
        }
        let call = invoke("alpha", "alpha_read");
        let a = post_as_agent_cert(&with_profile, "/mcp", call.clone()).await;
        let b = post_as_agent_cert(&without_profile, "/mcp", call).await;
        assert_eq!(
            (a.0, trace.replace_all(&a.1, "gw-ID").into_owned()),
            (b.0, trace.replace_all(&b.1, "gw-ID").into_owned()),
            "cold {cold}: an admitted backend's answer changed"
        );
    }
}

/// `beta` and the provider `caps` under a default profile leaving both out,
/// for a certificate whose rule admits everything; `beta`'s upstream swapped
/// for one that records each call, and `caps` counting its executions: the
/// router, the state, the recorder and the provider.
async fn hidden_recorded() -> (
    axum::Router,
    Arc<crate::gateway::router::AppState>,
    Arc<super::super::Upstream>,
    (Arc<crate::capability::CapabilityBackend>, tempfile::TempDir),
) {
    let profiles = HashMap::from([(
        "neither".to_string(),
        RoutingProfileConfig {
            deny_backends: Some(vec!["beta".to_string(), "caps".to_string()]),
            ..Default::default()
        },
    )]);
    let (router, state) = with_mtls_tuned(
        Auth::Off,
        move |meta| meta.with_profile_registry(ProfileRegistry::from_config(&profiles, "neither")),
        (&["*"], &["*"]),
        (&[], &[]),
    )
    .await;
    let upstream = Arc::new(super::super::Upstream {
        tools: vec!["beta_tool"],
        calls: parking_lot::Mutex::new(Vec::new()),
    });
    backend(&state, "beta")
        .set_transport_for_test(Arc::clone(&upstream) as Arc<dyn crate::transport::Transport>);
    let caps = caps_with_callback().await;
    state.meta_mcp.set_capabilities(Arc::clone(&caps.0));
    (router, state, upstream, caps)
}

/// A backend or provider the profile hides is refused at the profile stage
/// with the unregistered name's answer, never let through: on `/mcp` (the
/// invoke policy and the named-target admission) and on the per-backend route
/// (its profile refusal and the same admission), warm and cold, nothing is
/// sent to `beta` and no capability runs.
#[tokio::test]
async fn a_profile_hidden_backend_is_sent_nothing_on_either_route() {
    for cold in [false, true] {
        let (router, state, upstream, _caps) = hidden_recorded().await;
        if cold {
            go_cold(&state, "beta");
        }
        for (name, tool) in [("beta", "beta_tool"), ("caps", "cap_open")] {
            let call = json!({ "name": tool, "arguments": {} });
            let cases = [
                (
                    "/mcp",
                    "/mcp".to_string(),
                    invoke(name, tool),
                    invoke(UNREGISTERED, tool),
                ),
                (
                    "per-backend route",
                    format!("/mcp/{name}"),
                    call.clone(),
                    call,
                ),
            ];
            for (route, uri, params, twin) in cases {
                let before = executed();
                let hidden = post_cert_key(&router, &uri, None, params).await;
                assert_eq!(
                    executed(),
                    before,
                    "{route} {name}, cold {cold}: a hidden capability ran: {}",
                    hidden.1
                );
                let twin_uri = if route == "/mcp" {
                    uri
                } else {
                    format!("/mcp/{UNREGISTERED}")
                };
                let unregistered = post_cert_key(&router, &twin_uri, None, twin).await;
                assert_alike(
                    &format!("{route} {name}, cold {cold}"),
                    name,
                    &hidden,
                    &unregistered,
                );
            }
        }
        let sent = upstream.calls.lock().clone();
        assert!(
            sent.is_empty(),
            "cold {cold}: the hidden backend was sent {sent:?}"
        );
    }
}

/// The executions counted on this test's thread so far.
fn executed() -> usize {
    crate::capability::CapabilityBackend::executed_for_test()
}

/// A modern task submit of `gateway_invoke` on `server`'s `tool`, keyed by
/// `key`; returns the task id.
async fn submit_task(router: &axum::Router, server: &str, tool: &str, key: &str) -> String {
    let mut meta = crate::gateway::router::tests::modern_meta();
    meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!(key);
    let params = json!({"name": "gateway_invoke",
                        "arguments": {"server": server, "tool": tool, "arguments": {}},
                        "task": {}, "_meta": meta});
    let headers = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "tools/call"),
        ("mcp-name", "gateway_invoke"),
    ];
    let (_, body) = post_cert_headers(router, "/mcp", None, params, &headers).await;
    let body: Value = serde_json::from_str(&body).expect("json");
    body.pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("the submit was refused: {body}"))
        .to_owned()
}

/// Poll `tasks/get` for `id` until it is no longer working.
async fn settle_task(router: &axum::Router, id: &str) -> Value {
    let headers = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "tasks/get"),
        ("mcp-name", id),
    ];
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            let params =
                json!({"taskId": id, "_meta": crate::gateway::router::tests::modern_meta()});
            let (_, body) = post_rpc_cert_headers(router, "tasks/get", params, &headers).await;
            let body: Value = serde_json::from_str(&body).expect("json");
            if body.pointer("/result/status").and_then(Value::as_str) != Some("working") {
                return body;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the task never settled")
}

/// `method` with `params` on `/mcp` as the `agent` certificate, with extra
/// request `headers`.
async fn post_rpc_cert_headers(
    router: &axum::Router,
    method: &str,
    params: Value,
    headers: &[(&str, &str)],
) -> (u16, String) {
    let mut builder = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let mut request = builder
        .body(axum::body::Body::from(
            json!({ "jsonrpc": "2.0", "id": 6, "method": method, "params": params }).to_string(),
        ))
        .expect("request");
    request.extensions_mut().insert(agent_cert());
    let response = router.clone().oneshot(request).await.expect("answers");
    let status = response.status().as_u16();
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    (status, String::from_utf8_lossy(&body).into_owned())
}

/// Control for the zero-execution row's counts: a provider the caller sees is
/// executed, and counted on this test's thread, exactly once per call on each
/// route that can run it, and a visible backend is sent once on the
/// per-backend route. A route that read 0 here would make that row's zero
/// vacuous.
#[tokio::test]
async fn the_execution_count_sees_a_visible_capability_on_every_route() {
    let (router, state) = with_mtls_state((&["*"], &["*"]), (&[], &[])).await;
    let (caps, _dir) = caps_with_callback().await;
    state.meta_mcp.set_capabilities(caps);
    // Every route's count is recorded, then judged together, so one route's
    // miss cannot hide another's.
    let mut seen = executed();
    let mut counted = Vec::new();
    let mut once = |route: &str, answer: &str| {
        let now = executed();
        counted.push((
            route.to_string(),
            now - seen,
            answer.chars().take(300).collect::<String>(),
        ));
        seen = now;
    };
    let (_, answer) = post_as_agent_cert(&router, "/mcp", invoke("caps", "cap_open")).await;
    once("/mcp gateway_invoke", &answer);
    let chain = json!({"name": "gateway_execute", "arguments": {"chain": [
        {"tool": "caps:cap_open", "arguments": {}}
    ]}});
    let (_, answer) = post_as_agent_cert(&router, "/mcp", chain).await;
    once("gateway_execute chain step", &answer);
    // The per-backend route serves registry backends only (it resolves through
    // `backend_choke::backend_for`), never the capability provider: it is
    // proven live with an MCP backend's recorded sends instead.
    let upstream = Arc::new(super::super::Upstream {
        tools: vec!["beta_tool"],
        calls: parking_lot::Mutex::new(Vec::new()),
    });
    backend(&state, "beta")
        .set_transport_for_test(Arc::clone(&upstream) as Arc<dyn crate::transport::Transport>);
    let (_, answer) = post_cert_key(
        &router,
        "/mcp/beta",
        None,
        json!({"name": "beta_tool", "arguments": {}}),
    )
    .await;
    assert_eq!(
        upstream.calls.lock().len(),
        1,
        "per-backend route: a visible backend was not sent once: {answer}"
    );
    let id = submit_task(&router, "caps", "cap_open", "count-control").await;
    let settled = settle_task(&router, &id).await;
    once("task run", &settled.to_string());
    let wrong: Vec<_> = counted.iter().filter(|(_, n, _)| *n != 1).collect();
    assert!(
        wrong.is_empty(),
        "routes not counted exactly once: {wrong:#?}"
    );
}

/// Search lists no tool of a provider the caller's rule hides by name (its
/// allow list leaves `caps` out), as it lists none of an unregistered name.
#[tokio::test]
async fn search_lists_no_tool_of_a_hidden_provider() {
    let (router, state) = with_mtls_state((&["alpha", "beta"], &["*"]), (&[], &[])).await;
    let (caps, _dir) = caps_with_callback().await;
    state.meta_mcp.set_capabilities(caps);
    assert!(
        judgment(&state, None, Some(&agent_cert())).hides("caps"),
        "premise: the rule hides the provider"
    );
    for query in ["cap", "cap_open", "callback"] {
        let (_, body) = post_as_agent_cert(
            &router,
            "/mcp",
            json!({ "name": "gateway_search", "arguments": { "query": query } }),
        )
        .await;
        // The matches only: the answer also echoes the query.
        let matches = payload(&serde_json::from_str(&body).expect("json"))["matches"].clone();
        let named: Vec<String> = matches
            .as_array()
            .unwrap_or_else(|| panic!("matches array: {body}"))
            .iter()
            .filter_map(|m| {
                m["tool"]
                    .as_str()
                    .or_else(|| m["name"].as_str())
                    .map(str::to_string)
            })
            .collect();
        for name in ["cap_open", "cap_callback"] {
            assert!(
                !named.iter().any(|n| n.contains(name)),
                "search for {query:?} lists the hidden provider's {name}: {body}"
            );
        }
    }
}

/// Control for the search pin: with the provider visible, the same searches
/// list its tools, so an empty result for a hidden one is not an empty index
/// or a query that never matched.
#[tokio::test]
async fn search_lists_a_visible_providers_tools() {
    let (router, state) = with_mtls_state((&["*"], &["*"]), (&[], &[])).await;
    let (caps, _dir) = caps_with_callback().await;
    state.meta_mcp.set_capabilities(caps);
    for (query, expected) in [("cap_open", "cap_open"), ("callback", "cap_callback")] {
        let (_, body) = post_as_agent_cert(
            &router,
            "/mcp",
            json!({ "name": "gateway_search", "arguments": { "query": query } }),
        )
        .await;
        let matches = payload(&serde_json::from_str(&body).expect("json"))["matches"].clone();
        let named: Vec<String> = matches
            .as_array()
            .unwrap_or_else(|| panic!("matches array: {body}"))
            .iter()
            .filter_map(|m| {
                m["tool"]
                    .as_str()
                    .or_else(|| m["name"].as_str())
                    .map(str::to_string)
            })
            .collect();
        assert!(
            named.iter().any(|n| n.contains(expected)),
            "search for {query:?} does not list the visible provider's {expected}: {body}"
        );
    }
}
