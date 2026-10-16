// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8382 CONTROL rows F1 and D5 (design d2 §4.1, §7 drift guard): a
//! keyed caller that admission gives an execution principal is never
//! refused at intake. One cell per principal source admission reads
//! (`owner.principal()`, then `credential_or_subject_owner`), on both
//! routes. Green at the base. What the cells kill after the fix: dropping
//! `owner.principal()` from the intake's principal function fails the OIDC
//! and trusted-proxy cells, the only ones with no other source; dropping
//! `credential_or_subject_owner` fails the mTLS cell (owner empty with no
//! credential) and D5. The auth-off agent, credential and auth-on agent
//! cells carry both sources, so they guard that both still agree, not one
//! source alone. The exact principal value is A5's (stage 2, beside the
//! shared function).

use super::*;

/// One principal source: label, fixture, headers and the extensions the
/// request carries.
struct Source {
    label: &'static str,
    setup: fn() -> Setup,
    headers: &'static [(&'static str, &'static str)],
    caller: Caller,
    proxied: bool,
}

/// Auth on with one key, `/mcp` and `/mcp/{name}` public: a caller may
/// arrive with no credential, as behind an mTLS or agent-token front door.
fn auth_public_mcp() -> AuthConfig {
    AuthConfig {
        public_paths: vec!["/mcp".to_string()],
        ..key_for_alpha(None)
    }
}

fn trusted_proxy() -> Setup {
    Setup {
        caller_identity: Some(crate::security::caller_identity::CallerIdentityConfig {
            mode: crate::security::caller_identity::CallerIdentityMode::TrustedProxy,
            trusted_proxies: vec!["10.0.0.5".parse().expect("a literal IP parses")],
            authority: "corp-sso".to_string(),
            ..crate::security::caller_identity::CallerIdentityConfig::default()
        }),
        ..idempotent()
    }
}

fn keyed_auth() -> Setup {
    Setup {
        auth: Some(key_for_alpha(None)),
        ..idempotent()
    }
}

fn public_auth() -> Setup {
    Setup {
        auth: Some(auth_public_mcp()),
        ..idempotent()
    }
}

fn sources() -> [Source; 6] {
    [
        Source {
            label: "verified identity",
            setup: idempotent,
            headers: &[],
            caller: Caller::Oidc,
            proxied: false,
        },
        Source {
            label: "routed owner, auth-off trusted-proxy subject",
            setup: trusted_proxy,
            headers: &[("x-gateway-identity-subject", "alice")],
            caller: Caller::Anonymous,
            proxied: true,
        },
        Source {
            label: "routed agent owner, auth off",
            setup: idempotent,
            headers: &[],
            caller: Caller::Agent,
            proxied: false,
        },
        Source {
            label: "credential",
            setup: keyed_auth,
            headers: &[("authorization", "Bearer k")],
            caller: Caller::Anonymous,
            proxied: false,
        },
        Source {
            label: "mtls subject, no credential",
            setup: public_auth,
            headers: &[],
            caller: Caller::Cert,
            proxied: false,
        },
        Source {
            label: "agent_oauth subject, no credential",
            setup: public_auth,
            headers: &[],
            caller: Caller::Agent,
            proxied: false,
        },
    ]
}

/// A modern keyed `tools/call` of `name` with `arguments`, key `key`.
fn modern_keyed(name: &str, arguments: &Value, key: &str, extra: Option<Value>) -> Value {
    let mut meta = json!({
        (crate::protocol::mrtr::IDEMPOTENCY_KEY_META): key,
        "io.modelcontextprotocol/protocolVersion": crate::protocol::meta::MODERN_VERSIONS[0],
        "io.modelcontextprotocol/clientCapabilities": {},
    });
    if let Some(capabilities) = extra {
        meta["io.modelcontextprotocol/clientCapabilities"] = capabilities;
    }
    json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
        "params": {"name": name, "arguments": arguments, "_meta": meta}})
}

/// POST `body` to `uri` as `source`, with the modern mirrored headers.
async fn send(fx: &Fixture, uri: &str, body: &Value, source: &Source) -> (StatusCode, Value) {
    let name = body["params"]["name"].as_str().unwrap_or_default();
    let mut builder = axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header(
            "mcp-protocol-version",
            crate::protocol::meta::MODERN_VERSIONS[0],
        )
        .header("mcp-method", "tools/call")
        .header("mcp-name", name);
    for (header, value) in source.headers {
        builder = builder.header(*header, *value);
    }
    let mut request = builder
        .body(axum::body::Body::from(body.to_string()))
        .expect("a static request builds");
    if matches!(source.caller, Caller::Oidc) {
        request.extensions_mut().insert(VerifiedIdentity {
            subject: "1".to_string(),
            email: "one@example.invalid".to_string(),
            name: None,
            groups: vec![],
            issuer: "https://a.example.invalid".to_string(),
        });
    }
    insert_identity(&mut request, &source.caller);
    if source.proxied {
        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                [10, 0, 0, 5],
                4000,
            ))));
    }
    let response = fx
        .router
        .clone()
        .oneshot(request)
        .await
        .expect("the router is infallible");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("an in-memory body reads");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// F1 CONTROL (UNIFY.1a′ drift guard): for every principal source, a keyed
/// call on the direct route and on `/mcp` is admitted and runs once (HTTP
/// 200, a result that is not an error), and the same key again replays the
/// same result without a second dispatch (admission owned the key under that
/// caller). Every cell runs; failures are listed together.
#[tokio::test]
async fn f1_every_principal_source_is_admitted_keyed() {
    let mut wrong = Vec::new();
    for source in sources() {
        for (route, uri, body) in [
            (
                "direct",
                "/mcp/alpha",
                modern_keyed("t", &json!({"customer_id": "c"}), "f1-k", None),
            ),
            (
                "meta",
                "/mcp",
                modern_keyed(
                    "gateway_invoke",
                    &json!({"server": "alpha", "tool": "t", "arguments": {"customer_id": "c"}}),
                    "f1-k",
                    None,
                ),
            ),
        ] {
            let fx = fixture((source.setup)()).await;
            let (first_status, first) = send(&fx, uri, &body, &source).await;
            let after_first = fx.calls.load(Ordering::SeqCst);
            let (again_status, again) = send(&fx, uri, &body, &source).await;
            let after_again = fx.calls.load(Ordering::SeqCst);
            // Both answers are 200 successes with a result, the replay is the
            // same result, and exactly one dispatch happened, after each.
            let succeeded = |status: StatusCode, answer: &Value| {
                status == StatusCode::OK
                    && answer.get("error").is_none()
                    && answer.pointer("/result/isError") == Some(&json!(false))
            };
            if !succeeded(first_status, &first)
                || !succeeded(again_status, &again)
                || first.get("result") != again.get("result")
                || (after_first, after_again) != (1, 1)
            {
                wrong.push(format!(
                    "{} {route}: {first_status} {first} / again {again_status} {again} \
                     / calls {after_first}, {after_again}",
                    source.label
                ));
            }
        }
    }
    assert!(wrong.is_empty(), "f1 not admitted:\n{}", wrong.join("\n"));
}

/// D5 CONTROL: auth on, a caller with a proven mTLS subject and no
/// credential sends a keyed task submit. Admission gives it a principal (its
/// keyed sync call runs: the F1 `mtls` cell), so the intake check passes it
/// and today's answer stays: the missing-task answer (`task_route.rs`
/// `missing_task_error`, 200, -32602 "no such task", as
/// `tests/e2e_task_api_key_owner.rs` pins for a keyed create with no
/// credential), not -32003, and no task is created. Design d2 §4.1 expected
/// the -32600 task gate; the base answers this.
#[tokio::test]
async fn d5_mtls_subject_task_submit_is_not_refused_at_intake() {
    let fx = fixture(public_auth()).await;
    let source = sources()
        .into_iter()
        .find(|source| source.label == "mtls subject, no credential")
        .expect("F1 lists the mTLS source");
    let source = &source;
    let mut body = modern_keyed(
        "gateway_invoke",
        &json!({"server": "alpha", "tool": "t", "arguments": {"customer_id": "c"}}),
        "d5-k",
        Some(json!({"extensions": {"io.modelcontextprotocol/tasks": {}}})),
    );
    body["params"]["task"] = json!({});
    let (status, answer) = send(&fx, "/mcp", &body, source).await;
    assert_eq!(status, StatusCode::OK, "d5: {answer}");
    assert!(
        answer.pointer("/result/taskId").is_none(),
        "d5: a task was created: {answer}"
    );
    assert_eq!(
        refusal(&answer),
        (Some(-32602), "no such task"),
        "d5: {status} {answer}"
    );
    assert_eq!(fx.calls.load(Ordering::SeqCst), 0, "d5: dispatched");
}
