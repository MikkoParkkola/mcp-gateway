// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The direct route's reach and its declared effect. A direct call names a
//! registry backend; a capability provider is no registry backend, so the
//! direct route answers its name as absent and never records a grant.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::to_bytes;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::direct_guards_fixture::{Answer, Fx, fixture_logged};
use crate::gateway::meta_mcp::grant_audit_fixture::{entries, logger};
use crate::security::audit::AuditFailurePolicy;

/// The capability provider and its personal capability.
const CAPS: &str = "caps";
const PROBE: &str = "owned_probe";
/// The certificate subject that owns the capability and holds its grant.
const OWNER: &str = "agent-a";
/// An API key the fixture configures; the identity is the certificate's.
const KEY: &str = "k-std";

/// A personal REST capability [`PROBE`], owned by mTLS subject [`OWNER`],
/// served by `port`'s `/probe`.
fn personal_probe(port: u16) -> String {
    let base_url = crate::test_fixture_host::fixture_url(port);
    format!(
        "name: {PROBE}\ndescription: Personal probe\nmetadata:\n  read_only: true\n  \
         exposure: personal\n  identity_owner:\n    authority: mtls\n    subject: '{OWNER}'\n\
         providers:\n  primary:\n    service: rest\n    config:\n      base_url: {base_url}\n      \
         path: /probe\n      method: GET\n"
    )
}

/// A client certificate whose CN is [`OWNER`], parsed by the production parser.
fn owner_cert() -> crate::mtls::CertIdentity {
    let mut params = rcgen::CertificateParams::default();
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, OWNER);
    params.distinguished_name = dn;
    let key_pair = rcgen::KeyPair::generate().expect("a key pair");
    let der = params
        .self_signed(&key_pair)
        .expect("a cert")
        .der()
        .to_vec();
    crate::mtls::CertIdentity::from_der(&der)
        .expect("parses")
        .expect("names someone")
}

/// A `tools/call` of `name` to `uri` as [`KEY`] presenting the owner's
/// certificate: the JSON answer.
async fn call(fx: &Fx, uri: &str, name: &str, arguments: Value) -> Value {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
        "name": name, "arguments": arguments,
        "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                  "io.modelcontextprotocol/clientCapabilities": {}},
    }});
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("authorization", format!("Bearer {KEY}"))
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", name)
        .body(axum::body::Body::from(body.to_string()))
        .expect("a request");
    request.extensions_mut().insert(owner_cert());
    let response = fx.router.clone().oneshot(request).await.expect("an answer");
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap_or_default();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

/// GUARD (probe): the certificate's owner holds an execute grant on its
/// personal capability, and the meta route reaches it (the control: the
/// upstream is hit once and its answer served). The same identity naming
/// the capability on the direct route reaches nothing: the upstream is not
/// hit again, nothing is served, and the direct route's records name no
/// grant and record no declared effect.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn probe_direct_reaches_the_capability_backend() {
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a listener");
    let port = listener.local_addr().expect("its address").port();
    tokio::spawn(async move {
        let app = axum::Router::new().route(
            "/probe",
            axum::routing::get(move || {
                let n = counter.fetch_add(1, Ordering::SeqCst) + 1;
                async move { axum::Json(json!({"answer": format!("served-{n}")})) }
            }),
        );
        drop(axum::serve(listener, app).await);
    });
    let caps_dir = tempfile::tempdir().expect("a capability directory");
    std::fs::write(
        caps_dir.path().join(format!("{PROBE}.yaml")),
        personal_probe(port),
    )
    .expect("the capability writes");
    let executor = crate::capability::CapabilityExecutor::new().with_test_http_client(
        crate::test_fixture_host::fixture_client_builder()
            .build()
            .expect("a client"),
    );
    let caps = Arc::new(crate::capability::CapabilityBackend::new(
        CAPS,
        Arc::new(executor),
    ));
    caps.load_from_directory(caps_dir.path().to_str().expect("a utf-8 path"))
        .await
        .expect("the capability loads");
    let subject = crate::identity_grants::GrantSubject::for_test("mtls", OWNER, None);
    let grants = crate::identity_grants::LocalIdentityGrantStore::from_grants(vec![
        crate::identity_grants::IdentityGrant {
            grant_id: "g-direct-probe".to_owned(),
            subject: subject.clone(),
            agent: crate::identity_grants::GrantAgent::Any,
            capability: PROBE.to_owned(),
            tool: None,
            scope: crate::identity_grants::GrantScope::Execute,
            owner: Some(subject),
            expires_at: None,
            revoked_at: None,
            provenance: "test".to_owned(),
            reason: "direct-route probe".to_owned(),
        },
    ]);
    let log_dir = tempfile::tempdir().expect("a log directory");
    let log = logger(&log_dir, AuditFailurePolicy::FailClosed);
    let fx = fixture_logged(Answer::Ok, Arc::clone(&log), |mut meta| {
        meta.enable_transparency_log(log);
        meta.set_capabilities(caps);
        meta.set_identity_grants(grants);
        meta
    })
    .await;

    let control = call(
        &fx,
        "/mcp",
        "gateway_invoke",
        json!({"server": CAPS, "tool": PROBE, "arguments": {}}),
    )
    .await;
    assert!(
        control.to_string().contains("served-1"),
        "premise: the owner reaches the capability on the meta route: {control}"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 1, "premise: one upstream hit");
    let before = entries(&log_dir).len();

    let direct = call(&fx, &format!("/mcp/{CAPS}"), PROBE, json!({})).await;
    eprintln!("PROBE direct /mcp/{CAPS} {PROBE}: {direct}");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "the direct call reached the capability: {direct}"
    );
    let text = direct.to_string();
    assert!(
        !text.contains("served-"),
        "the direct call was served: {text}"
    );
    let after = entries(&log_dir).split_off(before);
    let records = serde_json::to_string(&after).expect("entries serialise");
    assert!(
        !records.contains("g-direct-probe") && !records.contains("grant_id"),
        "a direct record names a grant: {records}"
    );
    assert!(
        !records.contains("declared_effect") && !records.contains("capability_definition"),
        "the direct answer recorded an effect: {records}"
    );
}
