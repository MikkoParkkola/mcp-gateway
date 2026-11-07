// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Allows on the owner's personal capability over `/mcp`: a matched grant
//! ranks below a firewall rule that softened a block, and above every other
//! allow. The owner calls with its certificate and the fixture key.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{Value, json};

use super::super::rule_ids::firewall_id;
use super::super::{Answer, Logged, fixture, injected, invocations};
use crate::gateway::router::direct_effect_tests::{CAPS, PROBE, owner_cert, personal_probe};
use crate::identity_grants::{GrantAgent, GrantScope, GrantSubject, IdentityGrant};
use crate::security::firewall::{FirewallAction, FirewallRule, ScanType};
use crate::security::rule_id::RuleId;

/// The capability fixture and its upstream's hit count.
pub(super) struct Owned {
    pub(super) fx: Logged,
    pub(super) hits: Arc<AtomicUsize>,
}

/// An execute grant `grant_id` for the certificate owner on [`PROBE`].
pub(super) fn owner_grant(grant_id: &str) -> IdentityGrant {
    let subject = GrantSubject::for_test("mtls", "agent-a", None);
    IdentityGrant {
        grant_id: grant_id.to_owned(),
        subject: subject.clone(),
        agent: GrantAgent::Any,
        capability: PROBE.to_owned(),
        tool: None,
        scope: GrantScope::Execute,
        owner: Some(subject),
        expires_at: None,
        revoked_at: None,
        provenance: "test".to_owned(),
        reason: format!("allow attribution {grant_id}"),
    }
}

/// The firewalled fixture serving the owner's personal [`PROBE`] under
/// [`CAPS`], with `rows` as grants keyed under the gateway's rule key.
pub(super) async fn owned(rows: Vec<IdentityGrant>) -> Owned {
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
                counter.fetch_add(1, Ordering::SeqCst);
                async move { axum::Json(json!({"answer": "served"})) }
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
    let fx = fixture(Answer::Ok, Some(FirewallAction::Warn)).await;
    fx.state.meta_mcp.set_capabilities(caps);
    let key = super::super::mtls_rule_ids::rule_key(&fx);
    fx.state.meta_mcp.set_identity_grants(
        crate::identity_grants::LocalIdentityGrantStore::from_grants(rows).with_rule_ids(&key),
    );
    Owned { fx, hits }
}

/// The keyed id the published store holds for `grant_id`, asserted present.
pub(super) fn held_id(o: &Owned, grant_id: &str) -> RuleId {
    let (live, _) = o.fx.state.meta_mcp.identity_grant_sink();
    let id = live.read().rule_id(grant_id).cloned();
    id.unwrap_or_else(|| panic!("premise: the store holds an id for {grant_id}"))
}

/// `gateway_invoke` of [`PROBE`] as the owner with `arguments` and, when
/// given, a signing `nonce`: the answer.
pub(super) async fn invoke(fx: &Logged, arguments: Value, nonce: Option<&str>) -> Value {
    let mut invoke = json!({"server": CAPS, "tool": PROBE, "arguments": arguments});
    if let Some(nonce) = nonce {
        invoke["nonce"] = json!(nonce);
    }
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
        "name": "gateway_invoke", "arguments": invoke,
        "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                  "io.modelcontextprotocol/clientCapabilities": {}},
    }});
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("authorization", "Bearer k-std")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", "gateway_invoke")
        .body(axum::body::Body::from(body.to_string()))
        .expect("a request");
    request.extensions_mut().insert(owner_cert());
    let response = tower::ServiceExt::oneshot(fx.router.clone(), request)
        .await
        .expect("an answer");
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap_or_default();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

/// The owner's call under the published config with `rules` as its firewall
/// rules, asserted delivered with one more upstream hit: the new record's
/// `(kind, rule_id, grant_id)`.
pub(super) async fn delivered_under(
    o: &Owned,
    rules: Vec<FirewallRule>,
    arguments: Value,
) -> (Value, Value, Value) {
    let mut config = (*o.fx.state.live_config.get()).clone();
    config.security.firewall.rules = rules;
    o.fx.state.live_config.set(config);
    let before = (
        invocations(&o.fx).await.len(),
        o.hits.load(Ordering::SeqCst),
    );
    let answer = invoke(&o.fx, arguments, None).await;
    assert!(
        answer.get("error").is_none(),
        "premise, delivered: {answer}"
    );
    assert_eq!(
        o.hits.load(Ordering::SeqCst),
        before.1 + 1,
        "premise: the upstream was hit: {answer}"
    );
    named_last(&o.fx, before.0).await
}

/// The one record written since `seen` records: `(kind, rule_id, grant_id)`.
pub(super) async fn named_last(fx: &Logged, seen: usize) -> (Value, Value, Value) {
    let rows = invocations(fx).await;
    let [row] = &rows[seen..] else {
        panic!("wanted one new invocation record: {:?}", &rows[seen..]);
    };
    let d = &row["decision"];
    (
        d["kind"].clone(),
        d.get("rule_id").cloned().unwrap_or(Value::Null),
        d.get("grant_id").cloned().unwrap_or(Value::Null),
    )
}

/// A rule on [`PROBE`] with `action` for `scan`.
pub(super) fn probe_rule(o: &Owned, action: FirewallAction, scan: &[ScanType]) -> FirewallRule {
    let base =
        o.fx.state
            .live_config
            .get()
            .security
            .firewall
            .rules
            .first()
            .cloned()
            .expect("the fixture's rule");
    FirewallRule {
        tool_match: PROBE.to_owned(),
        action,
        scan: scan.to_vec(),
        ..base
    }
}

pub(super) fn as_grant(id: &RuleId, grant_id: &str) -> (Value, Value, Value) {
    (json!("grant"), json!(id.as_str()), json!(grant_id))
}

/// R7 (ATTR.2). A softener beside a matched grant: the firewall rule is
/// named, with no grant id. Kills M1 and M3.
#[tokio::test(flavor = "current_thread")]
async fn softener_beats_grant() {
    let o = owned(vec![owner_grant("g-m")]).await;
    held_id(&o, "g-m");
    let softener = probe_rule(&o, FirewallAction::Allow, &[ScanType::ShellInjection]);
    let got = delivered_under(&o, vec![softener.clone()], injected()).await;
    assert_eq!(
        got,
        (
            json!("firewall"),
            json!(firewall_id(&o.fx, &softener).as_str()),
            Value::Null
        )
    );
}

/// R8 (ATTR.2). A block-to-warn rule beside a matched grant: the call warns
/// through and the grant is named. Kills M4 (block-to-warn ranked first).
#[tokio::test(flavor = "current_thread")]
async fn block_to_warn_loses_to_grant() {
    let o = owned(vec![owner_grant("g-m")]).await;
    let expected = held_id(&o, "g-m");
    let to_warn = probe_rule(&o, FirewallAction::Warn, &[ScanType::ShellInjection]);
    let got = delivered_under(&o, vec![to_warn], injected()).await;
    assert_eq!(got, as_grant(&expected, "g-m"));
}

/// R10 (ATTR.2). A warn-to-allow rule beside a matched grant: the grant is
/// named. Kills M3 (grant and firewall-allow ranks swapped).
#[tokio::test(flavor = "current_thread")]
async fn warn_to_allow_loses_to_grant() {
    let o = owned(vec![owner_grant("g-m")]).await;
    let expected = held_id(&o, "g-m");
    let warn_to_allow = probe_rule(&o, FirewallAction::Allow, &[ScanType::SqlInjection]);
    let got = delivered_under(&o, vec![warn_to_allow], json!({"q": "' OR 1=1"})).await;
    assert_eq!(got, as_grant(&expected, "g-m"));
}
