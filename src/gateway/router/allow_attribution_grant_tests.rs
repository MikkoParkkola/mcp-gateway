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
    owned_with(rows, Signing::Off).await
}

/// Whether the gateway signs: armed, a `gateway_invoke` carrying a nonce
/// has its policy checked at signing and its dispatch only stamped.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Signing {
    Off,
    On,
}

/// [`owned`], with message signing per `signing`.
pub(super) async fn owned_with(rows: Vec<IdentityGrant>, signing: Signing) -> Owned {
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
    let fx = match signing {
        Signing::Off => fixture(Answer::Ok, Some(FirewallAction::Warn)).await,
        Signing::On => signed_fixture().await,
    };
    fx.state.meta_mcp.set_capabilities(caps);
    let key = super::super::mtls_rule_ids::rule_key(&fx);
    fx.state.meta_mcp.set_identity_grants(
        crate::identity_grants::LocalIdentityGrantStore::from_grants(rows).with_rule_ids(&key),
    );
    Owned { fx, hits }
}

/// [`fixture`] with message signing armed on the meta layer, nonces optional.
async fn signed_fixture() -> Logged {
    let (dir, log) = crate::gateway::router::route_matrix_driver_tests::response::temp_log(None);
    let meta_log = Arc::clone(&log);
    let fx = crate::gateway::router::direct_guards_fixture::fixture_firewalled_logged(
        Answer::Ok,
        Some(FirewallAction::Warn),
        Arc::clone(&log),
        |mut meta| {
            meta.enable_transparency_log(meta_log);
            meta.enable_message_signing(
                crate::security::message_signing::MessageSigner::new(
                    crate::gateway::router::direct_guards_fixture::SIGNING_KEY
                        .as_bytes()
                        .to_vec(),
                    None,
                    "attribution".into(),
                ),
                std::time::Duration::from_secs(300),
                false,
            );
            meta
        },
    )
    .await;
    fx.state
        .meta_mcp
        .set_live_config(Arc::clone(&fx.state.live_config));
    Logged { fx, log, _dir: dir }
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

/// The one invocation record written since `seen` records: `(kind,
/// rule_id, grant_id)`. The grant check's own `identity_grant_decision`
/// record beside it carries no decision object, so it is skipped.
pub(super) async fn named_last(fx: &Logged, seen: usize) -> (Value, Value, Value) {
    let rows = invocations(fx).await;
    let new: Vec<&Value> = rows[seen..]
        .iter()
        .filter(|r| r.get("decision").is_some())
        .collect();
    let [row] = new.as_slice() else {
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
    let got = delivered_under(&o, vec![warn_to_allow], json!({"cmd": "' OR 1=1"})).await;
    assert_eq!(got, as_grant(&expected, "g-m"));
}

/// R1 (ATTR.1, ATTR.2), the capability half of the ladder. A softener, a
/// grant, an allow entry and a warn-to-allow rule all match: the softener
/// is named. Without the softener the grant is, with its grant id. The
/// rungs below the grant run on a registry backend (`ladder_below_grant`):
/// without its grant this capability is refused. Kills M1.
#[tokio::test(flavor = "current_thread")]
async fn attribution_ladder_top() {
    let o = owned(vec![owner_grant("g-m")]).await;
    let expected = held_id(&o, "g-m");
    let mut config = (*o.fx.state.live_config.get()).clone();
    config.security.tool_policy.enabled = true;
    config.security.tool_policy.allow = vec![format!("{CAPS}:{PROBE}")];
    o.fx.state.live_config.set(config);
    let softener = probe_rule(&o, FirewallAction::Allow, &[ScanType::ShellInjection]);
    let warn_to_allow = probe_rule(&o, FirewallAction::Allow, &[ScanType::SqlInjection]);
    let mut args = injected();
    let cmd = format!("{} ' OR 1=1", args["cmd"].as_str().unwrap_or_default());
    args["cmd"] = json!(cmd);
    let all = vec![warn_to_allow.clone(), softener.clone()];
    let got = delivered_under(&o, all, args.clone()).await;
    assert_eq!(
        got,
        (
            json!("firewall"),
            json!(firewall_id(&o.fx, &softener).as_str()),
            Value::Null
        ),
        "every rung"
    );
    let mut sql_only = args;
    sql_only.as_object_mut().expect("an object").remove("cmd");
    let got = delivered_under(&o, vec![warn_to_allow], sql_only).await;
    assert_eq!(got, as_grant(&expected, "g-m"), "without the softener");
}

/// R14, R15 (ATTR.2), the grant variants. Grants apply only to capability
/// backends, which the root check refuses, so a root rule never meets a
/// grant: on a capability with no root rule a block-to-warn content rule
/// still loses to the grant. The root softeners' ranks are pinned by the
/// provenance unit rows and the rank merge rows.
#[tokio::test(flavor = "current_thread")]
async fn a_capability_without_root_rules_names_its_grant() {
    let o = owned(vec![owner_grant("g-m")]).await;
    let expected = held_id(&o, "g-m");
    let to_warn = probe_rule(&o, FirewallAction::Warn, &[]);
    assert!(to_warn.allowed_roots.is_none(), "premise: no root rule");
    let got = delivered_under(&o, vec![to_warn], injected()).await;
    assert_eq!(got, as_grant(&expected, "g-m"));
}

/// The owner's signed call with `nonce` and empty arguments, asserted
/// delivered with one more upstream hit: the new record's named triple.
async fn signed_call(o: &Owned, nonce: &str) -> (Value, Value, Value) {
    let before = (
        invocations(&o.fx).await.len(),
        o.hits.load(Ordering::SeqCst),
    );
    let answer = invoke(&o.fx, json!({}), Some(nonce)).await;
    assert!(
        answer.get("error").is_none(),
        "premise, delivered: {answer}"
    );
    assert_eq!(
        o.hits.load(Ordering::SeqCst),
        before.1 + 1,
        "premise: the upstream was hit once: {answer}"
    );
    named_last(&o.fx, before.0).await
}

/// R19 (ATTR.1). A signed `gateway_invoke` whose dispatch only stamps the
/// prepared target: the record names the grant from the signing-time check,
/// in exactly one new record. Kills M12 (the allow not kept at signing).
#[tokio::test(flavor = "current_thread")]
async fn signed_prepared_carries_allow() {
    let o = owned_with(vec![owner_grant("g-m")], Signing::On).await;
    let expected = held_id(&o, "g-m");
    let got = signed_call(&o, "attribution-nonce-1").await;
    assert_eq!(got, as_grant(&expected, "g-m"));
}

/// R22 (ATTR.1). Signed call 1 by grant g-m; a reload then swaps g-m for
/// g-n (the capability needs a grant, so the swap keeps one). Call 2 to the
/// same target names g-n, never call 1's g-m. Kills M11 (a request-wide
/// cell) and M13 (the allow outliving its invocation).
#[tokio::test(flavor = "current_thread")]
async fn no_inheritance_after_reload() {
    let o = owned_with(vec![owner_grant("g-m")], Signing::On).await;
    let first = held_id(&o, "g-m");
    assert_eq!(
        signed_call(&o, "attribution-nonce-a").await,
        as_grant(&first, "g-m"),
        "call 1"
    );
    let key = super::super::mtls_rule_ids::rule_key(&o.fx);
    o.fx.state.meta_mcp.set_identity_grants(
        crate::identity_grants::LocalIdentityGrantStore::from_grants(vec![owner_grant("g-n")])
            .with_rule_ids(&key),
    );
    let second = held_id(&o, "g-n");
    assert_ne!(first, second, "premise: distinct ids");
    assert_eq!(
        signed_call(&o, "attribution-nonce-b").await,
        as_grant(&second, "g-n"),
        "call 2"
    );
}

/// Signed-call refusal (ATTR.1). The owner holds the grant, but a firewall
/// rule blocks the call's arguments: the refusal wins, the record names the
/// firewall rule and no grant, and the upstream is not hit. A pin today;
/// it fails if a signing-time allow ever displaces a refusal.
#[tokio::test(flavor = "current_thread")]
async fn a_signed_call_refused_later_names_the_refusal() {
    let o = owned_with(vec![owner_grant("g-m")], Signing::On).await;
    held_id(&o, "g-m");
    let block = probe_rule(&o, FirewallAction::Block, &[ScanType::ShellInjection]);
    let mut config = (*o.fx.state.live_config.get()).clone();
    config.security.firewall.rules = vec![block.clone()];
    o.fx.state.live_config.set(config);
    let seen = invocations(&o.fx).await.len();
    let answer = invoke(&o.fx, injected(), Some("attribution-nonce-r")).await;
    assert!(
        answer.get("error").is_some() || answer.pointer("/result/isError") == Some(&json!(true)),
        "premise, refused: {answer}"
    );
    assert_eq!(o.hits.load(Ordering::SeqCst), 0, "the upstream was hit");
    let got = named_last(&o.fx, seen).await;
    assert_eq!(
        got,
        (
            json!("firewall"),
            json!(firewall_id(&o.fx, &block).as_str()),
            Value::Null
        )
    );
}
