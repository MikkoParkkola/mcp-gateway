// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8377 GUARD rows: what MIK-8350 already delivers for a stream's
//! request-time identity, pinned before MIK-8377 changes `live()`. Each row
//! is green on the base and names the mutant that turns it red.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::ConnectInfo;
use axum::http::HeaderValue;
use serde_json::json;

use super::audience_ear::{Ear, EventOutcome};
use super::audience_fixture::{SENTINEL, World, adapter_assertion, asserted, tool};
use crate::gateway::oauth::{AgentDefinition, AgentRegistry};
use crate::identity_grants::{
    GrantAgent, GrantAgentKey, GrantScope, GrantSubject, IdentityGrant, LocalIdentityGrantStore,
};
use crate::mtls::CertIdentity;
use crate::mtls::identity::CertNotAfter;
use crate::security::caller_identity::{CallerIdentityConfig, CallerIdentityMode};

const AUDIENCE: &str = "mik-8377";
const CF_HEADER: &str = "cf-access-jwt-assertion";
const PROXY_SUBJECT: &str = "x-gateway-identity-subject";
const PROXY_AUTHORITY: &str = "corp-sso";

fn alpha(read: &str) -> Vec<crate::protocol::Tool> {
    vec![
        tool("read", read),
        tool("write", "w"),
        tool("scan", "s"),
        tool("fetch", "f"),
    ]
}

/// Whether a listen stream ends before it writes anything more: everything
/// queued is decided, a sentinel is published behind it, and the very next
/// read is the end of the stream. A frame of any kind first is `false`;
/// [`Ear::closed`] would read past it to the end.
pub(super) async fn ended_unwritten(ear: &mut Ear, w: &World) -> bool {
    let Ear::Listen(events) = ear else {
        panic!("ended_unwritten() reads a listen stream");
    };
    w.settle().await;
    w.state.subscriptions.publish(json!({
        "jsonrpc": "2.0", "method": SENTINEL, "params": { "mark": u64::MAX }
    }));
    match events.next().await {
        EventOutcome::Eof => true,
        EventOutcome::Event(_) => false,
        EventOutcome::Timeout => panic!("VOID: no sentinel within ARRIVAL — closure unproven"),
        EventOutcome::Error(error) => panic!("VOID: listen body error: {error}"),
    }
}

/// Register (or replace) `client_id` with `scopes`, and a token it validates
/// for an hour. Re-registering keeps the secret, so an issued token stays
/// valid while the agent's scopes change.
pub(super) fn agent(registry: &AgentRegistry, client_id: &str, scopes: &[&str]) -> String {
    let secret = format!("{client_id}-mik-8377-secret-0123456789abcdef");
    registry.register(AgentDefinition {
        client_id: client_id.to_string(),
        name: client_id.to_string(),
        hs256_secret: Some(secret.clone()),
        rs256_public_key: None,
        scopes: scopes.iter().map(|s| (*s).to_string()).collect(),
        issuer: None,
        audience: Some(AUDIENCE.to_string()),
    });
    let now = crate::clock::unix_secs().expect("clock after 1970");
    jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &json!({ "sub": client_id, "exp": now + 3600, "iat": now, "aud": AUDIENCE }),
        &jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
    )
    .expect("sign agent token")
}

/// A personal capability `name` owned by `subject` under `authority`.
fn personal_cap(name: &str, (authority, subject): (&str, &str), description: &str) -> String {
    format!(
        "fulcrum: \"1.0\"\nname: {name}\ndescription: {description}\n\
schema:\n  input:\n    type: object\n    properties: {{}}\n\
metadata:\n  exposure: personal\n  identity_owner:\n    authority: \"{authority}\"\n    subject: {subject}\n\
providers:\n  primary:\n    service: rest\n    config:\n      base_url: https://example.invalid\n      path: /p\n      method: GET\n\
auth:\n  required: false\n  type: none\n"
    )
}

/// `subject`'s grant on capability `name`, held by `agent`.
fn grant(
    name: &str,
    (authority, subject): (&str, &str),
    agent: GrantAgent,
) -> LocalIdentityGrantStore {
    let owner = GrantSubject::new(authority.to_string(), subject, None);
    LocalIdentityGrantStore::from_grants([IdentityGrant {
        grant_id: format!("g-{name}"),
        subject: owner.clone(),
        agent,
        capability: name.to_string(),
        tool: None,
        scope: GrantScope::Any,
        owner: Some(owner),
        expires_at: None,
        revoked_at: None,
        provenance: "mik-8377".to_string(),
        reason: "GUARD row".to_string(),
    }])
}

/// A client certificate named `svc` with `ou` and these SAN URIs.
fn cert(ou: Option<&str>, san_uris: &[&str]) -> CertIdentity {
    CertIdentity {
        common_name: Some("svc".to_string()),
        organizational_unit: ou.map(str::to_string),
        san_uris: san_uris.iter().map(|u| (*u).to_string()).collect(),
        display_name: "svc".to_string(),
        ..CertIdentity::default()
    }
}

/// G-CERT.1: one key and two certificates that share a CN and differ in OU;
/// the policy admits OU `a` alone to `alpha`. A change there tells the OU `a`
/// stream only (killer M33c: the digest drops the certificate).
#[tokio::test]
async fn g_cert_1_two_certificates_of_one_key_differ_only_in_ou() {
    let key_server = Arc::new(crate::key_server::KeyServer::new(
        crate::config::KeyServerConfig::default(),
    ));
    let w = World::start_on(
        key_server,
        None,
        |meta| meta,
        super::audience_access::McpAccess::MtlsOu("a"),
    )
    .await;
    let mut ears = [
        w.listen_with("k-std", |r| {
            r.extensions_mut().insert(cert(Some("a"), &[]));
        })
        .await,
        w.listen_with("k-std", |r| {
            r.extensions_mut().insert(cert(Some("b"), &[]));
        })
        .await,
    ];
    w.store_shared("alpha", alpha("r2"));
    let told = [ears[0].told(&w).await, ears[1].told(&w).await];
    assert_eq!(told, [1, 0], "only the OU a certificate sees alpha");
}

/// G-AGENT.1: one gateway, two agents; A holds `alpha`, B holds `beta`. A
/// change to `alpha` tells A's stream only (killer M33b: the digest drops
/// the agent).
#[tokio::test]
async fn g_agent_1_two_agents_differ_only_in_scope() {
    let registry = Arc::new(AgentRegistry::new());
    let a = agent(&registry, "a1", &["tools:alpha:*"]);
    let b = agent(&registry, "b1", &["tools:beta:*"]);
    let w = World::start_agents(Arc::clone(&registry)).await;
    let mut ears = [w.listen(&a).await, w.listen(&b).await];
    w.store_shared("alpha", alpha("r2"));
    let told = [ears[0].told(&w).await, ears[1].told(&w).await];
    assert_eq!(told, [1, 0], "only the agent scoped to alpha sees it");
}

/// G-AGENT.2: one key acting for one adapter user, under two certificates
/// that prove different agent ids; the grant names cert A's id alone, so a
/// change to the capability tells A's stream only (killer M33d: the digest
/// drops the proven agent id). R9 proves the agent by JWT `sub`; this row
/// proves it by certificate.
#[tokio::test]
async fn g_agent_2_a_grant_for_one_certificate_agent_is_told_to_it_alone() {
    let authority = crate::gateway::openwebui_adapter::adapter_issuer(
        super::audience_fixture::ADAPTER_INSTALLATION,
    );
    let owner = (authority.as_str(), "alice");
    let agent_a = GrantAgent::Exact(GrantAgentKey {
        source: crate::security::ProofSource::MutualTls,
        id: "spiffe://audience/agent-a".to_string(),
    });
    let grants = grant("agent_cal", owner, agent_a);
    let w = World::start_adapter(|meta| meta.with_identity_grants(grants)).await;
    w.set_capability_yaml(&personal_cap("agent_cal", owner, "one"));
    w.settle().await;
    let alice = adapter_assertion("alice");
    let open = |uri: &'static str| {
        let alice = alice.clone();
        move |r: &mut axum::http::Request<axum::body::Body>| {
            asserted(r, Some(&alice));
            r.extensions_mut().insert(cert(None, &[uri]));
        }
    };
    let mut ears = [
        w.listen_with("k-std", open("spiffe://audience/agent-a"))
            .await,
        w.listen_with("k-std", open("spiffe://audience/agent-b"))
            .await,
    ];
    w.set_capability_yaml(&personal_cap("agent_cal", owner, "two"));
    let told = [ears[0].told(&w).await, ears[1].told(&w).await];
    assert_eq!(told, [1, 0], "only cert A's agent holds the grant");
}

/// A gateway in `cloudflare_access` mode over `harness`'s JWKS, with `grants`.
async fn cf_world(
    harness: &crate::key_server::oidc_test_harness::Harness,
    grants: LocalIdentityGrantStore,
) -> World {
    use crate::key_server::oidc_test_harness::AUD;
    let verifier = crate::key_server::OidcVerifier::with_http_client(
        harness.ks.config.oidc.clone(),
        reqwest::Client::new(),
    );
    let identity = CallerIdentityConfig {
        mode: CallerIdentityMode::CloudflareAccess,
        cloudflare_access: crate::security::caller_identity::CloudflareAccessConfig {
            team_domain: "audience.cloudflareaccess.com".to_string(),
            audiences: vec![AUD.to_string()],
        },
        ..CallerIdentityConfig::default()
    };
    World::start_with(move |meta| {
        meta.with_caller_identity(identity)
            .with_access_verifier_for_test(verifier)
            .with_identity_grants(grants)
    })
    .await
}

/// The request carries `assertion` as its Cloudflare Access assertion.
fn cf_asserted(assertion: &str) -> impl FnOnce(&mut axum::http::Request<axum::body::Body>) {
    let value: HeaderValue = assertion.parse().expect("a header value");
    move |r| {
        r.headers_mut().insert(CF_HEADER, value);
    }
}

/// G-CF.1: one key, two Cloudflare Access users; only alice holds a grant on
/// her personal capability, so its change tells alice's stream only (killer
/// M33a: the digest drops the grant subject).
#[tokio::test]
async fn g_cf_1_one_key_two_cloudflare_users_differ_only_in_subject() {
    use crate::key_server::oidc_test_harness::{Harness, ISS_A, config_yaml};
    let harness = Harness::start(&config_yaml("[]", "")).await;
    let owner = (ISS_A, "alice");
    let w = cf_world(&harness, grant("alice_cal", owner, GrantAgent::Any)).await;
    w.set_capability_yaml(&personal_cap("alice_cal", owner, "one"));
    w.settle().await;
    let (alice, bob) = (
        harness.mint(ISS_A, "alice", &json!({})),
        harness.mint(ISS_A, "bob", &json!({})),
    );
    let mut ears = [
        w.listen_with("k-std", cf_asserted(&alice)).await,
        w.listen_with("k-std", cf_asserted(&bob)).await,
    ];
    w.set_capability_yaml(&personal_cap("alice_cal", owner, "two"));
    let told = [ears[0].told(&w).await, ears[1].told(&w).await];
    assert_eq!(told, [1, 0], "only alice sees alice_cal");
}

/// The trusted proxy the proxy rows connect from.
const PROXY: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 7)),
    40_000,
);

/// A gateway in `trusted_proxy` mode trusting [`PROXY`], with `grants`.
async fn proxy_world(grants: LocalIdentityGrantStore) -> World {
    let identity = CallerIdentityConfig {
        mode: CallerIdentityMode::TrustedProxy,
        trusted_proxies: vec![PROXY.ip()],
        authority: PROXY_AUTHORITY.to_string(),
        ..CallerIdentityConfig::default()
    };
    World::start_with(move |meta| {
        meta.with_caller_identity(identity)
            .with_identity_grants(grants)
    })
    .await
}

/// The request arrives from [`PROXY`], naming `subject`.
fn proxied(subject: &'static str) -> impl FnOnce(&mut axum::http::Request<axum::body::Body>) {
    move |r| {
        r.extensions_mut().insert(ConnectInfo(PROXY));
        r.headers_mut()
            .insert(PROXY_SUBJECT, HeaderValue::from_static(subject));
    }
}

/// G-PROXY.1: one key, two users named by a trusted proxy; only alice holds
/// a grant on her personal capability, so its change tells alice's stream
/// only (killer M33a). The first fixture to present a `ConnectInfo` peer to
/// a stream (the gap `audience_source_tests` records).
#[tokio::test]
async fn g_proxy_1_one_key_two_proxied_users_differ_only_in_subject() {
    let owner = (PROXY_AUTHORITY, "alice");
    let w = proxy_world(grant("alice_cal", owner, GrantAgent::Any)).await;
    w.set_capability_yaml(&personal_cap("alice_cal", owner, "one"));
    w.settle().await;
    let mut ears = [
        w.listen_with("k-std", proxied("alice")).await,
        w.listen_with("k-std", proxied("bob")).await,
    ];
    w.set_capability_yaml(&personal_cap("alice_cal", owner, "two"));
    let told = [ears[0].told(&w).await, ears[1].told(&w).await];
    assert_eq!(told, [1, 0], "only alice sees alice_cal");
}

/// G-CF.2-get: `cf_2_rotation` on the GET stream. After the signing key
/// rotates, the next change closes the stream and is not written (killer:
/// `verify_held_cf` answering `Ok`).
#[tokio::test]
async fn g_cf_2_get_an_open_get_stream_dies_when_its_signing_key_rotates() {
    use crate::key_server::oidc_test_harness::{Harness, ISS_A, config_yaml};
    let harness = Harness::start(&config_yaml("[]", "")).await;
    let w = cf_world(&harness, LocalIdentityGrantStore::default()).await;
    let assertion = harness.mint(ISS_A, "alice", &json!({}));
    let mut ear = w.sse_with("k-std", cf_asserted(&assertion)).await;
    w.store_shared("alpha", alpha("r2"));
    assert_eq!(
        ear.told(&w).await,
        1,
        "premise: a verified assertion is told"
    );

    harness.key.rotate().expect("rotate the signing key");
    w.state
        .meta_mcp
        .access_verifier()
        .expect("cloudflare mode has a verifier")
        .expire_jwks_for_test();
    w.store_shared("alpha", alpha("r3"));
    assert_eq!(ear.told(&w).await, 0, "the change is not written");
    assert!(
        !ear.is_open(&w).await,
        "a rotated signing key closes the GET stream"
    );
}

/// G-LIVE.1-agent: once the agent is removed from the registry, the next
/// change closes both its streams, unwritten (killer M12: `current_caller`
/// skips the agent check, so the removed agent stays live).
#[tokio::test]
async fn g_live_1_agent_a_removed_agent_is_closed_on_both_routes() {
    let registry = Arc::new(AgentRegistry::new());
    let token = agent(&registry, "a1", &["tools:alpha:*"]);
    let w = World::start_agents(Arc::clone(&registry)).await;
    let (mut listen, mut get) = (w.listen(&token).await, w.sse(&token).await);
    w.store_shared("alpha", alpha("r2"));
    assert_eq!(
        [listen.told(&w).await, get.told(&w).await],
        [1, 1],
        "premise: a registered agent is told on both routes"
    );

    assert!(
        registry.remove("a1").is_some(),
        "premise: a1 was registered"
    );
    w.store_shared("alpha", alpha("r3"));
    assert!(
        ended_unwritten(&mut listen, &w).await,
        "the removed agent's listen stream is closed"
    );
    assert_eq!(get.told(&w).await, 0, "the change is not written on GET");
    assert!(
        !get.is_open(&w).await,
        "the removed agent's GET stream is closed"
    );
}

/// What every `mcp_view_liveness_dead_total` series reads after `row` runs on
/// a current-thread runtime inside a local recorder, so the forced clock and
/// the counter both stay on this thread.
#[cfg(feature = "metrics")]
pub(super) fn deaths_counted<F: std::future::Future<Output = ()>>(
    row: impl FnOnce() -> F,
) -> Vec<String> {
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    telemetry_metrics::with_local_recorder(&recorder, || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime")
            .block_on(row());
    });
    handle
        .render()
        .lines()
        .filter(|l| l.starts_with("mcp_view_liveness_dead_total{"))
        .map(str::to_string)
        .collect()
}

/// `series` is exactly one death, counted once under `reason`.
#[cfg(feature = "metrics")]
pub(super) fn assert_one_death(series: &[String], reason: &str) {
    assert_eq!(series.len(), 1, "one death, one series: {series:?}");
    assert!(
        series[0].contains(&format!("reason=\"{reason}\"")),
        "counted as {reason}: {series:?}"
    );
    assert!(
        matches!(series[0].rsplit(' ').next(), Some("1" | "1.0")),
        "counted once: {series:?}"
    );
}

/// G-LIVE.1-agent counter: the removed agent's death is counted once, as
/// `reason="bearer"` (its token no longer validates).
#[cfg(feature = "metrics")]
#[test]
fn g_live_1_agent_metric_a_removed_agent_is_counted_once_as_bearer() {
    let series = deaths_counted(|| async {
        let registry = Arc::new(AgentRegistry::new());
        let token = agent(&registry, "a1", &["tools:alpha:*"]);
        let w = World::start_agents(Arc::clone(&registry)).await;
        let mut ear = w.listen(&token).await;
        registry.remove("a1");
        w.store_shared("alpha", alpha("r2"));
        assert!(
            ended_unwritten(&mut ear, &w).await,
            "premise of the count: the stream died"
        );
    });
    assert_one_death(&series, "bearer");
}

/// How long the rows' certificate stays valid after the row starts.
pub(super) const VALID_FOR: u64 = 60;

/// The TLS layer's extensions for a certificate valid until `not_after`.
pub(super) fn with_cert(not_after: u64) -> impl FnOnce(&mut axum::http::Request<axum::body::Body>) {
    move |r| {
        r.extensions_mut().insert(cert(None, &[]));
        r.extensions_mut().insert(CertNotAfter(not_after));
    }
}

/// Both routes' streams for k-std under a certificate valid until `not_after`.
pub(super) async fn certified(w: &World, not_after: u64) -> (Ear, Ear) {
    (
        w.listen_with("k-std", with_cert(not_after)).await,
        w.sse_with("k-std", with_cert(not_after)).await,
    )
}

/// G-LIVE.1-eq: at exactly `notAfter` the certificate is still valid, as the
/// handshake verifier holds (rustls-webpki refuses only `time > not_after`),
/// so a change is told on both routes and neither closes. Green on the base
/// because nothing reads `notAfter`; once MIK-8377 does, it pins the
/// boundary (killer M4': `now <= not_after` becomes `now < not_after`).
#[tokio::test]
async fn g_live_1_eq_a_stream_at_its_certificate_not_after_is_still_told() {
    let w = World::start().await;
    let not_after = crate::clock::unix_secs().expect("clock after 1970") + VALID_FOR;
    let (mut listen, mut get) = certified(&w, not_after).await;
    let clock = crate::clock::test_clock::at_secs(not_after);
    w.store_shared("alpha", alpha("r2"));
    // GET first: a GET stream that closed reads as told 0 here, where a
    // closed listen stream would stop the read inside the fixture instead.
    assert_eq!(
        get.told(&w).await,
        1,
        "at notAfter the certificate is valid on GET"
    );
    assert_eq!(
        listen.told(&w).await,
        1,
        "at notAfter the certificate is valid on listen"
    );
    assert!(!listen.closed(&w).await, "the listen stream stays open");
    assert!(get.is_open(&w).await, "the GET stream stays open");
    drop(clock);
}

/// G-PROXY.2-bearer: a proxied stream whose API key expires is closed at
/// the next change, never judged as the public caller (killer M13: a bearer
/// that is no key and no token resolves as the public client). `k-exp`
/// expires once the forced clock passes `K_EXP_UNTIL`.
#[tokio::test]
async fn g_proxy_2_bearer_a_proxied_stream_whose_key_expires_is_closed() {
    let w = proxy_world(LocalIdentityGrantStore::default()).await;
    let mut ear = w.listen_with("k-exp", proxied("alice")).await;
    w.store_shared("alpha", alpha("r2"));
    assert_eq!(ear.told(&w).await, 1, "premise: a live key is told");

    let after = u64::try_from(super::audience_fixture::K_EXP_UNTIL).expect("after 1970") + 1;
    let clock = crate::clock::test_clock::at_secs(after);
    w.store_shared("alpha", alpha("r3"));
    assert!(
        ended_unwritten(&mut ear, &w).await,
        "the expired key's stream is closed"
    );
    drop(clock);
}
