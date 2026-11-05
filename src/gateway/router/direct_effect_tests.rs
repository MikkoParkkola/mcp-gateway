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

/// `read` declaring `readOnlyHint: hint`, or no hint, with the fixture
/// backend's input schema.
fn read_tool(hint: Option<bool>) -> crate::protocol::Tool {
    let mut tool = json!({"name": "read", "inputSchema": {
        "type": "object", "properties": {"cmd": {"type": "string"}}}});
    if let Some(hint) = hint {
        tool["annotations"] = json!({"readOnlyHint": hint});
    }
    serde_json::from_value(tool).expect("a tool")
}

/// The decision of every invocation record in `dir`'s log, in order.
fn decisions(dir: &tempfile::TempDir) -> Vec<Value> {
    entries(dir)
        .into_iter()
        .filter(|entry| {
            entry.get("tool").is_some() && entry["event"] != "response_delivery_attempt"
        })
        .filter_map(|entry| entry.get("decision").cloned())
        .collect()
}

/// The one decision a direct call of `read` on `backend` as `subject` (none
/// for the key alone) records.
async fn direct_decision(
    fx: &Fx,
    dir: &tempfile::TempDir,
    backend: &str,
    subject: Option<&str>,
) -> Value {
    let before = decisions(dir).len();
    let (status, body) =
        super::direct_continuation_tests::call(fx, backend, subject, json!({})).await;
    assert!(
        status.is_success() && body.get("result").is_some(),
        "premise: delivered: {status} {body}"
    );
    let mut after = decisions(dir).split_off(before);
    assert_eq!(after.len(), 1, "premise: one invocation record: {after:?}");
    after.remove(0)
}

/// A1: a direct call records what its slot declares for the tool, from the
/// tool's own annotation: read-only, may-write, or listed with no hint.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn a_direct_call_records_its_declared_effect() {
    for (hint, effect) in [
        (Some(true), "read_only"),
        (Some(false), "may_write"),
        (None, "undeclared"),
    ] {
        let dir = tempfile::tempdir().expect("a log directory");
        let log = logger(&dir, AuditFailurePolicy::FailClosed);
        let fx = fixture_logged(Answer::Ok, Arc::clone(&log), |mut meta| {
            meta.enable_transparency_log(log);
            meta
        })
        .await;
        let alpha = fx.state.backends.get("alpha").expect("alpha");
        alpha.declare_slot_effects_for_test(None, vec![read_tool(hint)]);
        let decision = direct_decision(&fx, &dir, "alpha", None).await;
        assert_eq!(decision["decided"], "fresh", "{decision}");
        assert_eq!(decision["declared_effect"], effect, "{hint:?}: {decision}");
        assert_eq!(
            decision["declared_effect_source"], "tool_annotation",
            "{hint:?}: {decision}"
        );
    }
}

/// A propagation strategy minting `<subject>@<audience>` for every caller.
struct Binds;

#[async_trait::async_trait]
impl crate::identity_propagation::IdentityPropagation for Binds {
    async fn propagate(
        &self,
        identity: &crate::key_server::oidc::VerifiedIdentity,
        backend: &crate::identity_propagation::BackendDescriptor,
    ) -> Result<
        crate::identity_propagation::PropagatedCredential,
        crate::identity_propagation::PropagationError,
    > {
        Ok(crate::identity_propagation::PropagatedCredential {
            expiry_synthetic: false,
            headers: vec![("Authorization".to_string(), "Bearer minted".to_string())],
            expires_at: i64::MAX,
            cache_binding: format!("{}@{}", identity.subject, backend.audience),
            subject_key: identity.subject.clone(),
            audience: backend.audience.clone(),
            scopes: Vec::new(),
        })
    }
}

/// alice's binding on `alpha`.
const ALICE_ALPHA: &str = "alice@aud-alpha";

/// bob's binding on `alpha`.
const BOB_ALPHA: &str = "bob@aud-alpha";

/// Whether the idempotency cache (stage 7a) answers a repeated key.
#[derive(Clone, Copy)]
enum Cache {
    On,
    Off,
}

/// The propagating fixture with its route log in `dir`, the idempotency
/// cache as `cache` says, and alice's and bob's per-user slots on `alpha`
/// reachable through the fixture's scripted transport.
async fn bound_with(dir: &tempfile::TempDir, cache: Cache) -> Fx {
    let log = logger(dir, AuditFailurePolicy::FailClosed);
    let fx = super::direct_guards_fixture::fixture_propagating_logged(Answer::Ok, log, |meta| {
        meta.set_identity_propagation(Arc::new(Binds));
        if let Cache::On = cache {
            meta.enable_idempotency(
                Arc::new(crate::idempotency::IdempotencyCache::new()),
                crate::idempotency::CLEANUP_INTERVAL,
            );
        }
    })
    .await;
    let alpha = fx.state.backends.get("alpha").expect("alpha");
    let shared = alpha
        .pooled_transport_for_test(&crate::backend::PoolKey::Shared)
        .expect("the fixture's scripted transport");
    for binding in [ALICE_ALPHA, BOB_ALPHA] {
        alpha.set_pooled_transport_for_test(
            &crate::backend::PoolKey::PerUser {
                binding: binding.to_owned(),
            },
            Arc::clone(&shared),
        );
    }
    fx
}

/// [`bound_with`] with the cache off: the live-call rows.
async fn bound(dir: &tempfile::TempDir) -> Fx {
    bound_with(dir, Cache::Off).await
}

/// A direct call of `read` on `alpha` as `subject`, keyed `key`: the status
/// and answer.
async fn keyed(fx: &Fx, subject: &str, key: &str) -> (axum::http::StatusCode, Value) {
    super::direct_continuation_tests::call(
        fx,
        "alpha",
        Some(subject),
        json!({"_meta": {(crate::protocol::mrtr::IDEMPOTENCY_KEY_META): key}}),
    )
    .await
}

/// A2: a propagated caller's direct call records its own bound slot's
/// declaration, never the shared slot's: the shared slot declares `read`
/// may-write, alice's slot read-only.
#[tokio::test]
async fn direct_effect_follows_the_caller_bound_slot() {
    let dir = tempfile::tempdir().expect("a log directory");
    let fx = bound(&dir).await;
    let alpha = fx.state.backends.get("alpha").expect("alpha");
    alpha.declare_slot_effects_for_test(None, vec![read_tool(Some(false))]);
    alpha.declare_slot_effects_for_test(Some(ALICE_ALPHA), vec![read_tool(Some(true))]);
    let decision = direct_decision(&fx, &dir, "alpha", Some("alice")).await;
    assert_eq!(decision["declared_effect"], "read_only", "{decision}");
    assert_eq!(
        decision["declared_effect_source"], "tool_annotation",
        "{decision}"
    );
}

/// A2, the slot not yet listed: alice's slot holds no list, and the shared
/// slot declares `read` read-only. The call lists alice's own slot (the
/// fixture's listing gives `read` no hint), so the record says undeclared:
/// alice's slot as listed for this call, never the shared slot's read-only.
#[tokio::test]
async fn direct_effect_of_an_unlisted_bound_slot_is_its_own() {
    let dir = tempfile::tempdir().expect("a log directory");
    let fx = bound(&dir).await;
    let alpha = fx.state.backends.get("alpha").expect("alpha");
    alpha.declare_slot_effects_for_test(None, vec![read_tool(Some(true))]);
    assert_eq!(
        alpha.declared_effect_for(Some(ALICE_ALPHA), "read"),
        None,
        "premise: alice's slot is not listed yet"
    );
    let decision = direct_decision(&fx, &dir, "alpha", Some("alice")).await;
    assert_eq!(
        alpha.declared_effect_for(Some(ALICE_ALPHA), "read"),
        Some(crate::security::decision_record::Effect::Undeclared),
        "premise: the call listed alice's slot from the fixture's listing"
    );
    assert_eq!(decision["declared_effect"], "undeclared", "{decision}");
}

/// alice's keyed call once, then again: the second is answered from the
/// idempotency cache (stage 7a), with `between` run before it. The decision
/// the hit records.
async fn cache_hit(fx: &Fx, dir: &tempfile::TempDir, key: &str, between: impl FnOnce()) -> Value {
    let (status, first) = keyed(fx, "alice", key).await;
    assert!(
        status.is_success() && first.get("result").is_some(),
        "premise: the first call ran: {first}"
    );
    let _ = super::backend_handlers::direct_lease_seams::served();
    between();
    let before = decisions(dir).len();
    let (_, hit) = keyed(fx, "alice", key).await;
    assert!(
        hit.get("result").is_some(),
        "premise: the hit delivered: {hit}"
    );
    assert_eq!(
        super::backend_handlers::direct_lease_seams::served(),
        Some(super::backend_handlers::direct_lease_seams::Served::Cache),
        "premise: stage 7a answered"
    );
    let mut after = decisions(dir).split_off(before);
    assert_eq!(after.len(), 1, "premise: one record for the hit: {after:?}");
    after.remove(0)
}

/// A3: a cache hit is keyed by the caller's binding, so it records what
/// alice's own slot declares (read-only), never the shared slot's may-write.
#[tokio::test]
async fn a_direct_cache_hit_records_the_callers_slot_effect() {
    let dir = tempfile::tempdir().expect("a log directory");
    let fx = bound_with(&dir, Cache::On).await;
    let alpha = fx.state.backends.get("alpha").expect("alpha");
    alpha.declare_slot_effects_for_test(None, vec![read_tool(Some(false))]);
    alpha.declare_slot_effects_for_test(Some(ALICE_ALPHA), vec![read_tool(Some(true))]);
    let decision = cache_hit(&fx, &dir, "k-7a", || {}).await;
    assert_eq!(decision["decided"], "replayed", "{decision}");
    assert_eq!(decision["declared_effect"], "read_only", "{decision}");
    assert_eq!(
        decision["declared_effect_source"], "tool_annotation",
        "{decision}"
    );
}

/// A3, the declaration flipped between the call and the hit (may-write to
/// read-only): the hit records alice's slot as it is now.
#[tokio::test]
async fn a_direct_cache_hit_reads_the_callers_slot_now() {
    let dir = tempfile::tempdir().expect("a log directory");
    let fx = bound_with(&dir, Cache::On).await;
    let alpha = fx.state.backends.get("alpha").expect("alpha");
    alpha.declare_slot_effects_for_test(None, vec![read_tool(Some(false))]);
    alpha.declare_slot_effects_for_test(Some(ALICE_ALPHA), vec![read_tool(Some(false))]);
    let decision = cache_hit(&fx, &dir, "k-7a-flip", || {
        alpha.declare_slot_effects_for_test(Some(ALICE_ALPHA), vec![read_tool(Some(true))]);
    })
    .await;
    assert_eq!(decision["declared_effect"], "read_only", "{decision}");
}

/// A3, alice's slot evicted after the call and re-armed unlisted, the shared
/// slot declaring read-only. The repeat lists alice's slot again before the
/// cache answers (the fixture's listing gives `read` no hint), so the hit
/// records her slot as refilled: undeclared, never the shared read-only.
#[tokio::test]
async fn a_direct_cache_hit_on_an_evicted_slot_reads_it_as_refilled() {
    let dir = tempfile::tempdir().expect("a log directory");
    let fx = bound_with(&dir, Cache::On).await;
    let alpha = fx.state.backends.get("alpha").expect("alpha");
    alpha.declare_slot_effects_for_test(None, vec![read_tool(Some(true))]);
    alpha.declare_slot_effects_for_test(Some(ALICE_ALPHA), vec![read_tool(Some(true))]);
    let shared = alpha
        .pooled_transport_for_test(&crate::backend::PoolKey::Shared)
        .expect("the fixture's scripted transport");
    let decision = cache_hit(&fx, &dir, "k-7a-evicted", || {
        alpha.retire_per_user_slot_for_test(ALICE_ALPHA);
        alpha.forget_caller_slots_for_test();
        alpha.set_pooled_transport_for_test(
            &crate::backend::PoolKey::PerUser {
                binding: ALICE_ALPHA.to_owned(),
            },
            shared,
        );
        assert_eq!(
            alpha.declared_effect_for(Some(ALICE_ALPHA), "read"),
            None,
            "premise: alice's slot is evicted and unlisted"
        );
    })
    .await;
    assert_eq!(
        alpha.declared_effect_for(Some(ALICE_ALPHA), "read"),
        Some(crate::security::decision_record::Effect::Undeclared),
        "premise: the repeat refilled alice's slot from the fixture's listing"
    );
    assert_eq!(decision["decided"], "replayed", "{decision}");
    assert_eq!(decision["declared_effect"], "undeclared", "{decision}");
}

/// GUARD: the stored-result stores are per caller. alice runs a keyed direct
/// call; bob, another verified identity on the same key and backend, sends
/// the same idempotency key and is never served alice's stored answer: his
/// call runs fresh under his own owner. Both stores: the execution store
/// alone (cache off), and the idempotency cache in front of it (cache on).
#[tokio::test]
async fn another_caller_on_the_same_key_is_never_served_a_stored_answer() {
    for cache in [Cache::Off, Cache::On] {
        let dir = tempfile::tempdir().expect("a log directory");
        let fx = bound_with(&dir, cache).await;
        let (_, alice) = keyed(&fx, "alice", "k-shared").await;
        assert!(alice.get("result").is_some(), "premise: alice ran: {alice}");
        let ran = super::direct_continuation_tests::dispatched(&fx);
        let _ = super::backend_handlers::direct_lease_seams::served();
        let (_, bob) = keyed(&fx, "bob", "k-shared").await;
        assert!(bob.get("result").is_some(), "bob is answered: {bob}");
        assert_eq!(
            super::backend_handlers::direct_lease_seams::served(),
            None,
            "bob was served a stored answer: {bob}"
        );
        assert_eq!(
            super::direct_continuation_tests::dispatched(&fx),
            ran + 1,
            "bob's call did not run fresh: {bob}"
        );
    }
}

/// A propagation strategy minting `<subject>@<audience>#<generation>`: a
/// bumped generation gives the same caller a new binding (a new slot), as a
/// rotated grant does, while the caller and so the execution store's owner
/// stay the same.
#[derive(Default)]
struct Generations(AtomicUsize);

#[async_trait::async_trait]
impl crate::identity_propagation::IdentityPropagation for Generations {
    async fn propagate(
        &self,
        identity: &crate::key_server::oidc::VerifiedIdentity,
        backend: &crate::identity_propagation::BackendDescriptor,
    ) -> Result<
        crate::identity_propagation::PropagatedCredential,
        crate::identity_propagation::PropagationError,
    > {
        let generation = self.0.load(Ordering::SeqCst);
        Ok(crate::identity_propagation::PropagatedCredential {
            expiry_synthetic: false,
            headers: vec![("Authorization".to_string(), "Bearer minted".to_string())],
            expires_at: i64::MAX,
            cache_binding: format!("{}@{}#{generation}", identity.subject, backend.audience),
            subject_key: identity.subject.clone(),
            audience: backend.audience.clone(),
            scopes: Vec::new(),
        })
    }
}

/// alice's binding on `alpha` at `generation`.
fn alice_at(generation: usize) -> String {
    format!("{ALICE_ALPHA}#{generation}")
}

/// The propagating fixture with the idempotency cache off (so a repeated
/// key is a stage-7b replay), its route log in `dir`, and alice's slots for
/// generations 1 and 2 reachable; the strategy starts at generation 1.
async fn generational(dir: &tempfile::TempDir) -> (Fx, Arc<Generations>) {
    let log = logger(dir, AuditFailurePolicy::FailClosed);
    let generations = Arc::new(Generations(AtomicUsize::new(1)));
    let strategy = Arc::clone(&generations);
    let fx = super::direct_guards_fixture::fixture_propagating_logged(Answer::Ok, log, |meta| {
        meta.set_identity_propagation(strategy);
    })
    .await;
    let alpha = fx.state.backends.get("alpha").expect("alpha");
    let shared = alpha
        .pooled_transport_for_test(&crate::backend::PoolKey::Shared)
        .expect("the fixture's scripted transport");
    for generation in [1, 2] {
        alpha.set_pooled_transport_for_test(
            &crate::backend::PoolKey::PerUser {
                binding: alice_at(generation),
            },
            Arc::clone(&shared),
        );
    }
    (fx, generations)
}

/// alice's keyed call at generation 1, then `between`, then the same key at
/// generation 2: a stage-7b replay of the first execution. The decision the
/// replay records.
async fn replayed_7b(
    (fx, generations): (&Fx, &Generations),
    dir: &tempfile::TempDir,
    key: &str,
    between: impl FnOnce(),
) -> Value {
    let (status, first) = keyed(fx, "alice", key).await;
    assert!(
        status.is_success() && first.get("result").is_some(),
        "premise: the first call ran: {first}"
    );
    let ran = super::direct_continuation_tests::dispatched(fx);
    generations.0.store(2, Ordering::SeqCst);
    between();
    let _ = super::backend_handlers::direct_lease_seams::served();
    let before = decisions(dir).len();
    let (_, replay) = keyed(fx, "alice", key).await;
    assert!(
        replay.get("result").is_some(),
        "premise: the replay delivered: {replay}"
    );
    assert_eq!(
        super::backend_handlers::direct_lease_seams::served(),
        Some(super::backend_handlers::direct_lease_seams::Served::Execution),
        "premise: stage 7b answered, not 7a"
    );
    assert_eq!(
        super::direct_continuation_tests::dispatched(fx),
        ran,
        "premise: nothing was sent again"
    );
    let mut after = decisions(dir).split_off(before);
    assert_eq!(
        after.len(),
        1,
        "premise: one record for the replay: {after:?}"
    );
    after.remove(0)
}

/// A4: a completed replay records the slot the first execution ran under
/// (alice's generation 1, read-only), never her current slot (generation 2,
/// may-write) nor the shared slot (no hint).
#[tokio::test]
async fn a_direct_completed_replay_records_the_stored_slot_effect() {
    let dir = tempfile::tempdir().expect("a log directory");
    let (fx, generations) = generational(&dir).await;
    let alpha = fx.state.backends.get("alpha").expect("alpha");
    alpha.declare_slot_effects_for_test(None, vec![read_tool(None)]);
    alpha.declare_slot_effects_for_test(Some(&alice_at(1)), vec![read_tool(Some(true))]);
    alpha.declare_slot_effects_for_test(Some(&alice_at(2)), vec![read_tool(Some(false))]);
    let decision = replayed_7b((&fx, &generations), &dir, "k-7b", || {}).await;
    assert_eq!(decision["decided"], "replayed", "{decision}");
    assert_eq!(decision["declared_effect"], "read_only", "{decision}");
    assert_eq!(
        decision["declared_effect_source"], "tool_annotation",
        "{decision}"
    );
}

/// A4, the stored slot's declaration flipped from may-write to read-only
/// between the run and the replay: the replay reads it now.
#[tokio::test]
async fn a_direct_completed_replay_reads_the_stored_slot_now() {
    let dir = tempfile::tempdir().expect("a log directory");
    let (fx, generations) = generational(&dir).await;
    let alpha = fx.state.backends.get("alpha").expect("alpha");
    alpha.declare_slot_effects_for_test(None, vec![read_tool(None)]);
    alpha.declare_slot_effects_for_test(Some(&alice_at(1)), vec![read_tool(Some(false))]);
    alpha.declare_slot_effects_for_test(Some(&alice_at(2)), vec![read_tool(Some(false))]);
    let decision = replayed_7b((&fx, &generations), &dir, "k-7b-flip", || {
        alpha.declare_slot_effects_for_test(Some(&alice_at(1)), vec![read_tool(Some(true))]);
    })
    .await;
    assert_eq!(decision["declared_effect"], "read_only", "{decision}");
}

/// A4, the stored slot's hint removed (the tool still listed): undeclared.
#[tokio::test]
async fn a_direct_completed_replay_of_a_removed_hint_records_undeclared() {
    let dir = tempfile::tempdir().expect("a log directory");
    let (fx, generations) = generational(&dir).await;
    let alpha = fx.state.backends.get("alpha").expect("alpha");
    alpha.declare_slot_effects_for_test(Some(&alice_at(1)), vec![read_tool(Some(true))]);
    alpha.declare_slot_effects_for_test(Some(&alice_at(2)), vec![read_tool(Some(false))]);
    let decision = replayed_7b((&fx, &generations), &dir, "k-7b-hint", || {
        alpha.declare_slot_effects_for_test(Some(&alice_at(1)), vec![read_tool(None)]);
    })
    .await;
    assert_eq!(decision["declared_effect"], "undeclared", "{decision}");
}

/// A4, the tool no longer listed on the stored slot: no effect, though
/// alice's current slot declares may-write.
#[tokio::test]
async fn a_direct_completed_replay_of_an_unlisted_tool_records_none() {
    let dir = tempfile::tempdir().expect("a log directory");
    let (fx, generations) = generational(&dir).await;
    let alpha = fx.state.backends.get("alpha").expect("alpha");
    alpha.declare_slot_effects_for_test(Some(&alice_at(1)), vec![read_tool(Some(true))]);
    alpha.declare_slot_effects_for_test(Some(&alice_at(2)), vec![read_tool(Some(false))]);
    let decision = replayed_7b((&fx, &generations), &dir, "k-7b-unlisted", || {
        alpha.declare_slot_effects_for_test(Some(&alice_at(1)), Vec::new());
    })
    .await;
    assert_eq!(decision["decided"], "replayed", "{decision}");
    assert!(decision.get("declared_effect").is_none(), "{decision}");
}

/// A4, the stored slot evicted after the run: no effect, never alice's
/// current slot (may-write) nor the shared slot (read-only).
#[tokio::test]
async fn a_direct_completed_replay_of_an_evicted_slot_records_none() {
    let dir = tempfile::tempdir().expect("a log directory");
    let (fx, generations) = generational(&dir).await;
    let alpha = fx.state.backends.get("alpha").expect("alpha");
    alpha.declare_slot_effects_for_test(None, vec![read_tool(Some(true))]);
    alpha.declare_slot_effects_for_test(Some(&alice_at(1)), vec![read_tool(Some(true))]);
    alpha.declare_slot_effects_for_test(Some(&alice_at(2)), vec![read_tool(Some(false))]);
    let decision = replayed_7b((&fx, &generations), &dir, "k-7b-evicted", || {
        alpha.retire_per_user_slot_for_test(&alice_at(1));
    })
    .await;
    assert!(decision.get("declared_effect").is_none(), "{decision}");
}

/// FIXTURE.1 (canary, what reaches the record today): no secret and no
/// caller-supplied text enters the decision object. A propagated caller
/// whose subject (and so its per-user binding) carries canary text makes an
/// allowed direct call; a meta call names a caller-chosen server and tool,
/// both canaries. The configured key's secret (`k-std`) and every canary are
/// absent from both serialised decisions.
#[tokio::test]
async fn the_decision_object_carries_no_secret_or_caller_text() {
    const SUBJECT: &str = "zq-canary-subject";
    let dir = tempfile::tempdir().expect("a log directory");
    let fx = bound(&dir).await;
    let alpha = fx.state.backends.get("alpha").expect("alpha");
    let binding = format!("{SUBJECT}@aud-alpha");
    let shared = alpha
        .pooled_transport_for_test(&crate::backend::PoolKey::Shared)
        .expect("the fixture's scripted transport");
    alpha.set_pooled_transport_for_test(
        &crate::backend::PoolKey::PerUser {
            binding: binding.clone(),
        },
        shared,
    );
    let direct = direct_decision(&fx, &dir, "alpha", Some(SUBJECT)).await;

    let before = decisions(&dir).len();
    let answer = call(
        &fx,
        "/mcp",
        "gateway_invoke",
        json!({"server": "zq-canary-server", "tool": "zq-canary-tool", "arguments": {}}),
    )
    .await;
    let after = decisions(&dir).split_off(before);
    let [meta] = after.as_slice() else {
        panic!("premise: one meta record: {after:?}; answer {answer}");
    };

    for decision in [&direct, meta] {
        let text = decision.to_string();
        for canary in [
            "k-std",
            SUBJECT,
            binding.as_str(),
            "zq-canary-server",
            "zq-canary-tool",
        ] {
            assert!(
                !text.contains(canary),
                "{canary} entered the decision: {text}"
            );
        }
    }
}
