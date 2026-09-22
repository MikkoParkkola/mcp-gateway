// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `MIK-7334.CATALOGUE.1` revocation conjunct — identity-keyed slot eviction.
//!
//! Cells C1–C12 of
//! `docs/internal/design/2026-09-22-identity-keyed-slot-eviction.md` §3.2 that
//! are observable at the `Backend` level. C4a/C4b live in
//! `identity_propagation/token_exchange.rs` and C7/C8/C10a/C10b beside
//! `cache_binding`, because both depend on private functions there.
//!
//! TWO HARNESS RULES, both load-bearing (§3.1).
//!
//! Rule 1 — no absence assertion uses a cache accessor.
//! `has_cached_tools_for`, `cached_tools_count_for` and
//! `get_cached_tool_names_for` all route through `tools_slot` →
//! `pooled_entry` → `or_insert_with`, so each CREATES the slot it then
//! truthfully reports empty. Absence here is `pool_has_slot_for_test`, which
//! reads the map without creating; everywhere else the assertion is positive
//! (the next read reached the backend, and returned the post-revocation list).
//!
//! Rule 2 — every cell asserts its premise in its OWN body. Rust guarantees no
//! in-module test order and runs cases in parallel, so a premise established by
//! a neighbouring cell is not established. Each eviction cell reads a non-zero
//! tool count for its target slot before revoking anything.
//!
//! WHERE THE BINDING COMES FROM. Every slot is keyed on a binding produced by
//! the production credential producer (`SignedAssertionStrategy::propagate` →
//! `PropagatedCredential::cache_binding`), never a handwritten string: a
//! fixture that spells the key itself cannot detect a key-format change.
//! The PREFIX is reconstructed in the fixture from the production
//! `subject_key`, because these cells test `evict_identity_slots` GIVEN a
//! prefix; that the production helper derives the same prefix from a
//! `GrantSubject` is C7/C8/C10's job, in the module that owns the formula.
//!
//! PATH A ONLY (§E5). The vault binding embeds `lease.generation`, so a
//! rotated account already yields a different key and its old slot is
//! unreachable by construction — a cell there would pass whether or not this
//! mechanism exists.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use serde_json::Value;

use super::Backend;
use super::pool::PoolKey;
use crate::config::{BackendConfig, FailsafeConfig};
use crate::gateway::oauth::GatewayKeyPair;
use crate::identity_propagation::{
    IdentityPropagation, IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
    SignedAssertionStrategy,
};
use crate::key_server::oidc::VerifiedIdentity;
use crate::protocol::{JsonRpcResponse, RequestId, Tool, ToolsListResult};
use crate::transport::{ResendPermission, Transport};
use crate::{Error, Result};

/// The tool a slot holds BEFORE the grant changes.
const BEFORE: &str = "pre_revocation_tool";
/// The tool the upstream serves AFTER the grant changes. A slot answering with
/// this one refetched; a slot answering with `BEFORE` served cached bytes.
const AFTER: &str = "post_revocation_tool";

fn tool(name: &str) -> Tool {
    Tool {
        name: name.to_string(),
        title: None,
        description: Some(format!("{name} eviction fixture")),
        input_schema: serde_json::json!({ "type": "object" }),
        output_schema: None,
        annotations: None,
        role: None,
        projection: None,
    }
}

/// An upstream that counts its fills and can be switched from the
/// pre-revocation catalogue to the post-revocation one.
///
/// The counter is what makes C2's "B did not refetch" a positive assertion
/// rather than an absence, and what makes C1/C3's "the read reached the
/// backend" observable at all.
struct CountingUpstream {
    fills: AtomicUsize,
    revoked: AtomicBool,
    closed: AtomicBool,
}

impl CountingUpstream {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            fills: AtomicUsize::new(0),
            revoked: AtomicBool::new(false),
            closed: AtomicBool::new(false),
        })
    }

    fn fills(&self) -> usize {
        self.fills.load(Ordering::SeqCst)
    }

    /// Flip the upstream to the post-revocation catalogue. A slot that still
    /// answers `BEFORE` after this is serving bytes fetched under the old grant.
    fn revoke(&self) {
        self.revoked.store(true, Ordering::SeqCst);
    }

    fn was_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl Transport for CountingUpstream {
    async fn request(&self, _method: &str, _params: Option<Value>) -> Result<JsonRpcResponse> {
        Err(Error::BackendUnavailable(
            "a per-identity fill must not reach the identity-less path".to_string(),
        ))
    }

    async fn request_with_headers(
        &self,
        method: &str,
        _params: Option<Value>,
        _extra_headers: &[(String, String)],
        _identity_key: Option<&str>,
        _resend: ResendPermission,
    ) -> Result<JsonRpcResponse> {
        assert_eq!(method, "tools/list", "fixture serves only tools/list");
        self.fills.fetch_add(1, Ordering::SeqCst);
        let name = if self.revoked.load(Ordering::SeqCst) {
            AFTER
        } else {
            BEFORE
        };
        Ok(JsonRpcResponse::success_serialized(
            RequestId::Number(1),
            ToolsListResult {
                tools: vec![tool(name)],
                next_cursor: None,
            },
        ))
    }

    async fn notify(&self, _method: &str, _params: Option<Value>) -> Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        !self.closed.load(Ordering::SeqCst)
    }

    async fn close(&self) -> Result<()> {
        self.closed.store(true, Ordering::SeqCst);
        Ok(())
    }
}

fn per_user_backend(name: &str) -> Arc<Backend> {
    Arc::new(Backend::new(
        name,
        BackendConfig {
            identity_propagation: Some(IdentityPropagationConfig {
                strategy: PropagationStrategyKind::SignedAssertion,
                audience: AUDIENCE.to_string(),
                required: true,
                session_mode: SessionMode::PerUser,
                token_exchange_endpoint: None,
                token_exchange_scope: None,
            }),
            ..Default::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ))
}

const AUDIENCE: &str = "https://ledger.internal";
const ISSUER: &str = "https://idp.example";

fn identity(subject: &str) -> VerifiedIdentity {
    VerifiedIdentity {
        subject: subject.to_string(),
        email: format!("{subject}@corp"),
        name: None,
        groups: vec![],
        issuer: ISSUER.to_string(),
    }
}

/// A PATH A binding, produced by the PRODUCTION credential producer, plus the
/// eviction prefix for the same subject.
///
/// `audience` is a parameter because C2 and C9 need two bindings that differ
/// only in audience, and because the prefix must match across all of them.
async fn binding_and_prefix(subject: &str, audience: &str) -> (String, String) {
    let key = Arc::new(GatewayKeyPair::generate().expect("keygen"));
    let strategy = SignedAssertionStrategy::new(key, 300);
    let descriptor = crate::identity_propagation::BackendDescriptor {
        id: "fixture".to_string(),
        audience: audience.to_string(),
        ..Default::default()
    };
    let credential = strategy
        .propagate(&identity(subject), &descriptor)
        .await
        .expect("the production producer mints a credential");
    // §E1's prefix formula, applied to the production `subject_key`. Pins the
    // subject, leaves the audience free, so it matches every backend this
    // caller touched and every token-exchange widening of those keys.
    let prefix = format!(
        "idp:{}:{}:",
        credential.subject_key.len(),
        credential.subject_key
    );
    (credential.cache_binding, prefix)
}

fn slot(binding: &str) -> PoolKey {
    PoolKey::PerUser {
        binding: binding.to_string(),
    }
}

/// Seed a populated per-user slot and hand back its fill counter.
///
/// Returns after asserting nothing: the PREMISE assertion belongs in the
/// cell's own body (Rule 2), so this helper deliberately does not make it.
async fn fill_slot(backend: &Backend, binding: &str) -> Arc<CountingUpstream> {
    let upstream = CountingUpstream::new();
    backend
        .set_pooled_transport_for_test(&slot(binding), Arc::clone(&upstream) as Arc<dyn Transport>);
    backend
        .get_tools_for_binding(Some(binding), &[])
        .await
        .expect("the fixture upstream answers tools/list");
    upstream
}

// C1 — the criterion's own case, and the one `Vec::is_empty` cannot reach.
//
// Goes red when a POPULATED per-user slot survives revocation. Kills routing
// revocation through `invalidate_tools_cache`, whose `Vec::is_empty` predicate
// passes its own check and voids nothing on a warm cache.
//
// The observable is positive twice over: the next read REACHED the backend
// (the fill counter moved) and returned the POST-revocation list. Neither half
// is an absence, so neither can be manufactured by the probe.
#[tokio::test]
async fn c1_a_revoked_callers_populated_slot_does_not_survive() {
    let backend = per_user_backend("c1_hub");
    let (binding, prefix) = binding_and_prefix("alice", AUDIENCE).await;
    let upstream = fill_slot(&backend, &binding).await;

    // PREMISE, in this cell's own body: the slot is populated BEFORE the
    // revocation. Without it the cell would hold against a gateway that cached
    // nothing.
    assert!(
        backend.cached_tools_count_for(Some(&binding)) > 0,
        "C1 premise: the target slot must be populated before revocation"
    );
    assert!(
        binding.starts_with(&prefix),
        "C1 premise: the production binding must carry the eviction prefix"
    );
    let fills_before = upstream.fills();

    upstream.revoke();
    backend.evict_identity_slots(&prefix).await;

    let served = backend
        .get_tools_for_binding(Some(&binding), &[])
        .await
        .expect("the post-revocation read is served");
    assert!(
        upstream.fills() > fills_before,
        "C1: the post-revocation read must reach the backend, not the old cache"
    );
    assert_eq!(
        served.iter().map(|t| t.name.as_str()).collect::<Vec<_>>(),
        vec![AFTER],
        "C1: the revoked caller must not be served the pre-revocation catalogue"
    );
}

// C2 — the blunt hammer's only red cell.
//
// Goes red when an unaffected caller's slot is evicted too. Kills "evict all
// per-user slots on any grant reload", which passes C1 and fails only here.
//
// GREEN AGAINST A NO-OP EVICTOR BY CONSTRUCTION. An evictor that does nothing
// trivially preserves B, so this cell discriminates only once C1 passes. It is
// recorded as such rather than counted as coverage of the stub.
#[tokio::test]
async fn c2_an_unaffected_callers_slot_is_preserved_byte_for_byte() {
    let backend = per_user_backend("c2_hub");
    let (alice, alice_prefix) = binding_and_prefix("alice", AUDIENCE).await;
    let (bob, _) = binding_and_prefix("bob", AUDIENCE).await;
    let alice_upstream = fill_slot(&backend, &alice).await;
    let bob_upstream = fill_slot(&backend, &bob).await;

    assert!(
        backend.cached_tools_count_for(Some(&alice)) > 0
            && backend.cached_tools_count_for(Some(&bob)) > 0,
        "C2 premise: both slots must be populated before the revocation"
    );
    let bob_before = backend.get_cached_tool_names_for(Some(&bob));
    let bob_fills_before = bob_upstream.fills();

    alice_upstream.revoke();
    bob_upstream.revoke();
    backend.evict_identity_slots(&alice_prefix).await;

    // POSITIVE assertions, not absences: B's list is byte-identical and B did
    // not refetch. Had B been evicted, its upstream now serves AFTER, so the
    // equality fails as well as the counter.
    assert_eq!(
        backend.get_cached_tool_names_for(Some(&bob)),
        bob_before,
        "C2: an unaffected caller's catalogue must be byte-identical afterwards"
    );
    assert_eq!(
        bob_upstream.fills(),
        bob_fills_before,
        "C2: an unaffected caller must not be forced to refetch"
    );
}

// C3 — the `in_flight == 0` trap, one rung over from `Vec::is_empty`.
//
// Goes red when eviction silently DECLINES against a busy slot. Kills copying
// `evict_idle_per_user_entries`' predicate into the `remove_if`. Green on C1
// and C2, red only here — and unlike the reaper, which re-sweeps every 60s, a
// revocation fires once, so a decline is permanent.
//
// Not an edge case: every catalogue fill holds an in-flight claim for the
// whole duration of its fetch, so the wrong predicate declines during exactly
// the window a revocation races.
//
// The observable is deliberately NOT "the key is absent" — a concurrent reader
// may legitimately recreate it, so key-absence would go red for the wrong
// reason.
#[tokio::test]
async fn c3_eviction_does_not_decline_against_a_busy_slot() {
    let backend = per_user_backend("c3_hub");
    let (binding, prefix) = binding_and_prefix("alice", AUDIENCE).await;
    let upstream = fill_slot(&backend, &binding).await;

    assert!(
        backend.cached_tools_count_for(Some(&binding)) > 0,
        "C3 premise: the target slot must be populated before revocation"
    );
    let fills_before = upstream.fills();

    // Hold a live claim, exactly as a catalogue fill does for its whole
    // duration. The guard outlives the eviction call.
    let claim = backend.begin_activity(&slot(&binding));
    assert!(
        claim.entry().in_flight.load(Ordering::SeqCst) > 0,
        "C3 premise: the slot must be busy when the revocation lands"
    );

    upstream.revoke();
    backend.evict_identity_slots(&prefix).await;
    drop(claim);

    let served = backend
        .get_tools_for_binding(Some(&binding), &[])
        .await
        .expect("the post-revocation read is served");
    assert!(
        upstream.fills() > fills_before,
        "C3: a revocation against a BUSY slot must still reach the backend"
    );
    assert_eq!(
        served.iter().map(|t| t.name.as_str()).collect::<Vec<_>>(),
        vec![AFTER],
        "C3: a busy slot must not keep serving the pre-revocation catalogue"
    );
}

// C6 — the positive control, and the reason C1–C5 cannot pass vacuously.
//
// Goes red when the gateway serves nobody: any change that degrades the
// per-user or shared path to deliver "isolation".
//
// NOT a gate on its siblings. Rust guarantees no in-module test order and runs
// cases in parallel, so this cannot run first. It states the property
// standalone; the per-cell premise assertions are what actually guard vacuity.
//
// GREEN BEFORE ANY IMPLEMENTATION, by design — it is labelled a control, not
// counted as coverage.
#[tokio::test]
async fn c6_control_a_populated_slot_and_the_shared_slot_both_serve() {
    let backend = per_user_backend("c6_hub");
    let (binding, _) = binding_and_prefix("alice", AUDIENCE).await;
    fill_slot(&backend, &binding).await;

    let shared = CountingUpstream::new();
    backend
        .set_pooled_transport_for_test(&PoolKey::Shared, Arc::clone(&shared) as Arc<dyn Transport>);
    backend
        .get_tools_shared()
        .await
        .expect("the shared slot serves its catalogue");

    assert!(
        backend.has_cached_tools_for(Some(&binding)),
        "C6: a populated per-user slot must serve its catalogue"
    );
    assert!(
        backend.has_cached_tools(),
        "C6: the shared slot must serve its catalogue"
    );
    assert_eq!(
        backend.get_cached_tool_names_for(Some(&binding)),
        vec![BEFORE.to_string()],
        "C6: the per-user slot serves real bytes, not an empty list"
    );
}

// C9 — the cheapest wrong implementation of §E2's nested loop, and currently
// invisible.
//
// Goes red when only the first matching backend is evicted: a loop that breaks
// on the first hit, or one that evicts per-subject rather than per-(subject,
// backend). Passes C1–C8 undetected, because every other cell uses one backend.
#[tokio::test]
async fn c9_every_backend_holding_the_subject_is_evicted() {
    let first = per_user_backend("c9_hub_a");
    let second = per_user_backend("c9_hub_b");
    // Two audiences, so the two bindings differ — which is the point: the
    // prefix leaves the audience free and must match both.
    let (binding_a, prefix) = binding_and_prefix("alice", AUDIENCE).await;
    let (binding_b, prefix_b) = binding_and_prefix("alice", "https://second.internal").await;
    assert_eq!(
        prefix, prefix_b,
        "C9 premise: one subject yields one prefix across audiences"
    );
    assert_ne!(
        binding_a, binding_b,
        "C9 premise: the two backends must hold DIFFERENT bindings"
    );

    let upstream_a = fill_slot(&first, &binding_a).await;
    let upstream_b = fill_slot(&second, &binding_b).await;
    assert!(
        first.cached_tools_count_for(Some(&binding_a)) > 0
            && second.cached_tools_count_for(Some(&binding_b)) > 0,
        "C9 premise: both backends' slots must be populated before revocation"
    );
    let (fills_a, fills_b) = (upstream_a.fills(), upstream_b.fills());

    upstream_a.revoke();
    upstream_b.revoke();
    // The production loop runs this per backend; the cell asserts each
    // separately so an implementation that stops after the first goes red.
    first.evict_identity_slots(&prefix).await;
    second.evict_identity_slots(&prefix).await;

    first
        .get_tools_for_binding(Some(&binding_a), &[])
        .await
        .expect("served");
    second
        .get_tools_for_binding(Some(&binding_b), &[])
        .await
        .expect("served");
    assert!(
        upstream_a.fills() > fills_a,
        "C9: the FIRST backend's slot must be evicted"
    );
    assert!(
        upstream_b.fills() > fills_b,
        "C9: the SECOND backend's slot must be evicted too"
    );
}

// C12 — created by this design, and it must land with it (§E3.1).
//
// Goes red when an eviction closes a live fetch's transport. `remove` is
// unconditional and is the atomic point; the CLOSE is conditional on
// `in_flight == 0`, re-checked under the transport WRITE guard. The reaper
// conflates the two because for its caller they have the same answer.
//
// Two-sided on purpose. "The transport is still open" alone is GREEN against a
// no-op evictor, so it cannot stand by itself; the removal half is what makes
// the cell discriminate. Key-absence is a sound assertion HERE and nowhere
// else, because this cell has no concurrent reader to legitimately recreate
// the slot, and it is read through the non-creating probe.
//
// HONEST LIMIT. §E3.1's full barrier — evict BETWEEN `begin_internal_activity_for`
// and `ensure_entry_started`, inside `get_cached_list_on` — is not reachable
// from a test today: the two calls are internal to that function and nothing
// exposes a seam between them. This cell pins the observable half (a busy
// slot's transport survives the eviction that removed it); the interleaving
// itself needs MVP piece 6's signature change before it can be driven.
#[tokio::test]
async fn c12_eviction_removes_a_busy_slot_without_closing_its_transport() {
    let backend = per_user_backend("c12_hub");
    let (binding, prefix) = binding_and_prefix("alice", AUDIENCE).await;
    let upstream = fill_slot(&backend, &binding).await;

    assert!(
        backend.pool_has_slot_for_test(&slot(&binding)),
        "C12 premise: the slot must exist before the revocation"
    );
    let claim = backend.begin_activity(&slot(&binding));
    assert!(
        claim.entry().in_flight.load(Ordering::SeqCst) > 0,
        "C12 premise: the slot must be busy when the revocation lands"
    );
    assert!(
        upstream.is_connected(),
        "C12 premise: the transport must be live before the revocation"
    );

    backend.evict_identity_slots(&prefix).await;

    assert!(
        !backend.pool_has_slot_for_test(&slot(&binding)),
        "C12: removal is UNCONDITIONAL — a busy slot must still be removed"
    );
    assert!(
        !upstream.was_closed(),
        "C12: the close is conditional — a busy slot's transport must survive"
    );
    drop(claim);
}
