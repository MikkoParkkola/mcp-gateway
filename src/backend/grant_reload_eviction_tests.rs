// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `MIK-7334.CATALOGUE.1` revocation conjunct — the chain COMPOSED.
//!
//! T9 of `docs/internal/design/2026-09-22-live-identity-grant-reload.md` §3,
//! and the only cell that drives `reload_identity_grants` against a POPULATED
//! per-user pool slot. Its siblings each pin one link:
//! `config_reload/grant_change_trigger_tests.rs` the trigger, C7/C10a/C10b the
//! prefix formula, `slot_eviction_tests.rs` the evictor given a prefix. All
//! three can be green while the chain is broken.
//!
//! ITS OWN FILE, not a cell in `slot_eviction_tests.rs`, only because that one
//! is at the 800-line ceiling. It reuses that module's fixtures through
//! `pub(super)` rather than restating them: a fixture that spells its own
//! binding cannot observe the two sides diverging, which is what this cell is
//! for.
//!
//! Both harness rules of `slot_eviction_tests.rs` §3.1 apply unchanged — no
//! absence assertion through a cache accessor, and the premise asserted in the
//! cell's own body.

use std::sync::Arc;
use std::time::Duration;

use super::slot_eviction_tests::{
    AUDIENCE, ISSUER, binding_and_prefix, fill_slot, per_user_backend, slot,
};
use crate::config::FailsafeConfig;
use crate::identity_grants::{GrantAgent, GrantScope, GrantSubject, IdentityGrant};

/// One grant row, with the subject authority the pool binding was minted under.
///
/// `authority` is [`ISSUER`] at every call site here, and it has to be: the
/// production chain reconstructs the eviction prefix FROM THIS FIELD, so a row
/// naming another authority describes a different person and correctly evicts
/// nothing.
fn grant_row(grant_id: &str, subject: &str, scope: GrantScope) -> IdentityGrant {
    IdentityGrant {
        grant_id: grant_id.to_string(),
        subject: GrantSubject::new(ISSUER.to_string(), subject.to_string(), None),
        agent: GrantAgent::Any,
        capability: "cal".to_string(),
        tool: None,
        scope,
        owner: None,
        expires_at: None,
        revoked_at: None,
        provenance: "fixture".to_string(),
        reason: "T9 composed cell".to_string(),
    }
}

/// Write a grants file the production reader accepts.
fn write_grants(path: &std::path::Path, rows: &[IdentityGrant]) {
    let file = serde_json::json!({
        "schema_version": crate::identity_grants::IDENTITY_GRANTS_FILE_SCHEMA_VERSION,
        "grants": rows,
    });
    crate::gateway::test_helpers::write_owner_only(
        path,
        serde_json::to_vec_pretty(&file).expect("serialize"),
    )
    .expect("write");
}

// T9 — the two designs COMPOSED, and the only cell that observes the chain end
// to end.
//
// Goes red when `reload_identity_grants` → `changed_grant_subjects` →
// `identity_binding_prefix` → `evict_identity_slots` reports success and evicts
// nothing. Every link is pinned alone — the trigger by
// `config_reload/grant_change_trigger_tests.rs`, the prefix formula by
// C7/C10a/C10b, the evictor GIVEN a prefix by C1–C13 above — and all three
// stayed green while the chain was broken: `identity_binding_prefix` once
// truncated the subject key by BYTES where the pool binding counts CHARACTERS,
// and the reload logged `slots_evicted = 0` through its success path. A
// composed cell is the only thing that sees that class, and the success string
// is not read here for exactly that reason.
//
// THE PREFIX IS NEVER SPELLED IN THIS CELL. `binding_and_prefix`'s second
// return value is discarded on purpose: a cell that recomputed the prefix and
// asserted the binding carries it would go red at its own PREMISE under a
// broken formula, and the composition would never run. The only prefix
// exercised is the one the production chain derives from the grant row; a
// mismatch surfaces as alice's slot surviving, which is the observable.
//
// THE FIRST RELOAD RUNS BEFORE THE SLOTS ARE FILLED, also on purpose.
// Publishing empty → two rows is itself a change, so it evicts alice; filling
// afterwards makes the SECOND reload — the rotation — the only eviction these
// assertions can be reading.
//
// BOB'S ROW SITS IN BOTH FILES, byte-identical. Without it the file names only
// alice, and an implementation that evicts every subject MENTIONED rather than
// every subject CHANGED passes unnoticed. With it, the trigger must return
// alice alone.
//
// TWO-SIDED, and both halves are load-bearing. The A half goes red against a
// no-op evictor, against dropping `changed_grant_subjects`' unequal-row arm,
// and against a wrong-length prefix. The B half is the only one that a blunt
// "evict every per-user slot on any reload" fails.
#[tokio::test]
async fn t9_a_grant_rotation_through_the_reload_trigger_evicts_only_that_subject() {
    let backend = per_user_backend("t9_hub");
    let registry = Arc::new(super::BackendRegistry::new());
    assert!(
        registry.register(Arc::clone(&backend)),
        "T9 premise: the reload only reaches backends the registry holds"
    );
    let meta = crate::gateway::test_helpers::MetaMcp::new(Arc::clone(&registry));

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("grants.json");
    write_grants(
        &path,
        &[
            grant_row("g1", "alice", GrantScope::Read),
            grant_row("g2", "bob", GrantScope::Read),
        ],
    );
    let (store, epoch) = meta.identity_grant_sink();
    let ctx = crate::config_reload::ReloadContext::new(
        path.clone(),
        Arc::new(crate::config_reload::LiveConfig::new(
            crate::config::Config::default(),
        )),
        Arc::clone(&registry),
        FailsafeConfig::default(),
        Duration::from_secs(300),
    )
    .with_identity_grant_sink(Arc::new(crate::config_reload::IdentityGrantSink::new(
        store,
        epoch,
        path.clone(),
    )));

    // Baseline: the live store now holds both rows, so the rotation below is
    // the only change the second reload can see.
    ctx.reload_identity_grants()
        .await
        .expect("a wired sink reloads")
        .expect("the fixture file is valid");

    let (alice, _) = binding_and_prefix("alice", AUDIENCE).await;
    let (bob, _) = binding_and_prefix("bob", AUDIENCE).await;
    let alice_upstream = fill_slot(&backend, &alice).await;
    let bob_upstream = fill_slot(&backend, &bob).await;

    // PREMISE, in this cell's own body: BOTH slots are populated before the
    // rotation. Without it a fixture that silently failed to populate would
    // make every assertion below vacuously true.
    assert!(
        backend.cached_tools_count_for(Some(&alice)) > 0
            && backend.cached_tools_count_for(Some(&bob)) > 0,
        "T9 premise: both slots must be populated before the rotation"
    );
    let bob_before = backend.get_cached_tool_names_for(Some(&bob));
    let bob_fills_before = bob_upstream.fills();

    // A ROTATION, NOT A REMOVAL: the same `grant_id`, carrying different
    // content. The row stays present, so only the unequal-row arm of
    // `changed_grant_subjects` can name alice.
    write_grants(
        &path,
        &[
            grant_row("g1", "alice", GrantScope::Execute),
            grant_row("g2", "bob", GrantScope::Read),
        ],
    );
    alice_upstream.revoke();
    bob_upstream.revoke();
    ctx.reload_identity_grants()
        .await
        .expect("a wired sink reloads")
        .expect("the rotated file is valid");

    // A half, and it is read through the NON-CREATING probe: every cache
    // accessor routes through `or_insert_with` and would recreate the key it
    // then truthfully reports empty (module header, Rule 1).
    assert!(
        !backend.pool_has_slot_for_test(&slot(&alice)),
        "T9: a rotation of alice's grant must remove alice's populated slot"
    );
    // B half, both positive: bob's catalogue is byte-identical and bob did not
    // refetch. Had bob been evicted his upstream now serves AFTER, so the
    // equality fails as well as the counter.
    assert_eq!(
        backend.get_cached_tool_names_for(Some(&bob)),
        bob_before,
        "T9: an unchanged subject's catalogue must be byte-identical afterwards"
    );
    assert_eq!(
        bob_upstream.fills(),
        bob_fills_before,
        "T9: an unchanged subject must not be forced to refetch"
    );
}
