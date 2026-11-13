// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A direct completed replay (stage 7b) records the slot its first execution
//! ran on, looked up as stored: never the replaying caller's current slot nor
//! the shared one. One caller whose propagated binding changes between the
//! run and the replay (as a rotated grant changes it) keeps the execution
//! store's owner, so the replay is served, while three slots declare three
//! different things.

use super::*;

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
            cache_binding: format!("{}@{}#{generation}", identity.subject(), backend.audience),
            subject_key: identity.subject().to_owned(),
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
async fn generational(dir: &Arc<tempfile::TempDir>) -> (Fx, Arc<Generations>) {
    let log = logger(dir, AuditFailurePolicy::FailClosed);
    let generations = Arc::new(Generations(AtomicUsize::new(1)));
    let strategy = Arc::clone(&generations);
    let fx =
        super::super::direct_guards_fixture::fixture_propagating_logged(Answer::Ok, log, |meta| {
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
    let ran = super::super::direct_continuation_tests::dispatched(fx);
    generations.0.store(2, Ordering::SeqCst);
    between();
    let _ = super::super::backend_handlers::direct_lease_seams::served();
    let before = decisions(dir).len();
    let (_, replay) = keyed(fx, "alice", key).await;
    assert!(
        replay.get("result").is_some(),
        "premise: the replay delivered: {replay}"
    );
    assert_eq!(
        super::super::backend_handlers::direct_lease_seams::served(),
        Some(super::super::backend_handlers::direct_lease_seams::Served::Execution),
        "premise: stage 7b answered, not 7a"
    );
    assert_eq!(
        super::super::direct_continuation_tests::dispatched(fx),
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
    let dir = crate::test_dir_keep::kept_tempdir();
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
    let dir = crate::test_dir_keep::kept_tempdir();
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
    let dir = crate::test_dir_keep::kept_tempdir();
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
    let dir = crate::test_dir_keep::kept_tempdir();
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
    assert!(
        decision.get("declared_effect_source").is_none(),
        "{decision}"
    );
}

/// A4, the stored slot evicted after the run: no effect, never alice's
/// current slot (may-write) nor the shared slot (read-only).
#[tokio::test]
async fn a_direct_completed_replay_of_an_evicted_slot_records_none() {
    let dir = crate::test_dir_keep::kept_tempdir();
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
    assert!(
        decision.get("declared_effect_source").is_none(),
        "{decision}"
    );
}
