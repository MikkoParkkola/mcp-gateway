// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Failing tests for S2 — transactional `import_tasks` and the principal `owner`
//! accessor. Written BEFORE the runtime they name.
//!
//! These compile against a refusing scaffold (`import_tasks` → `Capacity`,
//! `owner` → `InvalidIdentity`) and fail there at the first contract claim.
//! They earn green only against a later batch/hasher implementation.

use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{Value, json};

use super::*;

fn fixture() -> Arc<ExecutionAdmission> {
    let now = Arc::new(AtomicU64::new(1_000));
    ExecutionAdmission::new(Arc::new(move || now.load(Ordering::SeqCst)))
}

static OPERATION: LazyLock<Value> =
    LazyLock::new(|| json!({"backend": "orders", "tool": "create", "arguments": {"quantity": 1}}));
static REPRESENTATION: LazyLock<Value> = LazyLock::new(|| json!({"full": false}));

fn task_request<'a>(principal: &'a str, key: &'a str) -> Request<'a> {
    Request {
        principal,
        key,
        operation: &OPERATION,
        representation: &REPRESENTATION,
        mode: Mode::Task,
    }
}

fn owned_task(outcome: Result<TaskAdmission, Refusal>) -> TaskLease {
    match outcome {
        Ok(TaskAdmission::Owned(lease)) => lease,
        other => panic!("expected one task owner, got {other:?}"),
    }
}

fn existing_task(outcome: Result<TaskAdmission, Refusal>) -> (String, TaskBinding) {
    match outcome {
        Ok(TaskAdmission::Existing { task_id, binding }) => (task_id, binding),
        other => panic!("expected the existing task handle, got {other:?}"),
    }
}

/// Publish one task and hand back the binding admission retained for it.
/// The lease is consumed into publication so Drop cannot abandon the seed.
fn published(
    service: &Arc<ExecutionAdmission>,
    principal: &str,
    key: &str,
    id: &str,
) -> TaskBinding {
    let lease = owned_task(service.admit_task(task_request(principal, key)));
    let binding = lease.binding().clone();
    lease.into_publication().publish(id);
    binding
}

fn restored_from(binding: &TaskBinding) -> RestoredBinding {
    RestoredBinding {
        identity: binding.identity().to_owned(),
        principal_digest: binding.principal_digest().to_owned(),
        operation: binding.operation().to_owned(),
        representation: binding.representation().to_owned(),
        metadata_bytes: binding.metadata_bytes(),
    }
}

// Row 1 — valid first, malformed later: exact validation refusal, all-or-nothing.
#[test]
fn import_01_valid_then_malformed_rolls_back_and_corrected_batch_can_retry() {
    let donor = fixture();
    let first = published(&donor, "oidc:acme:alice", "k-1", "task-1");
    let second = published(&donor, "oidc:acme:alice", "k-2", "task-2");
    let donor_held = donor.snapshot();

    let service = fixture();
    let seed = published(&service, "oidc:acme:alice", "seed", "task-seed");
    let seeded = service.snapshot();
    assert!(seeded.metadata_bytes > 0);

    let good_first = restored_from(&first);
    let mut malformed_second = restored_from(&second);
    malformed_second.identity = "z".repeat(64);

    // Original order is the discriminator: a loop that commits as it goes would
    // already own `k-1` when the later record fails validation.
    assert_eq!(
        service
            .import_tasks(vec![
                (good_first.clone(), "task-1".to_owned()),
                (malformed_second, "task-2".to_owned()),
            ])
            .unwrap_err(),
        Refusal::InvalidIdentity
    );
    assert_eq!(service.snapshot(), seeded);
    assert_eq!(donor.snapshot(), donor_held);

    // First key is unclaimed: a temporary Owned lease must be dropped before
    // the corrected batch, or the retry would see InFlight instead of a hole.
    let probe = owned_task(service.admit_task(task_request("oidc:acme:alice", "k-1")));
    assert_eq!(probe.binding().identity(), first.identity());
    drop(probe);
    assert_eq!(service.snapshot(), seeded);

    // An empty task ID is the other malformed record: the binding validates but
    // the handle it restores would be unusable, so the batch owes the same
    // refusal and the same rollback.
    assert_eq!(
        service
            .import_tasks(vec![
                (good_first.clone(), "task-1".to_owned()),
                (restored_from(&second), String::new()),
            ])
            .unwrap_err(),
        Refusal::InvalidIdentity
    );
    assert_eq!(service.snapshot(), seeded);
    assert_eq!(donor.snapshot(), donor_held);

    let empty_id_probe = owned_task(service.admit_task(task_request("oidc:acme:alice", "k-1")));
    assert_eq!(empty_id_probe.binding().identity(), first.identity());
    drop(empty_id_probe);
    assert_eq!(service.snapshot(), seeded);

    service
        .import_tasks(vec![
            (good_first, "task-1".to_owned()),
            (restored_from(&second), "task-2".to_owned()),
        ])
        .expect("the same records in the same order import once the later one is well-formed");

    let (id1, b1) = existing_task(service.admit_task(task_request("oidc:acme:alice", "k-1")));
    let (id2, b2) = existing_task(service.admit_task(task_request("oidc:acme:alice", "k-2")));
    let (seed_id, seed_binding) =
        existing_task(service.admit_task(task_request("oidc:acme:alice", "seed")));
    assert_eq!(id1, "task-1");
    assert_eq!(id2, "task-2");
    assert_eq!(b1, first);
    assert_eq!(b2, second);
    assert_eq!(seed_id, "task-seed");
    assert_eq!(seed_binding, seed);
    assert_eq!(donor.snapshot(), donor_held);
}

// Row 2 — valid first, later collision with a published key; in-batch duplicate.
#[test]
fn import_02_published_collision_and_in_batch_duplicate_leave_seed_untouched() {
    let donor = fixture();
    let first = published(&donor, "oidc:acme:alice", "k-1", "task-1");
    let dup = published(&donor, "oidc:acme:alice", "dup", "task-dup-a");
    let donor_held = donor.snapshot();

    let service = fixture();
    let existing = published(&service, "oidc:acme:alice", "seed", "task-seed");
    let seeded = service.snapshot();

    // Same identity as the seed, different handle: overwrite would surface here.
    let colliding = restored_from(&existing);
    assert_eq!(
        service
            .import_tasks(vec![
                (restored_from(&first), "task-1".to_owned()),
                (colliding, "task-other".to_owned()),
            ])
            .unwrap_err(),
        Refusal::Mismatch
    );
    assert_eq!(service.snapshot(), seeded);

    let (kept_id, kept) =
        existing_task(service.admit_task(task_request("oidc:acme:alice", "seed")));
    assert_eq!(kept_id, "task-seed");
    assert_eq!(kept, existing);

    let probe = owned_task(service.admit_task(task_request("oidc:acme:alice", "k-1")));
    assert_eq!(probe.binding().identity(), first.identity());
    drop(probe);
    assert_eq!(service.snapshot(), seeded);

    // Same identity AND the same handle the seed already carries: reimporting
    // an identical record is still a collision, never a silent no-op.
    assert_eq!(
        service
            .import_tasks(vec![
                (restored_from(&first), "task-1".to_owned()),
                (restored_from(&existing), "task-seed".to_owned()),
            ])
            .unwrap_err(),
        Refusal::Mismatch
    );
    assert_eq!(service.snapshot(), seeded);

    let (same_handle_id, same_handle) =
        existing_task(service.admit_task(task_request("oidc:acme:alice", "seed")));
    assert_eq!(same_handle_id, "task-seed");
    assert_eq!(same_handle, existing);

    let same_handle_probe = owned_task(service.admit_task(task_request("oidc:acme:alice", "k-1")));
    assert_eq!(same_handle_probe.binding().identity(), first.identity());
    drop(same_handle_probe);
    assert_eq!(service.snapshot(), seeded);

    let restored = restored_from(&dup);
    assert_eq!(
        service
            .import_tasks(vec![
                (restored.clone(), "task-dup-a".to_owned()),
                (restored, "task-dup-b".to_owned()),
            ])
            .unwrap_err(),
        Refusal::Mismatch
    );
    assert_eq!(service.snapshot(), seeded);

    // The same binding with the same handle twice: deduplicating the pair would
    // hide a corrupt record instead of refusing it.
    assert_eq!(
        service
            .import_tasks(vec![
                (restored_from(&dup), "task-dup-a".to_owned()),
                (restored_from(&dup), "task-dup-a".to_owned()),
            ])
            .unwrap_err(),
        Refusal::Mismatch
    );
    assert_eq!(service.snapshot(), seeded);
    assert_eq!(donor.snapshot(), donor_held);
}

// Row 3 — anti-stub: a valid two-record batch is recoverable; empty is a no-op.
#[test]
fn import_03_valid_two_record_batch_retries_existing_and_empty_is_noop() {
    let donor = fixture();
    let first = published(&donor, "oidc:acme:alice", "k-1", "task-1");
    let second = published(&donor, "oidc:acme:alice", "k-2", "task-2");

    let service = fixture();
    let seed = published(&service, "oidc:acme:alice", "seed", "task-seed");
    let seeded = service.snapshot();

    service
        .import_tasks(Vec::new())
        .expect("an empty batch is a no-op");
    assert_eq!(service.snapshot(), seeded);

    service
        .import_tasks(vec![
            (restored_from(&first), "task-1".to_owned()),
            (restored_from(&second), "task-2".to_owned()),
        ])
        .expect("a well-formed two-record batch imports");

    assert_eq!(service.snapshot().entries, 3);
    assert_eq!(
        service.snapshot().metadata_bytes,
        seed.metadata_bytes() + first.metadata_bytes() + second.metadata_bytes()
    );
    assert_eq!(service.snapshot().result_bytes, 0);

    let (id1, b1) = existing_task(service.admit_task(task_request("oidc:acme:alice", "k-1")));
    let (id2, b2) = existing_task(service.admit_task(task_request("oidc:acme:alice", "k-2")));
    let (seed_id, seed_binding) =
        existing_task(service.admit_task(task_request("oidc:acme:alice", "seed")));
    assert_eq!(id1, "task-1");
    assert_eq!(id2, "task-2");
    assert_eq!(b1, first);
    assert_eq!(b2, second);
    assert_eq!(seed_id, "task-seed");
    assert_eq!(seed_binding, seed);
}

// Row 4 — owner accessor reuses the live principal digest bound; no new policy.
#[test]
fn owner_01_principal_digest_matches_binding_and_bounds_identity() {
    let service = fixture();
    let binding = published(&service, "oidc:acme:alice", "k-1", "task-1");
    let held = service.snapshot();

    let owner = ExecutionAdmission::owner("oidc:acme:alice")
        .expect("a non-empty in-limit principal hashes");
    assert_eq!(owner.as_digest(), binding.principal_digest());
    assert_eq!(
        owner.as_digest(),
        canonical_json_sha256(&json!([
            "mcp-gateway.execution-admission.principal.v1",
            "oidc:acme:alice"
        ]))
    );

    let other =
        ExecutionAdmission::owner("oidc:acme:mallory").expect("a different principal hashes");
    assert_ne!(other.as_digest(), owner.as_digest());
    assert_ne!(other.as_digest(), binding.principal_digest());

    assert_eq!(
        ExecutionAdmission::owner("").err(),
        Some(Refusal::InvalidIdentity)
    );
    assert_eq!(
        ExecutionAdmission::owner(&"x".repeat(METADATA_LIMIT + 1)).err(),
        Some(Refusal::MetadataTooLarge)
    );

    let at_limit = "y".repeat(METADATA_LIMIT);
    let at_limit_owner = ExecutionAdmission::owner(&at_limit)
        .expect("exactly METADATA_LIMIT is hashed, not refused");
    assert_eq!(
        at_limit_owner.as_digest(),
        canonical_json_sha256(&json!([
            "mcp-gateway.execution-admission.principal.v1",
            at_limit.as_str()
        ]))
    );

    // The established bound counts bytes. A two-byte principal reaches it at
    // half the characters, so a character-count implementation would both
    // refuse this one and accept the one below.
    let wide_at_limit = "д".repeat(METADATA_LIMIT / 2);
    assert_eq!(wide_at_limit.len(), METADATA_LIMIT);
    assert_eq!(wide_at_limit.chars().count(), METADATA_LIMIT / 2);
    let wide_owner = ExecutionAdmission::owner(&wide_at_limit)
        .expect("METADATA_LIMIT bytes of multibyte principal is hashed, not refused");
    assert_eq!(
        wide_owner.as_digest(),
        canonical_json_sha256(&json!([
            "mcp-gateway.execution-admission.principal.v1",
            wide_at_limit.as_str()
        ]))
    );

    let mut wide_over_limit = wide_at_limit.clone();
    wide_over_limit.push('x');
    assert_eq!(wide_over_limit.len(), METADATA_LIMIT + 1);
    assert_eq!(wide_over_limit.chars().count(), METADATA_LIMIT / 2 + 1);
    assert_eq!(
        ExecutionAdmission::owner(&wide_over_limit).err(),
        Some(Refusal::MetadataTooLarge)
    );
    assert_eq!(service.snapshot(), held);
}

// Row 5 — commit-time accounting failure: an overflow refuses the whole batch.
#[test]
fn import_04_generation_overflow_refuses_capacity_and_commits_nothing() {
    let donor = fixture();
    let first = published(&donor, "oidc:acme:alice", "k-1", "task-1");
    let second = published(&donor, "oidc:acme:alice", "k-2", "task-2");

    let service = fixture();
    published(&service, "oidc:acme:alice", "seed", "task-seed");
    let seeded = service.snapshot();

    // One generation left: the first record can be numbered, the second cannot.
    // A per-entry commit would spend it and keep what it had already inserted.
    service.state.lock().generation = u64::MAX - 1;

    assert_eq!(
        service
            .import_tasks(vec![
                (restored_from(&first), "task-1".to_owned()),
                (restored_from(&second), "task-2".to_owned()),
            ])
            .unwrap_err(),
        Refusal::Capacity
    );
    assert_eq!(service.snapshot(), seeded);

    // An Owned probe cannot testify here: admission needs a generation of its
    // own, so it would refuse `Capacity` whether or not the batch inserted
    // anything. Read the map directly, under the lock the transaction used.
    let state = service.state.lock();
    assert_eq!(state.generation, u64::MAX - 1);
    assert_eq!(state.entries.len(), seeded.entries);
    assert_eq!(state.metadata_bytes, seeded.metadata_bytes);
    assert_eq!(state.result_bytes, seeded.result_bytes);
    assert!(!state.entries.contains_key(first.identity()));
    assert!(!state.entries.contains_key(second.identity()));
    drop(state);
}

// Row 6 — a NEW identity claiming a handle a held identity already published.
// The in-batch handle set refuses two records naming one handle; held state is
// checked for identities only, so this collision has to be refused under the
// same mutex or one task ends up with two conflicting ownership bindings.
#[test]
fn import_05_new_identity_reusing_published_handle_refuses_and_reserves_nothing() {
    let donor = fixture();
    let first = published(&donor, "oidc:acme:alice", "k-1", "task-1");
    let second = published(&donor, "oidc:acme:alice", "k-2", "task-2");
    let donor_held = donor.snapshot();

    let service = fixture();
    let seed = published(&service, "oidc:acme:alice", "seed", "task-seed");
    let seeded = service.snapshot();

    // Both records are new identities the seed does not hold, so the identity
    // check passes for each. Only the later record's handle is already owned —
    // by `seed`, under a DIFFERENT identity, which is what makes it a collision
    // no in-batch set can see.
    assert_ne!(first.identity(), seed.identity());
    assert_ne!(second.identity(), seed.identity());
    assert_eq!(
        service
            .import_tasks(vec![
                (restored_from(&first), "task-1".to_owned()),
                (restored_from(&second), "task-seed".to_owned()),
            ])
            .unwrap_err(),
        Refusal::Mismatch
    );
    assert_eq!(service.snapshot(), seeded);

    // The seed keeps its own handle and its own binding: the refused record must
    // not have rebound `task-seed` to the identity that asked for it.
    let (kept_id, kept) =
        existing_task(service.admit_task(task_request("oidc:acme:alice", "seed")));
    assert_eq!(kept_id, "task-seed");
    assert_eq!(kept, seed);

    // Neither proposed identity is reserved. The valid first record is the one a
    // commit-as-you-go loop would already own; the colliding one is the record
    // that failed. Each probe is dropped so the hole stays a hole.
    let first_probe = owned_task(service.admit_task(task_request("oidc:acme:alice", "k-1")));
    assert_eq!(first_probe.binding().identity(), first.identity());
    drop(first_probe);
    assert_eq!(service.snapshot(), seeded);

    let second_probe = owned_task(service.admit_task(task_request("oidc:acme:alice", "k-2")));
    assert_eq!(second_probe.binding().identity(), second.identity());
    drop(second_probe);
    assert_eq!(service.snapshot(), seeded);

    assert_eq!(donor.snapshot(), donor_held);

    // Control: the same two records import once the later handle is its own, so
    // the refusal above is the handle collision and nothing else.
    service
        .import_tasks(vec![
            (restored_from(&first), "task-1".to_owned()),
            (restored_from(&second), "task-2".to_owned()),
        ])
        .expect("the same records import once the later handle is not already published");
    assert_eq!(service.snapshot().entries, 3);
    assert_eq!(donor.snapshot(), donor_held);
}

// The batch transaction's capacity boundary, stated beside these rows because it
// reuses their fixtures and helpers. Path is relative to this file's directory.
#[path = "task_service_capacity_tests.rs"]
mod capacity_tests;
