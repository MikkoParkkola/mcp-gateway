// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Capacity-boundary falsifiers for the batch import transaction.
//!
//! `import_tasks` bounds a batch by what the store would HOLD once it commits,
//! and that bound is inclusive: exactly `SLOT_LIMIT` held records is the last
//! accepted state, and one more is refused whole. Both claims are stated through
//! the supported operations only — a published task, the binding a restart would
//! restore, and `admit_task` — because the boundary is a contract about what the
//! store accepts, not about how it counts.

use std::sync::LazyLock;

use super::*;

// Named through the module that owns them rather than through the parent's own
// glob, so this file states its dependencies instead of inheriting them.
use crate::idempotency::admission::{Refusal, RestoredBinding, SLOT_LIMIT};

const PRINCIPAL: &str = "oidc:acme:alice";

fn import_key(index: usize) -> String {
    format!("import-k-{index}")
}

fn import_handle(index: usize) -> String {
    format!("task-import-{index}")
}

/// One donor population, built once for the whole test binary: `SLOT_LIMIT`
/// published tasks, each with the binding a restart would restore and the handle
/// it was published under. A live admission holds at most `SLOT_LIMIT` itself,
/// so this is the largest population one donor can testify about — and exactly
/// what the over-limit row needs beside a single held record.
static RESTORABLE: LazyLock<Vec<(RestoredBinding, String)>> = LazyLock::new(|| {
    let donor = fixture();
    (0..SLOT_LIMIT)
        .map(|index| {
            let handle = import_handle(index);
            let binding = published(&donor, PRINCIPAL, &import_key(index), &handle);
            (restored_from(&binding), handle)
        })
        .collect()
});

// Row A — a batch that lands exactly on `SLOT_LIMIT` held records commits, and
// what was already held survives it. `held > SLOT_LIMIT` is the only comparison
// that accepts this state: `held == SLOT_LIMIT` and `held >= SLOT_LIMIT` both
// refuse the batch that reaches the bound exactly.
#[test]
fn capacity_01_a_batch_landing_exactly_on_the_slot_limit_imports() {
    let service = fixture();
    let seed_a = published(&service, PRINCIPAL, "seed-a", "task-seed-a");
    let seed_b = published(&service, PRINCIPAL, "seed-b", "task-seed-b");
    let seeded = service.snapshot();
    assert_eq!(seeded.entries, 2);
    assert!(seeded.metadata_bytes > 0);

    let batch: Vec<_> = RESTORABLE.iter().take(SLOT_LIMIT - 2).cloned().collect();
    // The arithmetic is the row. One record fewer and the commit would land
    // BELOW the bound, where every comparison agrees, and this test would prove
    // nothing about where the limit is.
    assert_eq!(seeded.entries + batch.len(), SLOT_LIMIT);
    let imported_bytes: usize = batch.iter().map(|(record, _)| record.metadata_bytes).sum();

    service
        .import_tasks(&batch)
        .expect("exactly SLOT_LIMIT held records is the bound, not one past it");

    let held = service.snapshot();
    assert_eq!(held.entries, SLOT_LIMIT);
    assert_eq!(held.metadata_bytes, seeded.metadata_bytes + imported_bytes);
    assert_eq!(held.result_bytes, 0);

    // The records that were already there keep their own handles and bindings: a
    // full store is not an overwritten one.
    let (seed_a_id, kept_a) = existing_task(service.admit_task(task_request(PRINCIPAL, "seed-a")));
    assert_eq!(seed_a_id, "task-seed-a");
    assert_eq!(kept_a, seed_a);
    let (second_seed_id, kept_b) =
        existing_task(service.admit_task(task_request(PRINCIPAL, "seed-b")));
    assert_eq!(second_seed_id, "task-seed-b");
    assert_eq!(kept_b, seed_b);

    // The first and last imported records are recoverable by their own keys, so
    // the accepted batch restored bindings rather than merely counting slots.
    for index in [0, SLOT_LIMIT - 3] {
        let (record, handle) = RESTORABLE.get(index).expect("the donor holds this record");
        let (task_id, recovered) =
            existing_task(service.admit_task(task_request(PRINCIPAL, &import_key(index))));
        assert_eq!(&task_id, handle);
        assert_eq!(&restored_from(&recovered), record);
    }

    // Accepting the bound does not move it: the store is now full, and a NEW key
    // is refused for capacity without disturbing anything held.
    assert_eq!(
        service
            .admit_task(task_request(PRINCIPAL, "one-over"))
            .unwrap_err(),
        Refusal::Capacity
    );
    assert_eq!(service.snapshot(), held);
}

// Row B — one record past the bound is refused as a whole transaction: nothing
// held moves and nothing in the batch is reserved. A comparison that refuses
// only the exact bound (`held == SLOT_LIMIT`) accepts this batch and commits
// SLOT_LIMIT + 1 records, which is the state the limit exists to prevent.
#[test]
fn capacity_02_a_batch_one_record_over_the_slot_limit_commits_nothing() {
    let service = fixture();
    let seed = published(&service, PRINCIPAL, "seed-a", "task-seed-a");
    let seeded = service.snapshot();
    assert_eq!(seeded.entries, 1);
    assert!(seeded.metadata_bytes > 0);

    let batch = RESTORABLE.to_vec();
    assert_eq!(seeded.entries + batch.len(), SLOT_LIMIT + 1);

    assert_eq!(service.import_tasks(&batch).unwrap_err(), Refusal::Capacity);
    assert_eq!(service.snapshot(), seeded);

    // The held record keeps its handle and its binding: a refused batch is not a
    // partial one, and the seed is what proves the counters were not rewritten.
    let (kept_id, kept) = existing_task(service.admit_task(task_request(PRINCIPAL, "seed-a")));
    assert_eq!(kept_id, "task-seed-a");
    assert_eq!(kept, seed);

    // Nothing the batch named is reserved. The first record is the one a
    // commit-as-you-go loop would already own; the last is the one that crossed
    // the bound. Each probe is dropped, so the hole it proves stays a hole.
    for index in [0, SLOT_LIMIT - 1] {
        let (record, _) = RESTORABLE.get(index).expect("the donor holds this record");
        let probe = owned_task(service.admit_task(task_request(PRINCIPAL, &import_key(index))));
        assert_eq!(probe.binding().identity(), record.identity.as_str());
        drop(probe);
        assert_eq!(service.snapshot(), seeded);
    }
}
