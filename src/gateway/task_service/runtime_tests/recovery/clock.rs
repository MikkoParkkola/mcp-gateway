// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8202 part 2 (P2), T11: startup recovery on a store clock that reads
//! before 1970. A recovery settle is a recorder: it dates the row at the store
//! clock, so with no readable store clock the row is left as it was and the
//! next readable pass settles it.

use super::*;
use crate::gateway::task_service::{TaskStatus, open_runtime_with_recovery};

/// MIK-8202 RECORDER rule, P2 row 12. Mutant: settle at 1969 (raw
/// a raw chrono read ignoring the store clock).
#[tokio::test]
async fn t11_recovery_on_an_unreadable_store_clock_leaves_the_row_for_the_next_pass() {
    // GIVEN: an interrupted, never-dispatched row from a previous process
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("tasks");
    let row = vec![("x11", Seed::Undispatched, rows().remove(0).2)];
    let seeded = timeout(BUDGET, seed_store(&dir, row))
        .await
        .expect("seeded");
    // WHEN: startup recovery runs with the store clock before 1970
    let attempt = timeout(
        BUDGET,
        open_runtime_with_recovery(
            &dir,
            1,
            StoreLimits::default(),
            test_subscriptions(),
            fresh_admission(),
            &[],
            |service, _| {
                service.store.set_clock_for_test(Some(
                    chrono::DateTime::from_timestamp(-1, 0).expect("before 1970"),
                ));
            },
        ),
    )
    .await
    .expect("startup does not hang");
    if let Ok((service, _)) = attempt {
        service.shutdown().await.expect("custody released");
    }
    // THEN: the row is exactly as the previous process left it
    let reader = TaskService::open(&dir, StoreLimits::default(), fresh_admission())
        .await
        .expect("the store reopens");
    let untouched = reader.get(OWNER, &seeded[0].id).expect("still readable");
    assert_eq!(untouched.task.status(), TaskStatus::Working);
    assert_eq!(untouched.revision, seeded[0].revision, "no rewrite");
    reader.close().await.expect("custody released");
    // AND: the next readable pass settles it
    let (service, _executor) = open_runtime_with_admission(
        &dir,
        1,
        StoreLimits::default(),
        test_subscriptions(),
        fresh_admission(),
    )
    .await
    .expect("a readable clock recovers");
    let settled = service.get(OWNER, &seeded[0].id).expect("readable");
    assert!(judge(&seeded[0], &settled.task, settled.revision).is_empty());
    service.shutdown().await.expect("custody released");
}
