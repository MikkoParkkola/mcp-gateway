// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Concurrency bounds: the in-flight limit and delegated store commits.

use super::*;

#[test]
fn the_in_flight_bound_refuses_rather_than_queueing_without_limit() {
    let _serial = worker_test_lock();
    let tmp = tempfile::TempDir::new().expect("root");
    seed(tmp.path(), &[(&alice(), unexpired())]);

    multi_thread(async {
        let fx = start(tmp.path(), 1);
        assert_eq!(
            fx.handle.capacity(),
            1,
            "capacity is a constructor argument; the approved schema has no worker-queue field"
        );
        let recording = store_probe::watch(&config(tmp.path()).store_dir);
        let mut park = recording.park(StoreOp::Lookup);

        let occupying = {
            let handle = Arc::clone(&fx.handle);
            tokio::spawn(async move { handle.resolve(&alice()).await })
        };
        // The bound is only occupied once the phase is actually entered.
        park.wait_entered().await;

        assert_eq!(
            domain_err(fx.handle.resolve(&alice()).await, "over the bound"),
            CustodyError::Busy,
            "over the in-flight bound the answer is a typed refusal, never an unbounded queue"
        );
        park.release();
        refuse_scaffold(
            occupying.await.expect("occupying task"),
            "occupying command",
        )
        .expect("the in-flight command still completes");

        // The control: with the bound free again the same call succeeds, so the
        // refusal was capacity and not a permanent failure.
        refuse_scaffold(fx.handle.resolve(&alice()).await, "after the bound frees")
            .expect("capacity refusals are transient");
        drop(recording);
    });
}

/// The two delegating wrappers the handle exposes and nothing else drove:
/// `invalidate` and `commit_grant_if`.
///
/// This is service delegation, not a consent journey: the handle must forward
/// to the one `AccountService` and reach the REAL store, and its outcomes must
/// be the service's own. Three things are pinned together because they are one
/// causal chain — a stale expectation is fenced and writes nothing, a revoke is
/// durable, and a lease taken before the revoke stops releasing afterwards.
#[test]
fn invalidate_and_conditional_commit_delegate_to_the_real_store_off_the_caller_thread() {
    let _serial = worker_test_lock();
    let tmp = tempfile::TempDir::new().expect("root");
    seed(tmp.path(), &[(&alice(), unexpired())]);

    multi_thread(async {
        let fx = start(tmp.path(), 4);
        let recording = store_probe::watch(&config(tmp.path()).store_dir);
        let caller_thread = format!("{:?}", std::thread::current().id());
        let seeded = unexpired();

        // A lease taken while the account is still connected.
        let lease = refuse_scaffold(fx.handle.resolve(&alice()).await, "lease before revoke")
            .expect("a connected account resolves");
        assert_eq!(lease.generation, seeded.generation);

        // STALE conditional commit: the captured expectation says Absent, the
        // store holds a connected grant. Fenced, and nothing written.
        //
        // The delta is taken around THIS CALL ALONE. A stub that always answers
        // StaleConsentFenced without touching the store adds no acquisition and
        // fails here; `ops.contains` could not tell it apart, because `resolve`
        // above already recorded both a Lookup and an acquisition.
        let replacement = GrantRecord {
            generation: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            access_token: "synthetic-replacement-access-private-material-77d0".into(),
            ..grant()
        };
        let acquisitions = |recording: &store_probe::Recording| {
            recording
                .ops()
                .iter()
                .filter(|op| **op == StoreOp::AuthorityAcquired)
                .count()
        };
        let before = acquisitions(&recording);
        assert_eq!(
            domain_err(
                fx.handle
                    .commit_grant_if(&alice(), &ConsentExpectation::Absent, &replacement)
                    .await,
                "stale conditional commit",
            ),
            CustodyError::Account(AccountServiceError::StaleConsentFenced),
            "a stale expectation is fenced, and the wrapper reports the service's own outcome"
        );
        assert_eq!(
            acquisitions(&recording) - before,
            1,
            "the fenced conditional commit must take exactly one real authority guard: \
             one store operation, one acquisition, compared and refused under it"
        );

        // Readback through the handle, not the raw store: a synchronous
        // `store().lookup()` here would run a REAL store operation on the
        // runtime thread and fail this test's own off-thread assertion.
        let after_fence = refuse_scaffold(
            fx.handle.resolve(&alice()).await,
            "readback after the fenced commit",
        )
        .expect("the account is still connected after a fenced commit");
        assert_eq!(
            after_fence.generation, seeded.generation,
            "a fenced conditional commit must write nothing at all"
        );

        // Durable revoke through the wrapper.
        refuse_scaffold(fx.handle.invalidate(&alice()).await, "invalidate")
            .expect("invalidate revokes through the handle");

        // The lease taken before the revoke no longer releases.
        assert_eq!(
            domain_err(fx.handle.release(&lease).await, "release after revoke"),
            CustodyError::Account(AccountServiceError::LeaseRetired),
            "a lease issued before a revoke must stop releasing after it"
        );
        assert_eq!(
            fx.observer_calls.load(Ordering::SeqCst),
            0,
            "no credential may be published for a revoked account"
        );

        // `invalidate` reached the real revoke; the fenced commit was already
        // pinned by its own acquisition delta above.
        let ops = recording.ops();
        assert!(
            ops.contains(&StoreOp::Revoke),
            "invalidate must reach the real store revoke: {ops:?}"
        );
        assert!(
            ops.contains(&StoreOp::Lookup),
            "resolve and release must reach the real store lookup: {ops:?}"
        );
        // Every recorded operation, all of them driven through the handle.
        for entry in recording.entries() {
            assert_ne!(
                entry.thread, caller_thread,
                "{:?} ran on the calling runtime thread instead of a blocking thread",
                entry.op
            );
        }
        drop(recording);

        // Durable across a reopen: the revoke survived, the fenced grant never landed.
        refuse_scaffold(fx.handle.shutdown().await, "shutdown").expect("shutdown");
        let reopened = PersonalAccountStore::open(config(tmp.path())).expect("reopen");
        assert!(
            matches!(
                reopened.lookup(&alice()).expect("readback"),
                AccountLookup::Revoked(_)
            ),
            "the revoke is durable, and the fenced replacement never became the account"
        );
    });
}
