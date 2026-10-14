// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8202 P4b, section D (design r4, ruling (a)): an upstream cancel
//! claimed while the store clock reads before 1970 is written as the durable
//! MIK-8347 pending record, undated, and the first readable sweep sends it
//! exactly once, across a restart. Runtime-red rows and one green guard; the
//! rows that need new APIs are in `pending_cancel_clock_compile_red_tests.rs`.
//!
//! The one D fixture is [`dark_claim_then_restart`]: a dark-then-readable
//! store clock, the store reopened from the same directory with a new
//! executor, and the upstream sends counted at a [`ScriptedPeer`].

use std::ops::ControlFlow;
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;

use super::super::upstream::CancelSend;
use super::super::{CancelDelivery, TaskExecutor, TransitionWrite};
use super::tests::{
    BACKEND, Handle, ScriptedPeer, executor_over, fixture, fixture_with, open_service, settle,
};
use crate::gateway::task_service::TaskService;
use crate::gateway::task_service::record::ErrorAuthor;
use crate::gateway::task_service::store::targets::UpstreamCancelState::{self, Done, Pending};
use crate::gateway::task_service::store::{CancelHold, StoreError};
use crate::protocol::tasks::TaskTransition;
use crate::test_wait::{HANG_BOUND, wait_until};

/// The fixture's principal, tool and handle (`pending_cancel_tests.rs`).
const OWNER: &str = "verified-owner";
const TOOL: &str = "slow_echo";
const HANDLE: &str = "upstream-7";

pub(super) const DAY: Duration = Duration::from_secs(24 * 60 * 60);
pub(super) const DAY_MS: u64 = 24 * 60 * 60 * 1_000;
pub(super) const HOUR: Duration = Duration::from_secs(60 * 60);

/// Who meets the dark clock at the claim.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Claimant {
    /// The owner's cancel (the row's own durable descriptor).
    Owner,
    /// A worker offering the handle it holds, after the owner's cancel found
    /// no descriptor to claim.
    Worker,
}

/// The gateway after the restart, and what the first one left.
pub(super) struct Reopened {
    pub(super) service: Arc<TaskService>,
    pub(super) executor: Arc<TaskExecutor>,
    pub(super) owner_digest: String,
    pub(super) id: String,
    /// The row's cancel state when the first gateway stopped.
    pub(super) claimed_dark: Option<UpstreamCancelState>,
    _dir: tempfile::TempDir,
}

impl Reopened {
    pub(super) fn state(&self) -> Option<UpstreamCancelState> {
        self.service
            .store
            .upstream_cancel_state(&self.owner_digest, &self.id)
    }

    /// Install a fresh peer on the reopened executor.
    pub(super) fn peer(&self) -> Arc<ScriptedPeer> {
        let peer = ScriptedPeer::new([]);
        assert!(self.executor.install_recovery(peer.clone()));
        peer
    }

    /// One sweep's flush (`Due::ByTime`, every due row), awaited.
    pub(super) async fn sweep_flush(&self) {
        settle(self.executor.flush_pending_cancels(None)).await;
        self.executor.cancel_send_idle(&self.id).await;
    }

    /// Move the reopened store's clock `by` further on.
    pub(super) fn advance(&self, by: Duration) {
        let now = self.service.store.now().expect("a readable clock");
        let by = chrono::Duration::from_std(by).expect("a representable step");
        self.service.store.set_clock_for_test(Some(now + by));
    }
}

/// The one D fixture. A working row with `ttl_ms` retention; the store clock
/// is made to read before 1970 and `claimant` meets it at the claim; nothing
/// is sent while dark. The first gateway stops, the store is reopened from
/// the same directory with a new executor (all in-memory state gone), and
/// its clock is frozen readable at `after` past the time read before the
/// dark spell. No adapter is installed on the reopened executor: the caller
/// decides when a send can happen (an expiry pass with no adapter flushes
/// nothing).
pub(super) async fn dark_claim_then_restart(
    claimant: Claimant,
    ttl_ms: Option<u64>,
    after: Duration,
) -> Reopened {
    let handle = match claimant {
        Claimant::Owner => Handle::Durable,
        Claimant::Worker => Handle::Held,
    };
    let f = fixture_with(ttl_ms, handle).await;
    let first = ScriptedPeer::new([]);
    assert!(f.executor.install_recovery(first.clone()));
    let readable = f.service.store.now().expect("a readable clock at setup");
    let dark = chrono::DateTime::from_timestamp(-1, 0).expect("one second before 1970");
    if claimant == Claimant::Worker {
        // Premise: the owner's cancel finds no descriptor, so the only claim
        // left is the worker's.
        f.owner_cancels().await;
        f.executor.cancel_send_idle(&f.id).await;
        assert_eq!(
            f.state(),
            None,
            "premise: the owner's cancel claimed nothing"
        );
        f.service.store.set_clock_for_test(Some(dark));
        let job = crate::gateway::meta_mcp::upstream::DirectJob {
            server: BACKEND.to_owned(),
            tool: TOOL.to_owned(),
            arguments: json!({}),
        };
        let offer = f
            .executor
            .offered_descriptor(&f.owner_digest, &f.id, &job, HANDLE.to_owned())
            .expect("the row is readable");
        let _ = f
            .executor
            .cancel_upstream_once(&f.owner_digest, &f.id, Some(offer), CancelSend::Inline)
            .await;
    } else {
        f.service.store.set_clock_for_test(Some(dark));
        f.owner_cancels().await;
    }
    f.executor.cancel_send_idle(&f.id).await;
    assert_eq!(first.count(), 0, "a send ran while the clock was dark");
    let claimed_dark = f.state();
    f.service.shutdown().await.expect("the first gateway stops");
    let service = open_service(f.dir.path()).await;
    let after = chrono::Duration::from_std(after).expect("a representable step");
    service.store.set_clock_for_test(Some(readable + after));
    let executor = executor_over(&service);
    Reopened {
        service,
        executor,
        owner_digest: f.owner_digest,
        id: f.id,
        claimed_dark,
        _dir: f.dir,
    }
}

/// D-restart (MIK-8202.AC.16, AC.2). r4 D.1 and D.3: the owner's cancel on a
/// dark store clock writes the durable pending record, undated, so it
/// survives a restart; the first readable sweep after it sends the upstream
/// `tasks/cancel` exactly once.
/// Red on base: the dark claim fails (`Unavailable`), the offer is parked in
/// memory only and lost with the first gateway, so nothing is pending and the
/// reopened sweep sends 0.
/// Mutants: Dm1, no durable write on `ClockUnreadable`: killed at
/// "the dark claim wrote no pending record" (and at the send count, 0).
/// Dm5, the undated record treated as not due: killed at "sends after the
/// restart" (0), since the sweep's flush is the `ByTime` one.
#[tokio::test(flavor = "current_thread")]
async fn a_cancel_claimed_on_a_dark_clock_is_sent_once_after_a_restart() {
    let r = dark_claim_then_restart(Claimant::Owner, Some(DAY_MS), HOUR).await;
    assert_eq!(
        r.claimed_dark,
        Some(Pending { attempts: 0 }),
        "the dark claim wrote no pending record"
    );
    let peer = r.peer();
    r.sweep_flush().await;
    assert_eq!(peer.count(), 1, "sends after the restart");
    assert_eq!(r.state(), Some(Done));
}

/// D-worker (MIK-8202.AC.16, AC.2). r4 D.1 "one mechanism, any sender": a
/// worker's claim (not the owner's) that meets the dark clock writes the same
/// undated record; after a restart the readable sweep sends once.
/// Red on base: the worker's offer is parked in memory and lost with the
/// restart (0 sends).
/// Mutant: Dm1 on the worker's path (the record written for the owner's
/// claim only): killed at "the worker's dark claim wrote no pending record"
/// and at the send count (0).
#[tokio::test(flavor = "current_thread")]
async fn a_workers_claim_on_a_dark_clock_is_sent_once_after_a_restart() {
    let r = dark_claim_then_restart(Claimant::Worker, Some(DAY_MS), HOUR).await;
    assert_eq!(
        r.claimed_dark,
        Some(Pending { attempts: 0 }),
        "the worker's dark claim wrote no pending record"
    );
    let peer = r.peer();
    r.sweep_flush().await;
    assert_eq!(peer.count(), 1, "sends after the restart");
    assert_eq!(r.state(), Some(Done));
}

/// D-flap (MIK-8202.AC.16, AC.2). r4 D.2 "exactly once": once the dark
/// cancel is sent, later sweeps, and a backend-start flush, send nothing more.
/// Red on base: the first send never happens (count 0, not 1).
/// Mutant: Dm4 (plan r2), the post-send pending-state clear removed, so the
/// record stays due: killed at "a sent cancel was sent again" (2).
#[tokio::test(flavor = "current_thread")]
async fn a_cancel_sent_after_the_dark_spell_is_not_sent_again() {
    let r = dark_claim_then_restart(Claimant::Owner, Some(DAY_MS), HOUR).await;
    let peer = r.peer();
    r.sweep_flush().await;
    assert_eq!(peer.count(), 1, "the first readable sweep sends it");
    r.advance(HOUR);
    r.sweep_flush().await;
    settle(r.executor.flush_pending_cancels(Some(BACKEND))).await;
    r.executor.cancel_send_idle(&r.id).await;
    assert_eq!(peer.count(), 1, "a sent cancel was sent again");
}

/// Run one expiry pass (the sweep's first tick fires at once; the interval
/// never comes round again within the bound) and wait until `id` is deleted.
async fn removed_by_one_pass(
    service: &Arc<TaskService>,
    executor: &Arc<TaskExecutor>,
    owner: &str,
    id: &str,
) {
    let sweep = executor.start_expiry(HANG_BOUND).expect("a sweep starts");
    let gone = wait_until(HANG_BOUND, || {
        let row = service.store.get(owner, id).map(|_| ());
        let step = match row {
            Err(StoreError::NotFound) => ControlFlow::Break(()),
            other => ControlFlow::Continue(format!("{other:?}")),
        };
        async move { step }
    })
    .await;
    sweep.shutdown().await.expect("a clean stop");
    gone.expect("the row is removed by the normal retention rule");
}

/// D-hold-negative (MIK-8202.AC.16, AC.2; plan r3). r4 D.4 bounds the
/// retention skip to a cancelled row whose pending cancel is UNSENT: a
/// cancelled row whose cancel was already sent, and a non-cancelled terminal
/// row, are each removed by the normal rule on a readable pass past their ttl.
/// GREEN GUARD: base has no skip, so both are removed today.
/// Mutant: Dm6, the skip holds every cancelled row: killed at "the row is
/// removed by the normal retention rule" (the sent row is never deleted).
/// The two rows live in two stores, one pass each: the rule is per row.
#[tokio::test(flavor = "current_thread")]
async fn retention_removes_a_sent_cancel_and_a_completed_row_past_their_ttl() {
    let sent = fixture(Some(DAY_MS)).await;
    let peer = ScriptedPeer::new([]);
    assert!(sent.executor.install_recovery(peer.clone()));
    sent.owner_cancels().await;
    sent.state_becomes(Done).await;
    assert_eq!(peer.count(), 1, "premise: the cancel was sent");

    let completed = fixture(Some(DAY_MS)).await;
    let revision = completed
        .service
        .get(OWNER, &completed.id)
        .expect("row is readable")
        .revision;
    completed
        .executor
        .commit_transition(TransitionWrite::Settle {
            principal: OWNER,
            id: &completed.id,
            revision,
            event: TaskTransition::Complete(json!({ "content": [] })),
            targets: None,
            author: ErrorAuthor::Gateway,
            writes: crate::gateway::gateway_writes::WriteRecord::default(),
        })
        .await
        .expect("premise: the working row completes");

    for f in [&sent, &completed] {
        let now = f.service.store.now().expect("a readable clock");
        let later = chrono::Duration::from_std(DAY + HOUR).expect("a representable step");
        f.service.store.set_clock_for_test(Some(now + later));
        removed_by_one_pass(&f.service, &f.executor, &f.owner_digest, &f.id).await;
    }
}

/// G (MIK-8202 P4b, lead ruling A = narrow): retention holds only an UNDATED
/// pending cancel. A cancel claimed on a readable clock is dated, so its row
/// expires at its TTL as before P4b, and the MIK-8347 "expired" give-up stays
/// live. Here the backend is never ready, the claim is dated, and one expiry
/// pass past the TTL deletes the row.
/// Mutant A, the hold also catching dated records (`claimed_at.is_none()`
/// dropped from `held_for_cancel`): killed at "a dated pending cancel was
/// held past its ttl".
#[tokio::test(flavor = "current_thread")]
async fn a_dated_pending_cancel_expires_at_its_ttl() {
    let f = fixture(Some(60 * 60 * 1_000)).await;
    let peer = ScriptedPeer::new(std::iter::repeat_n(CancelDelivery::NotReady, 50));
    assert!(f.executor.install_recovery(peer.clone()));
    f.owner_cancels().await;
    f.state_becomes(Pending { attempts: 0 }).await;
    let pending = f
        .service
        .store
        .pending_cancel(&f.owner_digest, &f.id)
        .expect("premise: a pending cancel");
    assert!(pending.claimed_at.is_some(), "premise: the claim is dated");

    f.advance_store_clock(2 * HOUR);
    f.executor
        .expiry_pass_for_test()
        .await
        .expect("an expiry pass");
    assert!(
        matches!(
            f.service.store.get(&f.owner_digest, &f.id),
            Err(StoreError::NotFound)
        ),
        "a dated pending cancel was held past its ttl"
    );
}

/// B (MIK-8202 P4b, lead ruling B): with no upstream adapter installed,
/// nothing can ever send a held cancel, so retention holds nothing: an
/// undated pending cancel's row expires at its TTL as before P4b.
/// Mutant B, the hold applied without an adapter: killed at "a row was held
/// with no adapter to send its cancel".
#[tokio::test(flavor = "current_thread")]
async fn without_an_adapter_an_undated_cancel_is_not_held() {
    let r = dark_claim_then_restart(Claimant::Owner, Some(DAY_MS), DAY + HOUR).await;
    assert_eq!(r.claimed_dark, Some(Pending { attempts: 0 }), "premise");
    assert!(r.executor.recovery().is_none(), "premise: no adapter");
    r.executor
        .expiry_pass_for_test()
        .await
        .expect("an expiry pass");
    assert!(
        matches!(
            r.service.store.get(&r.owner_digest, &r.id),
            Err(StoreError::NotFound)
        ),
        "a row was held with no adapter to send its cancel"
    );
}

/// The race (MIK-8202 P4b, gpt seat HIGH): a cancel claimed AFTER the expiry
/// pass took its candidate snapshot keeps the row's revision, so only the
/// recheck under the ordering lock in `expire_blocking` can see it. Driven
/// deterministically through the store's own steps: snapshot, then a
/// worker's claim on a dark clock (undated), then the deletion at the
/// snapshot's revision.
/// Mutant: the recheck under the lock dropped: killed at "a cancel claimed
/// after enumeration was deleted with its row".
#[tokio::test(flavor = "current_thread")]
async fn a_cancel_claimed_after_enumeration_keeps_its_row() {
    let f = super::tests::fixture_with(Some(60 * 60 * 1_000), Handle::Held).await;
    let first = ScriptedPeer::new([]);
    assert!(f.executor.install_recovery(first.clone()));
    f.owner_cancels().await;
    f.executor.cancel_send_idle(&f.id).await;
    assert_eq!(
        f.state(),
        None,
        "premise: the owner's cancel claimed nothing"
    );

    let past = f.service.store.now().expect("a readable clock")
        + chrono::Duration::from_std(DAY).expect("a representable step");
    let candidates = f
        .service
        .store
        .expired_candidates(past, CancelHold::Undated);
    let revision = candidates
        .iter()
        .find(|(id, _)| *id == f.id)
        .map(|(_, revision)| *revision)
        .expect("premise: the row is an expiry candidate");

    let dark = chrono::DateTime::from_timestamp(-1, 0).expect("one second before 1970");
    f.service.store.set_clock_for_test(Some(dark));
    let job = crate::gateway::meta_mcp::upstream::DirectJob {
        server: BACKEND.to_owned(),
        tool: TOOL.to_owned(),
        arguments: json!({}),
    };
    let offer = f
        .executor
        .offered_descriptor(&f.owner_digest, &f.id, &job, HANDLE.to_owned())
        .expect("the row is readable");
    let _ = f
        .executor
        .cancel_upstream_once(&f.owner_digest, &f.id, Some(offer), CancelSend::Inline)
        .await;
    f.executor.cancel_send_idle(&f.id).await;
    assert_eq!(
        f.state(),
        Some(Pending { attempts: 0 }),
        "premise: the worker's claim wrote an undated pending cancel"
    );
    assert_eq!(
        f.service
            .get(OWNER, &f.id)
            .expect("the row is readable")
            .revision,
        revision,
        "premise: the claim kept the snapshot's revision, so only the locked recheck can refuse"
    );

    let deleted = f
        .service
        .store
        .expire(
            &f.id,
            revision,
            f.service.admission_arc(),
            CancelHold::Undated,
        )
        .await;
    assert!(
        matches!(deleted, Err(StoreError::RevisionConflict))
            && f.service.store.get(&f.owner_digest, &f.id).is_ok(),
        "a cancel claimed after enumeration was deleted with its row: {deleted:?}"
    );
}
