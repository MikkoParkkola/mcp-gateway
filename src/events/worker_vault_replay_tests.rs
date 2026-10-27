// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A dead-letter replay judges a vault row by its grant as delivery reads it
//! now: a record observed under the grant still current replays, one under a
//! grant that moved is refused by name, and a custody that cannot answer
//! queues nothing. A replay never accepts what the send would bury.

use std::sync::Arc;

use super::{DeadReason, EventsHub, FenceRead, fenced, queued_for};
use crate::events::admin::ReplayRefusal;
use crate::events::services::{AccessVerdict, forced_verdict};
use crate::events::store::{Claim, Settle};

/// A hub with `u1` on the managed backend, its services the replay's own,
/// and `u1`'s record buried as observed under the grant current now.
fn buried(dir: &std::path::Path) -> (Arc<EventsHub>, Arc<super::Fence>) {
    let (hub, services, config, fence) = fenced(dir, &["u1"]);
    assert!(hub.runtime.services.set(Arc::new(services)).is_ok());
    queued_for(&hub, &config, 9, "u1", &fence.current("u1"));
    let now = crate::clock::utc_now().expect("clock");
    let Claim::Ready(_) = hub.store.claim("evt_u1", now).expect("io") else {
        panic!("premise: the record is claimed");
    };
    let dead = Settle::Dead {
        reason: DeadReason::Observation,
        status: None,
    };
    (hub.store)
        .settle("evt_u1", now, dead, Ok(now), hub.dead_policy())
        .expect("io");
    (hub, fence)
}

fn actor() -> crate::events::governance::Actor {
    crate::events::governance::Actor {
        who: crate::security::audit::AuditWho::gateway(),
    }
}

fn still_dead(hub: &EventsHub) -> bool {
    hub.store.dead_letter_by_id("evt_u1").is_some()
}

/// Under the grant it was observed under, a vault record replays.
#[tokio::test(flavor = "current_thread")]
async fn a_vault_replay_under_the_same_grant_requeues() {
    let dir = tempfile::tempdir().expect("dir");
    let (hub, _fence) = buried(dir.path());
    let _admits = forced_verdict::answer(AccessVerdict::Admits);
    assert_eq!(hub.replay_dead("evt_u1", &actor()).await, Ok(()));
    assert!(!still_dead(&hub), "re-queued");
}

/// The grant rotated since: the send would bury it, so the replay is
/// refused now, by name, and nothing is queued.
#[tokio::test(flavor = "current_thread")]
async fn a_vault_replay_after_a_rotation_is_refused() {
    let dir = tempfile::tempdir().expect("dir");
    let (hub, fence) = buried(dir.path());
    fence.rotate_grant("u1");
    let _admits = forced_verdict::answer(AccessVerdict::Admits);
    assert_eq!(
        hub.replay_dead("evt_u1", &actor())
            .await
            .map_err(ReplayRefusal::as_str),
        Err("observation_changed")
    );
    assert!(still_dead(&hub), "nothing re-queued");
}

/// Custody cannot answer: no verdict on the grant, so nothing is queued on
/// a guess and the operator is told to try again.
#[tokio::test(flavor = "current_thread")]
async fn a_vault_replay_with_custody_busy_is_refused_unavailable() {
    let dir = tempfile::tempdir().expect("dir");
    let (hub, fence) = buried(dir.path());
    *fence.refuse.lock().expect("fence") = Some(FenceRead::Busy);
    let _admits = forced_verdict::answer(AccessVerdict::Admits);
    assert_eq!(
        hub.replay_dead("evt_u1", &actor())
            .await
            .map_err(ReplayRefusal::as_str),
        Err("unavailable")
    );
    assert!(still_dead(&hub), "nothing re-queued");
}
