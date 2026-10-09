// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7643: a re-probe's answer about a per-user slot the pool has removed is
//! not stored as the backend's era.
//!
//! A grant revocation removes a busy per-user slot but leaves its transport on
//! the orphaned entry until the last request lets go, so "the entry still holds
//! the probed transport" no longer means "the pool still serves it". The held
//! probe is the barrier: reading the era blocks until the detached re-probe has
//! decided, never a sleep.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use super::era_stale_probe_tests::{Answer, DISCOVER, Handles, Peer, WAIT, run};
use super::pool::PooledEntry;
use super::slot_eviction_tests::{per_user_backend, slot};
use super::*;
use crate::protocol::era::{Era, METHOD_NOT_FOUND_CODE};
use crate::transport::Transport;

const BINDING: &str = "rev:alpha";

/// A per-user slot serving `peer`, whose Modern era is cached, with a request
/// still in flight on it; then a `-32601` contradicts the era and a re-probe
/// of `peer` is held mid-flight.
async fn busy_slot_probing(
    backend: &Arc<Backend>,
    peer: &Arc<Peer>,
    handles: &mut Handles,
) -> (Arc<dyn Transport>, Arc<PooledEntry>) {
    let transport: Arc<dyn Transport> = peer.clone();
    backend.set_pooled_transport_for_test(&slot(BINDING), Arc::clone(&transport));
    let entry = entry_of(backend, BINDING);
    backend.resolve_era_for_entry_test(&transport, &entry).await;
    assert_eq!(entry.era.cached().await, Some(Era::Modern), "primed");
    entry.in_flight.fetch_add(1, Ordering::SeqCst);

    peer.hold.store(true, Ordering::SeqCst);
    backend
        .reprobe_if_code_contradicts(DISCOVER, METHOD_NOT_FOUND_CODE, &transport)
        .await;
    tokio::time::timeout(WAIT, &mut handles.started)
        .await
        .expect("the re-probe reached the peer in time")
        .expect("the re-probe reaches the peer");
    (transport, entry)
}

/// MIK-7643: the revocation removes the busy slot while its re-probe is on the
/// wire; the answer arrives after, about a slot the pool no longer serves, and
/// is not stored.
#[tokio::test]
async fn a_reprobe_answer_for_a_revoked_busy_slot_is_not_stored() {
    let backend = per_user_backend("era-retired");
    let (peer, mut handles) = Peer::new(Answer::Modern);
    let (_transport, entry) = busy_slot_probing(&backend, &peer, &mut handles).await;

    assert_eq!(
        backend.evict_identity_slots("rev:"),
        1,
        "the revoked slot left the pool"
    );
    let _ = handles.release.send(());

    let era = tokio::time::timeout(WAIT, entry.era.cached())
        .await
        .expect("the re-probe decided in time");
    assert_eq!(
        era, None,
        "an answer about a slot the pool no longer serves is not stored as its era"
    );
}

/// MIK-7643 guard: an answer that arrives while the slot is still pooled is
/// stored, and a revocation after that does not undo it.
#[tokio::test]
async fn a_reprobe_answer_before_the_revocation_is_stored() {
    let backend = per_user_backend("era-retired-guard");
    let (peer, mut handles) = Peer::new(Answer::Modern);
    let (_transport, entry) = busy_slot_probing(&backend, &peer, &mut handles).await;

    let _ = handles.release.send(());
    let era = tokio::time::timeout(WAIT, entry.era.cached())
        .await
        .expect("the re-probe decided in time");
    assert_eq!(era, Some(Era::Modern), "a pooled slot's answer is stored");

    assert_eq!(backend.evict_identity_slots("rev:"), 1);
    assert_eq!(
        entry.era.cached().await,
        Some(Era::Modern),
        "a later revocation leaves the stored era alone"
    );
}

/// The entry at `binding`, captured before a removal can take it out of the map.
fn entry_of(backend: &Arc<Backend>, binding: &str) -> Arc<PooledEntry> {
    Arc::clone(backend.pool.get(&slot(binding)).expect("the slot").value())
}

/// MIK-7643: both removal sites retire what they remove, before it leaves the
/// map: a revoked busy slot and an idle slot the reaper takes.
#[tokio::test]
async fn every_removed_slot_is_retired() {
    let backend = per_user_backend("era-retire-removal");
    let (revoked, _) = Peer::new(Answer::Modern);
    let (idle, _) = Peer::new(Answer::Modern);
    backend.set_pooled_transport_for_test(&slot(BINDING), revoked);
    backend.set_pooled_transport_for_test(&slot("idle:beta"), idle);
    let revoked = entry_of(&backend, BINDING);
    revoked.in_flight.fetch_add(1, Ordering::SeqCst);
    let idle = entry_of(&backend, "idle:beta");
    idle.last_used.store(0, Ordering::SeqCst);

    assert_eq!(backend.evict_identity_slots("rev:"), 1);
    assert_eq!(
        backend.evict_idle_per_user_entries(Duration::from_secs(1)),
        1
    );

    assert!(revoked.retired.load(Ordering::SeqCst), "the revoked slot");
    assert!(idle.retired.load(Ordering::SeqCst), "the reaped slot");
}

/// MIK-7643 guard: the reaper retires only what it removes. A busy slot and a
/// recently used one stay pooled and serving.
#[tokio::test]
async fn the_reaper_leaves_busy_and_recent_slots_serving() {
    let backend = per_user_backend("era-retire-reaper");
    let (busy, _) = Peer::new(Answer::Modern);
    let (recent, _) = Peer::new(Answer::Modern);
    backend.set_pooled_transport_for_test(&slot("busy:alpha"), busy);
    backend.set_pooled_transport_for_test(&slot("recent:beta"), recent);
    let busy = entry_of(&backend, "busy:alpha");
    busy.last_used.store(0, Ordering::SeqCst);
    busy.in_flight.fetch_add(1, Ordering::SeqCst);
    let recent = entry_of(&backend, "recent:beta");
    recent.touch();

    assert_eq!(
        backend.evict_idle_per_user_entries(Duration::from_secs(3600)),
        0
    );

    for (who, entry) in [("busy", busy), ("recent", recent)] {
        assert!(!entry.retired.load(Ordering::SeqCst), "{who} slot retired");
    }
}

/// MIK-7643: a contradiction found its slot, then the revocation removed that
/// slot before the era was judged. The discard is refused: a removed slot's
/// answer must not erase the backend's verdict either, nor be reported as a trigger.
#[test]
fn a_contradiction_from_a_slot_revoked_before_the_discard_keeps_the_era() {
    let records = run(a_contradiction_from_a_revoked_slot());
    // The priming probe's cache miss proves the capture saw this test's era records.
    assert!(
        records
            .iter()
            .any(|record| record["fields"]["hit"] == false),
        "the priming probe's miss was captured: {records:?}"
    );
    let triggers: Vec<_> = records
        .iter()
        .filter(|record| record["fields"]["reason"] == "trigger")
        .collect();
    assert!(
        triggers.is_empty(),
        "a refused discard reports no era trigger and starts no re-probe: {triggers:?}"
    );
}

async fn a_contradiction_from_a_revoked_slot() {
    use crate::test_pause::within;

    let backend = per_user_backend("era-retired-discard");
    let (peer, _handles) = Peer::new(Answer::Modern);
    let transport: Arc<dyn Transport> = peer;
    backend.set_pooled_transport_for_test(&slot(BINDING), Arc::clone(&transport));
    let entry = entry_of(&backend, BINDING);
    backend.resolve_era_for_entry_test(&transport, &entry).await;
    assert_eq!(entry.era.cached().await, Some(Era::Modern), "primed");
    entry.in_flight.fetch_add(1, Ordering::SeqCst);

    let (reached, release) = backend.after_reprobe_lookup.arm();
    let contradiction = tokio::spawn({
        let backend = Arc::clone(&backend);
        async move {
            backend
                .reprobe_if_code_contradicts(DISCOVER, METHOD_NOT_FOUND_CODE, &transport)
                .await;
        }
    });
    within("the contradiction finds its slot", reached.notified()).await;
    assert_eq!(
        backend.evict_identity_slots("rev:"),
        1,
        "the revoked slot left the pool inside the window"
    );
    release.notify_one();
    within("the contradiction finishes", contradiction)
        .await
        .expect("the contradiction task");

    assert_eq!(
        entry.era.cached().await,
        Some(Era::Modern),
        "a contradiction from a slot the pool no longer serves keeps the verdict"
    );
}

/// MIK-7643: a retired entry that still holds its transport is not serving.
#[test]
fn a_retired_entry_holding_its_transport_is_not_serving() {
    let entry = PooledEntry::new("retired", &crate::config::FailsafeConfig::default());
    let (peer, _handles) = Peer::new(Answer::Modern);
    let served: Arc<dyn Transport> = peer;
    *entry.transport.write() = Some(Arc::clone(&served));
    entry.retired.store(true, Ordering::SeqCst);

    assert!(!super::era::with_serving(&entry, &served, &mut || panic!(
        "a retired entry's answer must not be stored or cleared"
    )));
}

/// A per-user slot whose cached era is the primed peer's Modern, then revoked:
/// the entry is retired and out of the map.
async fn revoked_primed_slot(backend: &Arc<Backend>) -> Arc<PooledEntry> {
    let (peer, _handles) = Peer::new(Answer::Modern);
    let primed: Arc<dyn Transport> = peer;
    backend.set_pooled_transport_for_test(&slot(BINDING), Arc::clone(&primed));
    let entry = entry_of(backend, BINDING);
    backend.resolve_era_for_entry_test(&primed, &entry).await;
    assert_eq!(entry.era.cached().await, Some(Era::Modern), "primed");
    entry
}

/// MIK-7643: a start whose slot the revocation removed before the start's era
/// step neither discards the backend's verdict nor installs its peer's answer.
#[tokio::test]
async fn a_start_era_step_for_a_revoked_slot_keeps_the_era() {
    let backend = per_user_backend("era-retired-start");
    let entry = revoked_primed_slot(&backend).await;
    assert_eq!(
        backend.evict_identity_slots("rev:"),
        1,
        "the slot was revoked"
    );

    // Held, so a probe that ran would never return: the refusal must come first.
    let (legacy, mut handles) = Peer::new(Answer::MethodNotFound);
    legacy.hold.store(true, Ordering::SeqCst);
    let started: Arc<dyn Transport> = legacy;
    tokio::time::timeout(WAIT, backend.resolve_era_for_entry_test(&started, &entry))
        .await
        .expect("a refused era step returns without probing");
    assert!(
        handles.started.try_recv().is_err(),
        "no probe reached the revoked slot's peer"
    );

    assert_eq!(
        entry.era.cached().await,
        Some(Era::Modern),
        "a revoked slot's start must not replace its verdict"
    );
}

/// MIK-7643: the revocation lands while the start's probe is on the wire. The
/// verdict was discarded while the slot still served; the revoked peer's
/// answer is not installed.
#[test]
fn a_start_probe_answer_for_a_slot_revoked_mid_probe_is_not_stored() {
    let records = run(a_start_probe_answered_after_its_slot_was_revoked());
    // Refused for the slot, about the peer's real answer: not a probe that timed out.
    let refused: Vec<_> = records
        .iter()
        .filter(|record| record["fields"]["reason"] == "transport_replaced")
        .collect();
    assert_eq!(refused.len(), 1, "one refused start answer: {records:?}");
    assert_eq!(
        refused[0]["fields"]["evidence"], "method_not_found",
        "{refused:?}"
    );
    assert_eq!(refused[0]["fields"]["trigger"], "start", "{refused:?}");
}

async fn a_start_probe_answered_after_its_slot_was_revoked() {
    let backend = per_user_backend("era-retired-start-probe");
    let entry = revoked_primed_slot(&backend).await;

    let (legacy, mut handles) = Peer::new(Answer::MethodNotFound);
    legacy.hold.store(true, Ordering::SeqCst);
    let started: Arc<dyn Transport> = legacy;
    let step = tokio::spawn({
        let backend = Arc::clone(&backend);
        let entry = Arc::clone(&entry);
        async move { backend.resolve_era_for_entry_test(&started, &entry).await }
    });
    tokio::time::timeout(WAIT, &mut handles.started)
        .await
        .expect("the start's probe reached the peer in time")
        .expect("the start's probe reaches the peer");
    assert_eq!(
        backend.evict_identity_slots("rev:"),
        1,
        "the slot was revoked"
    );
    handles
        .release
        .send(())
        .expect("the held probe is still waiting");
    tokio::time::timeout(WAIT, step)
        .await
        .expect("the era step finished in time")
        .expect("the era step task");

    assert_eq!(
        entry.era.cached().await,
        None,
        "discarded while serving, and the revoked peer's Legacy answer not installed"
    );
}
