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

use super::era_stale_probe_tests::{Answer, DISCOVER, Handles, Peer, WAIT};
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
) -> Arc<dyn Transport> {
    let transport: Arc<dyn Transport> = peer.clone();
    backend.set_pooled_transport_for_test(&slot(BINDING), Arc::clone(&transport));
    backend.resolve_era_for_test(&transport).await;
    assert_eq!(backend.cached_era().await, Some(Era::Modern), "primed");
    let entry = Arc::clone(backend.pool.get(&slot(BINDING)).expect("the slot").value());
    entry.in_flight.fetch_add(1, Ordering::SeqCst);

    peer.hold.store(true, Ordering::SeqCst);
    backend
        .reprobe_if_code_contradicts(DISCOVER, METHOD_NOT_FOUND_CODE, &transport)
        .await;
    tokio::time::timeout(WAIT, &mut handles.started)
        .await
        .expect("the re-probe reached the peer in time")
        .expect("the re-probe reaches the peer");
    transport
}

/// MIK-7643: the revocation removes the busy slot while its re-probe is on the
/// wire; the answer arrives after, about a slot the pool no longer serves, and
/// is not stored.
#[tokio::test]
async fn a_reprobe_answer_for_a_revoked_busy_slot_is_not_stored() {
    let backend = per_user_backend("era-retired");
    let (peer, mut handles) = Peer::new(Answer::Modern);
    let _transport = busy_slot_probing(&backend, &peer, &mut handles).await;

    assert_eq!(
        backend.evict_identity_slots("rev:"),
        1,
        "the revoked slot left the pool"
    );
    let _ = handles.release.send(());

    let era = tokio::time::timeout(WAIT, backend.cached_era())
        .await
        .expect("the re-probe decided in time");
    assert_eq!(
        era, None,
        "an answer about a slot the pool no longer serves is not the backend's era"
    );
}

/// MIK-7643 guard: an answer that arrives while the slot is still pooled is
/// stored, and a revocation after that does not undo it.
#[tokio::test]
async fn a_reprobe_answer_before_the_revocation_is_stored() {
    let backend = per_user_backend("era-retired-guard");
    let (peer, mut handles) = Peer::new(Answer::Modern);
    let _transport = busy_slot_probing(&backend, &peer, &mut handles).await;

    let _ = handles.release.send(());
    let era = tokio::time::timeout(WAIT, backend.cached_era())
        .await
        .expect("the re-probe decided in time");
    assert_eq!(era, Some(Era::Modern), "a pooled slot's answer is stored");

    assert_eq!(backend.evict_identity_slots("rev:"), 1);
    assert_eq!(
        backend.cached_era().await,
        Some(Era::Modern),
        "a later revocation leaves the stored era alone"
    );
}
