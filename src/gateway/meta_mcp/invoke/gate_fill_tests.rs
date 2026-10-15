// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8361 (gpt delta r3): the gate's fill marks see a reload. A reload
//! replaces a backend's instance, and the old instance's fill counter cannot
//! see a fill on the new one, so a replacement counts as a fill and the nonce
//! stays spent.

use std::iter::once;
use std::sync::Arc;

use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::authz_tests::{counted_backend, counted_listing_backend};

#[test]
fn a_replaced_or_removed_backend_counts_as_a_fill() {
    let (registry, _) = counted_backend("alpha");
    let meta = MetaMcp::new(Arc::clone(&registry));
    let marks = meta.fill_marks(once("alpha"));
    assert!(
        !meta.filled_since(&marks, once("alpha")),
        "control: nothing changed"
    );

    let (reloaded, _) = counted_backend("alpha");
    let replacement = reloaded.get("alpha").expect("fixture backend");
    assert!(registry.register(replacement), "the reload's re-register");
    assert!(
        meta.filled_since(&marks, once("alpha")),
        "a replaced instance hides its fills from the old counter"
    );

    let marks = meta.fill_marks(once("alpha"));
    assert!(registry.remove("alpha"));
    assert!(
        meta.filled_since(&marks, once("alpha")),
        "a removed backend cannot prove it filled nothing"
    );
}

#[test]
fn a_backend_added_and_removed_mid_judgement_counts_as_a_fill() {
    let (registry, _) = counted_backend("alpha");
    let meta = MetaMcp::new(Arc::clone(&registry));
    // Marked absent: no instance to hold, so only the epoch can see the churn.
    let marks = meta.fill_marks(once("beta"));
    assert!(
        !meta.filled_since(&marks, once("beta")),
        "control: still absent"
    );

    let (other, _) = counted_backend("beta");
    let beta = other.get("beta").expect("fixture backend");
    assert!(registry.register(beta), "the mid-judgement add");
    assert!(registry.remove("beta"), "the mid-judgement remove");
    assert!(
        meta.filled_since(&marks, once("beta")),
        "an add and a remove that net to nothing still moved the membership"
    );
}

// No `a_mark_taken_mid_change_counts_as_a_fill` row: under the lock a mark
// cannot land mid-change, and the serialized shape (marks, control, change,
// filled) is exactly what `a_replaced_or_removed_backend_counts_as_a_fill`
// already covers. Instead this pins that a refused registration moves
// nothing, not even the epoch.
#[tokio::test]
async fn a_register_refused_during_shutdown_does_not_move_the_epoch() {
    let (registry, _) = counted_backend("alpha");
    registry.stop_all().await;
    let before = registry.with_membership(|epoch| epoch);
    let (other, _) = counted_backend("alpha");
    let replacement = other.get("alpha").expect("fixture backend");
    assert!(
        !registry.register(replacement),
        "a registration during shutdown must be refused"
    );
    assert_eq!(
        registry.with_membership(|epoch| epoch),
        before,
        "a refused registration must not move the membership epoch"
    );
}

#[tokio::test]
async fn a_fill_with_no_registration_change_counts_as_a_fill() {
    let (registry, _) = counted_listing_backend("alpha");
    let meta = MetaMcp::new(Arc::clone(&registry));
    let marks = meta.fill_marks(once("alpha"));
    // No test hook bumps the counter; a real cold fill does, without touching
    // the registry.
    let backend = registry.get("alpha").expect("fixture backend");
    backend.get_tools_shared().await.expect("the fill");
    assert!(
        meta.filled_since(&marks, once("alpha")),
        "a fill with no registration change still counts"
    );
}
