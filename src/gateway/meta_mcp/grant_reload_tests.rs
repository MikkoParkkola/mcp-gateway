// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `MIK-7334.CATALOGUE.1` revocation conjunct — the live grant-reload trigger.
//!
//! Cells from `docs/internal/design/2026-09-22-live-identity-grant-reload.md`
//! §3 that are drivable WITHOUT the design's §D2 sink. T7, T8 and T8b are
//! here; the rest are not, and the reason is recorded rather than left to be
//! rediscovered.
//!
//! WHY MOST T-CELLS ARE ABSENT. T1/T2/T3/T3b/T4/T5/T6/T9/T10/T10b all observe
//! a reload TRIGGER — `ReloadContext::reload_identity_grants()`. That function
//! needs MVP piece 1 first: `MetaMcp.identity_grants` must become
//! `Arc<RwLock<…>>` so a `ReloadContext` can hold a clone of it. Today the
//! field is a plain `RwLock` and `ReloadContext` holds no handle to it at all,
//! so there is no sink to publish into and no signature to write a test
//! against. That is a production change, not a stub, and this slice is
//! tests-only. T3b is blocked twice over: it must drive
//! `write_identity_grant_file`, a PRIVATE `async fn` in
//! `src/commands/identity.rs`, and reaching it needs a visibility widening.
//!
//! WHAT IS HERE INSTEAD. T8 and T8b are the two cells that need no trigger:
//! they are properties of the PUBLISHER, which exists today and is wrong
//! today. `set_identity_grants` bumps the epoch unconditionally, so a reload
//! that changed nothing flushes every caller's response cache — the epoch is
//! global, so the blast radius is every caller, not the one whose grant was
//! edited. Both are red against shipped code, not against absence.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use chrono::{Duration as ChronoDuration, Utc};

use super::BackendRegistry;
use super::MetaMcp;
use crate::identity_grants::{
    CapabilityExposure, GrantAgent, GrantScope, GrantSubject, IdentityGrant, IdentityGrantRequest,
    LocalIdentityGrantStore,
};

fn grant(grant_id: &str, subject: &str, capability: &str) -> IdentityGrant {
    IdentityGrant {
        grant_id: grant_id.to_string(),
        subject: GrantSubject::new("https://idp".to_string(), subject.to_string(), None),
        agent: GrantAgent::Any,
        capability: capability.to_string(),
        tool: None,
        scope: GrantScope::Read,
        owner: None,
        expires_at: None,
        revoked_at: None,
        provenance: "fixture".to_string(),
        reason: "grant-reload cell".to_string(),
    }
}

fn meta() -> MetaMcp {
    MetaMcp::new(Arc::new(BackendRegistry::new()))
}

// T7 — goes red when the publisher forgets the epoch, so a stale response-cache
// entry outlives the grant change.
//
// GREEN TODAY, and labelled rather than counted: `set_identity_grants` bumps
// unconditionally, which is exactly the behaviour T8 says is wrong in the other
// direction. The pair is the point — T7 pins that a real change advances the
// epoch, T8 pins that a non-change does not, and an implementation of piece 4
// that over-corrects by never bumping goes red HERE.
//
// HONEST LIMIT: driven through `set_identity_grants` rather than through
// `reload_identity_grants`, which does not exist. Driven that way it re-proves
// `policy_epoch_tests.rs`'s existing assertion; it earns its place only once
// the reload path is the caller.
#[test]
fn t7_a_grant_change_advances_the_epoch() {
    let meta = meta();
    meta.set_identity_grants(LocalIdentityGrantStore::from_grants([grant(
        "g1", "alice", "cal",
    )]));
    let before = meta.policy_epoch.load(Ordering::Acquire);

    // A genuine change: the grant is revoked.
    let mut revoked = grant("g1", "alice", "cal");
    revoked.revoked_at = Some(Utc::now());
    meta.set_identity_grants(LocalIdentityGrantStore::from_grants([revoked]));

    assert!(
        meta.policy_epoch.load(Ordering::Acquire) > before,
        "T7: a grant change must strand every key minted under the old grants"
    );
}

// T8 — RED TODAY against shipped code.
//
// Goes red when a no-op reload churns every caller's response cache.
// `set_identity_grants` bumps unconditionally, so a reload against a file
// byte-identical to the live store advances the global epoch and invalidates
// every caller's entries for nothing. This cell is what forces the `PartialEq`
// comparison, and why that comparison is MVP rather than polish.
#[test]
fn t8_publishing_an_unchanged_store_must_not_advance_the_epoch() {
    let meta = meta();
    let rows = [grant("g1", "alice", "cal"), grant("g2", "bob", "mail")];
    meta.set_identity_grants(LocalIdentityGrantStore::from_grants(rows.clone()));

    // PREMISE, in this cell's own body: the store really is populated, so the
    // cell cannot pass by publishing nothing into nothing.
    assert_eq!(
        meta.identity_grant_rows().len(),
        2,
        "T8 premise: the live store must be populated before the no-op reload"
    );
    let before = meta.policy_epoch.load(Ordering::Acquire);

    meta.set_identity_grants(LocalIdentityGrantStore::from_grants(rows));

    assert_eq!(
        meta.policy_epoch.load(Ordering::Acquire),
        before,
        "T8: a reload that changed nothing must not flush every caller's cache"
    );
}

// T8b — RED TODAY, same blast radius as T8 reached by a different route.
//
// Goes red when a REORDERED file reads as a change. This is the cell that
// forces the comparison to be defined on normalised store contents rather than
// on file bytes or the file's `Vec` order: `LocalIdentityGrantStore` is a
// `BTreeMap` keyed by grant id, so loading normalises order for free — but only
// if the comparison happens on the loaded store.
#[test]
fn t8b_a_reordered_file_must_not_read_as_a_change() {
    let meta = meta();
    let a = grant("g1", "alice", "cal");
    let b = grant("g2", "bob", "mail");
    meta.set_identity_grants(LocalIdentityGrantStore::from_grants([a.clone(), b.clone()]));

    assert_eq!(
        meta.identity_grant_rows().len(),
        2,
        "T8b premise: the live store must be populated before the reorder"
    );
    let before = meta.policy_epoch.load(Ordering::Acquire);

    // The same two rows, in the opposite file order.
    meta.set_identity_grants(LocalIdentityGrantStore::from_grants([b, a]));

    assert_eq!(
        meta.policy_epoch.load(Ordering::Acquire),
        before,
        "T8b: row order in the file is not a policy change"
    );
}

// T11 — the guard, and labelled as one rather than counted as new coverage.
//
// Goes red when expiry regressed: the one liveness property that already works
// against in-memory data, and the cheapest thing for this change to break.
// Time advances against the store with NO reload at all.
// GREEN BEFORE AND AFTER by design.
#[test]
fn t11_guard_expiry_is_live_without_any_reload() {
    let subject = GrantSubject::new("https://idp".to_string(), "alice".to_string(), None);
    let mut expiring = grant("g1", "alice", "cal");
    expiring.expires_at = Some(Utc::now() + ChronoDuration::seconds(60));
    let store = LocalIdentityGrantStore::from_grants([expiring]);

    let request = |now| IdentityGrantRequest {
        identity: Some(subject.clone()),
        agent_id: None,
        capability: "cal".to_string(),
        tool: None,
        scope: GrantScope::Read,
        exposure: CapabilityExposure::Personal,
        owner: Some(subject.clone()),
        now,
    };

    // PREMISE, in this cell's own body: the grant allows BEFORE its expiry.
    // Without it the denial below would hold for a store that denies
    // everything, which is the one-sided form this house has already refused.
    assert!(
        store.evaluate(&request(Utc::now())).allowed,
        "T11 premise: an unexpired grant must allow"
    );
    // Only the clock moves. No reload, no publish, no epoch bump.
    assert!(
        !store
            .evaluate(&request(Utc::now() + ChronoDuration::seconds(120)))
            .allowed,
        "T11: an elapsed expiry must deny with no reload at all"
    );
}
