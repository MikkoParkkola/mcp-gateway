// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `MIK-7334.CATALOGUE.1` revocation conjunct — the live grant-reload trigger.
//!
//! Cells from `docs/internal/design/2026-09-22-live-identity-grant-reload.md`
//! §3 that are drivable today. T7, T8, T8b and T11 are here; the rest are not,
//! and the reason is recorded rather than left to be rediscovered.
//!
//! WHY THE REST ARE ABSENT. T1/T2/T3/T4/T5/T6/T9/T10/T10b each need a piece
//! this slice does not build: a refusal vocabulary surfaced to the operator
//! (T2/T3/T4/T6), the busy-lock observable (T6/T10b), barriers that force an
//! interleaving (T10), or the single real operator entry point driven end to
//! end (T9). T3b is blocked on the atomic CLI write: it must drive
//! `write_identity_grant_file`, a PRIVATE `async fn` in
//! `src/commands/identity.rs`, and reaching it needs a visibility widening
//! nobody has asked for.
//!
//! WHERE THE NO-CHANGE COMPARISON LIVES, and why it is not in the publisher.
//! T8/T8b were first written against `set_identity_grants`, because
//! `reload_identity_grants` did not exist. That placement is unsatisfiable:
//! `policy_epoch_tests` publishes an empty store into an empty one and
//! requires the epoch to MOVE, so to it the publish IS the event, and a
//! no-change check inside the publisher reds it. The design puts the
//! comparison one level up, on the LOADED store, which is where these cells
//! now drive it. Their assertions are unchanged.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use chrono::{Duration as ChronoDuration, Utc};

use super::BackendRegistry;
use super::MetaMcp;
use crate::config_reload::{IdentityGrantSink, ReloadContext};
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

/// Write a grants file the production reader accepts.
fn write_grants(path: &std::path::Path, rows: &[IdentityGrant]) {
    let file = serde_json::json!({
        "schema_version": crate::identity_grants::IDENTITY_GRANTS_FILE_SCHEMA_VERSION,
        "grants": rows,
    });
    std::fs::write(path, serde_json::to_vec_pretty(&file).expect("serialize")).expect("write");
}

/// A reload context wired to `meta`'s live store and to `path`.
///
/// DRIVEN THROUGH THE REAL TRIGGER. An earlier draft of T8/T8b called
/// `set_identity_grants` directly, because `reload_identity_grants` did not
/// exist. That form cannot be satisfied: `policy_epoch_tests` publishes an
/// empty store into an empty one and requires the epoch to MOVE, so a
/// no-change comparison inside the publisher would red it. The comparison
/// belongs one level up, on the loaded store, which is where the design put
/// it and where these cells now observe it. The assertions are unchanged.
fn reload_ctx(meta: &MetaMcp, path: &std::path::Path) -> ReloadContext {
    let (store, epoch) = meta.identity_grant_sink();
    ReloadContext::new(
        path.to_path_buf(),
        Arc::new(crate::config_reload::LiveConfig::new(
            crate::config::Config::default(),
        )),
        Arc::new(BackendRegistry::new()),
        crate::config::FailsafeConfig::default(),
        std::time::Duration::from_secs(300),
    )
    .with_identity_grant_sink(Arc::new(IdentityGrantSink::new(
        store,
        epoch,
        path.to_path_buf(),
    )))
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
#[tokio::test]
async fn t8_publishing_an_unchanged_store_must_not_advance_the_epoch() {
    let meta = meta();
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("grants.json");
    let rows = [grant("g1", "alice", "cal"), grant("g2", "bob", "mail")];
    write_grants(&path, &rows);
    let ctx = reload_ctx(&meta, &path);

    ctx.reload_identity_grants()
        .await
        .expect("a wired sink reloads")
        .expect("the fixture file is valid");

    // PREMISE, in this cell's own body: the store really is populated, so the
    // cell cannot pass by publishing nothing into nothing.
    assert_eq!(
        meta.identity_grant_rows().len(),
        2,
        "T8 premise: the live store must be populated before the no-op reload"
    );
    let before = meta.policy_epoch.load(Ordering::Acquire);

    // The same file again, byte for byte.
    ctx.reload_identity_grants()
        .await
        .expect("a wired sink reloads")
        .expect("the fixture file is still valid");

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
#[tokio::test]
async fn t8b_a_reordered_file_must_not_read_as_a_change() {
    let meta = meta();
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("grants.json");
    let a = grant("g1", "alice", "cal");
    let b = grant("g2", "bob", "mail");
    write_grants(&path, &[a.clone(), b.clone()]);
    let ctx = reload_ctx(&meta, &path);

    ctx.reload_identity_grants()
        .await
        .expect("a wired sink reloads")
        .expect("the fixture file is valid");

    assert_eq!(
        meta.identity_grant_rows().len(),
        2,
        "T8b premise: the live store must be populated before the reorder"
    );
    let before = meta.policy_epoch.load(Ordering::Acquire);

    // The same two rows, in the opposite file order.
    write_grants(&path, &[b, a]);
    ctx.reload_identity_grants()
        .await
        .expect("a wired sink reloads")
        .expect("a reordered file is still valid");

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
