// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! S08/S09 compare-and-swap fencing and O4 descriptor fencing, at the STORE
//! boundary only.
//!
//! These cases stage the race sequentially rather than with threads, because
//! the property under test is expressible without concurrency: a snapshot taken
//! before a provider call must not apply after the manifest moved. Sequential
//! staging is the stronger evidence here — it is deterministic and cannot flake.
//! What it does NOT prove is dispatch-side behaviour: that no new lease is
//! issued, that transport is barred, that caches and connections are retired.
//! That needs the service and lease runtime and is out of this slice; these
//! tests must never be cited as complete S08/S09 evidence.
//!
//! Every successful transition is re-read through a REOPENED store, so an
//! in-memory-only mutation cannot satisfy any positive case.

use super::commit::{account, empty_store, reopen};
use super::{AccountLookup, GrantRecord, GrantVersion, RefreshOutcome, grant};

/// The non-secret version a caller snapshots before its provider call.
fn version(record: &GrantRecord) -> GrantVersion {
    GrantVersion {
        generation: record.generation.clone(),
        token_revision: record.token_revision,
        authorization_epoch: record.authorization_epoch,
        descriptor_revision: record.descriptor_revision.clone(),
    }
}

/// An ordinary refresh result: same generation and epoch, next token revision.
fn refreshed(record: &GrantRecord, token_revision: u64) -> GrantRecord {
    let mut next = record.clone();
    next.token_revision = token_revision;
    next.access_token = format!("synthetic-refreshed-access-r{token_revision}");
    next
}

#[test]
fn s08_a_refresh_holding_the_current_version_commits_durably() {
    let (_root, settings, store) = empty_store(16);
    let key = account("alice");
    let first = grant();
    assert_eq!(store.commit_grant(&key, &first), Ok(()));
    let next = refreshed(&first, first.token_revision + 1);
    assert_eq!(
        store.refresh_tokens(&key, &version(&first), &next),
        Ok(RefreshOutcome::Committed),
        "the expected version still held, so the swap applies"
    );
    assert_eq!(
        store.lookup(&key),
        Ok(AccountLookup::Connected(next.clone()))
    );
    drop(store);
    assert_eq!(
        reopen(&settings).lookup(&key),
        Ok(AccountLookup::Connected(next)),
        "an acknowledged refresh survives restart, it is not an in-memory swap"
    );
}

#[test]
fn s08_a_second_refresh_from_the_same_snapshot_cannot_roll_the_token_back() {
    let (_root, settings, store) = empty_store(16);
    let key = account("alice");
    let first = grant();
    assert_eq!(store.commit_grant(&key, &first), Ok(()));
    // Two callers snapshot the same version, both call the provider, both come
    // back. The generation never changed, so only the token revision separates
    // them: a fence that compares generation alone lets the loser overwrite.
    let staged = version(&first);
    let winner = refreshed(&first, first.token_revision + 1);
    let mut loser = refreshed(&first, first.token_revision + 1);
    // Distinct token material at the SAME proposed revision. Without this the
    // two records are byte-identical and the survival assertion below cannot
    // tell the winner from a loser that overwrote it.
    loser.access_token = "synthetic-loser-access-3c81f0".into();
    loser.refresh_token = Some("synthetic-loser-refresh-77d2ab".into());
    assert_eq!(loser.token_revision, winner.token_revision);
    assert_ne!(loser.access_token, winner.access_token);
    assert_ne!(loser.refresh_token, winner.refresh_token);
    assert_eq!(
        store.refresh_tokens(&key, &staged, &winner),
        Ok(RefreshOutcome::Committed)
    );
    assert_eq!(
        store.refresh_tokens(&key, &staged, &loser),
        Ok(RefreshOutcome::Rejected),
        "the second response held a token revision that had already been rotated"
    );
    assert_eq!(
        store.lookup(&key),
        Ok(AccountLookup::Connected(winner.clone()))
    );
    drop(store);
    assert_eq!(
        reopen(&settings).lookup(&key),
        Ok(AccountLookup::Connected(winner)),
        "the first result is what survives, durably"
    );
}

#[test]
fn s08_a_stale_snapshot_cannot_land_after_a_durable_revoke() {
    let (_root, settings, store) = empty_store(16);
    let key = account("alice");
    let first = grant();
    assert_eq!(store.commit_grant(&key, &first), Ok(()));
    // Snapshot taken before the provider call, exactly as a refresh would.
    let staged = version(&first);
    assert_eq!(store.revoke(&key), Ok(()));
    assert_eq!(
        store.refresh_tokens(&key, &staged, &refreshed(&first, first.token_revision + 1)),
        Ok(RefreshOutcome::Rejected),
        "a response that raced a durable revoke must not land"
    );
    assert_eq!(
        store.lookup(&key),
        Ok(AccountLookup::Revoked(version(&first))),
        "the tombstone discloses the version it retired, unchanged"
    );
    drop(store);
    assert_eq!(
        reopen(&settings).lookup(&key),
        Ok(AccountLookup::Revoked(version(&first))),
        "restart resurrects neither the old token nor the rejected one"
    );
}

#[test]
fn s09_a_late_refresh_cannot_overwrite_a_newer_generation() {
    let (_root, settings, store) = empty_store(16);
    let key = account("alice");
    let old = grant();
    assert_eq!(store.commit_grant(&key, &old), Ok(()));
    let staged = version(&old);
    // Revoke, then reconnect: re-consent mints a new generation over the
    // tombstone, which is legitimate. The late refresh below is not.
    assert_eq!(store.revoke(&key), Ok(()));
    let mut fresh = grant();
    fresh.generation = "00000000000000000000000000000009".into();
    fresh.access_token = "synthetic-reconnected-access-9a41".into();
    assert_eq!(store.commit_grant(&key, &fresh), Ok(()));
    assert_eq!(
        store.refresh_tokens(&key, &staged, &refreshed(&old, old.token_revision + 1)),
        Ok(RefreshOutcome::Rejected),
        "a refresh snapshotted against a retired generation must not apply"
    );
    assert_eq!(
        store.lookup(&key),
        Ok(AccountLookup::Connected(fresh.clone()))
    );
    drop(store);
    assert_eq!(
        reopen(&settings).lookup(&key),
        Ok(AccountLookup::Connected(fresh)),
        "the re-consented generation survives restart unchanged"
    );
}

#[test]
fn o4_a_changed_descriptor_revision_fences_the_grant_durably() {
    let (_root, settings, store) = empty_store(16);
    let key = account("alice");
    let first = grant();
    assert_eq!(store.commit_grant(&key, &first), Ok(()));
    let moved = "b".repeat(64);
    assert_ne!(moved, first.descriptor_revision);
    assert_eq!(store.mark_reconnect_required(&key, &moved), Ok(()));
    assert_eq!(
        store.lookup(&key),
        Ok(AccountLookup::ReconnectRequired(version(&first))),
        "the entry keeps the version it committed and changes only its state"
    );
    drop(store);
    assert_eq!(
        reopen(&settings).lookup(&key),
        Ok(AccountLookup::ReconnectRequired(version(&first))),
        "a fence that vanishes on restart is not a fence"
    );
}

#[test]
fn o4_an_unchanged_descriptor_revision_does_not_fence() {
    let (_root, settings, store) = empty_store(16);
    let key = account("alice");
    let first = grant();
    assert_eq!(store.commit_grant(&key, &first), Ok(()));
    assert_eq!(
        store.mark_reconnect_required(&key, &first.descriptor_revision),
        Ok(())
    );
    assert_eq!(
        store.lookup(&key),
        Ok(AccountLookup::Connected(first.clone())),
        "nothing moved, so a blanket fence cannot satisfy this pair"
    );
    drop(store);
    assert_eq!(
        reopen(&settings).lookup(&key),
        Ok(AccountLookup::Connected(first)),
        "and it did not quietly fence the persisted entry either"
    );
}
