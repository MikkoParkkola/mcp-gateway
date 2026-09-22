// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-6744.STORE.1 — the provenance half of the 3.x credential migration.
//!
//! These are acceptance tests written BEFORE the migration exists, and two of
//! the three are RED on purpose. They are here rather than in the acceptance
//! suite because they need NO new API: every call below is a call the tree
//! already compiles today, so they fail on behaviour rather than on a missing
//! symbol. That distinction is the whole reason this file is separate — a
//! compile error proves a function is unwritten, it does not prove a rule is
//! broken.
//!
//! WHAT IS BEING PINNED. Design §6 rules that a migrated grant must be
//! distinguishable on disk from a grant the user consented to, and carries that
//! mark in `AuthorityEntry.legacy_migration`. Design §6.1 concedes the guarded
//! commit cannot set it today. §6.1 is correct, and
//! `a_first_migration_commit_must_land_carrying_its_provenance_marker` is the
//! cheapest proof of that: it fails against the current tree and goes green
//! only when the provenance parameter of §6.1/§8.3 lands.
//!
//! TWO-DIRECTIONAL BY CONSTRUCTION. A suite that only asserted "the marker is
//! set" would pass for an implementation that stamps every grant as migrated,
//! which destroys the audit property §6.2 is buying. So the set-direction test
//! is paired with `a_grant_committed_outside_migration_must_stay_unmarked`,
//! and the pair has to hold together. That second test passes VACUOUSLY today —
//! nothing anywhere produces a `Some`, so "stays unmarked" is free — and it is
//! recorded here as vacuous rather than counted as coverage. It becomes
//! load-bearing the moment the plumbing lands, which is the point at which an
//! inverted implementation could otherwise ship unnoticed.

use super::{AccountKey, AccountLookup, ConsentExpectation, PersonalAccountStore, alice, config};
use crate::personal_accounts::consent::GuardedCommit;

/// The marker a migrated grant is expected to carry: the 3.x source file's
/// basename, per §6. The value is opaque to the store; only its presence and
/// its survival are behaviour.
const LEGACY_SOURCE_BASENAME: &str = "7d4f1c09a2b3e5f8_tokens.json";

/// An initialized, empty store plus the settings that reopen it.
fn empty_store() -> (
    tempfile::TempDir,
    super::StoreConfig,
    PersonalAccountStore,
) {
    let root = tempfile::tempdir().unwrap();
    let settings = config(root.path());
    let store = PersonalAccountStore::initialize(settings.clone())
        .expect("offline initialization on empty roots");
    (root, settings, store)
}

/// A grant shaped the way §7.2 says migration builds one from a 3.x record.
///
/// Only the fields the provenance question depends on matter here; the rest
/// reuse the module fixture so this file does not restate the record contract.
fn migrated_grant() -> super::GrantRecord {
    super::grant()
}

/// Read `legacy_migration` straight off the durable authority.
///
/// Through `lock_authority`, the store's only acquisition point, so this
/// observes what was actually published rather than anything the commit path
/// reports about itself.
fn provenance_of(store: &PersonalAccountStore, account: &AccountKey) -> Option<String> {
    let digest = account.digest().expect("fixture key digests");
    let authority = store.lock_authority();
    authority
        .as_ref()
        .expect("an initialized store holds its authority")
        .entries
        .get(&digest)
        .expect("the account was committed, so it has an entry")
        .legacy_migration
        .clone()
}

/// STORE.1 §6 / falsifier F17 — RED UNTIL §6.1's PLUMBING LANDS.
///
/// A first migration is exactly the case with no prior entry to carry a marker
/// forward from, so the carry-forward at `commit.rs:285-288` yields `None` and
/// every migrated grant lands indistinguishable from a consented one. That is
/// the grant the marker exists to label, and §5.5's accepted residual risk —
/// an operator who declares the wrong `principal_subject` — is precisely the
/// misattribution nobody can audit afterwards if this stays absent.
///
/// This test does not describe the gap, it fails on it.
#[test]
fn a_first_migration_commit_must_land_carrying_its_provenance_marker() {
    // GIVEN: an empty store, so this commit is a FIRST migration — no prior
    // entry exists for the carry-forward to copy a marker off.
    let (_root, _settings, store) = empty_store();
    let account = alice();
    let record = migrated_grant();
    assert_eq!(
        store.lookup(&account),
        Ok(AccountLookup::Absent),
        "control: the account must be absent, or this is not a first migration"
    );

    // WHEN: migration commits it through the guarded primitive §7.1a chose.
    assert_eq!(
        store.commit_grant_if_unchanged(&account, &ConsentExpectation::Absent, &record),
        Ok(GuardedCommit::Committed),
        "control: the guarded commit must succeed, or the assertion below is \
         about a grant that was never written"
    );

    // THEN: the published entry names the 3.x file it came from.
    assert_eq!(
        provenance_of(&store, &account).as_deref(),
        Some(LEGACY_SOURCE_BASENAME),
        "a migrated grant must be distinguishable on disk from one the user \
         consented to; today the guarded commit has no way to say so, which is \
         the gap design §6.1 costs and §8.3 lists"
    );
}

/// STORE.1 §6 — the other direction. VACUOUS TODAY, load-bearing after §6.1.
///
/// Stated plainly so nobody counts it as coverage before it can fail: with no
/// producer of `Some` anywhere in the tree, "stays unmarked" is true of every
/// commit and this test cannot go red. It is here because the moment the
/// provenance parameter exists, an implementation that stamps every grant —
/// the inverted oracle — makes it red, and nothing else in the suite would.
#[test]
fn a_grant_committed_outside_migration_must_stay_unmarked() {
    let (_root, _settings, store) = empty_store();
    let account = alice();

    assert_eq!(
        store.commit_grant_if_unchanged(&account, &ConsentExpectation::Absent, &super::grant()),
        Ok(GuardedCommit::Committed)
    );

    assert_eq!(
        provenance_of(&store, &account),
        None,
        "an ordinary consent commit must never be labelled as migrated: the \
         marker's only value is telling the two apart"
    );
}

/// STORE.1 §6.2 claim 1 — the carry-forward already works, so the plumbing in
/// §6.1 is needed only for the INITIAL set.
///
/// Design §6.2 rests its keep-the-field decision partly on this, and it is the
/// one part of §6 that can be proved against today's tree: a marker present on
/// an entry survives the next durable write for that account. The marker is
/// planted directly on the held authority rather than through a producer,
/// because no producer exists — that absence is what F17 above is about.
#[test]
fn a_provenance_marker_already_on_an_entry_survives_the_next_commit() {
    let (_root, _settings, store) = empty_store();
    let account = alice();
    let digest = account.digest().expect("fixture key digests");

    assert_eq!(
        store.commit_grant_if_unchanged(&account, &ConsentExpectation::Absent, &super::grant()),
        Ok(GuardedCommit::Committed)
    );

    // Plant the marker on the live authority, standing in for the producer
    // §6.1 has to add.
    {
        let mut authority = store.lock_authority();
        authority
            .as_mut()
            .expect("an initialized store holds its authority")
            .entries
            .get_mut(&digest)
            .expect("the account was just committed")
            .legacy_migration = Some(LEGACY_SOURCE_BASENAME.to_owned());
    }

    // A later durable write for the same account: a re-consent replacing the
    // grant, which is the shape §6.2 claims preserves the marker.
    let mut replacement = super::grant();
    replacement.generation = "00000000000000000000000000000002".into();
    replacement.token_revision = 2;
    let expected = ConsentExpectation::captured(
        &store.lookup(&account).expect("the committed account reads back"),
    );
    assert_eq!(
        store.commit_grant_if_unchanged(&account, &expected, &replacement),
        Ok(GuardedCommit::Committed),
        "control: the replacement must actually be written, or survival of the \
         marker is asserted about a write that never happened"
    );

    assert_eq!(
        provenance_of(&store, &account).as_deref(),
        Some(LEGACY_SOURCE_BASENAME),
        "commit.rs:285-299 carries the marker onto the replacement entry, so a \
         migrated grant stays labelled across refresh and re-consent"
    );
}
