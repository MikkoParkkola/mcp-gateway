// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Bounded regressions for the NOW-gated findings of runtime review r1.
//!
//! Second revision, after both test-review legs returned SHIP-WITH-FIXES. What
//! changed and why is worth stating, because each change removes a way a case
//! could pass while its defect was still live:
//!
//! - the refresh cases now start above revision 1 and include a genuine
//!   lower-but-positive proposal. The first revision only ever held the token
//!   revision EQUAL and stepped the authorization epoch 1 → 0, which
//!   `storage::validate_record` already refuses as `NotAuthentic` for its own
//!   reason — so no backward revision was ever actually tested;
//! - they assert a NON-COMMITTING REFUSAL with unchanged state and unchanged
//!   files, rather than demanding a particular error variant. The confirmed
//!   finding is that the proposal is not checked, not that a new taxonomy is
//!   owed; a repair using the existing outcome is a correct repair;
//! - each contradiction is its own test. In one loop the first failure aborts
//!   the rest, so four of five mechanisms never ran during RED;
//! - the manifest-orphan case iterates ONLY the manifest stages. The first
//!   revision started at `RecordWrite`, so it died on `persist_record` debris
//!   and never reached the window the finding names. That defect is real and
//!   keeps its own separately named case — with its own attribution;
//! - the byte-cap control now performs a transition that genuinely EXCEEDS the
//!   cap without adding an entry, instead of a shrinking revoke that never
//!   entered the branch at all.
//!
//! A separate file, and a child of `commit`, so every frozen test stays
//! byte-identical, and because two cases must hand the delete paths a pointer a
//! sealed manifest would never carry — which only a module inside the store can
//! construct.
//!
//! Finding 4 — `commit_grant` replacing state unconditionally — is NOT repaired
//! here and stays an open production blocker. `f4_…` below CHARACTERISES
//! today's behaviour so a later guarded entrypoint is visibly a change; it is
//! not coverage and must never be cited as any.

use super::{publish, revoke};
use crate::personal_accounts::faults;
use crate::personal_accounts::{
    AccountError, AccountKey, AccountLookup, Authority, AuthorityEntry, GrantRecord, GrantState,
    GrantVersion, PersonalAccountStore, RefreshOutcome, StoreConfig,
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const KEY: [u8; 32] = [0x51; 32];
const EPOCH: &str = "0123456789abcdef0123456789abcdef";

/// Both revisions start well above 1 so a proposal can step DOWN and still be a
/// well-formed record. At 1 the only available step is 0, which
/// `validate_record` refuses on its own terms, and a case refused for the wrong
/// reason proves nothing about the comparison under test.
const BASE_TOKEN_REVISION: u64 = 5;
const BASE_AUTHORIZATION_EPOCH: u64 = 3;

fn key() -> AccountKey {
    AccountKey {
        principal_authority: "https://identity.example".into(),
        principal_subject: "alice".into(),
        backend_id: "google-workspace".into(),
        resource: "https://www.googleapis.com/drive/v3".into(),
        oauth_issuer: "https://accounts.google.com".into(),
    }
}

fn other_key() -> AccountKey {
    let mut account = key();
    account.principal_subject = "bob".into();
    account
}

fn record() -> GrantRecord {
    GrantRecord {
        generation: "fedcba9876543210fedcba9876543210".into(),
        token_revision: BASE_TOKEN_REVISION,
        authorization_epoch: BASE_AUTHORIZATION_EPOCH,
        descriptor_revision: "0".repeat(64),
        scopes: vec!["https://www.googleapis.com/auth/drive.readonly".into()],
        access_token: "synthetic-repair-access-private-material-4b2e".into(),
        refresh_token: Some("synthetic-repair-refresh-private-material-7a10".into()),
        token_type: "Bearer".into(),
        expires_at: 0,
        provider_account_id: Some("synthetic-repair-provider-account-private-c3".into()),
        client_id: "synthetic-google-client".into(),
    }
}

fn version(of: &GrantRecord) -> GrantVersion {
    GrantVersion {
        generation: of.generation.clone(),
        token_revision: of.token_revision,
        authorization_epoch: of.authorization_epoch,
        descriptor_revision: of.descriptor_revision.clone(),
    }
}

/// An ordinary refresh result: same generation, epoch and descriptor, next
/// token revision. Every contradiction below starts from this and breaks
/// exactly one field, so the field under test is the only variable.
fn rotated(from: &GrantRecord) -> GrantRecord {
    let mut next = from.clone();
    next.token_revision = from.token_revision + 1;
    next.access_token = "synthetic-repair-access-rotated-2f77".into();
    next
}

fn settings(root: &Path) -> StoreConfig {
    let root = root.canonicalize().expect("fixture root exists");
    StoreConfig {
        instance_id: "gateway-instance".into(),
        store_dir: root.join("records"),
        authority_dir: root.join("authority"),
        current_key_id: "current".into(),
        keys: BTreeMap::from([("current".into(), KEY.to_vec())]),
        max_entries: 16,
        max_authority_bytes: 16_777_216,
    }
}

fn initialized() -> (tempfile::TempDir, StoreConfig, PersonalAccountStore) {
    let root = tempfile::tempdir().unwrap();
    let config = settings(root.path());
    let store = PersonalAccountStore::initialize(config.clone())
        .expect("offline initialization on empty roots");
    (root, config, store)
}

fn reopen(config: &StoreConfig) -> PersonalAccountStore {
    PersonalAccountStore::open(config.clone()).expect("the committed authority reopens")
}

/// Everything in the store directory except the lifetime lock. Scratch files
/// are deliberately INCLUDED: a leftover temporary is debris too, and filtering
/// dot files would hide it.
fn record_files(config: &StoreConfig) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(&config.store_dir)
        .expect("the store directory exists")
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name != ".personal-accounts.lock")
        .collect();
    names.sort();
    names
}

fn manifest_len(config: &StoreConfig) -> usize {
    let len = std::fs::metadata(config.authority_dir.join("authority.json"))
        .expect("the authority manifest exists after a commit")
        .len();
    usize::try_from(len).expect("manifest length fits in usize")
}

/// The two directories a hand-built authority needs, without going through
/// `initialize` — these cases must control the manifest's contents.
fn bare_dirs(root: &Path) -> StoreConfig {
    let config = settings(root);
    std::fs::create_dir_all(&config.store_dir).unwrap();
    std::fs::create_dir_all(&config.authority_dir).unwrap();
    config
}

/// An authority naming exactly one entry for `key()`, with a chosen pointer.
fn authority_naming(config: &StoreConfig, basename: &str, state: GrantState) -> Authority {
    let source = record();
    Authority {
        instance_id: config.instance_id.clone(),
        store_epoch: EPOCH.into(),
        commit_revision: 1,
        entries: BTreeMap::from([(
            key().digest().unwrap(),
            AuthorityEntry {
                generation: source.generation,
                token_revision: source.token_revision,
                authorization_epoch: source.authorization_epoch,
                descriptor_revision: source.descriptor_revision,
                record_basename: Some(basename.to_owned()),
                record_sha256: Some("0".repeat(64)),
                state,
                legacy_migration: None,
            },
        )]),
    }
}

/// Two victims and the two pointer shapes that reach them. Both live inside the
/// fixture: a test for a delete defect must never aim the defect at a real file.
///
/// The absolute form is the sharper of the two — `Path::join` DISCARDS the
/// store directory when the joined value is absolute, so no reasoning about
/// prefixes saves it, and a repair that only rejects `..` cannot pass.
fn escaping_pointers(root: &Path, config: &StoreConfig, tag: &str) -> (Vec<PathBuf>, Vec<String>) {
    let traversing = config
        .store_dir
        .join("..")
        .join(format!("victim-{tag}.json"));
    let absolute = root.join(format!("victim-{tag}-absolute.json"));
    for victim in [&traversing, &absolute] {
        std::fs::write(victim, b"a file the credential store must never reach").unwrap();
    }
    (
        vec![traversing, absolute.clone()],
        vec![
            format!("../victim-{tag}.json"),
            absolute.to_string_lossy().into_owned(),
        ],
    )
}

// ---------------------------------------------------------------------------
// Finding 1 — CRITICAL. A pointer read out of the manifest selects a file to
// DELETE without the validation the read path already applies to the very same
// field (`accepted_basename`, storage.rs).
// ---------------------------------------------------------------------------

#[test]
fn f1_publishing_over_an_escaping_previous_name_deletes_nothing_outside_the_store() {
    let root = tempfile::tempdir().unwrap();
    let config = bare_dirs(root.path());
    let (victims, pointers) = escaping_pointers(root.path(), &config, "publish");
    let digest = key().digest().unwrap();

    for pointer in pointers {
        let mut slot = Some(authority_naming(&config, &pointer, GrantState::Connected));
        let published = publish(&config, &mut slot, &digest, &key(), &record());
        assert!(
            published.is_ok() || published == Err(AccountError::NotAuthentic),
            "{pointer}: the commit either completes or refuses the malformed pointer, \
             never {published:?}"
        );
    }
    for victim in victims {
        assert!(
            victim.exists(),
            "a manifest pointer that escapes the store directory must never select a \
             file to delete: {victim:?}"
        );
    }
}

#[test]
fn f1_revoking_an_escaping_retired_name_deletes_nothing_outside_the_store() {
    let root = tempfile::tempdir().unwrap();
    let config = bare_dirs(root.path());
    let (victims, pointers) = escaping_pointers(root.path(), &config, "revoke");

    for pointer in pointers {
        let mut slot = Some(authority_naming(&config, &pointer, GrantState::Connected));
        let revoked = revoke(&config, &mut slot, &key());
        assert!(
            revoked.is_ok() || revoked == Err(AccountError::NotAuthentic),
            "{pointer}: revoke either completes or refuses the malformed pointer, \
             never {revoked:?}"
        );
    }
    for victim in victims {
        assert!(
            victim.exists(),
            "a retired pointer that escapes the store directory must never select a \
             file to delete: {victim:?}"
        );
    }
}

#[test]
fn f1_a_well_formed_superseded_candidate_is_still_removed() {
    // The control against repairing finding 1 by simply never deleting anything.
    let (_root, config, store) = initialized();
    assert_eq!(store.commit_grant(&key(), &record()), Ok(()));
    let after_first = record_files(&config);
    assert_eq!(after_first.len(), 1, "one candidate after the first commit");

    let mut second = record();
    second.generation = "00000000000000000000000000000002".into();
    second.access_token = "synthetic-repair-access-second-91fd".into();
    assert_eq!(store.commit_grant(&key(), &second), Ok(()));

    let after_second = record_files(&config);
    assert_eq!(
        after_second.len(),
        1,
        "the superseded candidate is removed once the manifest no longer names it, \
         leaving {after_second:?}"
    );
    assert_ne!(
        after_second, after_first,
        "and the survivor is the new candidate, not the old one"
    );
}

// ---------------------------------------------------------------------------
// Finding 3 — HIGH. The candidate record is written before the manifest. If the
// manifest never renames, that record is unreferenced forever.
//
// ONLY the manifest stages are iterated. Starting earlier means dying on
// `persist_record` debris — a different defect, below, with its own name — and
// never reaching the window this finding is about.
// ---------------------------------------------------------------------------

const MANIFEST_STAGES: [faults::Boundary; 5] = [
    faults::Boundary::CommitCheckpoint,
    faults::Boundary::ManifestWrite,
    faults::Boundary::ManifestSync,
    faults::Boundary::ManifestRename,
    faults::Boundary::ParentSync,
];

#[test]
fn f3_a_candidate_the_manifest_never_named_is_removed() {
    for boundary in MANIFEST_STAGES {
        let (_root, config, store) = initialized();
        assert!(
            record_files(&config).is_empty(),
            "{boundary:?}: the store starts with no candidate"
        );

        let armed = faults::arm(boundary);
        let refused = store.commit_grant(&key(), &record());
        assert!(
            armed.fired(),
            "{boundary:?} was never reached, so this case would prove nothing"
        );
        assert_eq!(refused, Err(AccountError::StorageUnavailable));
        drop(armed);
        drop(store);

        // `ParentSync` is the AUTHORITY directory's fsync, after the manifest
        // rename. The reopened store is the oracle for "is it named": a file
        // count alone cannot tell a referenced record from an orphan.
        let observed = reopen(&config).lookup(&key());
        let left = record_files(&config);
        if boundary == faults::Boundary::ParentSync {
            assert_eq!(
                observed,
                Ok(AccountLookup::Connected(record())),
                "{boundary:?}: the manifest moved, so the durable authority names this record"
            );
            assert_eq!(
                left.len(),
                1,
                "{boundary:?}: and the record it names must survive"
            );
        } else {
            assert_eq!(
                observed,
                Ok(AccountLookup::Absent),
                "{boundary:?}: the manifest never moved, so nothing is committed"
            );
            assert!(
                left.is_empty(),
                "{boundary:?}: a candidate the manifest never named is an orphan; found {left:?}"
            );
        }
    }
}

#[test]
fn persist_record_leaves_no_debris_when_its_own_sequence_fails() {
    // A DIFFERENT defect from finding 3, named separately so neither borrows the
    // other's evidence. `persist_record` documents that no debris is left behind
    // on any failure; its parent sync runs AFTER its rename, so a failure there
    // leaves the candidate itself rather than a temporary file.
    for boundary in [
        faults::Boundary::RecordWrite,
        faults::Boundary::RecordSync,
        faults::Boundary::RecordRename,
        faults::Boundary::RecordParentSync,
    ] {
        let (_root, config, store) = initialized();
        let armed = faults::arm(boundary);
        let refused = store.commit_grant(&key(), &record());
        assert!(armed.fired(), "{boundary:?} was never reached");
        assert_eq!(refused, Err(AccountError::StorageUnavailable));
        drop(armed);
        drop(store);

        let left = record_files(&config);
        assert!(
            left.is_empty(),
            "{boundary:?}: the record write failed, so it must leave nothing behind; found {left:?}"
        );
        assert_eq!(
            reopen(&config).lookup(&key()),
            Ok(AccountLookup::Absent),
            "{boundary:?}: and nothing was committed"
        );
    }
}

// ---------------------------------------------------------------------------
// Finding 5 — MEDIUM. Exceeding the configured authority byte cap is permanent,
// not transient, and the check fires only after a candidate is already on disk.
// ---------------------------------------------------------------------------

#[test]
fn f5_an_authority_over_its_byte_cap_refuses_as_capacity_and_leaves_no_orphan() {
    let root = tempfile::tempdir().unwrap();
    let mut config = settings(root.path());
    let store = PersonalAccountStore::initialize(config.clone()).unwrap();
    assert_eq!(store.commit_grant(&key(), &record()), Ok(()));
    drop(store);

    // Measured, not guessed: the cap is exactly what one committed entry
    // produces, so that manifest is still readable and a second cannot fit.
    config.max_authority_bytes = manifest_len(&config);
    let store = reopen(&config);
    let before = record_files(&config);
    assert_eq!(
        before.len(),
        1,
        "one committed candidate before the refusal"
    );

    assert_eq!(
        store.commit_grant(&other_key(), &record()),
        Err(AccountError::CapacityExhausted),
        "an authority that cannot fit another entry is at capacity, permanently, \
         not transiently unavailable"
    );
    assert_eq!(
        record_files(&config),
        before,
        "a permanent refusal must not leave a candidate the manifest can never name"
    );
}

#[test]
fn f5_a_transition_that_adds_no_entry_and_exceeds_the_cap_is_a_storage_fault() {
    // The control against over-repairing finding 5 by mapping every oversize
    // manifest to `CapacityExhausted`. This transition GENUINELY exceeds the cap
    // — the fence writes a longer state than the one it replaces — and adds no
    // entry, so capacity is not an answer it can honestly give.
    let root = tempfile::tempdir().unwrap();
    let mut config = settings(root.path());
    let store = PersonalAccountStore::initialize(config.clone()).unwrap();
    assert_eq!(store.commit_grant(&key(), &record()), Ok(()));
    drop(store);

    config.max_authority_bytes = manifest_len(&config);
    let store = reopen(&config);
    let moved = "1".repeat(64);
    assert_eq!(
        store.mark_reconnect_required(&key(), &moved),
        Err(AccountError::StorageUnavailable),
        "the fenced state is longer than the one it replaces, so this manifest does \
         not fit; a caller that added no entry must not be told it is at capacity"
    );
    drop(store);
    assert_eq!(
        reopen(&config).lookup(&key()),
        Ok(AccountLookup::Connected(record())),
        "and the refusal left the durable authority exactly as it was"
    );
}

// ---------------------------------------------------------------------------
// Finding 2 — HIGH. The compare-and-swap checks the STORED entry against the
// caller's expectation and never examines the record being written.
//
// One test per contradiction: in a single loop the first failure aborts the
// rest, so during RED only one mechanism would ever execute.
//
// The assertion is a NON-COMMITTING REFUSAL with unchanged state and unchanged
// files. The confirmed finding is that the proposal goes unchecked; which
// refusal a repair chooses is a separate question and is not prejudged here.
// ---------------------------------------------------------------------------

fn refusing_changes_nothing(why: &str, propose: impl Fn(&GrantRecord) -> GrantRecord) {
    let (_root, config, store) = initialized();
    let first = record();
    assert_eq!(store.commit_grant(&key(), &first), Ok(()));
    let held = record_files(&config);

    let outcome = store.refresh_tokens(&key(), &version(&first), &propose(&first));
    assert!(
        matches!(outcome, Ok(RefreshOutcome::Rejected) | Err(_)),
        "{why}: a proposal that contradicts the caller's own expectation must not \
         commit; got {outcome:?}"
    );
    assert_eq!(
        store.lookup(&key()),
        Ok(AccountLookup::Connected(first.clone())),
        "{why}: the held credential is untouched"
    );
    assert_eq!(
        record_files(&config),
        held,
        "{why}: nothing is written for a proposal that was refused"
    );
    drop(store);
    assert_eq!(
        reopen(&config).lookup(&key()),
        Ok(AccountLookup::Connected(first)),
        "{why}: and the refusal is durable, not merely an in-memory decision"
    );
}

#[test]
fn f2_a_refresh_proposing_a_different_generation_does_not_commit() {
    refusing_changes_nothing("a different generation", |from| {
        let mut next = rotated(from);
        next.generation = "00000000000000000000000000000007".into();
        next
    });
}

#[test]
fn f2_a_refresh_proposing_a_different_descriptor_revision_does_not_commit() {
    refusing_changes_nothing("a different descriptor revision", |from| {
        let mut next = rotated(from);
        next.descriptor_revision = "1".repeat(64);
        next
    });
}

#[test]
fn f2_a_refresh_reusing_the_expected_token_revision_does_not_commit() {
    refusing_changes_nothing("a token revision that does not advance", |from| {
        let mut next = rotated(from);
        next.token_revision = from.token_revision;
        next
    });
}

#[test]
fn f2_a_refresh_lowering_the_token_revision_does_not_commit() {
    // A genuine backward step that is still a WELL-FORMED record: 5 → 4, not
    // 1 → 0. The zero case is refused by `validate_record` for an unrelated
    // reason and would pass this test while the comparison stayed absent.
    refusing_changes_nothing("a token revision that moves backwards", |from| {
        let mut next = rotated(from);
        next.token_revision = from.token_revision - 1;
        assert!(next.token_revision > 0, "the fixture must stay well-formed");
        next
    });
}

#[test]
fn f2_a_refresh_lowering_the_authorization_epoch_does_not_commit() {
    refusing_changes_nothing("an authorization epoch that moves backwards", |from| {
        let mut next = rotated(from);
        next.authorization_epoch = from.authorization_epoch - 1;
        assert!(
            next.authorization_epoch > 0,
            "the fixture must stay well-formed"
        );
        next
    });
}

#[test]
fn f2_an_ordinary_rotation_still_commits() {
    // The control against repairing finding 2 by refusing every refresh.
    let (_root, config, store) = initialized();
    let first = record();
    assert_eq!(store.commit_grant(&key(), &first), Ok(()));
    let next = rotated(&first);
    assert_eq!(
        store.refresh_tokens(&key(), &version(&first), &next),
        Ok(RefreshOutcome::Committed)
    );
    assert_eq!(
        store.lookup(&key()),
        Ok(AccountLookup::Connected(next.clone()))
    );
    assert_eq!(
        record_files(&config).len(),
        1,
        "the rotation superseded the previous candidate rather than accumulating one"
    );

    // An ADVANCING authorization epoch is a legitimate re-authorization, not a
    // contradiction, so the rule must not forbid it.
    let mut widened = rotated(&next);
    widened.authorization_epoch = next.authorization_epoch + 1;
    assert_eq!(
        store.refresh_tokens(&key(), &version(&next), &widened),
        Ok(RefreshOutcome::Committed),
        "an epoch that advances is allowed; only one that moves backwards is not"
    );
}

// ---------------------------------------------------------------------------
// Finding 4 — open production blocker, deliberately NOT repaired here.
// ---------------------------------------------------------------------------

#[test]
fn f4_unconditional_replacement_is_characterised_not_covered() {
    // This is a CHARACTERISATION of today's behaviour, so that the guarded
    // entrypoint the service slice adds — expectation supplied by the consent
    // journey, under the same authority lock — is visibly a change rather than
    // silent drift. A passing result here is NOT coverage of finding 4 and must
    // never be cited as any.
    let (_root, _config, store) = initialized();
    assert_eq!(store.commit_grant(&key(), &record()), Ok(()));
    let mut again = record();
    again.generation = "00000000000000000000000000000003".into();
    assert_eq!(
        store.commit_grant(&key(), &again),
        Ok(()),
        "a second consent for an account that already holds one is currently accepted \
         with no expectation at all; fencing it is the open finding-4 blocker"
    );
}

#[test]
fn f5_an_existing_account_reconsent_that_exceeds_the_cap_is_a_storage_fault() {
    // Re-consent does not add an entry. Finding 5's CapacityExhausted answer is
    // only honest when a new slot cannot fit; TooLarge on a replacement is a
    // storage fault, the same distinction the reconnect control already draws.
    let (_fit_root, fit_config, fit_store) = initialized();
    assert_eq!(fit_store.commit_grant(&key(), &record()), Ok(()));
    let fitted = rotated(&record());
    assert_eq!(
        fit_store.commit_grant(&key(), &fitted),
        Ok(()),
        "an existing-account re-consent that still fits the authority is accepted"
    );
    drop(fit_store);
    assert_eq!(
        reopen(&fit_config).lookup(&key()),
        Ok(AccountLookup::Connected(fitted)),
        "and that fitted re-consent is what a restart reads back"
    );

    let mut large = record();
    large.token_revision = u64::MAX;
    large.access_token = "synthetic-repair-access-reconsent-cap-a17f".into();

    let (_roomy_root, roomy_config, roomy_store) = initialized();
    assert_eq!(roomy_store.commit_grant(&key(), &record()), Ok(()));
    assert_eq!(
        roomy_store.commit_grant(&key(), &large),
        Ok(()),
        "the larger revision is a well-formed existing-account re-consent; under a \
         roomy cap it commits, so a later refusal cannot be blamed on the proposal"
    );
    drop(roomy_store);
    assert_eq!(
        reopen(&roomy_config).lookup(&key()),
        Ok(AccountLookup::Connected(large.clone())),
        "roomy restart holds the larger revision"
    );

    let root = tempfile::tempdir().unwrap();
    let mut config = settings(root.path());
    let store = PersonalAccountStore::initialize(config.clone()).unwrap();
    assert_eq!(store.commit_grant(&key(), &record()), Ok(()));
    drop(store);

    // Measured: the cap is exactly the connected manifest one entry produces, so
    // replacing that entry with more digits in token_revision cannot fit, while
    // the authority remains readable.
    config.max_authority_bytes = manifest_len(&config);
    let store = reopen(&config);
    let before_files = record_files(&config);
    assert_eq!(
        store.lookup(&key()),
        Ok(AccountLookup::Connected(record())),
        "the connected grant is readable under the measured cap"
    );

    assert_eq!(
        store.commit_grant(&key(), &large),
        Err(AccountError::StorageUnavailable),
        "the replacement manifest is longer than the one it replaces and adds no \
         entry; a caller that did not grow the store must not be told it is at capacity"
    );
    assert_eq!(
        store.lookup(&key()),
        Ok(AccountLookup::Connected(record())),
        "lookup is unchanged after the refusal"
    );
    assert_eq!(
        record_files(&config),
        before_files,
        "a non-committing refusal must not leave a candidate the manifest does not name"
    );
    drop(store);
    assert_eq!(
        reopen(&config).lookup(&key()),
        Ok(AccountLookup::Connected(record())),
        "and the refusal left the durable authority exactly as it was"
    );
}
