// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! S10 crash durability and S13 replay refusal, across REAL process restarts.
//!
//! A store holds both directory locks for its lifetime, so every restart here
//! is a separate process, never a dropped struct. The mid-commit case dies at a
//! test-only checkpoint between the candidate's sync and the manifest
//! replacement — the one window where a crash can leave a written candidate
//! that no authority accepts. Planting such a file by hand afterwards would
//! only re-test lookup; letting the writer die there tests the writer.

use super::commit::generation;
use super::faults::Boundary;
use super::probe::{self, Outcome};
use super::{AccountLookup, PersonalAccountStore, alice, config, grant};
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

const CHILD: &str = "personal_accounts::tests::crash::account_child";
const SECOND: &str = "00000000000000000000000000000005";

/// Private test-binary entrypoint; no daemon or real credentials are involved.
#[test]
#[ignore = "private child entrypoint; driven by the account crash regressions"]
fn account_child() {
    let (root, action) = probe::assignment();
    let settings = config(&root);
    probe::ready();
    let store = match PersonalAccountStore::open(settings) {
        Ok(store) => store,
        Err(error) => return probe::report(&format!("open:{error:?}")),
    };
    let key = alice();
    let outcome = match action.as_str() {
        "commit" | "commit_then_abort" => match store.commit_grant(&key, &grant()) {
            Ok(()) => "committed".to_owned(),
            Err(error) => format!("commit:{error:?}"),
        },
        "commit_second" => match store.commit_grant(&key, &generation(SECOND)) {
            Ok(()) => "committed_second".to_owned(),
            Err(error) => format!("commit:{error:?}"),
        },
        "revoke" => match store.revoke(&key) {
            Ok(()) => "revoked".to_owned(),
            Err(error) => format!("revoke:{error:?}"),
        },
        "lookup" => match store.lookup(&key) {
            Ok(AccountLookup::Absent) => "absent".to_owned(),
            Ok(AccountLookup::Connected(record)) if record == grant() => "connected".to_owned(),
            Ok(AccountLookup::Revoked(_)) => "revoked".to_owned(),
            Ok(other) => format!("state:{other:?}"),
            Err(error) => format!("lookup:{error:?}"),
        },
        other => panic!("unknown child action: {other}"),
    };
    probe::report(&outcome);
    if action == "commit_then_abort" {
        // Die without unwinding, without Drop, without releasing the store
        // lock. The question is what survives an abrupt death, not a tidy one.
        std::process::abort();
    }
}

fn drive(root: &Path, action: &str, abort_at: Option<&str>) -> Outcome {
    probe::run(CHILD, root, action, abort_at, Duration::from_secs(20))
}

fn answered(text: &str) -> Outcome {
    Outcome::Answered {
        text: text.to_owned(),
        clean_exit: true,
    }
}

/// Candidate files this account has on disk, accepted or not.
fn candidates(store_dir: &Path) -> Vec<PathBuf> {
    let digest = alice().digest().expect("the fixture account key is valid");
    std::fs::read_dir(store_dir)
        .unwrap()
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with(&digest))
        })
        .collect()
}

fn write_private(path: &Path, bytes: &[u8]) {
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
}

/// Whether the child reported one of the two failures S10 permits after a
/// crash: unavailable, or corrupt. Nothing else qualifies — `InvalidAccountKey`,
/// `InvalidConfiguration` and `CapacityExhausted` are all wrong answers here,
/// and a prefix match would have accepted every one of them.
fn explicit_failure(outcome: &Outcome) -> bool {
    matches!(
        outcome,
        Outcome::Answered { text, .. } if matches!(
            text.as_str(),
            "open:StorageUnavailable"
                | "open:NotAuthentic"
                | "lookup:StorageUnavailable"
                | "lookup:NotAuthentic"
        )
    )
}

#[test]
fn s10_a_committed_generation_survives_an_abrupt_death() {
    let root = tempfile::tempdir().unwrap();
    // Initialize, then hold nothing: both directory locks belong to the child.
    PersonalAccountStore::initialize(config(root.path())).expect("offline initialization");
    assert_eq!(
        drive(root.path(), "lookup", None),
        answered("absent"),
        "control: the store is readable and genuinely empty first"
    );
    assert_eq!(
        drive(root.path(), "commit_then_abort", None),
        Outcome::Answered {
            text: "committed".to_owned(),
            clean_exit: false,
        },
        "the child acknowledges the commit and then dies without unwinding"
    );
    assert_eq!(
        drive(root.path(), "lookup", None),
        answered("connected"),
        "a completed generation is observable after its writer died, never silently empty"
    );
}

#[test]
fn s10_a_crash_between_candidate_sync_and_manifest_replacement_keeps_the_prior_grant() {
    let root = tempfile::tempdir().unwrap();
    let settings = config(root.path());
    PersonalAccountStore::initialize(settings.clone()).expect("offline initialization");
    assert_eq!(drive(root.path(), "commit", None), answered("committed"));
    assert_eq!(drive(root.path(), "lookup", None), answered("connected"));
    let before = candidates(&settings.store_dir).len();

    // Die in the one window that matters: the second candidate is written and
    // synced, the authority has not moved yet.
    assert_eq!(
        drive(
            root.path(),
            "commit_second",
            Some(Boundary::CommitCheckpoint.name())
        ),
        Outcome::Died {
            checkpoint: Some(Boundary::CommitCheckpoint.name().to_owned()),
        },
        "the child must die AT the named checkpoint, announced before it dies, \
         not merely end for some unexplained reason"
    );
    assert_eq!(
        candidates(&settings.store_dir).len(),
        before + 1,
        "the crash happened after the candidate was written, so the window was real"
    );

    // Restart. The prior generation, or an explicit failure. Never the
    // uncommitted candidate, never absence, never silence.
    let observed = drive(root.path(), "lookup", None);
    assert!(
        observed == answered("connected") || explicit_failure(&observed),
        "after a mid-commit crash: the prior generation or an explicit failure, never {observed:?}"
    );
}

#[test]
fn s13_restored_pre_revoke_ciphertext_stays_refused_across_restart() {
    let root = tempfile::tempdir().unwrap();
    let settings = config(root.path());
    PersonalAccountStore::initialize(settings.clone()).expect("offline initialization");
    assert_eq!(drive(root.path(), "commit", None), answered("committed"));
    // Control: this store does return Connected, so the refusal below is a
    // decision about the revoked generation and not a store that refuses all.
    assert_eq!(drive(root.path(), "lookup", None), answered("connected"));
    let accepted = candidates(&settings.store_dir)
        .pop()
        .expect("the commit wrote a candidate");
    let saved = std::fs::read(&accepted).unwrap();
    assert_eq!(drive(root.path(), "revoke", None), answered("revoked"));
    // Put the exact pre-revoke bytes back at the exact accepted path.
    write_private(&accepted, &saved);
    assert_eq!(std::fs::read(&accepted).unwrap(), saved);
    assert_eq!(
        drive(root.path(), "lookup", None),
        answered("revoked"),
        "the latest authority refuses restored ciphertext across a real restart"
    );
}
