// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! S10 crash durability and S13 replay refusal, across REAL process restarts.
//!
//! A store holds both directory locks for its lifetime, so every restart here
//! is a separate process, never a dropped struct. Planting a half-written file
//! by hand afterwards would only re-test lookup; letting the writer die tests
//! the writer.
//!
//! The commit path has exactly ONE instant that changes the RESTART-VISIBLE
//! answer: the authority rename at `commit.rs:224`. Every `boundary!` fires
//! BEFORE the step it names, so a crash at any of the eight boundaries up to
//! and including `ManifestRename` leaves the prior manifest in place; only the
//! `ParentSync` check — spelled out at `commit.rs:231-237` because it needs
//! the post-rename refusal category — runs after that rename, where the new
//! generation is already what a restart reads back. `every_named_boundary`
//! drives all nine and pins the single admissible generation for each, so
//! neither class is argued, both are measured, and a boundary added on the far
//! side of the rename cannot default into the wrong class.
//!
//! This harness kills the child process; it does not cut power. `rename(2)`
//! is not durable until its parent directory is synced, so between
//! `ManifestRename` and `ParentSync` a real power loss can still roll the
//! rename back — a process kill cannot, because a completed rename is already
//! visible to every reader on the same machine, crashed or not. Read
//! `ParentSync`'s "durable" here as durable-under-process-restart; it is not
//! power-loss durability evidence, and a future reader must not cite it as
//! such or remove that fsync as redundant.
//!
//! `faults::ALL` is a maintained list, not compile-time derived from
//! `Boundary`: adding a variant forces a compile error in every exhaustive
//! match over `Boundary` (`Boundary::name`, this module's
//! `admissible_after`), so a new boundary cannot silently misclassify, but it
//! does not automatically add itself to `ALL` — that still needs a person.

use super::commit::generation;
use super::faults::{self, Boundary};
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
            Ok(AccountLookup::Connected(record)) if record == generation(SECOND) => {
                "connected_second".to_owned()
            }
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

/// The one post-restart answer a crash at `boundary` may leave.
///
/// `boundary!` is expanded before the step it names — the candidate's write,
/// sync, rename and parent sync at `commit.rs:93-103`, the manifest's at
/// `commit.rs:216-223` — so all of those die with the authority manifest
/// untouched and the prior generation still the durable one. The candidate
/// written for the second commit is named by nothing: `open` never scans the
/// record directory (`storage.rs:405`) and `lookup` opens only the basename the
/// manifest names (`storage.rs:594-600`), so an uncommitted candidate cannot
/// produce a recovery failure — which is why this returns one exact answer and
/// not an answer-or-error disjunction. `ParentSync` is the sole exception: its
/// check at `commit.rs:231-237` runs AFTER `fs::rename` replaced the authority
/// at `commit.rs:224`, so the new generation is already the only admissible one.
///
/// Exhaustive on purpose. A boundary added on the far side of that rename must
/// not silently default into the prior-generation class; it must fail to
/// compile until someone classifies it.
fn admissible_after(boundary: Boundary) -> &'static str {
    match boundary {
        Boundary::RecordWrite
        | Boundary::RecordSync
        | Boundary::RecordRename
        | Boundary::RecordParentSync
        | Boundary::CommitCheckpoint
        | Boundary::ManifestWrite
        | Boundary::ManifestSync
        | Boundary::ManifestRename => "connected",
        Boundary::ParentSync => "connected_second",
    }
}

/// Initialize a store and commit the first generation through a real child, so
/// every case below starts from a durable prior generation nobody is holding.
fn store_with_first_generation() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    PersonalAccountStore::initialize(config(root.path())).expect("offline initialization");
    assert_eq!(drive(root.path(), "commit", None), answered("committed"));
    root
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

    // Restart. Exactly the prior generation. Never the uncommitted candidate,
    // never absence, never silence — and never a failure either: nothing names
    // the candidate, so there is no recovery step left to fail. A disjunction
    // with "or an explicit failure" would have been satisfied by a startup that
    // failed for a wholly unrelated reason.
    assert_eq!(
        drive(root.path(), "lookup", None),
        answered("connected"),
        "after a mid-commit crash the prior generation loads, with no failure arm"
    );
}

#[test]
fn s10_a_restart_with_no_crash_injected_loads_the_generation_that_was_committed() {
    let root = store_with_first_generation();
    // Leg one, the control the crash cases need: a restart that was never
    // interrupted still loads the prior generation, so "connected" after a
    // crash is durability and not an artifact of the reading process.
    assert_eq!(
        drive(root.path(), "lookup", None),
        answered("connected"),
        "a healthy restart loads the generation the previous process committed"
    );
    // Leg two: the same second commit the crash cases interrupt DOES move the
    // answer when it is allowed to finish. Without this, every "connected" above
    // would also be satisfied by a `commit_second` that quietly did nothing.
    assert_eq!(
        drive(root.path(), "commit_second", None),
        answered("committed_second")
    );
    assert_eq!(
        drive(root.path(), "lookup", None),
        answered("connected_second"),
        "a completed second commit is the new durable answer across a restart"
    );
}

#[test]
fn s10_a_crash_at_every_named_boundary_leaves_exactly_one_admissible_generation() {
    for boundary in faults::ALL {
        let root = store_with_first_generation();
        assert_eq!(
            drive(root.path(), "commit_second", Some(boundary.name())),
            Outcome::Died {
                checkpoint: Some(boundary.name().to_owned()),
            },
            "the child must die AT {}, announced before it dies, not merely end",
            boundary.name()
        );
        assert_eq!(
            drive(root.path(), "lookup", None),
            answered(admissible_after(boundary)),
            "a crash at {} admits exactly one generation after restart",
            boundary.name()
        );
    }
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
