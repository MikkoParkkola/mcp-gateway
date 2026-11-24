// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A held first key when the write around it goes wrong: the journal mark or
//! removal fails, the process stops between steps, or the config link moves
//! while the held reload runs. The route halves of these cases (no secret in
//! the answer, the added sentence, revoking a key that was never created)
//! are the create route's rows.

use std::sync::{Arc, Mutex};

use super::{BEARER, FIRST, Gw, starter};
use crate::config_persistence::commit::FileRevision;
use crate::config_persistence::journal::Recovered;
use crate::config_persistence::journal::fault::{self, Fault};
use crate::config_persistence::keyedit::Template;
use crate::config_reload::reload_context::replace::{
    Expected, Replace, ReplaceError, ReplaceReload, Replaced, StatusChange,
};

/// One valid setting beside `text`: a backend the reload registers.
fn with_backend(text: &str) -> String {
    format!("{text}backends:\n  b:\n    http_url: \"http://127.0.0.1:9/mcp\"\n")
}

/// The held write of the first key with `fault` armed on the journal; the
/// fault fired once and is disarmed again before this returns.
async fn held_with(gw: &Gw, fault: Fault) -> Result<ReplaceReload, ReplaceError> {
    let armed = fault::set(&gw.path, fault);
    let answer = gw
        .write(&starter(&[("first", FIRST)]), StatusChange::HoldForRestart)
        .await;
    assert_eq!(fault::fired(&gw.path), 1, "premise: the fault was reached");
    drop(armed);
    answer
}

/// W6 class one: the journal mark fails after the held reload. The answer
/// is `Unconfirmed` and the journal stays `staged`, so the create did not
/// happen: the next writer in the same process (a settings save of one
/// valid setting) first puts the original bytes back, at the revision from
/// before the create, then saves; no key exists and nothing waits.
#[tokio::test]
async fn w6_a_failed_mark_leaves_the_create_undone_by_the_next_writer() {
    let gw = Gw::start(&starter(&[]));
    let original = gw.file();
    let error = held_with(&gw, Fault::FailJournalMark)
        .await
        .expect_err("unconfirmed");
    assert!(
        matches!(error, ReplaceError::Unconfirmed { .. }),
        "{error:?}"
    );
    assert_eq!(gw.journal_state().as_deref(), Some("staged"));

    let seen = Arc::new(Mutex::new(None));
    let saw = Arc::clone(&seen);
    let next = with_backend(&original);
    let bytes = next.clone().into_bytes();
    let save = Replace {
        // Passes only if the bytes the writer reads are the original's.
        expected: Expected::Revision(FileRevision::of(original.as_bytes())),
        compute: Box::new(move |current| {
            *saw.lock().expect("seen") = Some(current.to_vec());
            Ok(Template::plain(bytes))
        }),
        replaced: Replaced::Discard,
        secrets: None,
        status_change: StatusChange::Refuse,
    };
    let reload = gw.run(save).await.expect("the next save applies");
    assert!(matches!(reload, ReplaceReload::Applied(_)), "{reload:?}");
    let seen = seen.lock().expect("seen").take();
    assert_eq!(
        seen.as_deref(),
        Some(original.as_bytes()),
        "the next writer read the restored original"
    );
    assert_eq!(gw.file(), next);
    assert_eq!(gw.journal_state(), None);
    assert!(!gw.original_left());
    assert_eq!(gw.live.waiting_keys(), None);
    assert!(!gw.accepts(FIRST));
}

/// What a held write with a failing journal removal answered and left, and
/// what the next write found: run on this thread so its warning is captured.
struct RemovalFailed {
    held: Result<ReplaceReload, ReplaceError>,
    state_after: Option<String>,
    next: Result<ReplaceReload, ReplaceError>,
    state_next: Option<String>,
    original_next: bool,
    waiting_next: Option<Vec<String>>,
}

/// W6 class two: the journal removal fails after the mark. The held outcome
/// is still returned, a warning is logged, and the next config write (here,
/// removing the key) cleans the journal up.
#[test]
fn w6_a_failed_journal_removal_still_holds_and_warns() {
    let gw = Gw::start(&starter(&[]));
    let (seen, warnings) = crate::test_log_capture::capture_warnings(|| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let held = held_with(&gw, Fault::FailJournalRemove).await;
            let state_after = gw.journal_state();
            let next = gw.write(&starter(&[]), StatusChange::Refuse).await;
            RemovalFailed {
                held,
                state_after,
                next,
                state_next: gw.journal_state(),
                original_next: gw.original_left(),
                waiting_next: gw.live.waiting_keys(),
            }
        })
    });
    match seen.held {
        Ok(ReplaceReload::HeldForRestart { keys, .. }) => assert_eq!(keys, ["first"]),
        other => panic!("expected the held outcome, got {other:?}"),
    }
    assert_eq!(seen.state_after.as_deref(), Some("all_renamed"));
    assert!(
        warnings.contains("WARN") && warnings.contains("replace journal failed"),
        "{warnings}"
    );
    assert!(
        matches!(seen.next, Ok(ReplaceReload::Applied(_))),
        "{:?}",
        seen.next
    );
    assert_eq!(seen.state_next, None);
    assert!(!seen.original_next);
    assert_eq!(seen.waiting_next, None);
}

/// W6 class three: stopped after the write and before the mark (the disk a
/// failed mark leaves: new bytes, a `staged` journal, the staged original).
/// The next start's recovery puts the original back and removes the journal
/// and the copy; the gateway then is single-user, the key unknown, nothing
/// waiting.
#[tokio::test]
async fn w6_stopped_before_the_mark_starts_on_the_original() {
    let gw = Gw::start(&starter(&[]));
    let original = gw.file();
    held_with(&gw, Fault::FailJournalMark)
        .await
        .expect_err("unconfirmed");
    assert_eq!(
        gw.file(),
        starter(&[("first", FIRST)]),
        "premise: the new bytes"
    );
    let (gw, recovered) = gw.restart();
    assert_eq!(recovered, Recovered::RolledBack);
    assert_eq!(gw.file(), original);
    assert_eq!(gw.journal_state(), None);
    assert!(!gw.original_left());
    assert!(!gw.multi_user());
    assert!(!gw.accepts(FIRST));
    assert!(gw.accepts(BEARER));
    assert_eq!(gw.live.waiting_keys(), None);
}

/// W6 class four: stopped after the mark (the disk a failed removal leaves:
/// new bytes, an `all_renamed` journal, the staged original). The next
/// start keeps the new bytes and removes the journal and the copy; the
/// gateway then is multi-user and the key authenticates.
#[tokio::test]
async fn w6_stopped_after_the_mark_starts_on_the_key() {
    let gw = Gw::start(&starter(&[]));
    held_with(&gw, Fault::FailJournalRemove)
        .await
        .expect("held");
    let (gw, recovered) = gw.restart();
    assert_eq!(recovered, Recovered::KeptNew);
    assert_eq!(gw.file(), starter(&[("first", FIRST)]));
    assert_eq!(gw.journal_state(), None);
    assert!(!gw.original_left());
    assert!(gw.multi_user());
    assert!(gw.accepts(FIRST));
    assert!(gw.accepts(BEARER));
}

/// W7: the config link re-pointed while a held write's reload runs. The
/// write is rolled back as any write is. The refused reload had set the
/// fact; the reload the roll-back owes recomputes it from the file it
/// reads, so the fact is judged after that reload, not right after the write.
#[cfg(unix)]
#[tokio::test]
async fn w7_a_held_write_whose_link_moves_is_rolled_back() {
    const BOUND: std::time::Duration = std::time::Duration::from_secs(30); // fail, never hang
    let gw = Gw::start_linked(&starter(&[]));
    let real = gw.dir.path().join("real.yaml");
    let pause = crate::config_reload::reload_pause::arm(&gw.path);
    let write = tokio::spawn(
        crate::config_reload::reload_context::replace::replace_detached(
            Arc::clone(&gw.ctx),
            super::replace(&starter(&[("first", FIRST)]), StatusChange::HoldForRestart),
            super::WAIT,
        ),
    );
    tokio::time::timeout(BOUND, pause.reached.notified())
        .await
        .expect("the held write's reload reaches its pause");
    std::fs::remove_file(&gw.path).expect("unlink");
    std::os::unix::fs::symlink(gw.dir.path().join("other.yaml"), &gw.path).expect("re-point");
    pause.release.notify_one();
    let error = tokio::time::timeout(BOUND, write)
        .await
        .expect("the write ends")
        .expect("write task")
        .expect_err("rolled back");
    assert!(matches!(error, ReplaceError::Unsupported(_)), "{error:?}");
    assert_eq!(std::fs::read_to_string(&real).expect("read"), starter(&[]));
    assert!(!crate::config_persistence::journal::journal_path(&real).exists());
    gw.ctx
        .reload_outcome()
        .await
        .expect("the owed reload applies");
    assert_eq!(gw.live.waiting_keys(), None);
    assert!(!gw.accepts(FIRST));
}
