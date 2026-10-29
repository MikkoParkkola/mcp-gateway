// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Write-ahead audit rows for the byte writer: pending
//! recovery gets its own intent before anything is recovered or reloaded,
//! and a failed intent leaves the disk and the running config as they were.

use std::path::Path;
use std::sync::{Arc, Mutex};

use super::reload_context::replace::{
    Audit, Expected, FileRevision, Intent, IntentId, IntentKind, IntentSink, ReplaceError,
    Replaced, replace_audited,
};
use super::replace_test_support::*;
use crate::config_persistence::journal;
use crate::gateway::test_helpers::write_owner_only;

/// What the disk held when one intent was appended.
#[derive(Debug)]
struct Seen {
    intent: Intent,
    file: String,
    journal_pending: bool,
}

/// Records each intent with the disk as it stood at that moment; refuses
/// every append when `fail` is set.
#[derive(Clone)]
struct Recorder {
    path: std::path::PathBuf,
    seen: Arc<Mutex<Vec<Seen>>>,
    fail: bool,
}

impl Recorder {
    fn new(path: &Path, fail: bool) -> Self {
        Self {
            path: path.to_path_buf(),
            seen: Arc::default(),
            fail,
        }
    }

    fn kinds(&self) -> Vec<IntentKind> {
        self.seen
            .lock()
            .expect("lock")
            .iter()
            .map(|s| s.intent.kind)
            .collect()
    }
}

impl IntentSink for Recorder {
    fn append(&mut self, intent: &Intent) -> Result<IntentId, String> {
        let mut seen = self.seen.lock().expect("lock");
        seen.push(Seen {
            intent: intent.clone(),
            file: read(&self.path),
            journal_pending: journal::journal_path(&self.path).exists(),
        });
        if self.fail {
            return Err("the audit log refused the append".to_owned());
        }
        Ok(IntentId(format!("intent-{}", seen.len())))
    }
}

/// The disk a writer killed after its rename leaves: `bytes` in place, the
/// original staged, the journal `staged`.
fn crashed_after_rename(path: &Path, bytes: &str) {
    journal::stage_original(path, START.as_bytes()).expect("stage");
    journal::begin(path, FileRevision::of(START.as_bytes()).as_str().to_owned()).expect("journal");
    write_owner_only(crate::identity_grants::journal::resolved(path), bytes).expect("rename");
}

/// W21: a crashed write is pending and the intent append fails: nothing is
/// recovered, nothing reloaded, nothing written.
#[tokio::test]
async fn a_pending_journal_with_a_failing_intent_changes_nothing() {
    let (_dir, path, ctx) = setup();
    crashed_after_rename(&path, NEXT);
    let recorder = Recorder::new(&path, true);

    let result = replace_audited(
        Arc::clone(&ctx),
        to(Expected::Any, NEXT, Replaced::Discard),
        Audit::Required {
            sink: Box::new(recorder.clone()),
            kind: IntentKind::Save,
        },
        WAIT,
    )
    .await;

    assert!(
        matches!(result, Err(ReplaceError::Refused(_))),
        "{result:?}"
    );
    assert_eq!(read(&path), NEXT, "the crashed bytes were recovered");
    assert!(
        journal::journal_path(&path).exists(),
        "the journal was settled"
    );
    assert!(!running_has_b(&ctx), "the crashed bytes were loaded");
    assert_eq!(recorder.kinds(), [IntentKind::Recovery]);
}

/// W22: a pending journal gets a recovery intent before it is recovered;
/// the operation's own intent follows, computed against the recovered bytes
/// and linked to the recovery's.
#[tokio::test]
async fn an_owed_reload_runs_after_its_recovery_intent() {
    let (_dir, path, ctx) = setup();
    crashed_after_rename(&path, NEXT);
    let recorder = Recorder::new(&path, false);

    replace_audited(
        Arc::clone(&ctx),
        to(Expected::Any, NEXT, Replaced::Discard),
        Audit::Required {
            sink: Box::new(recorder.clone()),
            kind: IntentKind::Save,
        },
        WAIT,
    )
    .await
    .expect("the write goes ahead");

    let seen = recorder.seen.lock().expect("lock");
    let kinds: Vec<_> = seen.iter().map(|s| s.intent.kind).collect();
    assert_eq!(kinds, [IntentKind::Recovery, IntentKind::Save]);
    assert!(seen[0].journal_pending, "recovery ran before its intent");
    assert_eq!(seen[0].file, NEXT, "recovery ran before its intent");
    assert_eq!(seen[1].intent.base, FileRevision::of(START.as_bytes()));
    assert_eq!(
        seen[1].intent.recovery_intent_id,
        Some(IntentId("intent-1".into()))
    );
}

/// W22, the in-memory flag alone: a reload owed after a failed one is
/// pending work the lock cannot see, and still gets its intent first.
#[tokio::test]
async fn an_owed_reload_flag_alone_gets_a_recovery_intent() {
    let (_dir, path, ctx) = setup();
    ctx.reload_owed
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let recorder = Recorder::new(&path, false);

    replace_audited(
        Arc::clone(&ctx),
        to(Expected::Any, NEXT, Replaced::Discard),
        Audit::Required {
            sink: Box::new(recorder.clone()),
            kind: IntentKind::Save,
        },
        WAIT,
    )
    .await
    .expect("the write goes ahead");

    assert_eq!(recorder.kinds(), [IntentKind::Recovery, IntentKind::Save]);
}

/// W8: the operation's own intent fails: nothing is written, the running
/// config is unchanged.
#[tokio::test]
async fn an_intent_failure_writes_nothing() {
    let (_dir, path, ctx) = setup();
    let recorder = Recorder::new(&path, true);

    let result = replace_audited(
        Arc::clone(&ctx),
        to(Expected::Any, NEXT, Replaced::Discard),
        Audit::Required {
            sink: Box::new(recorder.clone()),
            kind: IntentKind::Save,
        },
        WAIT,
    )
    .await;

    assert!(
        matches!(result, Err(ReplaceError::Refused(_))),
        "{result:?}"
    );
    assert_eq!(read(&path), START);
    assert!(!running_has_b(&ctx));
    assert_eq!(recorder.kinds(), [IntentKind::Save]);
}
