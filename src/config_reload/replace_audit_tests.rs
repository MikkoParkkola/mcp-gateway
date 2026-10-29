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

/// W29 to W31: the file-watch reload, the API reload and the admin tool all
/// reload through `reload_outcome`, the reader lock's one in-gateway holder.
/// On an audited gateway a pending journal gets its recovery intent first.
#[tokio::test]
async fn a_reload_appends_its_recovery_intent_first() {
    let (_dir, path, ctx) = setup();
    crashed_after_rename(&path, NEXT);
    let recorder = Recorder::new(&path, false);
    ctx.set_recovery_audit(Box::new(recorder.clone()));

    ctx.reload_outcome().await.expect("the reload goes ahead");

    let seen = recorder.seen.lock().expect("lock");
    let kinds: Vec<_> = seen.iter().map(|s| s.intent.kind).collect();
    assert_eq!(kinds, [IntentKind::Recovery]);
    assert!(
        seen[0].journal_pending,
        "the reload recovered before its intent"
    );
    assert_eq!(seen[0].file, NEXT, "the reload recovered before its intent");
}

/// The same paths with a failing intent: nothing is recovered or reloaded.
#[tokio::test]
async fn a_reload_whose_recovery_intent_fails_changes_nothing() {
    let (_dir, path, ctx) = setup();
    crashed_after_rename(&path, NEXT);
    let recorder = Recorder::new(&path, true);
    ctx.set_recovery_audit(Box::new(recorder.clone()));

    assert!(ctx.reload_outcome().await.is_err());

    assert_eq!(read(&path), NEXT, "the crashed bytes were recovered");
    assert!(
        journal::journal_path(&path).exists(),
        "the journal was settled"
    );
    assert!(!running_has_b(&ctx), "the crashed bytes were loaded");
    assert_eq!(recorder.kinds(), [IntentKind::Recovery]);
}

/// A reload dropped while its audited recovery runs: the recovery keeps
/// the config lock until it finishes, and the recovery sink stays in its
/// slot. The recovery is parked inside its task, so the drop lands at that
/// await and nowhere else.
#[tokio::test]
async fn a_reload_dropped_mid_recovery_keeps_the_lock_and_the_sink() {
    use crate::config_persistence::lock::{NotLocked, lock_config};
    use crate::test_pause::within;
    let (_dir, path, ctx) = setup();
    crashed_after_rename(&path, NEXT);
    ctx.set_recovery_audit(Box::new(Recorder::new(&path, false)));
    let (reached, release) = ctx.recovery_pause.arm();

    let mut reload = Box::pin(ctx.reload_outcome());
    tokio::select! {
        _ = &mut reload => panic!("the reload finished before its recovery parked"),
        () = within("the recovery parks", reached.notified()) => {}
    }
    drop(reload);
    // Observed while the recovery is parked, then released before any
    // assert, so a red run cannot leave the recovery task parked.
    let sink_kept = ctx.recovery_audit.lock().is_some();
    let probe = lock_config(&path, std::time::Instant::now()).await;
    let lock_held = matches!(probe, Err(NotLocked::Busy));
    drop(probe);
    release.notify_one();
    let after = within(
        "the recovery releases the lock",
        lock_config(
            &path,
            std::time::Instant::now() + std::time::Duration::from_secs(30),
        ),
    )
    .await;

    assert!(
        lock_held,
        "the config lock was released under a running recovery"
    );
    assert!(
        sink_kept,
        "the dropped reload took the recovery sink with it"
    );
    assert!(
        after.is_ok(),
        "the lock was never released: {:?}",
        after.err()
    );
    assert_eq!(
        read(&path),
        START,
        "the recovery did not put the original back"
    );
    assert!(
        !journal::journal_path(&path).exists(),
        "the journal was left"
    );
    // The recovery rolled the file back with nobody left to reload it: the
    // reload is owed, so the next lock holder reconciles the running config.
    assert!(
        ctx.reload_owed.load(std::sync::atomic::Ordering::SeqCst),
        "the rollback's reload was lost with the dropped caller"
    );
}

/// A crashed write whose config is gone: the recovery intent names the
/// empty revision, and the recovery goes ahead.
#[tokio::test]
async fn a_missing_config_is_recorded_as_the_empty_revision() {
    let (_dir, path, ctx) = setup();
    crashed_after_rename(&path, NEXT);
    std::fs::remove_file(&path).expect("remove the config");
    let recorder = Recorder::new(&path, false);
    ctx.set_recovery_audit(Box::new(recorder.clone()));

    drop(ctx.reload_outcome().await);

    let seen = recorder.seen.lock().expect("lock");
    assert_eq!(seen.len(), 1, "one recovery intent");
    assert_eq!(seen[0].intent.base, FileRevision::of(b""));
    assert!(
        !journal::journal_path(&path).exists(),
        "nothing was recovered"
    );
}

/// A crashed write whose config cannot be read (here a directory stands
/// in its place): no intent is appended and nothing is recovered.
#[tokio::test]
async fn an_unreadable_config_appends_no_intent_and_recovers_nothing() {
    let (_dir, path, ctx) = setup();
    crashed_after_rename(&path, NEXT);
    std::fs::remove_file(&path).expect("remove the config");
    std::fs::create_dir(&path).expect("a directory in its place");
    let recorder = Recorder::new(&path, false);
    ctx.set_recovery_audit(Box::new(recorder.clone()));

    let skipped = ctx
        .reload_outcome()
        .await
        .expect_err("the reload is skipped");

    assert!(skipped.contains("for the recovery's record"), "{skipped}");
    assert!(
        recorder.kinds().is_empty(),
        "an intent named a revision never read"
    );
    assert!(
        journal::journal_path(&path).exists(),
        "the journal was settled"
    );
}

/// Every `.rs` file under `dir`, test files excluded.
fn production_sources(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("list src") {
        let path = entry.expect("entry").path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if path.is_dir() {
            if name != "tests" {
                production_sources(&path, out);
            }
        } else if path.extension().is_some_and(|e| e == "rs")
            && !name.ends_with("_tests.rs")
            && !name.contains("test_support")
        {
            out.push(path);
        }
    }
}

/// Source pin for the reload choke point: the file-watch reload, the UI
/// reload route and the admin reload tool reach the config lock only
/// through `ReloadContext::reload_outcome`, and nothing in the gateway takes
/// the reader lock except that path, so a fourth reload path cannot skip
/// the recovery intent unseen.
#[test]
fn every_in_gateway_reload_takes_the_lock_through_reload_outcome() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    production_sources(&src, &mut files);
    let mut takers = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).expect("read source");
        for (n, line) in text.lines().enumerate() {
            let calls = line.contains("reader_lock(") || line.contains("reader_lock_deferred(");
            if calls && !line.trim_start().starts_with("//") && !line.contains("fn reader_lock") {
                takers.push(format!(
                    "{}:{}",
                    file.strip_prefix(&src).unwrap_or(file).display(),
                    n + 1
                ));
            }
        }
    }
    takers.retain(|t| !t.starts_with("config_persistence_lock.rs:"));
    assert!(
        takers
            .iter()
            .all(|t| t.starts_with("config_reload/replace_audit.rs:")),
        "the reader lock is taken outside the reload choke point: {takers:?}"
    );
    let reload =
        std::fs::read_to_string(src.join("config_reload/reload_context.rs")).expect("read");
    assert!(
        reload.contains(".reader_lock_for_reload("),
        "reload_outcome no longer takes its lock through reader_lock_for_reload"
    );
    for entry in [
        "config_reload/watcher.rs",
        "gateway/ui/mod.rs",
        "gateway/meta_mcp/invoke/admin.rs",
    ] {
        let text = std::fs::read_to_string(src.join(entry)).expect("read entry point");
        assert!(
            text.contains(".reload_outcome().await"),
            "{entry} no longer reloads through ReloadContext::reload_outcome"
        );
    }
}
