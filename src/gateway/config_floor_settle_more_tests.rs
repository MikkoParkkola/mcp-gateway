// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Settle rows P6, P7 and P10 of the config floor: a disconnected write is
//! settled before the checkpoint certifies, only `replay_owed` can cause a
//! replay, and a pause landing around the watcher's admission loses no trigger.

use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};

use futures::FutureExt;
use tokio::time::Instant;

use super::seams::{AdmittedPoint, ReloadSource};
use super::support::{self, BASE, BOUND, Booted, WatcherFixture};
use super::{ConfigGate, FloorAdapter};

/// A row's hold on one hook point: `reached` fires when production calls the
/// hook there, and the held caller blocks until `release` is sent.
struct Hold {
    reached: Receiver<()>,
    release: Sender<()>,
}

/// Install a hook on `gate` that blocks the caller at `at` until released.
fn hold_at(gate: &ConfigGate, at: AdmittedPoint) -> Hold {
    let (reached_tx, reached) = channel();
    let (release, release_rx) = channel::<()>();
    let release_rx = Mutex::new(release_rx);
    gate.set_admitted_hook(Some(Arc::new(move |point| {
        if point == at {
            let _ = reached_tx.send(());
            let _ = release_rx.lock().unwrap().recv_timeout(BOUND);
        }
    })));
    Hold { reached, release }
}

fn edited(value: &str) -> String {
    format!("{BASE}environment: \"{value}\"\n")
}

fn deadline() -> Instant {
    Instant::now() + BOUND
}

/// One poll of a checkpoint future: `None` while it is still pending.
fn poll_once<T>(fut: &mut (impl std::future::Future<Output = T> + Unpin)) -> Option<T> {
    fut.now_or_never()
}

async fn joined<T>(handle: tokio::task::JoinHandle<T>, what: &str) -> T {
    tokio::time::timeout(BOUND, handle)
        .await
        .unwrap_or_else(|_| panic!("never finished: {what}"))
        .unwrap_or_else(|_| panic!("panicked: {what}"))
}

/// P7: a pause landing while the watcher's tick has started and not asked for
/// admission refuses that admission; the replay stays owed and runs once on
/// the next resume. Only `replay_owed` is set here: no file event, no pending
/// trigger, polling disabled.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p7_replay_owed_survives_a_refused_watcher_admission() {
    const ROW: &str = "p7";
    // GIVEN: a paused gate, and a manual reload that folded into the owed replay.
    let booted = Booted::new(BASE);
    let mut floor = booted.floor();
    floor.pause(deadline()).await.expect("pause");
    booted.cfg.rewrite(&edited("e1"));
    let folded = support::manual_reload(&booted.gate, &booted.ctx).await;
    assert!(folded.is_err(), "{ROW}: a reload while paused answers 409");
    assert!(
        booted.gate.replay_owed(),
        "{ROW}: the manual reload owes a replay"
    );
    // WHEN: resume pokes, the tick is held before admission and a pause lands.
    let hold = hold_at(&booted.gate, AdmittedPoint::WatcherBeforeAdmission);
    floor.resume();
    let watcher = Arc::new(WatcherFixture::new(&booted));
    let tick = tokio::spawn({
        let watcher = Arc::clone(&watcher);
        async move { support::tick(&watcher).await }
    });
    support::recv_bounded(&hold.reached, "p7 tick held before admission");
    floor.pause(deadline()).await.expect("second pause");
    hold.release.send(()).expect("release the tick");
    joined(tick, "p7 tick").await;
    // THEN: its admission was refused, nothing replayed, the replay is still owed.
    let replays = support::reload_values(&booted.gate, ReloadSource::Replay);
    assert!(
        replays.is_empty(),
        "{ROW}: no replay while paused: {replays:?}"
    );
    assert!(booted.gate.replay_owed(), "{ROW}: replay_owed still set");
    floor.resume();
    support::tick(&watcher).await;
    let replays = support::reload_values(&booted.gate, ReloadSource::Replay);
    assert_eq!(replays, vec!["e1".to_owned()], "{ROW}: exactly one replay");
}

/// P10 case A: a pause landing between the watcher's admission and its trigger
/// take waits for the watcher's guard, and the reload then runs once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p10_pause_after_watcher_admission_waits_and_reload_runs_once() {
    const ROW: &str = "p10a";
    // GIVEN: an outside edit and a watcher tick held after its admission.
    let booted = Booted::new(BASE);
    let mut floor = booted.floor();
    let hold = hold_at(&booted.gate, AdmittedPoint::WatcherAfterAdmission);
    booted.cfg.rewrite(&edited("e1"));
    // The OS delivers the notify event for the outside edit.
    booted.gate.record_file_event();
    let watcher = Arc::new(WatcherFixture::new(&booted));
    let tick = tokio::spawn({
        let watcher = Arc::clone(&watcher);
        async move { support::tick(&watcher).await }
    });
    support::recv_bounded(&hold.reached, "p10a tick held after admission");
    // WHEN: the pause lands and a checkpoint starts.
    floor.pause(deadline()).await.expect("pause");
    let mut checkpoint = floor.checkpoint(deadline());
    // THEN: the watcher's guard holds the checkpoint pending.
    assert_eq!(
        booted.gate.admissions_in_flight(),
        1,
        "{ROW}: the watcher's guard is counted"
    );
    assert!(
        poll_once(&mut checkpoint).is_none(),
        "{ROW}: checkpoint waits for the watcher"
    );
    hold.release.send(()).expect("release the tick");
    joined(tick, "p10a tick").await;
    let done = tokio::time::timeout(BOUND, checkpoint).await;
    assert!(
        matches!(done, Ok(Ok(()))),
        "{ROW}: checkpoint certifies: {done:?}"
    );
    let watched = support::reload_values(&booted.gate, ReloadSource::Watcher);
    assert_eq!(watched, vec!["e1".to_owned()], "{ROW}: the reload ran once");
}

/// P10 twin: a pause landing before admission refuses it; the trigger stays
/// and resume plus one tick replays it once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p10_pause_before_watcher_admission_keeps_trigger_for_one_replay() {
    const ROW: &str = "p10b";
    // GIVEN: an outside edit while paused.
    let booted = Booted::new(BASE);
    let mut floor = booted.floor();
    floor.pause(deadline()).await.expect("pause");
    booted.cfg.rewrite(&edited("e1"));
    // The OS delivers the notify event for the outside edit.
    booted.gate.record_file_event();
    let watcher = WatcherFixture::new(&booted);
    // WHEN: a tick runs and is refused.
    support::tick(&watcher).await;
    // THEN: nothing reloaded, the refusal is on the decision log.
    assert!(
        booted.gate.reload_log().is_empty(),
        "{ROW}: no reload while paused"
    );
    let refused = booted.gate.decisions().iter().any(|d| !d.admitted);
    assert!(refused, "{ROW}: the watcher's admission was refused");
    floor.resume();
    support::tick(&watcher).await;
    let replays = support::reload_values(&booted.gate, ReloadSource::Replay);
    assert_eq!(
        replays,
        vec!["e1".to_owned()],
        "{ROW}: the trigger replays once"
    );
}

#[cfg(feature = "webui")]
mod disconnect {
    use std::collections::BTreeSet;
    use std::path::Path;

    use super::*;
    use crate::config_persistence::keyedit::{Segment, SlotId, Template};
    use crate::config_reload::{
        AuditPosture, Expected, GatewayAuth, IntentKind, RELOAD_LOCK_WAIT, Replace, Replaced,
        SecretStep, replace_audited,
    };
    use crate::secret_store::{FilesStore, NewSecretOwned, Vault, unused_entries};
    use crate::wiped_bytes::WipedBytes;

    /// The prefix every written file keeps, literally, before the slot's reference.
    const PREFIX: &str = "backends:\n  a:\n    http_url: \"http://127.0.0.1:9/mcp\"\n  b:\n    http_url: \"http://127.0.0.1:9/mcp\"\n    env:\n      K: \"";

    fn slot() -> SlotId {
        SlotId(
            ["backends", "b", "env", "K"]
                .map(|k| Segment::Key(k.to_owned()))
                .to_vec(),
        )
    }

    fn vault(dir: &Path) -> Vault {
        Vault::with_lock(dir, dir.join("vault.lock"))
    }

    /// The live store entries no config names.
    fn live_entries(dir: &Path) -> usize {
        let store = FilesStore::new(dir);
        unused_entries(&vault(dir), &[&store], &BTreeSet::new())
            .expect("list entries")
            .len()
    }

    /// The byte writer's real entry point with one secret to save. The wiring
    /// stage passes the gate to the writer; the row never changes.
    fn secret_write(
        gate: &ConfigGate,
        ctx: Arc<crate::config_reload::ReloadContext>,
        dir: &Path,
    ) -> impl std::future::Future<Output = ()> + Send + 'static {
        let _ = gate;
        let text = format!("{PREFIX}{}\"\n", Template::placeholder_for(&slot()));
        let template = Template::from_placeholders(text.into_bytes(), &[slot()]).expect("slot");
        let step = SecretStep {
            vault: vault(dir),
            store: Arc::new(FilesStore::new(dir)),
            values: vec![NewSecretOwned {
                field: "backends.b.env.K".to_owned(),
                value: WipedBytes::new(b"p6-secret-value".to_vec()),
            }],
        };
        let replace = Replace {
            expected: Expected::Any,
            compute: Box::new(move |_| Ok(template)),
            replaced: Replaced::Discard,
            secrets: Some(step),
        };
        let audit = AuditPosture::of(None, GatewayAuth::Off)
            .audit(IntentKind::Adopt)
            .expect("an unaudited gateway with auth off writes");
        async move {
            let _ = replace_audited(ctx, replace, audit, RELOAD_LOCK_WAIT).await;
        }
    }

    /// P6: a write whose client disconnects while it settles its secret entry
    /// is still counted in flight; the checkpoint waits for it and certifies
    /// the bytes it wrote.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn p6_disconnected_write_settles_before_checkpoint_certifies() {
        const ROW: &str = "p6";
        // GIVEN: a secret-saving write held after it released both locks.
        let booted = Booted::new(BASE);
        let vault_dir = tempfile::tempdir().expect("vault dir");
        let hold = hold_at(&booted.gate, AdmittedPoint::WriterAfterLocks);
        let client = tokio::spawn(secret_write(
            &booted.gate,
            Arc::clone(&booted.ctx),
            vault_dir.path(),
        ));
        support::recv_bounded(&hold.reached, "p6 write held after its locks");
        // WHEN: the client disconnects and a checkpoint starts.
        client.abort();
        let mut floor = booted.floor();
        floor.pause(deadline()).await.expect("pause");
        let mut checkpoint = floor.checkpoint(deadline());
        // THEN: the detached write is counted and holds the checkpoint pending.
        assert_eq!(
            booted.gate.admissions_in_flight(),
            1,
            "{ROW}: the write is in flight"
        );
        assert!(
            poll_once(&mut checkpoint).is_none(),
            "{ROW}: checkpoint waits"
        );
        hold.release.send(()).expect("release the write");
        support::wait_until("p6 write settled and left flight", || {
            booted.gate.admissions_in_flight() == 0
        });
        assert_eq!(
            live_entries(vault_dir.path()),
            1,
            "{ROW}: the new entry is live"
        );
        let done = tokio::time::timeout(BOUND, checkpoint).await;
        assert!(
            matches!(done, Ok(Ok(()))),
            "{ROW}: checkpoint certifies: {done:?}"
        );
        let written = std::fs::read_to_string(&booted.cfg.path).expect("read config");
        assert!(
            written.starts_with(PREFIX),
            "{ROW}: the write landed: {written}"
        );
        assert_ne!(
            written, BASE,
            "{ROW}: the bytes differ from the pre-write bytes"
        );
        let cert = floor.certification().expect("certification");
        assert_eq!(
            cert.sha256,
            support::sha256_hex(written.as_bytes()),
            "{ROW}: hash"
        );
    }
}
