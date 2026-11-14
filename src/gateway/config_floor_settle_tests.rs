// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Pause and settle rows P1 to P3: admitted work held at a guard-held, lock-free
//! hook point keeps the checkpoint Pending on the settle wait alone, and the
//! checkpoint certifies the literal bytes once the work is released.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, channel};
use std::sync::{Arc, Barrier, Mutex};

use futures::future::BoxFuture;
use tokio::time::Instant;

use super::seams::{AdmittedPoint, GateDecision};
use super::support::{BASE, BOUND, Booted, Probe, recv_bounded, sha256_hex, tick, wait_until};
use super::{AdmitKind, ConfigFloor, ConfigGate, FloorFault};
use crate::gateway::restart_floor::FloorAdapter;

/// Work parked at one named point: the hook reports it was reached, then waits
/// for `release`. Only the first call at the point is held.
struct Hold {
    reached: Receiver<()>,
    release: Arc<Barrier>,
}

fn hold_at(gate: &ConfigGate, point: AdmittedPoint) -> Hold {
    hold_with_panic(gate, point, None)
}

/// Like [`hold_at`], and the first call at `panic_at` panics (the holder dies).
fn hold_with_panic(
    gate: &ConfigGate,
    point: AdmittedPoint,
    panic_at: Option<AdmittedPoint>,
) -> Hold {
    let (tx, reached) = channel();
    let tx = Mutex::new(tx);
    let release = Arc::new(Barrier::new(2));
    let (gate_release, taken) = (Arc::clone(&release), AtomicBool::new(false));
    let died = AtomicBool::new(false);
    gate.set_admitted_hook(Some(Arc::new(move |at| {
        if Some(at) == panic_at && !died.swap(true, Ordering::SeqCst) {
            panic!("the write task dies after staging its secret entries");
        }
        if at == point && !taken.swap(true, Ordering::SeqCst) {
            tx.lock().unwrap().send(()).ok();
            gate_release.wait();
        }
    })));
    Hold { reached, release }
}

impl Hold {
    fn wait_reached(&self, row: &str, what: &str) {
        recv_bounded(&self.reached, &format!("{row}: hook reached for {what}"));
    }

    fn release(&self) {
        self.release.wait();
    }
}

fn deadline() -> Instant {
    Instant::now() + BOUND * 4
}

type Checkpoint<'a> = BoxFuture<'a, Result<(), FloorFault>>;

/// Polls the checkpoint once; true when it is still Pending.
async fn is_pending(fut: &mut Checkpoint<'_>) -> bool {
    futures::poll!(fut).is_pending()
}

async fn finish(fut: Checkpoint<'_>, row: &str) {
    let done = tokio::time::timeout(BOUND, fut).await;
    assert_eq!(done, Ok(Ok(())), "{row}: checkpoint Ok after release");
}

#[cfg(feature = "webui")]
fn assert_probes_free(row: &str, booted: &Booted) {
    assert_eq!(
        booted.config_probe(),
        Probe::Free,
        "{row}: config lock free"
    );
    assert_eq!(
        booted.reload_probe(),
        Probe::Free,
        "{row}: reload lock free"
    );
}

fn admitted(row: &str, gate: &ConfigGate, kind: AdmitKind) {
    let log: Vec<GateDecision> = gate.decisions();
    let hit = log.iter().any(|d| d.kind == kind && d.admitted);
    assert!(hit, "{row}: the decision log shows an admitted {kind:?}");
    assert_eq!(
        gate.admissions_in_flight(),
        1,
        "{row}: exactly one in flight"
    );
}

fn certified_hash(row: &str, floor: &ConfigFloor, bytes: &[u8]) {
    let held = floor.certification().expect("certified");
    assert_eq!(held.sha256, sha256_hex(bytes), "{row}: literal hash");
}

/// P1: a byte-writer write held after its locks drop settles before certify.
#[cfg(feature = "webui")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p1_held_write_keeps_checkpoint_pending_then_certifies() {
    const ROW: &str = "P1";
    let booted = Booted::new(BASE);
    let hold = hold_at(&booted.gate, AdmittedPoint::WriterAfterLocks);
    let text = format!("{BASE}environment: \"p1\"\n");
    let write = tokio::spawn({
        let (gate, ctx, text) = (booted.gate.clone(), Arc::clone(&booted.ctx), text.clone());
        async move { super::support::write_bytes(&gate, ctx, &text).await }
    });
    hold.wait_reached(ROW, "the write");
    let mut floor = booted.floor();
    floor.pause(deadline()).await.expect("pause");
    let mut fut = floor.checkpoint(deadline());
    assert!(is_pending(&mut fut).await, "{ROW}: checkpoint Pending");
    assert_probes_free(ROW, &booted);
    hold.release();
    finish(fut, ROW).await;
    assert!(write.await.expect("join").is_ok(), "{ROW}: write succeeded");
    certified_hash(ROW, &floor, text.as_bytes());
}

/// P1 subcase: the last guard drops inside the settle window, after the count
/// read above zero and before the await; a lost wakeup hangs the checkpoint and
/// the bound fails the row.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p1_settle_wakes_when_the_last_guard_drops_inside_the_window() {
    const ROW: &str = "P1 window";
    let booted = Booted::new(BASE);
    // This row plays a direct gate client: it owns the admission guard.
    let guard = booted.gate.admit(AdmitKind::Write).expect("admitted");
    let slot = Mutex::new(Some(guard));
    let seen = Arc::new(AtomicUsize::new(usize::MAX));
    let (gate, seen_in) = (booted.gate.clone(), Arc::clone(&seen));
    booted.gate.set_settle_window(Some(Arc::new(move || {
        drop(slot.lock().unwrap().take());
        seen_in.store(gate.admissions_in_flight(), Ordering::SeqCst);
    })));
    let mut floor = booted.floor();
    floor.pause(deadline()).await.expect("pause");
    finish(floor.checkpoint(deadline()), ROW).await;
    assert_eq!(seen.load(Ordering::SeqCst), 0, "{ROW}: window ran, count 0");
    certified_hash(ROW, &floor, BASE.as_bytes());
}

/// A save that stages one secret entry; the row's hook kills the write task
/// after staging, so the entry is discarded by detached cleanup.
#[cfg(feature = "webui")]
async fn failing_secret_save(
    ctx: Arc<crate::config_reload::ReloadContext>,
    dir: std::path::PathBuf,
) -> Result<crate::config_reload::ReplaceOutcome, crate::config_reload::ReplaceError> {
    use crate::config_persistence::keyedit::{Segment, SlotId, Template};
    use crate::config_reload::{
        AuditPosture, Expected, GatewayAuth, IntentKind, RELOAD_LOCK_WAIT, Replace, Replaced,
        SecretStep, replace_audited,
    };
    use crate::secret_store::{FilesStore, NewSecretOwned, Vault};
    let slot = SlotId(
        ["backends", "b", "env", "K"]
            .map(|k| Segment::Key(k.to_owned()))
            .to_vec(),
    );
    let text = format!(
        "{BASE}  b:\n    http_url: \"http://127.0.0.1:9/mcp\"\n    env:\n      K: {}\n",
        Template::placeholder_for(&slot)
    );
    let template = Template::from_placeholders(text.into_bytes(), &[slot]).expect("one slot");
    let step = SecretStep {
        vault: Vault::with_lock(&dir, dir.join("vault.lock")),
        store: Arc::new(FilesStore::new(&dir)),
        values: vec![NewSecretOwned {
            field: "backends.b.env.K".to_owned(),
            value: crate::wiped_bytes::WipedBytes::new(b"p2-secret".to_vec()),
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
    replace_audited(ctx, replace, audit, RELOAD_LOCK_WAIT).await
}

/// The live secret entries no config names, in the store at `dir`.
#[cfg(feature = "webui")]
fn live_entries(dir: &std::path::Path) -> Vec<String> {
    use crate::secret_store::{FilesStore, Vault, unused_entries};
    let vault = Vault::with_lock(dir, dir.join("vault.lock"));
    let store = FilesStore::new(dir);
    unused_entries(&vault, &[&store], &std::collections::BTreeSet::new())
        .expect("list entries")
        .into_iter()
        .map(|entry| entry.name)
        .collect()
}

/// P2: a write task that dies after staging ends first; its detached cleanup
/// alone holds the settle. (No cancellation variant: the writer has no await
/// between staging and the rename, and the hook is synchronous.)
#[cfg(feature = "webui")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p2_dead_write_cleanup_alone_keeps_checkpoint_pending() {
    const ROW: &str = "P2";
    let booted = Booted::new(BASE);
    let store_dir = tempfile::tempdir().expect("store dir");
    let hold = hold_with_panic(
        &booted.gate,
        AdmittedPoint::Cleanup,
        Some(AdmittedPoint::WriterAfterStaging),
    );
    let save = tokio::spawn(failing_secret_save(
        Arc::clone(&booted.ctx),
        store_dir.path().to_path_buf(),
    ));
    let answer = tokio::time::timeout(BOUND, save).await;
    let answer = answer.expect("P2: the save task finished").expect("join");
    assert!(answer.is_err(), "{ROW}: the dead save answers a failure");
    hold.wait_reached(ROW, "the cleanup");
    assert_eq!(
        booted.gate.admissions_in_flight(),
        1,
        "{ROW}: only the cleanup's own count remains"
    );
    assert_probes_free(ROW, &booted);
    let mut floor = booted.floor();
    floor.pause(deadline()).await.expect("pause");
    let mut fut = floor.checkpoint(deadline());
    assert!(
        is_pending(&mut fut).await,
        "{ROW}: Pending on the cleanup alone"
    );
    hold.release();
    finish(fut, ROW).await;
    let live = live_entries(store_dir.path());
    assert_eq!(
        live,
        Vec::<String>::new(),
        "{ROW}: the staged entry was discarded"
    );
    certified_hash(ROW, &floor, BASE.as_bytes());
}

/// Shared body of the P3 cases: work is already admitted and held; pause, check
/// the settle alone holds the checkpoint, release, and check the literal hash.
async fn p3_case(
    row: &str,
    booted: &Booted,
    kind: AdmitKind,
    reload_probe: Probe,
    release: impl FnOnce(),
) {
    let mut floor = booted.floor();
    floor.pause(deadline()).await.expect("pause");
    let mut fut = floor.checkpoint(deadline());
    assert!(is_pending(&mut fut).await, "{row}: checkpoint Pending");
    admitted(row, &booted.gate, kind);
    assert_eq!(
        booted.config_probe(),
        Probe::Free,
        "{row}: config lock free"
    );
    assert_eq!(
        booted.reload_probe(),
        reload_probe,
        "{row}: reload lock probe"
    );
    release();
    finish(fut, row).await;
    certified_hash(row, &floor, &booted.cfg.bytes());
}

fn edited_booted(value: &str) -> Booted {
    let booted = Booted::new(BASE);
    booted
        .cfg
        .rewrite(&format!("{BASE}environment: \"{value}\"\n"));
    booted
}

/// P3 case 1: a watcher reload held after its admission.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p3_watcher_reload_held_after_admission() {
    const ROW: &str = "P3 watcher";
    let booted = edited_booted("p3w");
    // Plays the OS delivering the notify event for the outside edit.
    booted.gate.record_file_event();
    let hold = hold_at(&booted.gate, AdmittedPoint::WatcherAfterAdmission);
    let watcher = super::support::WatcherFixture::new(&booted);
    let ticking = tokio::spawn(async move { tick(&watcher).await });
    hold.wait_reached(ROW, "the watcher after admission");
    p3_case(ROW, &booted, AdmitKind::Watcher, Probe::Free, || {
        hold.release()
    })
    .await;
    ticking.await.expect("tick joined");
}

/// P3 case 2: a manual reload held after its admission, before the reload lock.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p3_manual_reload_held_after_admission() {
    const ROW: &str = "P3 manual";
    let booted = edited_booted("p3m");
    let hold = hold_at(&booted.gate, AdmittedPoint::ManualAfterAdmission);
    let reload = tokio::spawn({
        let (gate, ctx) = (booted.gate.clone(), Arc::clone(&booted.ctx));
        async move { super::support::manual_reload(&gate, &ctx).await }
    });
    hold.wait_reached(ROW, "the manual reload after admission");
    p3_case(ROW, &booted, AdmitKind::ManualReload, Probe::Free, || {
        hold.release()
    })
    .await;
    assert!(reload.await.expect("join").is_ok(), "{ROW}: reload ran");
}

/// P3 case 3: a manual reload queued on the reload lock behind an outside
/// holder; the lock is Busy only through that holder, released before the
/// checkpoint's own take.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p3_manual_reload_queued_behind_outside_reload_lock() {
    const ROW: &str = "P3 queued";
    let booted = edited_booted("p3q");
    let outside = booted.registry.reload_lock_handle().lock_owned().await;
    let reload = tokio::spawn({
        let (gate, ctx) = (booted.gate.clone(), Arc::clone(&booted.ctx));
        async move { super::support::manual_reload(&gate, &ctx).await }
    });
    wait_until("P3 queued: the manual reload was admitted", || {
        booted
            .gate
            .decisions()
            .iter()
            .any(|d| d.kind == AdmitKind::ManualReload && d.admitted)
    });
    p3_case(ROW, &booted, AdmitKind::ManualReload, Probe::Busy, || {
        drop(outside)
    })
    .await;
    assert!(reload.await.expect("join").is_ok(), "{ROW}: reload ran");
}

/// P3 case 4: a watcher reload queued on the reload lock behind an outside
/// holder, released before the checkpoint's own take.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p3_watcher_reload_queued_behind_outside_reload_lock() {
    const ROW: &str = "P3 watcher queued";
    let booted = edited_booted("p3wq");
    let outside = booted.registry.reload_lock_handle().lock_owned().await;
    // Plays the OS delivering the notify event for the outside edit.
    booted.gate.record_file_event();
    let watcher = super::support::WatcherFixture::new(&booted);
    let ticking = tokio::spawn(async move { tick(&watcher).await });
    wait_until("P3 watcher queued: the watcher was admitted", || {
        booted
            .gate
            .decisions()
            .iter()
            .any(|d| d.kind == AdmitKind::Watcher && d.admitted)
    });
    p3_case(ROW, &booted, AdmitKind::Watcher, Probe::Busy, || {
        drop(outside)
    })
    .await;
    ticking.await.expect("tick joined");
}
