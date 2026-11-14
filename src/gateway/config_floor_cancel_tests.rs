// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Cancel and retry rows X1-X3: a refused checkpoint through `run_checkpoint`
//! leaves the config owner recovered, and a retry certifies.

use std::sync::Arc;

use futures::future::BoxFuture;
use tokio::time::Instant;

use super::support::{self, BASE, Booted, Probe};
use super::{AdmitKind, ConfigFloor, GateState};
use crate::gateway::restart_floor::{
    CancelReason, Cancelled, FloorAdapter, FloorFault, FloorOwner, FloorStage, run_checkpoint,
};

/// The floor behind a shared handle, so a row can read the certification after
/// the coordinator has boxed the adapter.
struct Shared(Arc<tokio::sync::Mutex<ConfigFloor>>);

impl Shared {
    fn sync(&self) -> tokio::sync::MutexGuard<'_, ConfigFloor> {
        self.0
            .try_lock()
            .expect("no call of the floor is in flight")
    }
}

impl FloorAdapter for Shared {
    fn owner(&self) -> FloorOwner {
        self.sync().owner()
    }

    fn pause(&mut self, deadline: Instant) -> BoxFuture<'_, Result<(), FloorFault>> {
        let floor = Arc::clone(&self.0);
        Box::pin(async move { floor.lock().await.pause(deadline).await })
    }

    fn checkpoint(&mut self, deadline: Instant) -> BoxFuture<'_, Result<(), FloorFault>> {
        let floor = Arc::clone(&self.0);
        Box::pin(async move { floor.lock().await.checkpoint(deadline).await })
    }

    fn resume(&mut self) {
        self.sync().resume();
    }

    fn release_for_stop(&mut self) {
        self.sync().release_for_stop();
    }

    fn commit(&mut self) {
        self.sync().commit();
    }

    fn settled(&self) -> bool {
        self.sync().settled()
    }
}

/// The floor of `booted` as the coordinator holds it, plus the shared handle.
fn coordinated(
    booted: &Booted,
) -> (
    Vec<Box<dyn FloorAdapter>>,
    Arc<tokio::sync::Mutex<ConfigFloor>>,
) {
    let floor = Arc::new(tokio::sync::Mutex::new(booted.floor()));
    (vec![Box::new(Shared(Arc::clone(&floor)))], floor)
}

/// One `run_checkpoint` whose certified outcome is released at once.
async fn run(adapters: &mut [Box<dyn FloorAdapter>], deadline: Instant) -> Result<(), Cancelled> {
    run_checkpoint(adapters, deadline).await.map(drop)
}

fn in_bound() -> Instant {
    Instant::now() + support::BOUND
}

/// After a cancel: gate Open and both certification locks free.
fn assert_recovered(row: &str, booted: &Booted) {
    assert_eq!(booted.gate.state(), GateState::Open, "{row} gate state");
    assert_eq!(booted.config_probe(), Probe::Free, "{row} config lock");
    assert_eq!(booted.reload_probe(), Probe::Free, "{row} reload lock");
}

/// The retry's certification carries the hash of the literal `bytes`.
async fn assert_certified_retry(
    row: &str,
    adapters: &mut [Box<dyn FloorAdapter>],
    floor: &tokio::sync::Mutex<ConfigFloor>,
    bytes: &str,
) {
    let retry = run_checkpoint(adapters, in_bound()).await;
    assert!(retry.is_ok(), "{row} the second checkpoint certifies");
    drop(retry);
    let held = floor.lock().await;
    let sha = held.certification().map(|c| c.sha256.clone());
    assert_eq!(
        sha,
        Some(support::sha256_hex(bytes.as_bytes())),
        "{row} certified hash"
    );
}

/// The expected cancel of the config owner at the checkpoint stage.
fn config_cancel(reason: CancelReason) -> Cancelled {
    Cancelled {
        owner: FloorOwner::Config,
        stage: FloorStage::Checkpoint,
        reason,
    }
}

#[tokio::test]
async fn x1_v1_journal_cancels_then_retry_certifies() {
    const ROW: &str = "X1";
    // GIVEN: a config beside a (v1) journal, which only its presence marks.
    let booted = Booted::new(BASE);
    let journal = booted.cfg.beside(".gateway.yaml.replace-journal");
    std::fs::write(&journal, "{\"version\":1}").expect("plant journal");
    let (mut adapters, floor) = coordinated(&booted);
    // WHEN: the checkpoint runs.
    let first = run(&mut adapters, in_bound()).await;
    // THEN: it cancels at the config owner, and the owner is recovered.
    assert_eq!(
        first,
        Err(config_cancel(CancelReason::SaveFailed)),
        "{ROW} first run"
    );
    assert_recovered(ROW, &booted);
    // A direct gate client is admitted again (the row plays the writer here).
    assert!(
        booted.gate.admit(AdmitKind::Write).is_ok(),
        "{ROW} write admitted"
    );
    // An unrelated call is served: an outside edit reloads into the running config.
    let edited = format!("{BASE}environment: \"e1\"\n");
    booted.cfg.rewrite(&edited);
    let reloaded = support::manual_reload(&booted.gate, &booted.ctx).await;
    assert!(reloaded.is_ok(), "{ROW} manual reload served");
    assert_eq!(
        booted.running_environment().as_deref(),
        Some("e1"),
        "{ROW} running value"
    );
    // The journal goes; the retry certifies the literal bytes.
    std::fs::remove_file(&journal).expect("remove journal");
    assert_certified_retry(ROW, &mut adapters, &floor, &edited).await;
}

#[tokio::test]
async fn x2_invalid_file_cancels_then_fixed_file_certifies() {
    const ROW: &str = "X2";
    // GIVEN: a booted config that an outside edit then breaks (invalid YAML).
    let booted = Booted::new(BASE);
    booted.cfg.rewrite("backends: [unclosed\n");
    let (mut adapters, floor) = coordinated(&booted);
    // WHEN: the checkpoint runs.
    let first = run(&mut adapters, in_bound()).await;
    // THEN: it cancels at the config owner, and the owner is recovered.
    assert_eq!(
        first,
        Err(config_cancel(CancelReason::SaveFailed)),
        "{ROW} first run"
    );
    assert_recovered(ROW, &booted);
    // A direct gate client is admitted again (the row plays the writer here).
    assert!(
        booted.gate.admit(AdmitKind::Write).is_ok(),
        "{ROW} write admitted"
    );
    // Rewriting the file valid lets the retry certify its literal bytes.
    let fixed = format!("{BASE}environment: \"e2\"\n");
    booted.cfg.rewrite(&fixed);
    assert_certified_retry(ROW, &mut adapters, &floor, &fixed).await;
}

/// Hold the byte writer at `WriterAfterLocks` until the returned sender fires;
/// the receiver is told when the writer got there.
#[cfg(feature = "webui")]
fn hold_writer(
    gate: &super::ConfigGate,
) -> (std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>) {
    use super::seams::{AdmittedHook, AdmittedPoint};
    let (reached_tx, reached_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let release_rx = std::sync::Mutex::new(release_rx);
    let hook: AdmittedHook = Arc::new(move |point| {
        if point == AdmittedPoint::WriterAfterLocks {
            let _ = reached_tx.send(());
            let _ = release_rx.lock().unwrap().recv_timeout(support::BOUND);
        }
    });
    gate.set_admitted_hook(Some(hook));
    (release_tx, reached_rx)
}

#[cfg(feature = "webui")]
#[tokio::test(start_paused = true)]
async fn x3_held_settle_past_deadline_cancels_then_retry_certifies() {
    const ROW: &str = "X3";
    // GIVEN: a write on its own thread and runtime, held at WriterAfterLocks.
    let booted = Booted::new(BASE);
    let (release, reached) = hold_writer(&booted.gate);
    let written = format!("{BASE}environment: \"w3\"\n");
    let writer = {
        let (gate, ctx, text) = (
            booted.gate.clone(),
            Arc::clone(&booted.ctx),
            written.clone(),
        );
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(support::write_bytes(&gate, ctx, &text)).is_ok()
        })
    };
    support::recv_bounded(&reached, "the writer reached WriterAfterLocks");
    let (mut adapters, floor) = coordinated(&booted);
    // WHEN: the settle wait outlasts the deadline on the paused clock.
    let deadline = Instant::now() + std::time::Duration::from_secs(10);
    let (first, ()) = tokio::join!(
        run(&mut adapters, deadline),
        tokio::time::advance(std::time::Duration::from_secs(11))
    );
    // THEN: the coordinator cancels with the deadline, not an adapter fault.
    assert_eq!(
        first,
        Err(config_cancel(CancelReason::DeadlineExceeded)),
        "{ROW} first run"
    );
    assert_recovered(ROW, &booted);
    // The held write is released and lands in the running config.
    release.send(()).expect("release the writer");
    assert!(
        support::join_bounded(writer, "the writer finished"),
        "{ROW} write succeeded"
    );
    assert_eq!(
        booted.running_environment().as_deref(),
        Some("w3"),
        "{ROW} running value"
    );
    assert_certified_retry(ROW, &mut adapters, &floor, &written).await;
}
