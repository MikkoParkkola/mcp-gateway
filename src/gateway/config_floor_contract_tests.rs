// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Cancel-safety and contract rows of the config floor adapter: a dropped
//! checkpoint holds nothing, a certified adapter holds both locks until its
//! recovery call, and the commit edge keeps only the config lock.

use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::task::Poll;

use futures::future::BoxFuture;
use tokio::time::Instant;

use super::GateState;
use super::seams::{CheckHook, CheckStep, LockVerdict, SlotEntry, SlotOutcome};
use super::support::{self, BASE, BOUND, Booted, Probe, sha256_hex};
use crate::gateway::restart_floor::{FloorAdapter, FloorFault};

type Checkpoint<'a> = BoxFuture<'a, Result<(), FloorFault>>;

/// The test side of a blocking hook: told when the hook is reached, and the
/// way to release it.
struct Held {
    reached: Receiver<u64>,
    release: Sender<()>,
}

/// A check hook that signals its attempt at `Start` and blocks until released.
fn blocking_check_hook() -> (CheckHook, Held) {
    let (reached_tx, reached) = channel();
    let (release, release_rx) = channel::<()>();
    let (reached_tx, release_rx) = (Mutex::new(reached_tx), Mutex::new(release_rx));
    let hook: CheckHook = Arc::new(move |attempt, step| {
        if step == CheckStep::Start {
            let _ = reached_tx.lock().unwrap().send(attempt);
            let _ = release_rx.lock().unwrap().recv_timeout(BOUND);
        }
    });
    (hook, Held { reached, release })
}

fn deadline() -> Instant {
    Instant::now() + BOUND
}

/// Poll `fut` by hand until `held` signals, failing if it settles first.
async fn drive_until_reached(row: &str, fut: &mut Checkpoint<'_>, held: &Held) -> u64 {
    let end = std::time::Instant::now() + BOUND;
    loop {
        let polled = std::future::poll_fn(|cx| Poll::Ready(fut.as_mut().poll(cx))).await;
        assert!(
            polled.is_pending(),
            "{row} checkpoint settled before the hook"
        );
        if let Ok(attempt) = held.reached.try_recv() {
            return attempt;
        }
        assert!(std::time::Instant::now() < end, "{row} hook never reached");
        tokio::task::yield_now().await;
    }
}

/// A floor on `b` that paused and certified, answering Ok.
async fn certified(row: &str, b: &Booted) -> super::ConfigFloor {
    let mut floor = b.floor();
    floor.pause(deadline()).await.expect("pause");
    floor.checkpoint(deadline()).await.expect("checkpoint");
    let hash = sha256_hex(BASE.as_bytes());
    let got = floor.certification().map(|c| c.sha256.clone());
    assert_eq!(got, Some(hash), "{row} certified the literal bytes");
    floor
}

fn assert_probes(row: &str, b: &Booted, want: Probe, when: &str) {
    assert_eq!(b.config_probe(), want, "{row} config lock {when}");
    assert_eq!(b.reload_probe(), want, "{row} reload lock {when}");
}

#[tokio::test]
async fn k2_dropped_checkpoint_holds_nothing() {
    const ROW: &str = "K2";
    let b = Booted::new(BASE);
    let mut floor = b.floor();
    let (hook, held) = blocking_check_hook();
    floor.set_check_hook(Some(hook));
    floor.pause(deadline()).await.expect("pause");
    {
        let mut fut = floor.checkpoint(deadline());
        drive_until_reached(ROW, &mut fut, &held).await;
    }
    assert_probes(ROW, &b, Probe::Free, "free after the drop");
    assert!(!floor.settled(), "{ROW} the blocked check is late work");
    held.release.send(()).expect("release the hook");
    support::wait_until("K2 check task ended", || floor.settled());
    assert_eq!(b.gate.state(), GateState::Paused(1), "{ROW} still paused");
    floor.commit();
    assert_eq!(b.config_probe(), Probe::Free, "{ROW} no certification held");
}

#[tokio::test]
async fn k4_certified_holds_both_until_recovery() {
    const ROW: &str = "K4";
    let b = Booted::new(BASE);
    let mut floor = certified(ROW, &b).await;
    assert_probes(ROW, &b, Probe::Busy, "held while certified");
    floor.resume();
    assert_probes(ROW, &b, Probe::Free, "free after resume");
    let stop = Booted::new(BASE);
    let mut floor = certified(ROW, &stop).await;
    assert_probes(ROW, &stop, Probe::Busy, "held on the twin");
    floor.release_for_stop();
    assert_probes(ROW, &stop, Probe::Free, "free after release_for_stop");
}

#[tokio::test]
async fn k3_superseded_attempt_hands_nothing() {
    const ROW: &str = "K3";
    let b = Booted::new(BASE);
    let mut floor = b.floor();
    let slots = floor.seams.slots.clone();
    let (reached_tx, reached) = channel();
    let (rel1, rx1) = channel::<()>();
    let (rel2, rx2) = channel::<()>();
    let (reached_tx, rx1, rx2) = (Mutex::new(reached_tx), Mutex::new(rx1), Mutex::new(rx2));
    floor.set_lock_hook(Some(Arc::new(move |attempt| {
        let _ = reached_tx.lock().unwrap().send(attempt);
        let own = if attempt == 1 { &rx1 } else { &rx2 };
        let _ = own.lock().unwrap().recv_timeout(BOUND);
        LockVerdict::Proceed
    })));
    let held = Held {
        reached,
        release: rel1,
    };
    floor.pause(deadline()).await.expect("pause 1");
    {
        let mut first = floor.checkpoint(deadline());
        assert_eq!(
            drive_until_reached(ROW, &mut first, &held).await,
            1,
            "{ROW} attempt 1 holds"
        );
    }
    floor.resume();
    floor.pause(deadline()).await.expect("pause 2");
    let mut second = floor.checkpoint(deadline());
    assert_eq!(
        drive_until_reached(ROW, &mut second, &held).await,
        2,
        "{ROW} attempt 2 holds"
    );
    held.release.send(()).expect("release attempt 1");
    let superseded = SlotEntry {
        attempt: 1,
        outcome: SlotOutcome::DroppedSuperseded,
    };
    support::wait_until("K3 attempt 1 superseded", || {
        slots.snapshot().contains(&superseded)
    });
    assert_eq!(
        b.config_probe(),
        Probe::Free,
        "{ROW} superseded guard dropped"
    );
    rel2.send(()).expect("release attempt 2");
    second.await.expect("attempt 2 certifies");
    let handed = SlotEntry {
        attempt: 2,
        outcome: SlotOutcome::Handed,
    };
    assert!(
        slots.snapshot().contains(&handed),
        "{ROW} attempt 2 handed its guard"
    );
    let got = floor.certification().map(|c| c.sha256.clone());
    assert_eq!(got, Some(sha256_hex(BASE.as_bytes())), "{ROW} literal hash");
    floor.resume();
    assert_probes(ROW, &b, Probe::Free, "free after resume");
    assert!(floor.settled(), "{ROW} settled after resume");
}

#[tokio::test]
async fn k6_cli_writer_waits_behind_commit() {
    const ROW: &str = "K6";
    let b = Booted::new(BASE);
    let mut floor = certified(ROW, &b).await;
    let cli = support::spawn_cli_writer(&b.gate, &b.cfg.path, "cli1");
    cli.waiting
        .recv_timeout(BOUND)
        .expect("K6 writer never reached the lock wait");
    floor.commit();
    assert_eq!(
        b.gate.state(),
        GateState::Terminal,
        "{ROW} commit is terminal"
    );
    assert!(
        !cli.join.is_finished(),
        "{ROW} writer still waits after commit"
    );
    assert_eq!(
        b.config_probe(),
        Probe::Busy,
        "{ROW} config lock kept at commit"
    );
    drop(floor);
    let done = support::join_bounded(cli.join, "K6 writer after the adapter drop");
    assert_eq!(done, Ok(()), "{ROW} writer succeeds once released");
    let text = String::from_utf8(b.cfg.bytes()).expect("utf8");
    assert!(
        text.contains("environment: cli1"),
        "{ROW} file holds the write: {text}"
    );
}

/// K1: a checkpoint dropped in the settle wait, then each recovery call.
#[cfg(feature = "webui")]
mod held_write {
    use super::*;
    use crate::gateway::restart_config_floor::seams::{AdmittedPoint, ReloadSource, WatcherPoke};
    use support::WatcherFixture;

    /// Hold a UI write at `WriterAfterLocks`, then plant the trigger "a1" on
    /// disk; both locks are free there, so only the settle wait can hold a
    /// checkpoint.
    async fn held_write(row: &str, b: &Booted) -> (Sender<()>, tokio::task::JoinHandle<()>) {
        let (reached_tx, reached) = channel();
        let (release, release_rx) = channel::<()>();
        let (reached_tx, release_rx) = (Mutex::new(reached_tx), Mutex::new(release_rx));
        b.gate.set_admitted_hook(Some(Arc::new(move |point| {
            if point == AdmittedPoint::WriterAfterLocks {
                let _ = reached_tx.lock().unwrap().send(());
                let _ = release_rx.lock().unwrap().recv_timeout(BOUND);
            }
        })));
        let (gate, ctx) = (b.gate.clone(), Arc::clone(&b.ctx));
        let text = format!("{BASE}environment: w1\n");
        let write = tokio::spawn(async move {
            let _ = support::write_bytes(&gate, ctx, &text).await;
        });
        reached
            .recv_timeout(BOUND)
            .unwrap_or_else(|_| panic!("{row} write never reached WriterAfterLocks"));
        b.cfg.rewrite(&format!("{BASE}environment: a1\n"));
        // The OS delivers the notify event for the outside edit.
        b.gate.record_file_event();
        assert_eq!(
            b.gate.admissions_in_flight(),
            1,
            "{row} the held write is counted"
        );
        assert_probes(row, b, Probe::Free, "free while the write is held");
        (release, write)
    }

    /// Pause, poll one checkpoint Pending in the settle wait, drop it, then
    /// release the write and let it finish.
    async fn drop_settling_checkpoint(
        row: &str,
        b: &Booted,
        floor: &mut super::super::ConfigFloor,
    ) {
        let (release, write) = held_write(row, b).await;
        floor.pause(deadline()).await.expect("pause");
        {
            let mut fut = floor.checkpoint(deadline());
            let polled = std::future::poll_fn(|cx| Poll::Ready(fut.as_mut().poll(cx))).await;
            assert!(
                polled.is_pending(),
                "{row} checkpoint waits on the held write"
            );
        }
        release.send(()).expect("release the write");
        write.await.expect("write task");
        // The tick that sees the event while paused keeps the trigger.
        support::tick(&WatcherFixture::new(b)).await;
        assert!(
            b.gate.reload_log().is_empty(),
            "{row} paused tick reloads nothing"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn k1_resume_replays_the_planted_trigger() {
        const ROW: &str = "K1";
        let b = Booted::new(BASE);
        let mut floor = b.floor();
        drop_settling_checkpoint(ROW, &b, &mut floor).await;
        floor.resume();
        assert_eq!(
            b.gate.pending_pokes(),
            vec![WatcherPoke::Resume],
            "{ROW} resume pokes"
        );
        support::tick(&WatcherFixture::new(&b)).await;
        let replays = support::reload_values(&b.gate, ReloadSource::Replay);
        assert_eq!(replays, vec!["a1".to_owned()], "{ROW} exactly one replay");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn k1_release_for_stop_replays_nothing() {
        const ROW: &str = "K1 twin";
        let b = Booted::new(BASE);
        let mut floor = b.floor();
        drop_settling_checkpoint(ROW, &b, &mut floor).await;
        floor.release_for_stop();
        assert!(b.gate.pending_pokes().is_empty(), "{ROW} no poke recorded");
        support::tick(&WatcherFixture::new(&b)).await;
        assert!(
            b.gate.reload_log().is_empty(),
            "{ROW} no reload after the tick"
        );
        assert_eq!(b.gate.state(), GateState::Released, "{ROW} released");
    }
}
