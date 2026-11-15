// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Handoff rows. Expected ids are `config_revision` over literal parts built
//! here. A step the row holds is parked on a channel; the wait is 30s. Nothing
//! sleeps to open a window.
//!
//! The account-bound, background and stdio rows here drive only the handoff
//! order that path has. The startup functions are exercised by the rows in
//! the gateway server.

use std::sync::Arc;
use std::sync::mpsc::Receiver;
use std::thread::JoinHandle;
use std::time::Duration;

use super::super::CapabilityBackend;
use super::{Step, StepGate, arm};
use crate::capability::CapabilityExecutor;
use crate::config::Config;
use crate::config_reload::LiveConfig;
use crate::config_reload::revision::{
    AppliedInputs, CapabilityPart, PartDigest, RawInputs, config_revision, part_digest,
};

const YAML: &[u8] = b"server:\n  port: 1\n";
const HANG: Duration = Duration::from_secs(30);

fn key() -> [u8; 32] {
    crate::gateway::record_principal::test_record_key().config_revision_key()
}

fn loaded(path: &str, byte: u8) -> CapabilityPart<PartDigest> {
    CapabilityPart::Loaded(vec![(path.to_owned(), [byte; 32])])
}

/// The id of the literal gateway bytes with `part` and nothing else.
fn id_of(part: &CapabilityPart<PartDigest>) -> String {
    config_revision(
        &key(),
        &AppliedInputs {
            gateway_yaml: part_digest(&key(), YAML),
            capabilities: part.clone(),
            ..AppliedInputs::default()
        },
    )
}

fn started() -> LiveConfig {
    LiveConfig::new(Config::default())
        .with_revision_key(key())
        .with_applied(RawInputs {
            gateway_yaml: YAML.to_vec(),
            capabilities: CapabilityPart::NotLoaded,
            ..RawInputs::default()
        })
}

fn published_id(live: &LiveConfig) -> String {
    live.applied_now()
        .published
        .expect("a revision is published")
        .revision
        .clone()
}

struct Started {
    backend: Arc<CapabilityBackend>,
    live: Arc<LiveConfig>,
    part: CapabilityPart<PartDigest>,
}

fn scanning(part: CapabilityPart<PartDigest>) -> Started {
    let backend = Arc::new(CapabilityBackend::new(
        "caps",
        Arc::new(CapabilityExecutor::new()),
    ));
    backend.begin_initial_scan();
    Started {
        backend,
        live: Arc::new(started()),
        part,
    }
}

fn scan_part() -> CapabilityPart<PartDigest> {
    loaded("caps/scan.yaml", 0x5c)
}

/// A step that takes locks. A deadlock fails at 30s, on the channel's own
/// timeout.
fn within_30s(step: impl FnOnce() + Send + 'static) {
    let (done, wait) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        step();
        let _ = done.send(());
    });
    match wait.recv_timeout(HANG) {
        Ok(()) => worker.join().expect("the step panicked"),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => panic!("hung past 30s"),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => match worker.join() {
            Err(panic) => std::panic::resume_unwind(panic),
            Ok(()) => panic!("the step ended without reporting"),
        },
    }
}

fn wait_arrived(worker: JoinHandle<()>, arrived: Receiver<()>) -> JoinHandle<()> {
    match arrived.recv_timeout(HANG) {
        Ok(()) => worker,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => panic!("hung past 30s"),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => match worker.join() {
            Err(panic) => std::panic::resume_unwind(panic),
            Ok(()) => panic!("the step ended before it was held"),
        },
    }
}

fn finish_30s(worker: JoinHandle<()>) {
    let (done, wait) = std::sync::mpsc::channel();
    let joiner = std::thread::spawn(move || {
        let _ = done.send(worker.join());
    });
    match wait.recv_timeout(HANG) {
        Ok(Ok(())) => {
            joiner.join().expect("the joiner panicked");
        }
        Ok(Err(panic)) => std::panic::resume_unwind(panic),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => panic!("hung past 30s"),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => match joiner.join() {
            Err(panic) => std::panic::resume_unwind(panic),
            Ok(()) => panic!("the joiner ended"),
        },
    }
}

/// Arm `step` on a fresh thread, wait until that step is held, release it,
/// and return the thread still finishing the rest of `body`.
fn hold(step: Step, body: impl FnOnce() + Send + 'static) -> JoinHandle<()> {
    let (gate, arrived, release) = StepGate::open(step);
    let worker = std::thread::spawn(move || {
        arm(gate);
        body();
    });
    let worker = wait_arrived(worker, arrived);
    release
        .send(())
        .expect("the step stopped waiting before it was released");
    worker
}

fn assert_scan_published(started: &Started) {
    let delivered = started.backend.handoff().delivered();
    assert_eq!(
        delivered.len(),
        1,
        "the held part delivered exactly once"
    );
    assert!(
        delivered[0].0 == 1 && delivered[0].1 == started.part,
        "the delivered part is the scan's"
    );
    assert_eq!(
        started.backend.scan_completions(),
        1,
        "readiness turns true exactly once"
    );
    assert!(
        started.backend.initial_scan_complete(),
        "readiness is true"
    );
    assert_eq!(
        published_id(&started.live),
        id_of(&started.part),
        "the published coverage is the scan's"
    );
}

#[test]
fn h1_park_then_attach() {
    let started = scanning(scan_part());
    let backend = Arc::clone(&started.backend);
    let part = started.part.clone();
    let parked = hold(Step::Park, move || {
        backend.handoff().publish_and_end(1, part);
    });
    assert!(
        !started.backend.initial_scan_complete(),
        "a parked scan is not ready"
    );
    finish_30s(parked);
    let backend = Arc::clone(&started.backend);
    let live = Arc::clone(&started.live);
    let attached = hold(Step::Attach, move || {
        backend.handoff().attach_revision(live);
    });
    finish_30s(attached);
    assert_scan_published(&started);
}

#[test]
fn h1_attach_then_park() {
    let started = scanning(scan_part());
    let backend = Arc::clone(&started.backend);
    let live = Arc::clone(&started.live);
    let attached = hold(Step::Attach, move || {
        backend.handoff().attach_revision(live);
    });
    finish_30s(attached);
    let backend = Arc::clone(&started.backend);
    let part = started.part.clone();
    let parked = hold(Step::Park, move || {
        backend.handoff().publish_and_end(1, part);
    });
    finish_30s(parked);
    assert_scan_published(&started);
}

#[test]
fn h1_attach_between_publish_and_end() {
    let started = scanning(scan_part());
    let (gate, arrived, release) = StepGate::open(Step::Park);
    let backend = Arc::clone(&started.backend);
    let part = started.part.clone();
    let scan = std::thread::spawn(move || {
        arm(gate);
        backend.handoff().publish_and_end(1, part);
    });
    let scan = wait_arrived(scan, arrived);
    assert!(
        started.backend.handoff().lock_held(),
        "the scan still holds the handoff"
    );
    // Attach is started while that hold lasts. It cannot report that it is
    // waiting for the mutex until the scan releases, so the release is not
    // delayed for it.
    let backend = Arc::clone(&started.backend);
    let live = Arc::clone(&started.live);
    let attach = std::thread::spawn(move || {
        backend.handoff().attach_revision(live);
    });
    release
        .send(())
        .expect("the scan stopped waiting before it was released");
    finish_30s(scan);
    finish_30s(attach);
    assert_scan_published(&started);
}

/// A scan that fails before it publishes delivers nothing. The row's "exactly
/// once" is the success interleavings; a failure publishes no part.
#[test]
fn h1_scan_fails_before_publishing() {
    let started = scanning(scan_part());
    let backend = Arc::clone(&started.backend);
    within_30s(move || {
        backend.end_failed(&crate::backend::BackendRegistry::new());
    });
    assert_eq!(
        started.backend.handoff().scan(),
        super::Scan::Failed,
        "a scan that fails before publishing ends Failed"
    );
    assert!(
        started.backend.handoff().delivered().is_empty(),
        "a failed scan publishes no part"
    );
    assert_eq!(
        started.backend.scan_completions(),
        1,
        "readiness turns true exactly once"
    );
    assert!(started.backend.initial_scan_complete(), "readiness is true");
    assert_eq!(
        published_id(&started.live),
        id_of(&CapabilityPart::NotLoaded),
        "the published coverage stays the startup part"
    );
}

#[derive(Clone, Copy)]
enum Release {
    AttachFirst,
    PublishFirst,
}

/// Seq 2 is published unattached. Attach would then deliver it, while a
/// publish of seq 3 sits between its own unlock and the delivery. Both are
/// held, then released in `order`.
fn race_after_unlock(
    order: Release,
    seq2: CapabilityPart<PartDigest>,
    seq3: CapabilityPart<PartDigest>,
) -> String {
    let started = scanning(seq2.clone());
    started.backend.handoff().publish(2, seq2);
    let (attach_gate, attach_arrived, attach_release) = StepGate::open(Step::Deliver);
    let (publish_gate, publish_arrived, publish_release) = StepGate::open(Step::Deliver);
    let backend = Arc::clone(&started.backend);
    let live = Arc::clone(&started.live);
    let attach = std::thread::spawn(move || {
        arm(attach_gate);
        backend.handoff().attach_revision(live);
    });
    let backend = Arc::clone(&started.backend);
    let publish = std::thread::spawn(move || {
        arm(publish_gate);
        backend.handoff().publish(3, seq3);
    });
    let attach = wait_arrived(attach, attach_arrived);
    let publish = wait_arrived(publish, publish_arrived);
    match order {
        Release::AttachFirst => {
            attach_release
                .send(())
                .expect("attach stopped waiting before it was released");
            publish_release
                .send(())
                .expect("the publish stopped waiting before it was released");
        }
        Release::PublishFirst => {
            publish_release
                .send(())
                .expect("the publish stopped waiting before it was released");
            attach_release
                .send(())
                .expect("attach stopped waiting before it was released");
        }
    }
    finish_30s(attach);
    finish_30s(publish);
    published_id(&started.live)
}

#[test]
fn h1b_seq3_stays_published_in_both_orders() {
    let seq2 = loaded("caps/seq2.yaml", 0x22);
    let seq3 = loaded("caps/seq3.yaml", 0x33);
    assert_ne!(
        id_of(&seq2),
        id_of(&seq3),
        "the two parts name different revisions"
    );
    let attach_first = race_after_unlock(Release::AttachFirst, seq2.clone(), seq3.clone());
    let expected = id_of(&seq3);
    let publish_first = race_after_unlock(Release::PublishFirst, seq2, seq3);
    assert_eq!(
        attach_first, expected,
        "seq 3's id stays published when attach is released first"
    );
    assert_eq!(
        publish_first, expected,
        "seq 3's id stays published when the publish is released first"
    );
}

#[test]
fn h1c_cancel_after_publish_ends_ended_not_failed() {
    let started = scanning(scan_part());
    let backend = Arc::clone(&started.backend);
    let part = started.part.clone();
    within_30s(move || {
        backend.handoff().publish_and_end(1, part);
        backend.end_failed(&crate::backend::BackendRegistry::new());
    });
    assert_eq!(
        started.backend.handoff().scan(),
        super::Scan::Ended,
        "a scan cancelled after it published ends Ended, not Failed"
    );
    assert!(
        started.backend.initial_scan_loaded_every_directory(),
        "the cancellation does not mark the scan failed"
    );
    assert_eq!(
        started.backend.scan_completions(),
        1,
        "readiness turns true exactly once"
    );
}

/// Integration row. Account-bound HTTP parks the scan, then attaches. The
/// test makes no extra publish and does not finish the scan itself.
#[test]
fn h2_account_bound_http_parks_first() {
    let started = scanning(scan_part());
    let backend = Arc::clone(&started.backend);
    let part = started.part.clone();
    let parked = hold(Step::Park, move || {
        backend.handoff().publish_and_end(1, part);
    });
    assert!(
        !started.backend.initial_scan_complete(),
        "a parked scan is not ready"
    );
    finish_30s(parked);
    let backend = Arc::clone(&started.backend);
    let live = Arc::clone(&started.live);
    let attached = hold(Step::Attach, move || {
        backend.handoff().attach_revision(live);
    });
    finish_30s(attached);
    assert_scan_published(&started);
}

/// Integration row. Background HTTP attaches while the scan has not ended.
/// The watcher would hold a reload for that whole time; this row does not
/// drive the watcher. Attach, then the scan's own publish. The test makes
/// no extra publish and does not finish the scan itself.
#[test]
fn h2_background_http_attaches_while_loading() {
    let started = scanning(scan_part());
    assert!(
        !started.backend.initial_scan_complete(),
        "the scan is still loading"
    );
    let backend = Arc::clone(&started.backend);
    let live = Arc::clone(&started.live);
    let attached = hold(Step::Attach, move || {
        backend.handoff().attach_revision(live);
    });
    finish_30s(attached);
    assert!(
        !started.backend.initial_scan_complete(),
        "attach does not finish a scan that has not ended"
    );
    let backend = Arc::clone(&started.backend);
    let part = started.part.clone();
    // Deliver, not park: attach already ran, so the publish's hold is the
    // gap after the unlock. The park gate would be the unattached decision.
    let published = hold(Step::Deliver, move || {
        backend.handoff().publish_and_end(1, part);
    });
    finish_30s(published);
    assert_scan_published(&started);
}

/// Integration row. Stdio attaches before the first load, then the scan
/// publishes. The test makes no extra publish and does not finish the scan
/// itself.
#[test]
fn h2_stdio_attaches_before_the_first_load() {
    let started = scanning(scan_part());
    let backend = Arc::clone(&started.backend);
    let live = Arc::clone(&started.live);
    let attached = hold(Step::Attach, move || {
        backend.handoff().attach_revision(live);
    });
    finish_30s(attached);
    assert!(
        !started.backend.initial_scan_complete(),
        "attach before the first load leaves the scan unfinished"
    );
    let backend = Arc::clone(&started.backend);
    let part = started.part.clone();
    let published = hold(Step::Deliver, move || {
        backend.handoff().publish_and_end(1, part);
    });
    finish_30s(published);
    assert_scan_published(&started);
}

#[test]
fn r24_stale_publish_after_attach_is_dropped() {
    let part2 = loaded("caps/two.yaml", 0x22);
    let part1 = loaded("caps/one.yaml", 0x11);
    assert_ne!(
        id_of(&part1),
        id_of(&part2),
        "the two parts name different revisions"
    );
    let started = scanning(part2.clone());
    let backend = Arc::clone(&started.backend);
    let live = Arc::clone(&started.live);
    let newer = part2.clone();
    let older = part1;
    within_30s(move || {
        backend.handoff().publish(2, newer);
        backend.handoff().attach_revision(live);
        backend.handoff().publish(1, older);
    });
    assert_eq!(
        published_id(&started.live),
        id_of(&part2),
        "seq 2 stays published; the stale seq 1 is dropped"
    );
    let delivered = started.backend.handoff().delivered();
    assert!(
        delivered.iter().all(|(seq, _)| *seq != 1),
        "seq 1 was not delivered"
    );
    assert_eq!(
        delivered.iter().filter(|(seq, _)| *seq == 2).count(),
        1,
        "seq 2 was delivered once"
    );
}
