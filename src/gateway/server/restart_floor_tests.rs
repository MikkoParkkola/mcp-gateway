// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows for the restart cancel floor (fake adapters; real owners come later).

use std::cell::RefCell;
use std::rc::Rc;
use std::time::{Duration, Instant};

use super::restart_floor::{
    CancelReason, Cancelled, FloorAdapter, FloorFault, FloorOwner, FloorSetupError, FloorStage,
    StopSaveOutcome, StopSaveOwner, run_checkpoint, settle_stop_save, validate_owners,
};

type Log = Rc<RefCell<Vec<String>>>;

struct Fake {
    owner: FloorOwner,
    pause: Result<(), FloorFault>,
    checkpoint: Result<(), FloorFault>,
    checkpoint_takes: Duration,
    log: Log,
}

impl Fake {
    fn ok(owner: FloorOwner, log: &Log) -> Box<dyn FloorAdapter> {
        Self::with(owner, log, Ok(()), Ok(()))
    }
    fn with(
        owner: FloorOwner,
        log: &Log,
        pause: Result<(), FloorFault>,
        checkpoint: Result<(), FloorFault>,
    ) -> Box<dyn FloorAdapter> {
        Box::new(Self {
            owner,
            pause,
            checkpoint,
            checkpoint_takes: Duration::ZERO,
            log: Rc::clone(log),
        })
    }
}

impl FloorAdapter for Fake {
    fn owner(&self) -> FloorOwner {
        self.owner
    }
    fn pause(&mut self) -> Result<(), FloorFault> {
        self.log
            .borrow_mut()
            .push(format!("pause {:?}", self.owner));
        self.pause
    }
    fn checkpoint(&mut self) -> Result<(), FloorFault> {
        self.log
            .borrow_mut()
            .push(format!("checkpoint {:?}", self.owner));
        std::thread::sleep(self.checkpoint_takes);
        self.checkpoint
    }
    fn resume(&mut self) {
        self.log
            .borrow_mut()
            .push(format!("resume {:?}", self.owner));
    }
}

fn far() -> Instant {
    Instant::now() + Duration::from_secs(30)
}

fn three(log: &Log, failing: Option<(FloorOwner, FloorFault)>) -> Vec<Box<dyn FloorAdapter>> {
    [
        FloorOwner::TaskStore,
        FloorOwner::Config,
        FloorOwner::Health,
    ]
    .into_iter()
    .map(|o| match failing {
        Some((f, fault)) if f == o => Fake::with(o, log, Ok(()), Err(fault)),
        _ => Fake::ok(o, log),
    })
    .collect()
}

fn resumes(log: &Log) -> Vec<String> {
    log.borrow()
        .iter()
        .filter(|l| l.starts_with("resume"))
        .cloned()
        .collect()
}

fn expect_cancel(adapters: &mut [Box<dyn FloorAdapter>], deadline: Instant) -> Cancelled {
    match run_checkpoint(adapters, deadline) {
        Ok(_) => panic!("the checkpoint certified; a cancel was required"),
        Err(c) => c,
    }
}

fn save_error_cancels(owner: FloorOwner) {
    let log = Log::default();
    let mut a = three(&log, Some((owner, FloorFault::SaveFailed)));
    let c = expect_cancel(&mut a, far());
    assert_eq!(
        c,
        Cancelled {
            owner,
            stage: FloorStage::Checkpoint,
            reason: CancelReason::SaveFailed
        }
    );
    assert_eq!(
        resumes(&log).len(),
        3,
        "every owner resumes exactly once: {:?}",
        log.borrow()
    );
}

#[test]
fn a_task_store_save_error_cancels_and_resumes_all() {
    save_error_cancels(FloorOwner::TaskStore);
}

#[test]
fn a_config_save_error_cancels_and_resumes_all() {
    save_error_cancels(FloorOwner::Config);
}

#[test]
fn a_health_save_error_cancels_and_resumes_all() {
    save_error_cancels(FloorOwner::Health);
}

#[test]
fn a_lost_worker_result_cancels_with_that_reason() {
    let log = Log::default();
    let mut a = three(&log, Some((FloorOwner::Config, FloorFault::WorkerLost)));
    assert_eq!(
        expect_cancel(&mut a, far()).reason,
        CancelReason::WorkerLost
    );
}

#[test]
fn an_unavailable_owner_cancels_with_that_reason() {
    let log = Log::default();
    let mut a = three(&log, Some((FloorOwner::Health, FloorFault::Unavailable)));
    assert_eq!(
        expect_cancel(&mut a, far()).reason,
        CancelReason::Unavailable
    );
}

#[test]
fn a_failed_pause_cancels_at_the_pause_stage_and_skips_later_owners() {
    let log = Log::default();
    let mut a: Vec<Box<dyn FloorAdapter>> = vec![
        Fake::ok(FloorOwner::TaskStore, &log),
        Fake::with(
            FloorOwner::Config,
            &log,
            Err(FloorFault::Unavailable),
            Ok(()),
        ),
        Fake::ok(FloorOwner::Health, &log),
    ];
    let c = expect_cancel(&mut a, far());
    assert_eq!((c.owner, c.stage), (FloorOwner::Config, FloorStage::Pause));
    assert!(
        !log.borrow().iter().any(|l| l == "pause Health"),
        "{:?}",
        log.borrow()
    );
    assert!(
        !log.borrow().iter().any(|l| l.starts_with("checkpoint")),
        "{:?}",
        log.borrow()
    );
    assert_eq!(resumes(&log).len(), 3);
}

#[test]
fn a_checkpoint_past_the_deadline_cancels() {
    let log = Log::default();
    let mut a = three(&log, None);
    a[1] = Box::new(Fake {
        owner: FloorOwner::Config,
        pause: Ok(()),
        checkpoint: Ok(()),
        checkpoint_takes: Duration::from_millis(60),
        log: Rc::clone(&log),
    });
    let c = expect_cancel(&mut a, Instant::now() + Duration::from_millis(20));
    assert_eq!(c.reason, CancelReason::DeadlineExceeded);
    assert_eq!(resumes(&log).len(), 3);
}

#[test]
fn a_deadline_already_past_cancels_before_any_pause() {
    let log = Log::default();
    let mut a = three(&log, None);
    let c = expect_cancel(&mut a, Instant::now() - Duration::from_millis(1));
    assert_eq!(c.reason, CancelReason::DeadlineExceeded);
    assert!(
        !log.borrow().iter().any(|l| l.starts_with("pause")),
        "{:?}",
        log.borrow()
    );
}

#[test]
fn a_certified_checkpoint_holds_every_pause_until_abort() {
    let log = Log::default();
    let mut a = three(&log, None);
    let certified = run_checkpoint(&mut a, far())
        .ok()
        .expect("all three certify");
    assert!(
        resumes(&log).is_empty(),
        "no resume before abort: {:?}",
        log.borrow()
    );
    certified.abort();
    assert_eq!(resumes(&log).len(), 3);
}

#[test]
fn a_recoverable_fault_cancels_once_then_the_retry_certifies() {
    let log = Log::default();
    let mut bad = three(&log, Some((FloorOwner::TaskStore, FloorFault::SaveFailed)));
    let _ = expect_cancel(&mut bad, far());
    let mut good = three(&log, None);
    assert!(run_checkpoint(&mut good, far()).is_ok());
}

#[test]
fn exactly_three_distinct_floor_owners_are_required() {
    let log = Log::default();
    assert_eq!(validate_owners(&three(&log, None)), Ok(()));
    let two = vec![
        Fake::ok(FloorOwner::TaskStore, &log),
        Fake::ok(FloorOwner::Config, &log),
    ];
    assert_eq!(
        validate_owners(&two),
        Err(FloorSetupError::NotExactlyThreeOwners)
    );
    let dup = vec![
        Fake::ok(FloorOwner::TaskStore, &log),
        Fake::ok(FloorOwner::Config, &log),
        Fake::ok(FloorOwner::Config, &log),
    ];
    assert_eq!(
        validate_owners(&dup),
        Err(FloorSetupError::NotExactlyThreeOwners)
    );
}

#[test]
fn the_cancel_audit_detail_names_owner_stage_and_reason_only() {
    let c = Cancelled {
        owner: FloorOwner::Health,
        stage: FloorStage::Checkpoint,
        reason: CancelReason::SaveFailed,
    };
    let d = c.audit_detail();
    assert_eq!(d["owner"], "health");
    assert_eq!(d["stage"], "checkpoint");
    assert_eq!(d["reason"], "save_failed");
    assert_eq!(d.len(), 3);
}

#[test]
fn a_counters_save_error_and_a_later_floor_save_error_log_and_proceed() {
    for owner in [
        StopSaveOwner::Counters,
        StopSaveOwner::Floor(FloorOwner::TaskStore),
        StopSaveOwner::Floor(FloorOwner::Config),
        StopSaveOwner::Floor(FloorOwner::Health),
    ] {
        assert_eq!(
            settle_stop_save(owner, Err("disk full")),
            StopSaveOutcome::FailedLoggedProceeding
        );
        assert_eq!(
            settle_stop_save::<&str>(owner, Ok(())),
            StopSaveOutcome::Saved
        );
    }
}
