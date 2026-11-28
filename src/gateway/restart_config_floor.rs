// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The config owner of the restart floor: a gate that admits or refuses every
//! operation that can change `gateway.yaml` or the running config, and the
//! adapter that pauses it, settles admitted work and certifies the file.
//!
//! The gate lives on the backend registry beside the reload lock; the adapter
//! (built by the restart coordinator) drives it: pause, settle, both locks,
//! read-only certification, then resume, release for a stop, or commit. Every
//! test seam lives in `seams` under `cfg(test)`.
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the restart coordinator wiring, a later slice, constructs these"
    )
)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use futures::future::BoxFuture;
use tokio::time::Instant;

use crate::config_persistence::lock::Locked;

use super::restart_floor::{FloorAdapter, FloorFault, FloorOwner};

/// Where startup's own resolution found the config. Certify never probes to
/// decide which: `Booted` is a file loaded at boot, `Defaults` a fileless run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ConfigSource {
    Booted(PathBuf),
    Defaults,
}

#[path = "restart_config_gate.rs"]
mod gate;
pub(crate) use gate::{AdmissionGuard, AdmitKind, ConfigGate, GateState, Refusal};

/// What a checkpoint certified: the sha256 (lower hex) of the config bytes
/// and a revision (the attempt that certified it).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Certification {
    pub(crate) sha256: String,
    pub(crate) revision: u64,
}

#[path = "restart_config_certify.rs"]
mod certify;
use certify::CheckInput;
#[path = "restart_config_locks.rs"]
mod locks;

/// The config owner of the floor: pause sets the gate at once, checkpoint
/// settles admitted work, takes both locks and certifies the file read-only.
pub(crate) struct ConfigFloor {
    gate: ConfigGate,
    reload_lock: Arc<tokio::sync::Mutex<()>>,
    source: ConfigSource,
    candidates: Vec<PathBuf>,
    attempt: u64,
    certification: Option<Certification>,
    /// The lock and check tasks, which outlive a dropped checkpoint; `settled`
    /// is false until each has ended.
    checks: Vec<locks::Task>,
    /// The guards a successful checkpoint hands over, until a recovery call.
    held: locks::Held,
    #[cfg(test)]
    seams: seams::FloorSeams,
}

/// The calling thread's test keychain reader, if a row installed one.
#[cfg(test)]
type TestKeychain = Option<Arc<dyn crate::config::keychain::KeychainRead>>;

impl ConfigFloor {
    /// `reload_lock` is the registry's reload mutex, `candidates` the four
    /// fallback paths startup's `Config` supplies (see `production_candidates`).
    pub(crate) fn new(
        gate: ConfigGate,
        reload_lock: Arc<tokio::sync::Mutex<()>>,
        source: ConfigSource,
        candidates: Vec<PathBuf>,
    ) -> Self {
        Self {
            gate,
            reload_lock,
            source,
            candidates,
            attempt: 0,
            certification: None,
            checks: Vec::new(),
            held: locks::Held::default(),
            #[cfg(test)]
            seams: seams::FloorSeams::default(),
        }
    }

    /// The certification the last successful checkpoint produced, if any.
    pub(crate) fn certification(&self) -> Option<&Certification> {
        self.certification.as_ref()
    }

    /// The file to certify: the booted path, or the first fallback that
    /// exists now (`None`: a fileless run, not configured).
    fn configured_path(&self) -> Option<PathBuf> {
        match &self.source {
            ConfigSource::Booted(path) => Some(path.clone()),
            ConfigSource::Defaults => certify::first_existing(self.candidates_now()),
        }
    }

    fn candidates_now(&self) -> &[PathBuf] {
        #[cfg(test)]
        {
            self.active_candidates()
        }
        #[cfg(not(test))]
        {
            &self.candidates
        }
    }

    /// Terminal and Released are final: recovery calls leave the guards alone.
    fn is_final(&self) -> bool {
        let state = self.gate.inner.lock().state;
        matches!(state, GateState::Terminal | GateState::Released)
    }

    fn prune_tasks(&mut self) {
        self.checks.retain(|task| !task.finished());
    }

    /// Both locks and the read-only checks; every guard is a local of this
    /// future until it succeeds, so a dropped checkpoint holds nothing.
    async fn run_checkpoint(
        &mut self,
        deadline: Instant,
        #[cfg(test)] test_keychain: TestKeychain,
    ) -> Result<(), FloorFault> {
        self.held.release_all();
        self.certification = None;
        let attempt = self.attempt;
        // Admitted work settles before the candidate search, so a fallback file
        // that appears while it runs is seen, and a fileless run is still gated.
        locks::until(deadline, self.gate.settle()).await;
        let Some(path) = self.configured_path() else {
            return self.certify_gate(attempt);
        };
        let reload = locks::until(deadline, Arc::clone(&self.reload_lock).lock_owned()).await;
        let locked = self.lock_config(&path, attempt, deadline).await?;
        let input = self.check_input(
            path,
            &locked,
            attempt,
            #[cfg(test)]
            test_keychain,
        );
        let certified = self.run_check(input, deadline).await?;
        self.certify_gate(attempt)?;
        self.held = locks::Held::new(reload, locked);
        self.certification = Some(certified);
        Ok(())
    }

    /// Moves the gate to Certified for this attempt; a gate that moved on refuses.
    fn certify_gate(&self, attempt: u64) -> Result<(), FloorFault> {
        if self.gate.certify(attempt) {
            Ok(())
        } else {
            Err(FloorFault::Unavailable)
        }
    }

    async fn lock_config(
        &mut self,
        path: &Path,
        attempt: u64,
        deadline: Instant,
    ) -> Result<Locked, FloorFault> {
        let (task, reply) = locks::spawn_lock(
            &self.gate,
            path.to_path_buf(),
            attempt,
            deadline,
            #[cfg(test)]
            self.seams.clone(),
        );
        self.checks.push(task);
        let locked = locks::take_lock(reply, deadline).await?;
        #[cfg(test)]
        self.seams.slots.push(seams::SlotEntry {
            attempt,
            outcome: seams::SlotOutcome::Handed,
        });
        Ok(locked)
    }

    /// The test keychain reader is thread-local, so `checkpoint` captured it
    /// on the calling thread and it arrives here by value.
    fn check_input(
        &self,
        configured: PathBuf,
        locked: &Locked,
        attempt: u64,
        #[cfg(test)] test_keychain: TestKeychain,
    ) -> CheckInput {
        let gate = self.gate.clone();
        CheckInput {
            attempt,
            configured,
            locked_target: locked.target.clone(),
            owed: Arc::new(move || gate.any_owed()),
            #[cfg(test)]
            test_keychain,
            #[cfg(test)]
            check_hook: self.seams.check_hook.clone(),
            #[cfg(test)]
            meta_hook: self.seams.meta_hook.clone(),
        }
    }

    async fn run_check(
        &mut self,
        input: CheckInput,
        deadline: Instant,
    ) -> Result<Certification, FloorFault> {
        let (task, reply) = locks::spawn_check(
            input,
            #[cfg(test)]
            self.seams.attempts.clone(),
        );
        self.checks.push(task);
        locks::take_check(reply, deadline).await
    }
}

impl FloorAdapter for ConfigFloor {
    fn owner(&self) -> FloorOwner {
        FloorOwner::Config
    }

    fn pause(&mut self, _deadline: Instant) -> BoxFuture<'_, Result<(), FloorFault>> {
        // The gate is set before the future exists, so a pause future dropped
        // unpolled has still paused; the adapter, not the future, holds it.
        self.prune_tasks();
        self.attempt += 1;
        let paused = self.gate.pause(self.attempt);
        Box::pin(async move { paused })
    }

    fn checkpoint(&mut self, deadline: Instant) -> BoxFuture<'_, Result<(), FloorFault>> {
        self.prune_tasks();
        // Captured before the future's first await: the reader is thread-local.
        #[cfg(test)]
        let test_keychain = crate::config::keychain::current_test_keychain();
        Box::pin(self.run_checkpoint(
            deadline,
            #[cfg(test)]
            test_keychain,
        ))
    }

    fn resume(&mut self) {
        self.prune_tasks();
        if !self.is_final() {
            self.held.release_all();
        }
        self.gate.reopen();
    }

    fn release_for_stop(&mut self) {
        self.prune_tasks();
        if !self.is_final() {
            self.held.release_all();
        }
        self.gate.finish(GateState::Released);
    }

    fn commit(&mut self) {
        self.prune_tasks();
        if !self.is_final() {
            self.held.release_reload();
        }
        self.gate.finish(GateState::Terminal);
    }

    fn settled(&self) -> bool {
        self.checks.iter().all(locks::Task::finished)
    }
}

/// Every test seam, defined here and nowhere else. Release builds compile none
/// of it, and every field or call that touches it carries `cfg(test)`.
#[cfg(test)]
pub(crate) mod seams {
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};

    use super::{AdmitKind, ConfigFloor, ConfigGate, GateState};

    /// A test-owned log: pushes from any thread, snapshots for assertions.
    #[derive(Debug)]
    pub(crate) struct SeamLog<T>(Arc<Mutex<Vec<T>>>);

    impl<T> Default for SeamLog<T> {
        fn default() -> Self {
            Self(Arc::default())
        }
    }

    impl<T> Clone for SeamLog<T> {
        fn clone(&self) -> Self {
            Self(Arc::clone(&self.0))
        }
    }

    impl<T: Clone> SeamLog<T> {
        pub(crate) fn push(&self, item: T) {
            self.0.lock().unwrap().push(item);
        }

        pub(crate) fn snapshot(&self) -> Vec<T> {
            self.0.lock().unwrap().clone()
        }
    }

    /// Named points where a holder of an admission guard calls the hook.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum AdmittedPoint {
        /// Byte writer, its secret entries staged, before `write_atomic`: a row
        /// kills the write task here so `Entries::drop` runs the detached discard.
        WriterAfterStaging,
        /// Byte writer, after it released both locks, during secret settlement.
        WriterAfterLocks,
        /// Inside the detached secret-entry cleanup.
        Cleanup,
        /// A watcher tick that started and has not asked for admission.
        WatcherBeforeAdmission,
        /// The watcher after admission, before `pending_trigger.take()`.
        WatcherAfterAdmission,
        /// A manual reload after admission, before it takes the reload lock.
        ManualAfterAdmission,
    }

    /// Called by the guard holder at a named point; a row blocks it on a Barrier.
    pub(crate) type AdmittedHook = Arc<dyn Fn(AdmittedPoint) + Send + Sync>;

    /// Runs inside the settle loop after the count reads above zero and before
    /// the await; the row's closure drops a test-owned guard synchronously.
    pub(crate) type SettleWindow = Arc<dyn Fn() + Send + Sync>;

    /// Runs inside `admit` after the decision and before it is recorded and
    /// counted, while the gate's mutex is held: a row parks a submission there.
    pub(crate) type AdmitWindow = Arc<dyn Fn() + Send + Sync>;

    /// One admission decision: the state the gate held at that decision.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct GateDecision {
        pub(crate) seq: u64,
        pub(crate) state: GateState,
        pub(crate) kind: AdmitKind,
        pub(crate) admitted: bool,
    }

    /// Who completed a reload.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum ReloadSource {
        Watcher,
        Manual,
        Write,
        Replay,
    }

    /// A completed reload and the running config's `environment` at that moment
    /// (empty when unset): one fixed key, which every row that reads the log edits.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) struct ReloadEntry {
        pub(crate) source: ReloadSource,
        pub(crate) value: String,
    }

    /// The watcher's Notify records, consumed by the tick each authorizes.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum WatcherPoke {
        /// `resume()` poked the watcher.
        Resume,
        /// A file event reached the watcher.
        FileEvent,
    }

    /// The gate's seams, one set per gate instance.
    #[derive(Clone, Default)]
    pub(crate) struct ConfigGateSeams {
        pub(crate) admitted_hook: Arc<Mutex<Option<AdmittedHook>>>,
        pub(crate) settle_window: Arc<Mutex<Option<SettleWindow>>>,
        pub(crate) admit_window: Arc<Mutex<Option<AdmitWindow>>>,
        pub(crate) decisions: SeamLog<GateDecision>,
        pub(crate) reloads: SeamLog<ReloadEntry>,
        pub(crate) pokes: SeamLog<WatcherPoke>,
    }

    impl ConfigGateSeams {
        /// Appends one admission decision with the state it was decided in;
        /// the gate calls it under its own mutex, so the log is in decision order.
        pub(crate) fn record_decision(&self, state: GateState, kind: AdmitKind, admitted: bool) {
            let seq = self.decisions.snapshot().len() as u64 + 1;
            self.decisions.push(GateDecision {
                seq,
                state,
                kind,
                admitted,
            });
        }

        /// The settle loop's window: the count read above zero, nothing awaited yet.
        pub(crate) fn call_settle_window(&self) {
            let hook = self.settle_window.lock().unwrap().clone();
            if let Some(hook) = hook {
                hook();
            }
        }

        /// The admission's window: decided, not yet recorded or counted.
        pub(crate) fn call_admit_window(&self) {
            let hook = self.admit_window.lock().unwrap().clone();
            if let Some(hook) = hook {
                hook();
            }
        }

        pub(crate) fn record_resume_poke(&self) {
            self.pokes.push(WatcherPoke::Resume);
        }
    }

    impl std::fmt::Debug for ConfigGateSeams {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("ConfigGateSeams")
        }
    }

    /// Steps of the check task the `CheckHook` and the check log name.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum CheckStep {
        /// Both locks held, before any read.
        Start,
        /// After the unsettled-write checks (step 3), before the target identity
        /// check and the trusted read (steps 4 and 5): C3 repoints the link here so
        /// only step 4 can catch it.
        BeforeRead,
        /// After the trusted read of the file.
        AfterRead,
        /// After validation, before the re-check (step 8).
        AfterValidation,
    }

    /// Called by the check task at each step with its attempt; a row may block
    /// it, swap the file under it, or panic in it.
    pub(crate) type CheckHook = Arc<dyn Fn(u64, CheckStep) + Send + Sync>;

    /// What the config-lock acquisition does at its deadline.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum LockVerdict {
        Proceed,
        /// Return Busy as if the std deadline expired.
        Busy,
    }

    /// Called by the lock-acquisition task with its attempt; may block or panic.
    pub(crate) type LockHook = Arc<dyn Fn(u64) -> LockVerdict + Send + Sync>;

    /// Called by the lock task with its attempt after its hand-off, before the
    /// task marks itself finished; may block, which holds `settled` false.
    pub(crate) type AfterHandOff = Arc<dyn Fn(u64) + Send + Sync>;

    /// Replaces the metadata call for the abandoned path: the row injects a
    /// real non-`NotFound` error (`PermissionDenied`) without arranging the disk.
    pub(crate) type MetaHook = Arc<dyn Fn(&Path) -> std::io::Result<bool> + Send + Sync>;

    /// Outcome of the lock-handoff slot for one attempt's guard.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum SlotOutcome {
        Handed,
        DroppedSuperseded,
    }

    /// Slot log entry: the attempt whose guard reached the slot, and its fate.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct SlotEntry {
        pub(crate) attempt: u64,
        pub(crate) outcome: SlotOutcome,
    }

    /// What an attempt's task recorded.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum AttemptEvent {
        LockAcquired,
        LockBusy,
        /// The check task ended: certified (true) or faulted (false).
        CheckDone(bool),
    }

    /// Attempt log entry: which attempt did what.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct AttemptEntry {
        pub(crate) attempt: u64,
        pub(crate) event: AttemptEvent,
    }

    /// The adapter's seams, one set per adapter instance.
    #[derive(Clone, Default)]
    pub(crate) struct FloorSeams {
        pub(crate) check_hook: Option<CheckHook>,
        pub(crate) lock_hook: Option<LockHook>,
        pub(crate) after_hand_off: Option<AfterHandOff>,
        pub(crate) meta_hook: Option<MetaHook>,
        /// The candidate-path override a row sets; `None` uses the input paths.
        pub(crate) candidate_override: Option<Vec<PathBuf>>,
        pub(crate) slots: SeamLog<SlotEntry>,
        pub(crate) attempts: SeamLog<AttemptEntry>,
    }

    impl ConfigGate {
        /// The state word as the gate holds it now.
        pub(crate) fn gate_state(&self) -> GateState {
            self.inner.lock().state
        }

        /// Admission guards alive now.
        pub(crate) fn admissions_in_flight(&self) -> usize {
            self.inner.lock().in_flight
        }

        pub(crate) fn set_admitted_hook(&self, hook: Option<AdmittedHook>) {
            *self.seams.admitted_hook.lock().unwrap() = hook;
        }

        pub(crate) fn set_settle_window(&self, hook: Option<SettleWindow>) {
            *self.seams.settle_window.lock().unwrap() = hook;
        }

        pub(crate) fn set_admit_window(&self, hook: Option<AdmitWindow>) {
            *self.seams.admit_window.lock().unwrap() = hook;
        }

        /// Whether any thread holds the gate's mutex now; never takes it.
        pub(crate) fn gate_mutex_held(&self) -> bool {
            self.inner.is_locked()
        }

        /// A guard holder calls this at a named point while it holds its guard.
        pub(crate) fn call_admitted(&self, point: AdmittedPoint) {
            let hook = self.seams.admitted_hook.lock().unwrap().clone();
            if let Some(hook) = hook {
                hook(point);
            }
        }

        pub(crate) fn decisions(&self) -> Vec<GateDecision> {
            self.seams.decisions.snapshot()
        }

        /// Every completed reload appends here (production calls it under
        /// `cfg(test)`), with the running `environment` after that reload.
        pub(crate) fn record_reload(&self, source: ReloadSource, value: &str) {
            let value = value.to_owned();
            self.seams.reloads.push(ReloadEntry { source, value });
        }

        pub(crate) fn reload_log(&self) -> Vec<ReloadEntry> {
            self.seams.reloads.snapshot()
        }

        /// The test watcher records a file event it saw.
        pub(crate) fn record_file_event(&self) {
            self.seams.pokes.push(WatcherPoke::FileEvent);
        }

        /// Pokes recorded and not yet consumed by a tick, oldest first.
        pub(crate) fn pending_pokes(&self) -> Vec<WatcherPoke> {
            self.seams.pokes.snapshot()
        }

        /// A tick consumes the record it runs for; false when none authorizes it.
        pub(crate) fn consume_poke(&self) -> bool {
            let mut pokes = self.seams.pokes.0.lock().unwrap();
            (!pokes.is_empty()).then(|| pokes.remove(0)).is_some()
        }
    }

    impl ConfigFloor {
        pub(crate) fn set_check_hook(&mut self, hook: Option<CheckHook>) {
            self.seams.check_hook = hook;
        }

        pub(crate) fn set_lock_hook(&mut self, hook: Option<LockHook>) {
            self.seams.lock_hook = hook;
        }

        pub(crate) fn set_after_hand_off(&mut self, hook: Option<AfterHandOff>) {
            self.seams.after_hand_off = hook;
        }

        pub(crate) fn set_meta_hook(&mut self, hook: Option<MetaHook>) {
            self.seams.meta_hook = hook;
        }

        /// The candidate-path override: a row passes its temp paths here.
        pub(crate) fn override_candidates(&mut self, paths: Vec<PathBuf>) {
            self.seams.candidate_override = Some(paths);
        }

        /// The paths a Defaults certify searches: the override, else the input.
        pub(crate) fn active_candidates(&self) -> &[PathBuf] {
            self.seams
                .candidate_override
                .as_deref()
                .unwrap_or(&self.candidates)
        }

        /// The attempt number the last pause started (0 before any pause).
        pub(crate) fn attempt(&self) -> u64 {
            self.attempt
        }
    }
}

#[cfg(tp4)]
#[cfg(test)]
#[path = "config_floor_cancel_tests.rs"]
mod cancel_tests;
#[cfg(tp4)]
#[cfg(test)]
#[path = "config_floor_certify_more_tests.rs"]
mod certify_more_tests;
#[cfg(tp4)]
#[cfg(test)]
#[path = "config_floor_certify_tests.rs"]
mod certify_tests;
#[cfg(tp4)]
#[cfg(test)]
#[path = "config_floor_contract_more_tests.rs"]
mod contract_more_tests;
#[cfg(tp4)]
#[cfg(test)]
#[path = "config_floor_contract_tests.rs"]
mod contract_tests;
#[cfg(tp4)]
#[cfg(test)]
#[path = "config_floor_settle_more_tests.rs"]
mod settle_more_tests;
#[cfg(tp4)]
#[cfg(test)]
#[path = "config_floor_settle_tests.rs"]
mod settle_tests;
#[cfg(tp4)]
#[cfg(test)]
#[path = "config_floor_source_tests.rs"]
mod source_tests;
#[cfg(test)]
#[path = "config_floor_support_tests.rs"]
pub(crate) mod support;
