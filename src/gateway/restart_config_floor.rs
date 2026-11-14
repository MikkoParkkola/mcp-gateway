// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The config owner of the restart floor: a gate that admits or refuses every
//! operation that can change `gateway.yaml` or the running config, and the
//! adapter that pauses it, settles admitted work and certifies the file.
//!
//! This is the red-first skeleton: the gate admits everything and the adapter
//! answers Ok and does nothing, so every row fails at its own assertion until
//! the behaviour lands. Every test seam lives in `seams` under `cfg(test)`.
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the restart coordinator wiring, a later slice, constructs these"
    )
)]

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use futures::future::BoxFuture;
use tokio::time::Instant;

use super::restart_floor::{FloorAdapter, FloorFault, FloorOwner};

/// Where startup's own resolution found the config. Certify never probes to
/// decide which: `Booted` is a file loaded at boot, `Defaults` a fileless run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ConfigSource {
    Booted(PathBuf),
    Defaults,
}

/// The gate's state word. `Paused` and `Certified` carry the attempt number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GateState {
    Open,
    Paused(u64),
    Certified(u64),
    Terminal,
    Released,
}

/// Who asks the gate for admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AdmitKind {
    /// The byte writer, every UI write to the config file.
    Write,
    /// A manual reload: the UI route or the meta-tool.
    ManualReload,
    /// The watcher, before it takes its pending trigger.
    Watcher,
}

/// Why the gate refused. The caller maps it to its 409 body.
#[cfg_attr(
    test,
    allow(
        dead_code,
        reason = "red-phase: remove when the implementation uses it"
    )
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// Paused or Certified: a UI write is refused, retry later.
    Busy,
    /// Paused or Certified: a manual reload folded into the owed replay.
    ReplayOwed,
    /// Terminal: "the gateway is restarting".
    Restarting,
    /// Released: "the gateway is stopping".
    Stopping,
}

/// Counted in flight until dropped. Stub: counts nothing.
#[derive(Debug)]
pub(crate) struct AdmissionGuard {
    _gate: ConfigGate,
}

#[cfg_attr(
    test,
    allow(
        dead_code,
        reason = "red-phase: remove when the implementation uses it"
    )
)]
#[derive(Debug, Default)]
struct GateInner {
    owed_flags: Vec<Arc<AtomicBool>>,
}

/// One per gateway, shared by the byte writer, every reload context, the
/// watcher and the adapter. Cloning shares the same gate.
#[cfg_attr(
    test,
    allow(
        dead_code,
        reason = "red-phase: remove when the implementation uses it"
    )
)]
#[derive(Clone, Debug, Default)]
pub(crate) struct ConfigGate {
    inner: Arc<Mutex<GateInner>>,
    #[cfg(test)]
    seams: seams::GateSeams,
}

#[cfg_attr(
    test,
    allow(
        dead_code,
        reason = "red-phase: remove when the implementation uses it"
    )
)]
impl ConfigGate {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Ask for admission; the guard is held for the whole operation.
    pub(crate) fn admit(&self, _kind: AdmitKind) -> Result<AdmissionGuard, Refusal> {
        Ok(AdmissionGuard {
            _gate: self.clone(),
        })
    }

    /// A reload context or the watcher registers an owed-reload fault flag.
    pub(crate) fn register_owed(&self, flag: Arc<AtomicBool>) {
        self.inner.lock().unwrap().owed_flags.push(flag);
    }

    /// Whether a manual reload folded into an owed replay (stub: never).
    pub(crate) fn replay_owed(&self) -> bool {
        false
    }

    /// The watcher clears the flag once it holds its admission guard.
    pub(crate) fn take_replay_owed(&self, _held: &AdmissionGuard) -> bool {
        false
    }

    /// resume() turns the owed replay into a watcher trigger. Stub: no poke.
    pub(crate) fn poke_watcher(&self) {}
}

/// What a checkpoint certified: the sha256 (lower hex) of the config bytes
/// and a revision. Stub: an empty hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Certification {
    pub(crate) sha256: String,
    pub(crate) revision: u64,
}

/// The four fallback locations of the startup search, in order. Stub: none.
pub(crate) fn production_candidates() -> Vec<PathBuf> {
    Vec::new()
}

/// The config owner of the floor. Stub: every call answers Ok and does nothing.
#[cfg_attr(
    test,
    allow(
        dead_code,
        reason = "red-phase: remove when the implementation uses it"
    )
)]
pub(crate) struct ConfigFloor {
    gate: ConfigGate,
    reload_lock: Arc<tokio::sync::Mutex<()>>,
    source: ConfigSource,
    candidates: Vec<PathBuf>,
    attempt: u64,
    certification: Option<Certification>,
    #[cfg(test)]
    seams: seams::FloorSeams,
}

#[cfg_attr(
    test,
    allow(
        dead_code,
        reason = "red-phase: remove when the implementation uses it"
    )
)]
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
            #[cfg(test)]
            seams: seams::FloorSeams::default(),
        }
    }

    /// The gate this adapter drives.
    pub(crate) fn gate(&self) -> &ConfigGate {
        &self.gate
    }

    /// The source startup resolved.
    pub(crate) fn source(&self) -> &ConfigSource {
        &self.source
    }

    /// The certification the last successful checkpoint produced, if any.
    pub(crate) fn certification(&self) -> Option<&Certification> {
        self.certification.as_ref()
    }

    fn dummy_certification(&mut self) {
        self.certification = Some(Certification {
            sha256: String::new(),
            revision: self.attempt,
        });
    }
}

impl FloorAdapter for ConfigFloor {
    fn owner(&self) -> FloorOwner {
        FloorOwner::Config
    }

    fn pause(&mut self, _deadline: Instant) -> BoxFuture<'_, Result<(), FloorFault>> {
        Box::pin(async { Ok(()) })
    }

    fn checkpoint(&mut self, _deadline: Instant) -> BoxFuture<'_, Result<(), FloorFault>> {
        self.dummy_certification();
        Box::pin(async { Ok(()) })
    }

    fn resume(&mut self) {}

    fn release_for_stop(&mut self) {}

    fn commit(&mut self) {}

    fn settled(&self) -> bool {
        true
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

    /// One admission decision: the state the gate held at that decision.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct GateDecision {
        pub(crate) seq: u64,
        pub(crate) state: GateState,
        pub(crate) kind: AdmitKind,
        pub(crate) admitted: bool,
    }

    /// Who completed a reload.
    #[cfg_attr(
        test,
        allow(
            dead_code,
            reason = "red-phase: remove when the implementation uses it"
        )
    )]
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
    #[cfg_attr(
        test,
        allow(
            dead_code,
            reason = "red-phase: remove when the implementation uses it"
        )
    )]
    #[derive(Clone, Default)]
    pub(crate) struct GateSeams {
        pub(crate) admitted_hook: Arc<Mutex<Option<AdmittedHook>>>,
        pub(crate) settle_window: Arc<Mutex<Option<SettleWindow>>>,
        pub(crate) decisions: SeamLog<GateDecision>,
        pub(crate) reloads: SeamLog<ReloadEntry>,
        pub(crate) pokes: SeamLog<WatcherPoke>,
    }

    impl std::fmt::Debug for GateSeams {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("GateSeams")
        }
    }

    /// Steps of the check task the CheckHook and the check log name.
    #[cfg_attr(
        test,
        allow(
            dead_code,
            reason = "red-phase: remove when the implementation uses it"
        )
    )]
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

    /// Replaces the metadata call for the abandoned path: the row injects a
    /// real non-NotFound error (PermissionDenied) without arranging the disk.
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
    #[cfg_attr(
        test,
        allow(
            dead_code,
            reason = "red-phase: remove when the implementation uses it"
        )
    )]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum AttemptEvent {
        LockAcquired,
        LockBusy,
        /// The check task ended: certified (true) or faulted (false).
        CheckDone(bool),
        /// A trusted read happened.
        Read,
        /// Validation ran.
        Validated,
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
        pub(crate) meta_hook: Option<MetaHook>,
        /// The candidate-path override a row sets; `None` uses the input paths.
        pub(crate) candidate_override: Option<Vec<PathBuf>>,
        pub(crate) slots: SeamLog<SlotEntry>,
        pub(crate) attempts: SeamLog<AttemptEntry>,
    }

    #[cfg_attr(
        test,
        allow(
            dead_code,
            reason = "red-phase: remove when the implementation uses it"
        )
    )]
    impl ConfigGate {
        /// The state word as the gate holds it now. Stub: always Open.
        pub(crate) fn state(&self) -> GateState {
            GateState::Open
        }

        /// Admission guards alive now. Stub: always 0.
        pub(crate) fn admissions_in_flight(&self) -> usize {
            0
        }

        pub(crate) fn set_admitted_hook(&self, hook: Option<AdmittedHook>) {
            *self.seams.admitted_hook.lock().unwrap() = hook;
        }

        pub(crate) fn set_settle_window(&self, hook: Option<SettleWindow>) {
            *self.seams.settle_window.lock().unwrap() = hook;
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

    #[cfg_attr(
        test,
        allow(
            dead_code,
            reason = "red-phase: remove when the implementation uses it"
        )
    )]
    impl ConfigFloor {
        pub(crate) fn set_check_hook(&mut self, hook: Option<CheckHook>) {
            self.seams.check_hook = hook;
        }

        pub(crate) fn set_lock_hook(&mut self, hook: Option<LockHook>) {
            self.seams.lock_hook = hook;
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

        pub(crate) fn slot_log(&self) -> Vec<SlotEntry> {
            self.seams.slots.snapshot()
        }

        pub(crate) fn attempt_log(&self) -> Vec<AttemptEntry> {
            self.seams.attempts.snapshot()
        }

        /// The attempt number the last pause started. Stub: 0.
        pub(crate) fn attempt(&self) -> u64 {
            self.attempt
        }

        /// The registry's reload mutex the adapter takes, for lock probes.
        pub(crate) fn reload_lock(&self) -> Arc<tokio::sync::Mutex<()>> {
            Arc::clone(&self.reload_lock)
        }
    }
}

#[cfg(test)]
#[path = "config_floor_cancel_tests.rs"]
mod cancel_tests;
#[cfg(test)]
#[path = "config_floor_certify_more_tests.rs"]
mod certify_more_tests;
#[cfg(test)]
#[path = "config_floor_certify_tests.rs"]
mod certify_tests;
#[cfg(test)]
#[path = "config_floor_contract_more_tests.rs"]
mod contract_more_tests;
#[cfg(test)]
#[path = "config_floor_contract_tests.rs"]
mod contract_tests;
#[cfg(test)]
#[path = "config_floor_settle_more_tests.rs"]
mod settle_more_tests;
#[cfg(test)]
#[path = "config_floor_settle_tests.rs"]
mod settle_tests;
#[cfg(test)]
#[path = "config_floor_source_tests.rs"]
mod source_tests;
#[cfg(test)]
#[path = "config_floor_support_tests.rs"]
pub(crate) mod support;
