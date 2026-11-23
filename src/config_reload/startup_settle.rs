// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The config-write startup gate: before the gateway serves, settle a dead writer's pending
//! config-write artifacts (the v2 journal, the abandoned file, the retired manifest) under the
//! config lock, or prove without the lock that none can exist.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config_persistence::journal::journal_path;
use crate::config_persistence::journal::v2::drain::file::{Handover, drain_abandoned, handover_of};
use crate::config_persistence::journal::v2::drain::{DrainError, DrainSession, JournalDrain};
use crate::config_persistence::journal::v2::{
    JournalV2, OpenJournal, abandoned_path, retired_path,
};
use crate::config_persistence::lock::{
    Locked, NoResult, NotLocked, absent, dispatch_journal, lock_config_deferred, lock_path,
    no_writer_possible, off_runtime,
};
use crate::config_persistence::{CLI_LOCK_WAIT, Unrecovered, recover_recorded};
use crate::identity_grants::journal::resolved;
use crate::security::transparency_log::TransparencyLogger;

/// A startup that may go on to load the config: the lock held, or proven unneeded. Not `Clone`.
pub(crate) struct StartupSession {
    state: StartupState,
}

enum StartupState {
    // Boxed: the held session is far larger than the unlocked variant.
    Locked(Box<DrainSession>),
    ArtifactFreeUnlocked {
        configured: PathBuf,
        target: PathBuf,
    },
}

/// Why the gateway must not start. Each class prints one fixed sentence naming what to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StartError {
    Busy,
    RepairPending,
    JournalPending,
    AbandonedPending,
    InvalidAuditPayload,
    ArtifactCheckFailed,
    /// A v1 replace journal met by a construction that may not write.
    RecoveryPending,
    /// A retired manifest, which this build cannot read yet.
    ManifestUnread,
    /// A v1 journal whose recovery would leave a config that does not load. The logged cause names
    /// the files and the steps to finish by hand.
    UnloadableRecovery,
}

impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Busy => {
                "Another gateway or command holds the config lock past the 30-second wait. Start again when it has finished."
            }
            Self::RepairPending => {
                "A config write that crashed left the config in a state its journal could neither confirm nor restore. Compare the config with the revisions the journal records before changing anything, then start again."
            }
            Self::JournalPending => {
                "A config write's journal beside the config still owes audit records to the log it was bound to. Start with that audit log configured and reachable."
            }
            Self::AbandonedPending => {
                "The abandoned config-write file beside the config holds audit records this gateway cannot deliver. Configure the log it names, or move the file aside by hand to keep it as evidence."
            }
            Self::InvalidAuditPayload => {
                "The audit log refused a pending config-write record as invalid. The record is parked and kept as evidence, and it needs an operator's decision before this gateway can start."
            }
            Self::ArtifactCheckFailed => {
                "This gateway could not confirm that no config write is pending beside the config. Fix access to the config directory, then start again."
            }
            Self::RecoveryPending => {
                "An interrupted config write needs recovering before this config is used. Call mcp_gateway::config_reload::recover_before_start on it, or start the gateway once with serve, then build again."
            }
            Self::ManifestUnread => crate::config_persistence::lock::MANIFEST_UNREAD,
            Self::UnloadableRecovery => {
                "Nothing was recovered: the config a crashed write would restore does not load."
            }
        })
    }
}

/// The serving audit log a start settles with. Off and failed are different answers: a config
/// with logging off may leave an abandoned file for later, while a log that should have opened
/// and did not must not let one through.
pub(crate) enum ServingLog {
    /// Logging is configured off.
    Off,
    /// Logging is configured on, and the best-effort open failed.
    Failed,
    /// The serving log, open.
    Open(Arc<TransparencyLogger>),
}

impl ServingLog {
    fn logger(&self) -> Option<Arc<TransparencyLogger>> {
        match self {
            Self::Open(log) => Some(Arc::clone(log)),
            Self::Off | Self::Failed => None,
        }
    }
}

/// An open log, or none meaning logging off (the rows' spelling of the two cases they use).
impl From<Option<Arc<TransparencyLogger>>> for ServingLog {
    fn from(log: Option<Arc<TransparencyLogger>>) -> Self {
        log.map_or(Self::Off, Self::Open)
    }
}

impl fmt::Debug for StartupSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StartupSession")
            .field("target", &self.target())
            .finish_non_exhaustive()
    }
}

impl StartupSession {
    /// The resolved config the gate checked. The caller loads the config, and derives the serving
    /// logger, from this path only.
    pub(crate) fn target(&self) -> &Path {
        match &self.state {
            StartupState::Locked(session) => session.target(),
            StartupState::ArtifactFreeUnlocked { target, .. } => target,
        }
    }
}

// The worker drops its session before returning this, so the lock is released there.
struct Refusal {
    class: StartError,
    path: PathBuf,
    cause: String,
}

/// Take the config lock (waiting up to [`CLI_LOCK_WAIT`]) and repair what a crashed write left,
/// or prove that no writer and no artifact can exist here.
pub(crate) async fn prepare_start(config: &Path) -> Result<StartupSession, StartError> {
    prepare_start_within(config, CLI_LOCK_WAIT).await
}

/// [`prepare_start`] with the lock wait as a parameter, for rows.
pub(crate) async fn prepare_start_within(
    config: &Path,
    wait: Duration,
) -> Result<StartupSession, StartError> {
    let configured = config.to_path_buf();
    // The configured path, as given: resolving it here would touch the filesystem on this task.
    let named = configured.clone();
    match lock_config_deferred(config, Instant::now() + wait).await {
        Err(NotLocked::Busy) => Err(logged(refuse(StartError::Busy, named, "Busy"))),
        Err(NotLocked::Failed(_) | NotLocked::Refused(_)) => {
            from_worker(named, move || unlocked(configured)).await
        }
        Ok(locked) => from_worker(named, move || open_locked(locked, configured)).await,
    }
}

/// Settle what `prepare_start` left owed, with the serving log the gateway will serve with, then
/// release the lock.
pub(crate) async fn finish_start(
    session: StartupSession,
    log: impl Into<ServingLog>,
) -> Result<(), StartError> {
    let log = log.into();
    let named = session.target().to_path_buf();
    match session.state {
        StartupState::ArtifactFreeUnlocked { configured, target } => {
            from_worker(named, move || recheck(&configured, &target)).await
        }
        StartupState::Locked(session) => {
            // Captured on the caller: the worker is not inside a runtime until `block_on`.
            let handle = tokio::runtime::Handle::current();
            from_worker(named, move || handle.block_on(drain_locked(*session, log))).await
        }
    }
}

/// The journal drain's error, as a start refusal.
pub(crate) fn journal_stage(error: DrainError) -> Result<(), StartError> {
    Err(match error {
        DrainError::NoLogger
        | DrainError::OtherLog
        | DrainError::Journal
        | DrainError::Refused
        | DrainError::Unconfirmed
        | DrainError::Finish
        | DrainError::FileRefused => StartError::JournalPending,
        DrainError::RepairPending => StartError::RepairPending,
        DrainError::Parked => StartError::InvalidAuditPayload,
    })
}

/// The abandoned-file drain's error, as a start refusal (`NoLogger`: logging off, P6, accepts).
pub(crate) fn file_stage(error: DrainError) -> Result<(), StartError> {
    match error {
        DrainError::NoLogger => Ok(()),
        DrainError::Parked => Err(StartError::InvalidAuditPayload),
        DrainError::OtherLog
        | DrainError::FileRefused
        | DrainError::Journal
        | DrainError::Refused
        | DrainError::Unconfirmed
        | DrainError::Finish
        | DrainError::RepairPending => Err(StartError::AbandonedPending),
    }
}

/// The gate for a construction with no startup session behind it. It never writes, so it never
/// repairs or recovers: under the config lock (waiting up to [`CLI_LOCK_WAIT`]) the journal, the
/// abandoned file and the retired manifest must all be proven absent, and each one found refuses
/// with its class. Where the lock cannot be taken because no writer can exist, the unlocked
/// probe decides. The lock is let go before this returns.
pub(crate) async fn check_sessionless(config: &Path) -> Result<(), StartError> {
    let path = config.to_path_buf();
    let deadline = Instant::now() + CLI_LOCK_WAIT;
    let reads: Box<dyn FnOnce() -> Result<(), Refusal> + Send> =
        match lock_config_deferred(config, deadline).await {
            // Moved into the worker, which lets the lock go once its reads are done.
            Ok(held) => Box::new(move || nothing_pending(&held)),
            Err(NotLocked::Busy) => {
                return Err(logged(refuse(StartError::Busy, path, "Busy")));
            }
            Err(_) => {
                let unheld = path.clone();
                Box::new(move || probe(&unheld).map(drop))
            }
        };
    from_worker(path, reads).await
}

// Reads only, the lock held: the first artifact that stops a sessionless construction.
fn nothing_pending(held: &Locked) -> Result<(), Refusal> {
    let journal = journal_path(&held.target);
    let found = match dispatch_journal(held) {
        Ok(None) => None,
        Ok(Some(OpenJournal::Legacy(_))) => Some((StartError::RecoveryPending, "v1".to_owned())),
        Ok(Some(OpenJournal::Current(_))) => Some((StartError::JournalPending, "v2".to_owned())),
        Err(why) => Some((StartError::JournalPending, format!("{why:?}"))),
    };
    if let Some((class, cause)) = found {
        return Err(refuse(class, journal, cause));
    }
    let beside = [
        (abandoned_path(&held.target), StartError::AbandonedPending),
        (retired_path(&held.target), StartError::ManifestUnread),
    ];
    for (artifact, class) in beside {
        proven_absent(artifact, class)?;
    }
    Ok(())
}

/// `artifact` proven absent, or the refusal: `class` when it is there, and the unproven class for
/// any answer other than "not found".
fn proven_absent(artifact: PathBuf, class: StartError) -> Result<(), Refusal> {
    let unproven = match std::fs::symlink_metadata(&artifact).map_err(|error| error.kind()) {
        Err(std::io::ErrorKind::NotFound) => return Ok(()),
        Err(_) => true,
        Ok(_) => false,
    };
    Err(if unproven {
        refuse(StartError::ArtifactCheckFailed, artifact, "unproven")
    } else {
        refuse(class, artifact, "present")
    })
}

// Stalled retries. Lost proves nothing about the artifacts. Every refusal, these included, is logged
// once on the caller with a path and its cause; `path` names the config for the two no-result causes.
async fn from_worker<T: Send + 'static>(
    path: PathBuf,
    work: impl FnOnce() -> Result<T, Refusal> + Send + 'static,
) -> Result<T, StartError> {
    match off_runtime(Some(&path), work).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(refusal)) => Err(logged(refusal)),
        Err(NoResult::Stalled) => Err(logged(refuse(StartError::Busy, path, "Stalled"))),
        Err(NoResult::Lost) => Err(logged(refuse(
            StartError::ArtifactCheckFailed,
            path,
            "Lost",
        ))),
    }
}

fn logged(Refusal { class, path, cause }: Refusal) -> StartError {
    tracing::error!(
        path = %path.display(),
        cause = %cause,
        "config-write startup refused: {class}"
    );
    class
}

fn refuse(class: StartError, path: PathBuf, cause: impl Into<String>) -> Refusal {
    Refusal {
        class,
        path,
        cause: cause.into(),
    }
}

// Creating the lock sidecar is this probe's only write, and that creation is the refusal.
fn probe(configured: &Path) -> Result<PathBuf, Refusal> {
    let target = resolved(configured);
    if no_writer_possible(&target).is_none() {
        let path = lock_path(&target);
        return Err(refuse(
            StartError::ArtifactCheckFailed,
            path,
            "no_writer_possible",
        ));
    }
    for (path, cause) in [
        (journal_path(&target), "journal"),
        (abandoned_path(&target), "abandoned"),
        (retired_path(&target), "retired"),
    ] {
        if !absent(&path) {
            return Err(refuse(StartError::ArtifactCheckFailed, path, cause));
        }
    }
    Ok(target)
}

fn unlocked(configured: PathBuf) -> Result<StartupSession, Refusal> {
    let target = probe(&configured)?;
    Ok(StartupSession {
        state: StartupState::ArtifactFreeUnlocked { configured, target },
    })
}

fn recheck(configured: &Path, target: &Path) -> Result<(), Refusal> {
    let found = probe(configured)?;
    if found.as_path() == target {
        Ok(())
    } else {
        Err(refuse(StartError::ArtifactCheckFailed, found, "resolved"))
    }
}

fn held(locked: Locked, configured: PathBuf, state: Option<JournalV2>) -> StartupSession {
    StartupSession {
        state: StartupState::Locked(Box::new(DrainSession::new(locked, configured, state))),
    }
}

fn open_locked(locked: Locked, configured: PathBuf) -> Result<StartupSession, Refusal> {
    // A retired manifest is evidence this build cannot read yet: refused before any recovery, as
    // the unlocked probe and the sessionless gate refuse it. The abandoned file is the drain's.
    proven_absent(retired_path(&locked.target), StartError::ManifestUnread)?;
    let path = journal_path(&locked.target);
    match dispatch_journal(&locked) {
        Ok(None) => Ok(held(locked, configured, None)),
        Ok(Some(OpenJournal::Legacy(legacy))) => {
            drop(legacy);
            recover_recorded(&locked, &super::startup_recovery_intent)
                .map(|()| held(locked, configured, None))
                .map_err(|why| match why {
                    Unrecovered::Unloadable(why) => {
                        refuse(StartError::UnloadableRecovery, path, why)
                    }
                    Unrecovered::Other(why) => refuse(StartError::JournalPending, path, why),
                })
        }
        Ok(Some(OpenJournal::Current(state))) => match handover_of(&state) {
            // Repair refuses a donor. The file drain's resume finishes a full handover.
            Handover::All => Ok(held(locked, configured, Some(*state))),
            Handover::Partial => Err(refuse(StartError::JournalPending, path, "Partial")),
            Handover::NotHandedOver => {
                let mut session = DrainSession::new(locked, configured, Some(*state));
                match JournalDrain::repair(&mut session, true) {
                    Ok(_) => Ok(StartupSession {
                        state: StartupState::Locked(Box::new(session)),
                    }),
                    Err(other) => {
                        let class = if other == DrainError::RepairPending {
                            StartError::RepairPending
                        } else {
                            StartError::JournalPending
                        };
                        drop(session);
                        Err(refuse(class, path, format!("{other:?}")))
                    }
                }
            }
        },
        Err(error) => Err(refuse(
            StartError::JournalPending,
            path,
            format!("{error:?}"),
        )),
    }
}

// The session drops here, on the worker, including when the caller was cancelled.
async fn drain_locked(mut session: DrainSession, serving: ServingLog) -> Result<(), Refusal> {
    let log = serving.logger();
    let abandoned = abandoned_path(session.target());
    if session
        .journal()
        .is_some_and(|state| handover_of(state) != Handover::All)
    {
        session = match JournalDrain::run(session, log.clone()).await {
            Ok(session) => session,
            Err(failure) => {
                let error = failure.error();
                let cause = format!("{error:?}");
                // Named from the failed session itself; dropping it lets the lock go.
                let journal = journal_path(failure.target());
                drop(failure);
                // `journal_stage` refuses every variant. Ok would skip the file, so it refuses too.
                let class = match journal_stage(error) {
                    Err(class) => class,
                    Ok(()) => StartError::JournalPending,
                };
                return Err(refuse(class, journal, cause));
            }
        };
    }
    let outcome = drain_abandoned(&mut session, log).await.or_else(|error| {
        let cause = format!("{error:?}");
        // No logger accepts the file only when logging is off, never when its open failed.
        if error == DrainError::NoLogger && matches!(serving, ServingLog::Failed) {
            return Err(refuse(
                StartError::AbandonedPending,
                abandoned,
                "log open failed",
            ));
        }
        file_stage(error).map_err(|class| refuse(class, abandoned, cause))
    });
    drop(session);
    outcome
}

#[cfg(tp3)]
#[cfg(test)]
#[path = "startup_settle_tests.rs"]
mod tests;
