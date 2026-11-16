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
use crate::config_persistence::{CLI_LOCK_WAIT, recover_recorded};
use crate::identity_grants::journal::resolved;
use crate::security::transparency_log::TransparencyLogger;

/// A startup that may go on to load the config: the lock held, or proven unneeded. Not `Clone`.
pub(crate) struct StartupSession {
    state: StartupState,
    // The caller's path: DrainSession keeps its copy private, so a re-resolve has to live here.
    configured: PathBuf,
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
        })
    }
}

impl StartupSession {
    /// The resolved config the gate checked. The caller loads the config, and derives the serving
    /// logger, from this path only.
    pub(crate) fn target(&self) -> &Path {
        // Cloned on both builds so the field is read when the re-resolve arm is compiled out.
        // Only the on-arm follows the path again; the off-arm still returns the held target.
        let configured = self.configured.clone();
        let _ = configured.as_os_str();
        match &self.state {
            StartupState::Locked(session) => mutant!("g26", {
                let path: &Path = Box::leak(resolved(&configured).into_boxed_path());
                path
            }, session.target()),
            StartupState::ArtifactFreeUnlocked { target, .. } => mutant!("g26", {
                let path: &Path = Box::leak(resolved(&configured).into_boxed_path());
                path
            }, target),
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
    let deadline = Instant::now() + wait;
    match mutant!("g5",
        crate::config_persistence::lock::lock_config_blocking_deferred(config, deadline, |_| {}),
        lock_config_deferred(config, deadline).await,
    ) {
        Err(NotLocked::Busy) => mutant!("g1", Err(logged(refuse(StartError::ArtifactCheckFailed, named, "Busy"))), Err(logged(refuse(StartError::Busy, named, "Busy")))),
        Err(NotLocked::Failed(_) | NotLocked::Refused(_)) => {
            from_worker(named, move || unlocked(configured)).await
        }
        Ok(locked) => mutant!("g41",
            match open_locked(locked, configured) {
                Ok(value) => Ok(value),
                Err(Refusal { class, .. }) => Err(class),
            },
            from_worker(named, move || open_locked(locked, configured)).await),
    }
}

/// Settle what `prepare_start` left owed, with the logger the gateway will serve with (`None`:
/// logging is configured off), then release the lock.
pub(crate) async fn finish_start(
    session: StartupSession,
    log: Option<Arc<TransparencyLogger>>,
) -> Result<(), StartError> {
    let named = session.target().to_path_buf();
    match session.state {
        StartupState::ArtifactFreeUnlocked { configured, target } => {
            from_worker(named, move || mutant!("g9", Ok(()), recheck(&configured, &target))).await
        }
        StartupState::Locked(session) => {
            // Captured on the caller: the worker is not inside a runtime until `block_on`.
            let handle = tokio::runtime::Handle::current();
            mutant!("g27",
                match handle.clone().block_on(drain_locked(*session, log)) {
                    Ok(()) => Ok(()),
                    Err(Refusal { class, .. }) => Err(class),
                },
                from_worker(named, move || handle.block_on(drain_locked(*session, log))).await)
        }
    }
}

/// The journal drain's error, as a start refusal.
pub(crate) fn journal_stage(error: DrainError) -> Result<(), StartError> {
    match error {
        DrainError::NoLogger => mutant!("g11", Ok(()), Err(StartError::JournalPending)),
        DrainError::OtherLog => mutant!("g23", Ok(()), Err(StartError::JournalPending)),
        DrainError::Journal => mutant!("g32", Ok(()), Err(StartError::JournalPending)),
        DrainError::Refused => mutant!("g29", Ok(()), Err(StartError::JournalPending)),
        DrainError::Unconfirmed => mutant!("g30", Ok(()), Err(StartError::JournalPending)),
        DrainError::Finish => mutant!("g31", Ok(()), Err(StartError::JournalPending)),
        DrainError::FileRefused => mutant!("g33", Ok(()), Err(StartError::JournalPending)),
        DrainError::RepairPending => mutant!("g34", Ok(()), Err(StartError::RepairPending)),
        DrainError::Parked => mutant!("g24", Err(StartError::JournalPending), Err(StartError::InvalidAuditPayload)),
    }
}

/// The abandoned-file drain's error, as a start refusal (`NoLogger`: logging off, P6, accepts).
pub(crate) fn file_stage(error: DrainError) -> Result<(), StartError> {
    match error {
        DrainError::NoLogger => mutant!("g13", Err(StartError::AbandonedPending), Ok(())),
        DrainError::Parked => mutant!("g15", Err(StartError::AbandonedPending), Err(StartError::InvalidAuditPayload)),
        DrainError::OtherLog => mutant!("g12", Ok(()), Err(StartError::AbandonedPending)),
        DrainError::FileRefused => mutant!("g16", Ok(()), Err(StartError::AbandonedPending)),
        DrainError::Journal => mutant!("g35", Ok(()), Err(StartError::AbandonedPending)),
        DrainError::Refused => mutant!("g36", Ok(()), Err(StartError::AbandonedPending)),
        DrainError::Unconfirmed => mutant!("g37", Ok(()), Err(StartError::AbandonedPending)),
        DrainError::Finish => mutant!("g38", Ok(()), Err(StartError::AbandonedPending)),
        DrainError::RepairPending => mutant!("g39", Ok(()), Err(StartError::AbandonedPending)),
    }
}

// Stalled retries. Lost proves nothing about the artifacts. Every refusal, these included, is logged
// once on the caller with a path and its cause; `path` names the config for the two no-result causes.
async fn from_worker<T: Send + 'static>(
    path: PathBuf,
    work: impl FnOnce() -> Result<T, Refusal> + Send + 'static,
) -> Result<T, StartError> {
    match off_runtime(work).await {
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
    if mutant!("g4", false, no_writer_possible(&target).is_none()) {
        let path = lock_path(&target);
        return Err(refuse(
            StartError::ArtifactCheckFailed,
            path,
            "no_writer_possible",
        ));
    }
    for (path, cause) in [
        (mutant!("g22", target.join(".not-the-journal"), journal_path(&target)), "journal"),
        (mutant!("g2", target.join(".not-the-abandoned"), abandoned_path(&target)), "abandoned"),
        (mutant!("g3", target.join(".not-the-retired"), retired_path(&target)), "retired"),
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
        state: StartupState::ArtifactFreeUnlocked {
            configured: configured.clone(),
            target,
        },
        configured,
    })
}

fn recheck(configured: &Path, target: &Path) -> Result<(), Refusal> {
    let found = probe(configured)?;
    if mutant!("g25", true, found.as_path() == target) {
        Ok(())
    } else {
        Err(refuse(StartError::ArtifactCheckFailed, found, "resolved"))
    }
}

fn held(locked: Locked, configured: PathBuf, state: Option<JournalV2>) -> StartupSession {
    StartupSession {
        state: StartupState::Locked(Box::new(DrainSession::new(locked, configured.clone(), state))),
        configured,
    }
}

fn open_locked(locked: Locked, configured: PathBuf) -> Result<StartupSession, Refusal> {
    let path = journal_path(&locked.target);
    match dispatch_journal(&locked) {
        Ok(None) => Ok(held(locked, configured, None)),
        Ok(Some(OpenJournal::Legacy(legacy))) => {
            drop(legacy);
            if mutant!("g7", true, false) {
                return Ok(held(locked, configured, None));
            }
            // The `?` that stops recovery lives inside recover_recorded, not here. Calling
            // journal::recover directly is a record failure that cannot refuse.
            mutant!("g21",
                crate::config_persistence::journal::recover(&locked.target)
                    .map(|_| ())
                    .map_err(|why| format!("{why:?}")),
                recover_recorded(
                    &locked,
                    mutant!("g20",
                        &((|_: &Locked, _: &crate::config::Config| Ok::<(), String>(()))
                            as fn(&Locked, &crate::config::Config) -> Result<(), String>),
                        &(super::startup_recovery_intent
                            as fn(&Locked, &crate::config::Config) -> Result<(), String>),
                    ),
                ),
            )
            .map(|()| held(locked, configured, None))
            .map_err(|why| refuse(StartError::JournalPending, path, why))
        }
        Ok(Some(OpenJournal::Current(state))) => match mutant!("g28", {
            // Vacuous-All: JournalV2's token fields are pub(super). Debug is the readable form.
            let shown = format!("{state:?}");
            if shown.contains("writer: None") && shown.contains("attempts: []") {
                Handover::All
            } else {
                handover_of(&state)
            }
        }, handover_of(&state)) {
            // Repair refuses a donor. The file drain's resume finishes a full handover.
            Handover::All => mutant!("g8", {
                let mut session = DrainSession::new(locked, configured.clone(), Some(*state));
                let repaired = JournalDrain::repair(&mut session, true);
                match repaired {
                    Ok(_) => Ok(StartupSession {
                        state: StartupState::Locked(Box::new(session)),
                        configured,
                    }),
                    Err(other) => {
                        // A donor refuses here, before any write.
                        let class = if other == DrainError::RepairPending {
                            StartError::RepairPending
                        } else {
                            StartError::JournalPending
                        };
                        drop(session);
                        Err(refuse(class, path.clone(), format!("{other:?}")))
                    }
                }
            }, Ok(held(locked, configured, Some(*state)))),
            Handover::Partial => mutant!("g19",
                Ok(held(locked, configured, Some(*state))),
                Err(refuse(StartError::JournalPending, path, "Partial")),
            ),
            Handover::NotHandedOver => {
                let mut session = DrainSession::new(locked, configured.clone(), Some(*state));
                if mutant!("g6", true, false) {
                    return Ok(StartupSession {
                        state: StartupState::Locked(Box::new(session)),
                        configured,
                    });
                }
                match JournalDrain::repair(&mut session, true) {
                    Ok(_) => Ok(StartupSession {
                        state: StartupState::Locked(Box::new(session)),
                        configured,
                    }),
                    Err(other) => {
                        if mutant!("g40", other != DrainError::RepairPending, false) {
                            return Ok(StartupSession {
                                state: StartupState::Locked(Box::new(session)),
                                configured,
                            });
                        }
                        let class = if mutant!("g14", false, other == DrainError::RepairPending) {
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
        Err(error) => mutant!("g17",
            Ok(held(locked, configured, None)),
            Err(refuse(
                StartError::JournalPending,
                path,
                format!("{error:?}"),
            )),
        ),
    }
}

// The session drops here, on the worker, including when the caller was cancelled.
async fn drain_locked(
    mut session: DrainSession,
    log: Option<Arc<TransparencyLogger>>,
) -> Result<(), Refusal> {
    let journal = journal_path(session.target());
    let abandoned = abandoned_path(session.target());
    if session
        .journal()
        .is_some_and(|state| handover_of(state) != Handover::All)
    {
        session = match mutant!("g10", Ok(session), JournalDrain::run(session, log.clone()).await) {
            Ok(session) => session,
            Err(failure) => {
                let error = failure.error();
                let cause = format!("{error:?}");
                drop(failure);
                // `journal_stage` refuses every variant. Ok would skip the file, so it refuses too.
                let class = match journal_stage(error) {
                    Err(class) => class,
                    Ok(()) => mutant!("g11", return Ok(()), mutant!("g23", return Ok(()), StartError::JournalPending)),
                };
                return Err(refuse(class, journal, cause));
            }
        };
    }
    let outcome = mutant!("g18", Ok(()), drain_abandoned(&mut session, log).await.or_else(|error| {
        let cause = format!("{error:?}");
        file_stage(error).map_err(|class| refuse(class, abandoned, cause))
    }));
    drop(session);
    outcome
}

#[cfg(test)]
#[path = "startup_settle_tests.rs"]
mod tests;
