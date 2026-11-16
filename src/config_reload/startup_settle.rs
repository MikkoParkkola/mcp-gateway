// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The config-write startup gate: before the gateway serves, settle a dead writer's pending
//! config-write artifacts (the v2 journal, the abandoned file, the retired manifest) under the
//! config lock, or prove without the lock that none can exist.
//!
//! STUB (red phase): today's shape, so the rows fail for the reasons they name. The lock wait
//! blocks the caller's thread, `Busy` is not typed, the probe looks at the journal only, and
//! `finish_start` settles nothing.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config_persistence::CLI_LOCK_WAIT;
use crate::config_persistence::journal::v2::drain::DrainSession;
use crate::config_persistence::lock::{self, NotLocked};
use crate::security::transparency_log::TransparencyLogger;

/// A startup that may go on to load the config: the lock held, or proven unneeded. Not `Clone`.
pub(crate) struct StartupSession {
    state: StartupState,
}

enum StartupState {
    Locked(DrainSession),
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
        match &self.state {
            StartupState::Locked(session) => session.target(),
            StartupState::ArtifactFreeUnlocked { target, .. } => target,
        }
    }
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
    match lock::lock_config_blocking_deferred(config, Instant::now() + wait, |_| {}) {
        Ok(locked) => Ok(StartupSession {
            state: StartupState::Locked(DrainSession::new(locked, configured, None)),
        }),
        Err(NotLocked::Busy) => Err(StartError::ArtifactCheckFailed),
        Err(NotLocked::Failed(_) | NotLocked::Refused(_)) => {
            match lock::no_writer_possible(config) {
                Some(_) if !lock::journal_pending(config) => Ok(StartupSession {
                    state: StartupState::ArtifactFreeUnlocked {
                        target: crate::identity_grants::journal::resolved(config),
                        configured,
                    },
                }),
                _ => Err(StartError::ArtifactCheckFailed),
            }
        }
    }
}

/// Settle what `prepare_start` left owed, with the logger the gateway will serve with (`None`:
/// logging is configured off), then release the lock.
pub(crate) async fn finish_start(
    session: StartupSession,
    log: Option<Arc<TransparencyLogger>>,
) -> Result<(), StartError> {
    drop((session, log));
    Ok(())
}

/// The journal drain's error, as a start refusal.
pub(crate) fn journal_stage(
    error: crate::config_persistence::journal::v2::drain::DrainError,
) -> Result<(), StartError> {
    drop(error);
    Ok(())
}

/// The abandoned-file drain's error, as a start refusal (`NoLogger`: logging off, P6, accepts).
pub(crate) fn file_stage(
    error: crate::config_persistence::journal::v2::drain::DrainError,
) -> Result<(), StartError> {
    drop(error);
    Ok(())
}

#[cfg(test)]
#[path = "startup_settle_tests.rs"]
mod tests;
