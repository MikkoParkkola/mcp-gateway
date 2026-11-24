// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The startup gate's fixed refusal sentences and its drain-error mapping, kept apart from the
//! gate's disk rows so each file stays under the size ceiling.

use super::*;

/// GATE.2, GATE.4: each `StartError` displays its one fixed sentence.
#[test]
fn start_error_texts() {
    for error in [
        StartError::Busy,
        StartError::RepairPending,
        StartError::JournalPending,
        StartError::AbandonedPending,
        StartError::InvalidAuditPayload,
        StartError::ArtifactCheckFailed,
        StartError::UnloadableRecovery,
    ] {
        let sentence = match error {
            StartError::Busy => {
                "Another gateway or command holds the config lock past the 30-second wait. Start again when it has finished."
            }
            StartError::RepairPending => {
                "A config write that crashed left the config in a state its journal could neither confirm nor restore. Compare the config with the revisions the journal records before changing anything, then start again."
            }
            StartError::JournalPending => {
                "A config write's journal beside the config still owes audit records to the log it was bound to. Start with that audit log configured and reachable."
            }
            StartError::AbandonedPending => {
                "The abandoned config-write file beside the config holds audit records this gateway cannot deliver. Configure the log it names, or move the file aside by hand to keep it as evidence."
            }
            StartError::InvalidAuditPayload => {
                "The audit log refused a pending config-write record as invalid. The record is parked and kept as evidence, and it needs an operator's decision before this gateway can start."
            }
            StartError::ArtifactCheckFailed => {
                "This gateway could not confirm that no config write is pending beside the config. Fix access to the config directory, then start again."
            }
            StartError::UnloadableRecovery => {
                "Nothing was recovered: the config a crashed write would restore does not load."
            }
            // Not in the list above: the sessionless constructor rows pin these two in full.
            StartError::RecoveryPending | StartError::ManifestUnread => {
                unreachable!("start_error_texts: {error:?} is pinned by the sessionless rows")
            }
        };
        assert_eq!(
            error.to_string(),
            sentence,
            "start_error_texts: {error:?} displays its sentence"
        );
    }
}

/// GATE.4: every `DrainError` variant maps to that stage's literal result.
#[test]
fn stage_maps_every_drain_error() {
    let pending = Err(StartError::JournalPending);
    let abandoned = Err(StartError::AbandonedPending);
    let repair = Err(StartError::RepairPending);
    let invalid = Err(StartError::InvalidAuditPayload);
    for error in [
        DrainError::Journal,
        DrainError::RepairPending,
        DrainError::NoLogger,
        DrainError::OtherLog,
        DrainError::Refused,
        DrainError::Unconfirmed,
        DrainError::Parked,
        DrainError::Finish,
        DrainError::FileRefused,
    ] {
        let (journal, file) = match error {
            DrainError::NoLogger => (pending, Ok(())),
            DrainError::RepairPending => (repair, abandoned),
            DrainError::Parked => (invalid, invalid),
            DrainError::Journal
            | DrainError::OtherLog
            | DrainError::Refused
            | DrainError::Unconfirmed
            | DrainError::Finish
            | DrainError::FileRefused => (pending, abandoned),
        };
        let row = "stage_maps_every_drain_error";
        assert_eq!(journal_stage(error), journal, "{row}: journal {error:?}");
        assert_eq!(file_stage(error), file, "{row}: file {error:?}");
    }
}
