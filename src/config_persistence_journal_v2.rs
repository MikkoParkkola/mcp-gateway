// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Durable v2 journal state; legacy writers remain on v1 until activation.

#[cfg(test)]
use std::io::Write as _;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::Journal;
use crate::config_persistence::commit::{Action, CommitToken, FileRevision};
use crate::config_persistence::lock::Locked;
use crate::config_persistence::{FileMode, Symlink, sync_dir_of, write_atomic};
use crate::security::transparency_log::identity::LogId;
use crate::security::transparency_log::settle::{Attribution, Reason, Role};

pub(crate) const MAX_JOURNAL_BYTES: usize = 1_048_576;

/// The journal-owned token, distinct from the legacy appender's returned id.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct IntentId(pub(super) String);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ResultClass {
    Written,
    NotWritten,
    Unproven,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TerminalRole {
    Outcome,
    Abandoned,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Decision {
    pub(super) result: ResultClass,
    pub(super) reason: Reason,
    pub(super) settled_by: Option<IntentId>,
    pub(super) terminal: TerminalRole,
    pub(super) delivery_stopped: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ParkReason {
    InvalidPayload,
    ContentConflict,
    ArtifactCorrupt,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FrozenRecord {
    #[serde(
        serialize_with = "codec::role::serialize_ref",
        deserialize_with = "codec::role::deserialize"
    )]
    pub(super) role: Role,
    pub(super) payload_json: Vec<u8>,
    #[serde(
        serialize_with = "codec::attribution::serialize_ref",
        deserialize_with = "codec::attribution::deserialize"
    )]
    pub(super) attribution: Option<Attribution>,
    pub(super) caller_digest: String,
    pub(super) delivered: bool,
    pub(super) parked: Option<ParkReason>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TokenState {
    #[serde(rename = "token")]
    pub(super) intent_id: IntentId,
    pub(super) intent: FrozenRecord,
    pub(super) intent_counter: Option<u64>,
    pub(super) decision: Option<Decision>,
    pub(super) records: Vec<FrozenRecord>,
    pub(super) handed_over: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Pending {
    pub(super) action: Action,
    pub(super) expected: FileRevision,
    pub(super) pre_action: FileRevision,
    pub(super) tried: bool,
}

/// On-disk claims are not `CommitToken`s; `record_fact` requires A's proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Fact {
    Untouched,
    Committed(FileRevision),
    RolledBack(FileRevision),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Phase {
    Intended,
    Staged,
    Accepted,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct JournalV2 {
    pub(super) version: u32,
    pub(super) binding: Option<LogId>,
    pub(super) phase: Phase,
    pub(super) original_revision: Option<FileRevision>,
    pub(super) new_revision: Option<FileRevision>,
    pub(super) pending: Option<Pending>,
    pub(super) fact: Option<Fact>,
    pub(super) writer: Option<TokenState>,
    pub(super) attempts: Vec<TokenState>,
}

#[derive(Debug)]
pub(crate) enum OpenJournal {
    Legacy(Journal),
    Current(Box<JournalV2>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum JournalError {
    Unreadable,
    InvalidState,
    UnsupportedVersion,
    ChangedDecision,
    Persist,
    Finish,
}

pub(crate) fn open(locked: &Locked) -> Result<Option<OpenJournal>, JournalError> {
    let path = super::journal_path(&locked.target);
    let Some(text) =
        crate::config::read_recovery_journal_v2(&path).map_err(|_| JournalError::Unreadable)?
    else {
        return Ok(None);
    };
    match serde_json::from_str::<serde_json::Value>(&text)
        .map_err(|_| JournalError::Unreadable)?["version"].as_u64()
    {
        Some(1) => super::read_checked(&locked.target, &path, &super::original_path(&locked.target))
            .map(|state| state.map(OpenJournal::Legacy))
            .map_err(|_| JournalError::Unreadable),
        Some(2) => JournalV2::decode(text.as_bytes())
            .map(|state| Some(OpenJournal::Current(Box::new(state)))),
        Some(_) => Err(JournalError::UnsupportedVersion),
        None => Err(JournalError::Unreadable),
    }
}

#[cfg(test)]
pub(crate) fn create_intended(
    locked: &Locked,
    state: JournalV2,
) -> Result<JournalSession, JournalError> {
    if state.phase != Phase::Intended
        || state.pending.is_some()
        || state.fact != Some(Fact::Untouched)
    {
        return Err(JournalError::InvalidState);
    }
    let bytes = state.encode()?;
    let path = super::journal_path(&locked.target);
    let scratch = super::beside(&locked.target, ".replace-journal.new");
    let publish = || -> std::io::Result<()> {
        super::remove_if_present(&scratch)?;
        let mut file = super::super::create_new_private(&scratch)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::hard_link(&scratch, &path)
    };
    let result = publish();
    let _ = std::fs::remove_file(&scratch);
    result
        .and_then(|()| sync_dir_of(&path))
        .map_err(|_| JournalError::Persist)?;
    Ok(JournalSession {
        target: locked.target.clone(),
        state,
    })
}

#[derive(Debug)]
pub(crate) struct JournalSession {
    target: PathBuf,
    state: JournalV2,
}

impl JournalSession {
    pub(crate) fn persist(&mut self) -> Result<(), JournalError> {
        let bytes = self.state.encode()?;
        let path = super::journal_path(&self.target);
        write_atomic(&path, &bytes, FileMode::Private, Symlink::Replace)
            .and_then(|()| sync_dir_of(&path))
            .map_err(|_| JournalError::Persist)
    }

    #[cfg(test)]
    pub(crate) fn stage(
        &mut self,
        original: &[u8],
        new_revision: FileRevision,
    ) -> Result<(), JournalError> {
        let original_revision = FileRevision::of(original);
        if self.state.phase != Phase::Intended
            || self.state.pending.is_some()
            || self
                .state
                .original_revision
                .as_ref()
                .is_some_and(|r| r != &original_revision)
        {
            return Err(JournalError::InvalidState);
        }
        super::stage_original(&self.target, original).map_err(|_| JournalError::Persist)?;
        self.state.original_revision = Some(original_revision);
        self.state.new_revision = Some(new_revision);
        self.state.phase = Phase::Staged;
        self.persist()
    }

    pub(crate) fn begin_action(
        &mut self,
        action: Action,
        expected: FileRevision,
    ) -> Result<(), JournalError> {
        let pre_action = self.state.pre_action(action)?.clone();
        if self.state.phase != Phase::Staged
            || self.state.pending.is_some()
            || &expected != self.state.destination(action)?
        {
            return Err(JournalError::InvalidState);
        }
        self.state.pending = Some(Pending {
            action,
            expected,
            pre_action,
            tried: false,
        });
        self.state.fact = None;
        self.persist()
    }

    pub(crate) fn record_fact(
        &mut self,
        action: Action,
        proof: &CommitToken,
    ) -> Result<(), JournalError> {
        let pending = self
            .state
            .pending
            .as_ref()
            .ok_or(JournalError::InvalidState)?;
        if pending.action != action || &pending.expected != proof.revision() {
            return Err(JournalError::InvalidState);
        }
        self.state.fact = Some(match action {
            Action::Forward => Fact::Committed(proof.revision().clone()),
            Action::Restore => Fact::RolledBack(proof.revision().clone()),
        });
        self.state.pending = None;
        self.persist()
    }

    pub(crate) fn decide(
        &mut self,
        token: &IntentId,
        decision: Decision,
    ) -> Result<(), JournalError> {
        let owner = self
            .state
            .writer
            .iter_mut()
            .chain(self.state.attempts.iter_mut())
            .find(|owner| &owner.intent_id == token)
            .ok_or(JournalError::InvalidState)?;
        if let Some(existing) = &owner.decision {
            // Retry the sync too: a prior persist may have failed after rename.
            if existing == &decision {
                return self.persist();
            }
            let mut stopped = existing.clone();
            stopped.delivery_stopped = true;
            if stopped != decision {
                return Err(JournalError::ChangedDecision);
            }
        }
        decision.validate()?;
        owner.decision = Some(decision);
        self.persist()
    }

    pub(crate) fn finish(&mut self) -> Result<(), JournalError> {
        self.state.validate()?;
        if self.state.pending.is_some()
            || self.state.fact.is_none()
            || (matches!(self.state.fact, Some(Fact::Committed(_)))
                && self.state.phase != Phase::Accepted)
            || !self
                .state
                .writer
                .iter()
                .chain(&self.state.attempts)
                .all(|owner| owner.finished(&self.state.attempts))
        {
            return Err(JournalError::Finish);
        }
        super::remove_if_present(&super::original_path(&self.target))
            .map_err(|_| JournalError::Finish)?;
        #[cfg(test)]
        observe::note(&self.target, observe::Event::OriginalUnlinked);
        super::remove_if_present(&super::journal_path(&self.target))
            .map_err(|_| JournalError::Finish)?;
        #[cfg(test)]
        observe::note(&self.target, observe::Event::JournalUnlinked);
        sync_dir_of(&super::journal_path(&self.target)).map_err(|_| JournalError::Finish)?;
        #[cfg(test)]
        observe::note(&self.target, observe::Event::DirectorySynced);
        Ok(())
    }
}

impl JournalV2 {
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, JournalError> {
        codec::decode(bytes)
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, JournalError> {
        self.validate()?;
        codec::encode(self)
    }

    fn pre_action(&self, action: Action) -> Result<&FileRevision, JournalError> {
        match action {
            Action::Forward => &self.original_revision,
            Action::Restore => &self.new_revision,
        }
        .as_ref()
        .ok_or(JournalError::InvalidState)
    }

    fn destination(&self, action: Action) -> Result<&FileRevision, JournalError> {
        match action {
            Action::Forward => &self.new_revision,
            Action::Restore => &self.original_revision,
        }
        .as_ref()
        .ok_or(JournalError::InvalidState)
    }

    fn validate(&self) -> Result<(), JournalError> {
        if self.version != 2 {
            return Err(JournalError::UnsupportedVersion);
        }
        if (self.pending.is_some() && self.fact.is_some())
            || (self.phase == Phase::Accepted
                && (self.new_revision.is_none()
                    || self.fact != self.new_revision.clone().map(Fact::Committed)))
            || (self.binding.is_none() && (self.writer.is_some() || !self.attempts.is_empty()))
        {
            return Err(JournalError::InvalidState);
        }
        if let Some(pending) = &self.pending
            && (&pending.pre_action != self.pre_action(pending.action)?
                || &pending.expected != self.destination(pending.action)?)
        {
            return Err(JournalError::InvalidState);
        }
        let fact_matches = match &self.fact {
            Some(Fact::Committed(r)) => Some(r) == self.new_revision.as_ref(),
            Some(Fact::RolledBack(r)) => Some(r) == self.original_revision.as_ref(),
            _ => true,
        };
        if !fact_matches {
            return Err(JournalError::InvalidState);
        }
        let mut tokens = std::collections::HashSet::new();
        for owner in self.writer.iter().chain(&self.attempts) {
            if !tokens.insert(owner.intent_id.0.as_str()) {
                return Err(JournalError::InvalidState);
            }
            if let Some(decision) = &owner.decision {
                decision.validate()?;
            }
            let mut deferred = owner.records.iter().filter(|r| r.role == Role::Deferred);
            if let Some(first) = deferred.next()
                && !deferred.all(|r| r.same_content(first))
            {
                return Err(JournalError::InvalidState);
            }
        }
        Ok(())
    }
}

impl Decision {
    fn validate(&self) -> Result<(), JournalError> {
        let valid = match self.terminal {
            TerminalRole::Outcome => match self.result {
                ResultClass::Written => matches!(
                    self.reason,
                    Reason::Committed | Reason::RolledBack | Reason::KeptNew
                ),
                ResultClass::NotWritten => matches!(
                    self.reason,
                    Reason::RolledBack
                        | Reason::NothingPending
                        | Reason::DeletedDuringCompute
                        | Reason::ComputeRefused
                        | Reason::SecretsRefused
                        | Reason::WriterDied
                        | Reason::Panicked
                        | Reason::OperatorAbandoned
                        | Reason::Moved
                        | Reason::Refused
                ),
                ResultClass::Unproven => false,
            },
            // `settled_by` belongs to an outcome alone: an abandoned terminal cannot carry it, so
            // a decision that names one could never be matched by its terminal and never finish.
            TerminalRole::Abandoned => {
                matches!(self.result, ResultClass::NotWritten | ResultClass::Unproven)
                    && self.reason == Reason::Abandoned
                    && self.settled_by.is_none()
            }
        };
        if valid {
            Ok(())
        } else {
            Err(JournalError::InvalidState)
        }
    }
}

impl TokenState {
    fn finished(&self, attempts: &[TokenState]) -> bool {
        if self.intent.parked.is_some() || self.records.iter().any(|r| r.parked.is_some()) {
            return false;
        }
        if self.handed_over {
            return true;
        }
        let Some(decision) = &self.decision else {
            return false;
        };
        let terminal = match decision.terminal {
            TerminalRole::Outcome => Role::Outcome,
            TerminalRole::Abandoned => Role::Abandoned,
        };
        let mut terminals = self
            .records
            .iter()
            .filter(|r| matches!(r.role, Role::Outcome | Role::Abandoned));
        let Some(first) = terminals.next() else {
            return false;
        };
        // Retries collapse by frozen content, never by delivery state or digest alone.
        if first.role != terminal
            || !codec::terminal_matches(first, decision, self, attempts)
            || !terminals.all(|r| r.role == terminal && r.same_content(first))
        {
            return false;
        }
        self.intent.delivered
            && self.intent_counter.is_some()
            && self.records.iter().all(|r| r.delivered)
            && (!decision.delivery_stopped
                || self.records.iter().any(|r| r.role == Role::DeliveryStopped))
    }
}

impl FrozenRecord {
    fn same_content(&self, other: &Self) -> bool {
        self.payload_json == other.payload_json
            && self.attribution == other.attribution
            && self.caller_digest == other.caller_digest
    }
}

#[path = "config_persistence_journal_v2_codec.rs"]
mod codec;

#[cfg(test)]
#[path = "config_persistence_journal_v2_codec_tests.rs"]
mod codec_tests;
#[cfg(test)]
#[path = "config_persistence_journal_v2_fixtures_tests.rs"]
mod fixtures;
#[cfg(test)]
#[path = "config_persistence_journal_v2_observe_tests.rs"]
mod observe;
#[cfg(test)]
#[path = "config_persistence_journal_v2_state_tests.rs"]
mod state_tests;
