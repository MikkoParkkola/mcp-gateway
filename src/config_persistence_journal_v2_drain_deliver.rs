// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Delivery to the log: every intent first, then the owed terminals frozen, then every record,
//! each persisted before the next is sent; a record the log refuses is parked.

#[cfg(test)]
use std::path::Path;

use super::super::{IntentId, JournalSession, ParkReason};
use super::decide::{freeze_records, owner_mut};
#[cfg(test)]
use super::fault;
use super::{Delivery, DrainError, SettleSink};
use crate::security::transparency_log::identity::LogId;
#[cfg(test)]
use crate::security::transparency_log::settle::Role;
use crate::security::transparency_log::settle::Unsettled;

/// Every intent first, then the owed terminals frozen, then every record: the one delivery order,
/// for the journal and for the abandoned file.
pub(super) async fn deliver_all(
    journal: &mut JournalSession,
    sink: &dyn SettleSink,
    binding: &LogId,
) -> Result<(), DrainError> {
    let owners: Vec<_> = journal
        .state
        .writer
        .iter()
        .chain(&journal.state.attempts)
        .map(|owner| owner.intent_id.clone())
        .collect();
    for token in &owners {
        send_record(journal, sink, binding, token, None).await?;
    }
    // Counters are now acknowledged; freeze only missing caller payloads.
    freeze_records(journal)?;
    let terminal_order: Vec<_> = journal
        .state
        .attempts
        .iter()
        .chain(journal.state.writer.iter())
        .map(|owner| owner.intent_id.clone())
        .collect();
    for token in terminal_order {
        let count = owner_mut(journal, &token)?.records.len();
        for index in 0..count {
            send_record(journal, sink, binding, &token, Some(index)).await?;
        }
    }
    Ok(())
}

async fn send_record(
    journal: &mut JournalSession,
    sink: &dyn SettleSink,
    binding: &LogId,
    token: &IntentId,
    index: Option<usize>,
) -> Result<(), DrainError> {
    let owner = owner_mut(journal, token)?;
    let record = match index {
        Some(index) => &owner.records[index],
        None => &owner.intent,
    };
    if record.parked.is_some() {
        return Err(DrainError::Parked);
    }
    if record.delivered {
        return Ok(());
    }
    let Ok(payload) = serde_json::from_slice(&record.payload_json) else {
        return park_record(journal, token, index, ParkReason::ArtifactCorrupt);
    };
    let delivery = Delivery {
        binding: binding.clone(),
        token: token.clone(),
        role: record.role,
        payload,
        attribution: record.attribution.clone(),
    };
    #[cfg(test)]
    super::super::observe::note(&journal.target, super::super::observe::Event::BStarted);
    let appended = sink.settle(&delivery).await;
    let receipt = match appended {
        Ok(receipt) if receipt.id == *binding => receipt,
        Ok(_) | Err(Unsettled::OtherLog) => return Err(DrainError::OtherLog),
        Err(Unsettled::Refused(_)) => return Err(DrainError::Refused),
        Err(Unsettled::Unconfirmed(_)) => return Err(DrainError::Unconfirmed),
        Err(Unsettled::Invalid(_)) => {
            #[cfg(test)]
            super::super::observe::note(&journal.target, super::super::observe::Event::BInvalid);
            return park_record(journal, token, index, ParkReason::InvalidPayload);
        }
    };
    #[cfg(test)]
    appended_boundary(&journal.target, delivery.role)?;
    let owner = owner_mut(journal, token)?;
    if let Some(index) = index {
        owner.records[index].delivered = true;
    } else {
        owner.intent_counter.get_or_insert(receipt.counter);
        owner.intent.delivered = true;
    }
    journal.persist().map_err(|_| DrainError::Journal)?;
    #[cfg(test)]
    super::super::observe::note(&journal.target, super::super::observe::Event::FlagSynced);
    #[cfg(test)]
    if delivery.role == Role::Deferred {
        fault::hit(&journal.target, fault::At::DeferredFlagged).map_err(|_| DrainError::Journal)?;
    }
    Ok(())
}

fn park_record(
    journal: &mut JournalSession,
    token: &IntentId,
    index: Option<usize>,
    reason: ParkReason,
) -> Result<(), DrainError> {
    let owner = owner_mut(journal, token)?;
    let record = match index {
        Some(index) => &mut owner.records[index],
        None => &mut owner.intent,
    };
    record.parked = Some(reason);
    journal.persist().map_err(|_| DrainError::Journal)?;
    Err(DrainError::Parked)
}

#[cfg(test)]
fn appended_boundary(target: &Path, role: Role) -> Result<(), DrainError> {
    let at = match role {
        Role::Intent(_) | Role::RecoveryIntent => fault::At::IntentAppended,
        Role::Outcome | Role::Abandoned => fault::At::OutcomeAppended,
        _ => return Ok(()),
    };
    // The fault registry observes armed hits; ordinary runs still observe the boundary.
    let before = fault::fired(target);
    fault::hit(target, at).map_err(|_| DrainError::Journal)?;
    if fault::fired(target) == before {
        super::super::observe::note(target, fault::event(at));
    }
    Ok(())
}
