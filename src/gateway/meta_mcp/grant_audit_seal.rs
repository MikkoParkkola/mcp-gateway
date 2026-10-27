// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A1: the grant slot is written and sealed before the answer's delivery
//! record. A failed write then refuses the answer before its record, not
//! after it, and a decision noted after the seal is refused (-32005) rather
//! than queued for the slot's close, where its failed write would replace an
//! answer already recorded. The seal is set and read under the `notes` lock,
//! so no note slips in between.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use super::{GRANT_SLOT, GrantNote, Slot, spawn_write, write_owned};
use crate::security::TransparencyLogger;
use crate::{Error, Result};

/// Write every decision the open slot holds, then seal it. Outside a slot
/// there is nothing to write or seal.
pub(crate) async fn seal_open_slot() -> Result<()> {
    let Ok((logger, notes)) = GRANT_SLOT.try_with(|slot| {
        // invariant: nothing panics while holding the slot lock, so it is never poisoned.
        let mut held = slot.notes.lock().expect("grant slot lock");
        slot.sealed.store(true, Ordering::SeqCst);
        (Arc::clone(&slot.logger), std::mem::take(&mut *held))
    }) else {
        return Ok(());
    };
    if notes.is_empty() {
        return Ok(());
    }
    write_owned(&logger, notes).await
}

/// Put `note` in `slot` unless it is sealed; `false` when sealed.
pub(super) fn note_unless_sealed(slot: &Slot, note: &GrantNote) -> bool {
    // invariant: nothing panics while holding the slot lock, so it is never poisoned.
    let mut notes = slot.notes.lock().expect("grant slot lock");
    if slot.sealed.load(Ordering::SeqCst) {
        return false;
    }
    notes.push(note.clone());
    true
}

/// A decision past the answer's record: refused, and still written.
pub(super) fn refuse_late(
    logger: &Arc<TransparencyLogger>,
    (server, tool): (&str, &str),
    note: GrantNote,
) -> Result<()> {
    tracing::error!(
        server,
        tool,
        "grant decision after the answer's record; refused"
    );
    spawn_write(logger, vec![note]);
    Err(Error::AuditUnavailable)
}
