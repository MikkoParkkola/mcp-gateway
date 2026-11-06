// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The best-effort write of a withheld surfaced call's own grant decision.

/// The one warning a failed best-effort withheld record logs (the withheld surfaced
/// call's record); the upgrade note tells operators to alert on it.
pub(in crate::gateway::meta_mcp) const WITHHELD_RECORD_FAILED: &str = "The audit record of a withheld surfaced call could not be written; \
     the call is answered as a name that matches no tool";

/// The `FailClosed` exception for the withheld surfaced
/// call's own grant record ONLY: run `noting`, then move the decisions it
/// noted out of the slot's fail-closed notes into its best-effort list and
/// return at once. The slot opener writes that list after the wrapped work
/// returns (so after the call's own invocation append), on its own task; a
/// failed write logs [`WITHHELD_RECORD_FAILED`] and never becomes the
/// request's verdict (under `FailClosed` it would answer -32005 and reveal the
/// name exists). No caller waits for the write. Every note added before
/// `noting` stays in the slot and fails closed as before. Outside a slot
/// `noting` runs alone and its note is written at once. Any other use is a
/// new exception and needs its own design decision.
pub(in crate::gateway::meta_mcp) async fn note_withheld_best_effort<T>(
    _server: &str,
    noting: impl FnOnce() -> T,
) -> T {
    // invariant: nothing panics while holding the slot lock, so it is never poisoned.
    let before = super::GRANT_SLOT
        .try_with(|slot| slot.notes.lock().expect("grant slot lock").len())
        .ok();
    let output = noting();
    let _ = before.map(|before| {
        super::GRANT_SLOT.try_with(|slot| {
            // invariant: nothing panics while holding the slot lock, so it is never poisoned.
            let mut held = slot.notes.lock().expect("grant slot lock");
            let at = before.min(held.len());
            let taken = held.split_off(at);
            drop(held);
            // invariant: nothing panics while holding the slot lock, so it is never poisoned.
            slot.best_effort
                .lock()
                .expect("grant slot lock")
                .extend(taken);
        })
    });
    output
}
