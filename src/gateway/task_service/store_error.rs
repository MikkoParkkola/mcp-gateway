// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The task store's error type, split out of `store.rs` for the 800-line
//! ceiling (MIK-8202 P4b). Re-exported there, so every `store::StoreError`
//! path keeps working.

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum StoreError {
    #[error("task store unavailable")]
    Unavailable,
    #[error("unsafe task store")]
    UnsafeStore,
    /// The store directory or lease could not be inspected (not absent, not
    /// unsafe): a failure to look, distinct from `Unavailable`.
    #[error("task store path could not be inspected")]
    Uninspectable,
    #[error("corrupt task record")]
    CorruptRecord,
    #[error("task store is already owned")]
    AlreadyOwned,
    #[error("task not found")]
    NotFound,
    #[error("task revision changed")]
    RevisionConflict,
    #[error("task capacity exceeded")]
    Capacity,
    #[error("task storage operation failed")]
    Storage,
    /// The model refused the offered event, whether as a malformed payload or as
    /// an illegal transition. Nothing was serialized and nothing was written.
    #[error("invalid task transition")]
    InvalidTransition,
    /// The offered record reuses a live task identifier or admission identity.
    /// Writing it would replace a task or leave a store the loader will reject.
    #[error("duplicate task record")]
    Duplicate,
    /// The store clock reads before 1970, so a claim that needs a time
    /// cannot be dated (MIK-8202 P4b). Distinct from `Unavailable`: an
    /// upstream-cancel sender writes its claim undated instead of parking
    /// it in memory.
    #[error("task store clock unreadable")]
    ClockUnreadable,
}
