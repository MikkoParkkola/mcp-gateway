// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The first API key on a single-user gateway. A gateway never changes
//! between single-user and multi-user while running (ADR-008); this module is
//! the one place that decides whether a write may still keep a file whose only
//! fault is that change, which a restart then applies.

use super::{Generation, ReloadOutcome};
use crate::config::{Config, EnvOverlay};

/// What the guarded writer does with a candidate whose reload would change
/// the gateway between single-user and multi-user. Every write names one:
/// there is no default, so a caller that could hold bytes is visible here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StatusChange {
    /// Refused before anything is written, as before this module existed.
    Refuse,
    /// Kept on disk for the next start when the candidate only waits for a
    /// restart (see [`waiting_first_key`]); the first-key create alone.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "the create route passes it once the hold lands")
    )]
    HoldForRestart,
}

/// The reload a written replacement ended with.
#[derive(Debug)]
pub(crate) enum ReplaceReload {
    /// The reload accepted the new bytes.
    Applied(ReloadOutcome),
    /// The reload refused the bytes only for the status change; they stay on
    /// disk and a restart applies them. `keys` are the waiting keys' names.
    #[expect(dead_code, reason = "the writer answers it once the hold lands")]
    HeldForRestart { refusal: String, keys: Vec<String> },
}

/// Whether a candidate is a first key that only a restart can apply.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "asked by the writer once the hold lands")
)]
pub(crate) enum Waiting {
    /// The status rule accepts the candidate.
    No,
    /// The status rule refuses it, it adds keys the running table lacks, those
    /// keys build, and a start from it is not refused. Never empty.
    Yes { keys: Vec<String> },
    /// The status rule refuses it and some other check fails as well; the text
    /// is that check's own.
    Faulty { reason: String },
}

/// The one question every writer, reload and route asks about a candidate.
#[expect(
    unused_variables,
    reason = "answered for real once the first-key hold lands"
)]
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "asked by the writer once the hold lands")
)]
pub(crate) fn waiting_first_key(
    running: &Config,
    published: &Generation,
    candidate: &Config,
    overlay: &EnvOverlay,
) -> Waiting {
    Waiting::No
}
