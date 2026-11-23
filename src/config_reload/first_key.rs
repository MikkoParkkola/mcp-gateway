// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The first API key on a single-user gateway. A gateway never changes
//! between single-user and multi-user while running (ADR-008); this module is
//! the one place that decides whether a write may still keep a file whose only
//! fault is that change, which a restart then applies.

use super::ReloadOutcome;

/// What the guarded writer does with a candidate whose reload would change
/// the gateway between single-user and multi-user. Every write names one:
/// there is no default, so a caller that could hold bytes is visible here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StatusChange {
    /// Refused before anything is written, as before this module existed.
    Refuse,
}

/// The reload a written replacement ended with.
#[derive(Debug)]
pub(crate) enum ReplaceReload {
    /// The reload accepted the new bytes.
    Applied(ReloadOutcome),
}
