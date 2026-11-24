// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! CLI login, server side: the attempt store and its rate limits. Nothing
//! calls them yet; the cli-login routes that will are a later change.
#![allow(
    dead_code,
    reason = "internal until the cli-login routes call it; that change removes this"
)]

pub(crate) mod attempts;
pub(crate) mod limits;

#[cfg(tp3)]
#[cfg(test)]
mod attempts_tests;
#[cfg(tp3)]
#[cfg(test)]
mod limits_tests;
