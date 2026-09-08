// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Durable Task store prerequisite. Transport publication is a separate owner.
//!
//! Nothing in production constructs a `PreparedTask` yet: the reviewed
//! `TaskBinding` conversion belongs to the admission owner and the route wiring is
//! a separate slice, so every symbol below is currently reachable only from tests.
//! That produces real dead-code warnings, and they are LEFT VISIBLE on purpose —
//! the static gate for this slice stays open until route integration closes it.
//! Suppressing them here would hide an unfinished integration behind a green gate.

mod record;
mod store;

#[cfg(test)]
mod store_tests;
