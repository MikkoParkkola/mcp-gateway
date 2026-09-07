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
//!
//! `model` is package-local on this base. The snapshots this package was
//! qualified against carried the flat Tasks model at `crate::protocol::tasks`,
//! where this checkout still holds the older routed model that
//! `protocol::task_store` and the `tasks/*` route handlers are written against.
//! Promoting the flat model over that name would rewrite a live route surface
//! this slice does not own, so it lands here verbatim and the two models are
//! reconciled by the route slice that adopts one of them.

mod model;
mod record;
mod store;

#[cfg(test)]
mod store_tests;

mod service;

#[cfg(test)]
mod service_tests;
