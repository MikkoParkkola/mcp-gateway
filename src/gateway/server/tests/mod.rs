// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Server-module tests that need more than one file.
//!
//! Existing server tests are flat siblings (`http_lifecycle_tests`,
//! `test_support`). This directory exists because the allocation checkpoint
//! needs three files that only make sense together: the meter, the fixture and
//! the oracles.
//!
//! Loaded by `server/mod.rs` as `#[cfg(test)] #[path = "tests/mod.rs"] mod
//! signing_allocation_tests;` — the name `tests` is already taken by the inline
//! test module further down that file.

mod admission_allocations;
mod alloc_meter;
mod input_key_allocations;
mod signing_nonce_allocations;
mod signing_nonce_allocations_support;
mod visibility_allocations;
mod visibility_reload_race;

mod signing_stdio_routing;

mod dispatcher_admission_arms;
#[cfg(feature = "metrics")]
mod unkeyed_admission;

mod stdout_death_admission;

mod r2_stdio_keys;
mod stdio_listing_scope;

mod stdio_initialize_order;

mod stdio_sole_operator;

mod stdio_catalogue_sole_operator;

#[cfg(feature = "cost-governance")]
mod stdio_cost_persistence;

#[cfg(feature = "cost-governance")]
mod http_cost_persistence;
