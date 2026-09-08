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

mod alloc_meter;
mod signing_nonce_allocations;
mod signing_nonce_allocations_support;

mod signing_stdio_routing;
