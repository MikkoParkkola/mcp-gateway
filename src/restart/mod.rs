// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! In-place restart's process side (restart slice 4): the invocation
//! a restart re-execs. Everything here is crate-private: no embedder entry can
//! reach it.

pub(crate) mod invocation;

#[cfg(test)]
#[path = "invocation_tests.rs"]
mod invocation_tests;
