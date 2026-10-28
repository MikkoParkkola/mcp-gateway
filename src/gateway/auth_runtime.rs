// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Per-client rate-limit buckets and circuit breakers, kept apart from the
//! resolved key list: one store for the process, shared by every resolved
//! auth config built over it, so a reload that rebuilds the key list does not
//! reset any client's usage or breaker.

/// The shared per-client store (stub: not yet used by the auth config).
#[derive(Debug, Default)]
pub(crate) struct AuthRuntime;

#[cfg(test)]
#[path = "auth_runtime_tests.rs"]
mod tests;
