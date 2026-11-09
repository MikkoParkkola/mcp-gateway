// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The command plan (ADR-027): whether a typed command fetches a registry
//! package before it runs. `npx` and `uvx` fetch exactly one npm or PyPI
//! package named by a plain registry spec; any other program runs as typed.
#![cfg_attr(
    not(test),
    expect(dead_code, reason = "the Linux fetch step, a later part, calls plan")
)]

use std::ffi::OsString;

use super::{Refusal, Target};

/// The package a preview fetches before its run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Fetch {
    /// An npm spec: `name` or `@scope/name`, optional `@version`.
    Npm(String),
    /// A PyPI spec: a name, optional `==version`.
    Uv(String),
}

/// A typed command split into its phases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Phases {
    pub(crate) fetch: Option<Fetch>,
    /// The server's own arguments, after the spec.
    pub(crate) run_args: Vec<OsString>,
}

/// Split `target` into its fetch and run phases.
pub(crate) fn plan(target: &Target) -> Result<Phases, Refusal> {
    Ok(Phases {
        fetch: None,
        run_args: target.args.clone(),
    })
}

#[cfg(test)]
#[path = "fetch_tests.rs"]
mod tests;
