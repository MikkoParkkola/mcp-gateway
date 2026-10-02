// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Build a CLI capability's argv from its pinned template and the caller's
//! validated parameters (MIK-7782).
//!
//! Strict on purpose, and deliberately not the REST substitution in
//! `params.rs`: that one re-parses substituted text that looks like JSON and
//! expands `{env.X}`, which is exactly what must never happen to argv. Here a
//! template item is exactly one argv element, a parameter value is never
//! split, never re-parsed, and can only appear where the template put it.

use serde_json::Value;

use crate::capability::definition::CliConfig;
use crate::{Error, Result};

/// Most items one `each:` element may expand to.
pub(crate) const MAX_EACH_ITEMS: usize = 64;
/// Most bytes all argv elements together may hold.
pub(crate) const MAX_ARGV_BYTES: usize = 128 * 1024;
/// Most bytes a call may write to a child's stdin.
pub(crate) const MAX_STDIN_BYTES: usize = 1024 * 1024;

/// A fully built CLI call: nothing in it is a template any more.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CliInvocation {
    /// The command exactly as the pinned file spells it (resolved at spawn).
    pub command: String,
    /// argv after the program name.
    pub args: Vec<String>,
    /// Bytes for the child's stdin, when the file declares `stdin`.
    pub stdin: Option<String>,
}

/// Build the invocation.
///
/// `input_schema` is the capability's `schema.input`; it is read only for a
/// property's `format: multiline`, the one opt-in for line breaks in an
/// option value.
///
/// # Errors
///
/// `Error::Config` for a template the rules forbid (a file defect, also caught
/// by the validator); a JSON-RPC invalid-params error for a parameter that is
/// missing, of the wrong type, or holds a byte its slot refuses.
pub(crate) fn build_cli_invocation(
    config: &CliConfig,
    params: &Value,
    input_schema: &Value,
) -> Result<CliInvocation> {
    let _ = (
        config,
        params,
        input_schema,
        MAX_EACH_ITEMS,
        MAX_ARGV_BYTES,
        MAX_STDIN_BYTES,
    );
    Err(Error::Config(
        "CLI argument building is not implemented yet".into(),
    ))
}

#[cfg(test)]
#[path = "cli_argv_tests.rs"]
mod tests;
