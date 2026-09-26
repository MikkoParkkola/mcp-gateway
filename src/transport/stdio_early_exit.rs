// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A stdio child that dies before `initialize` (#526).
//!
//! Red-first: the accessor the tests read exists and reports nothing. The
//! start still waits out the request timeout on an early exit.

use super::StdioTransport;

impl StdioTransport {
    /// The redacted stderr tail of the last start that ended in an early exit.
    ///
    /// For the gateway log and `doctor`, never for an MCP client.
    #[must_use]
    pub fn start_failure_excerpt(&self) -> Option<String> {
        None
    }
}

#[cfg(all(test, unix))]
#[path = "stdio_early_exit_tests.rs"]
mod tests;
