// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Classifying one JSON-RPC line read from a backend (MIK-8014 PERF.1a).

use super::JsonRpcMessage;

impl JsonRpcMessage {
    /// One line from a backend, as a request, a notification or a response.
    pub(crate) fn from_line(line: &str) -> serde_json::Result<Self> {
        serde_json::from_str::<Self>(line)
    }
}

#[cfg(test)]
#[path = "messages_classify_tests.rs"]
mod tests;
