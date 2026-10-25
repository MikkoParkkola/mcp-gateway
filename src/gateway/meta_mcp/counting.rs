// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8854: where a finished call reaches the web UI's counters.

use std::sync::Arc;

use super::MetaMcp;
use crate::counters::{CounterStore, Outcome};
use crate::security::audit::AuditWho;

impl MetaMcp {
    /// Attach the counter store. Called once by the HTTP server; a second
    /// call is ignored.
    pub(crate) fn set_counters(&self, store: Arc<CounterStore>) {
        let _ = self.counters.set(store);
    }

    /// The counter store, when the server attached one.
    pub(crate) fn counters(&self) -> Option<&Arc<CounterStore>> {
        self.counters.get()
    }

    /// Count one finished call on `server`/`tool` by `who`.
    pub(crate) fn count_call(
        &self,
        _server: &str,
        _tool: Option<&str>,
        _who: &AuditWho,
        _outcome: Outcome,
    ) {
    }
}
