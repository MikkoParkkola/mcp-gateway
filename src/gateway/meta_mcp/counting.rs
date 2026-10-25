// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8854: where a finished call reaches the web UI's counters.
//!
//! Every writer of a call's one invocation record calls [`MetaMcp::count_call`]
//! in its "counted before the log check" step, so the counters cover exactly
//! the calls the records do, with or without an audit log. A server keeps its
//! name only when it is configured and a tool only when the catalogue lists
//! it: any other name was chosen by the caller and only adds to an overflow
//! count.

use std::sync::Arc;

use super::MetaMcp;
use super::scoped_backends::Unscoped;
use crate::counters::{Call, CounterStore, Label, Outcome, Tally, caller_label};
use crate::security::audit::{AuditWho, CredentialKind};

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
        server: &str,
        tool: Option<&str>,
        who: &AuditWho,
        outcome: Outcome,
    ) {
        let Some(store) = self.counters.get() else {
            return;
        };
        let tally = Tally::from_outcome(outcome);
        if tally.is_empty() {
            return;
        }
        // A recorder writes nothing on a clock it cannot read (MIK-8202).
        let Ok(now) = crate::clock::unix_secs() else {
            return;
        };
        let (server, tool) = self.trusted_labels(server, tool);
        let caller = caller_label(
            who.credential_kind.unwrap_or(CredentialKind::None),
            &who.account,
        );
        let call = Call {
            caller: &caller,
            server,
            tool,
            tally,
        };
        store.record(&call, now, &chrono::Local);
    }

    /// `server` and `tool` as labels: kept only when configured and
    /// catalogued, never as the caller spelled something else.
    fn trusted_labels<'a>(&self, server: &'a str, tool: Option<&'a str>) -> (Label<'a>, Label<'a>) {
        if let Some(capabilities) = self.get_capabilities()
            && capabilities.name == server
        {
            let tool = tool
                .filter(|t| capabilities.has_capability(t))
                .map_or(Label::Untrusted, Label::Known);
            return (Label::Known(server), tool);
        }
        let Some(backend) = self.backends.get_for(Unscoped::Admin, server) else {
            return (Label::Untrusted, Label::Untrusted);
        };
        let tool = tool
            .filter(|t| backend.with_cached_tool_for(None, t, |_| ()).is_some())
            .map_or(Label::Untrusted, Label::Known);
        (Label::Known(server), tool)
    }
}
