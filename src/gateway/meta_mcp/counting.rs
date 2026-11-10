// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Where a finished call reaches the web UI's counters.
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
    #[cfg(feature = "webui")]
    pub(crate) fn counters(&self) -> Option<&Arc<CounterStore>> {
        self.counters.get()
    }

    /// Count one finished call on `server`/`tool` by `who`, with its backend
    /// send time when a send began.
    pub(crate) fn count_call(
        &self,
        server: &str,
        tool: Option<&str>,
        who: &AuditWho,
        outcome: Outcome,
        sample: Option<(std::time::Duration, crate::counters::End)>,
    ) {
        let Some(store) = self.counters.get() else {
            return;
        };
        let tally = Tally::from_outcome(outcome);
        if tally.is_empty() {
            return;
        }
        // A recorder writes nothing on a clock it cannot read.
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
        store.record_timed(&call, now, &crate::local_day::host_zone(), sample);
    }

    /// Whether `server` is a name this gateway was configured with. The one
    /// test for every server name the call history keeps: counters and
    /// chart markers alike.
    pub(crate) fn configured_server(&self, server: &str) -> bool {
        self.configured(server).is_some()
    }

    /// `server` and `tool` as labels: kept only when configured and
    /// catalogued, never as the caller spelled something else.
    fn trusted_labels<'a>(&self, server: &'a str, tool: Option<&'a str>) -> (Label<'a>, Label<'a>) {
        let listed = match self.configured(server) {
            None => return (Label::Untrusted, Label::Untrusted),
            Some(Configured::Capabilities(capabilities)) => {
                tool.filter(|t| capabilities.has_capability(t))
            }
            Some(Configured::Backend(backend)) => {
                tool.filter(|t| backend.lists_tool_in_any_slot(t))
            }
        };
        (
            Label::Known(server),
            listed.map_or(Label::Untrusted, Label::Known),
        )
    }

    fn configured(&self, server: &str) -> Option<Configured> {
        if let Some(capabilities) = self.get_capabilities()
            && capabilities.name == server
        {
            return Some(Configured::Capabilities(capabilities));
        }
        self.backends
            .get_for(Unscoped::Admin, server)
            .map(Configured::Backend)
    }
}

/// What a configured server name resolves to.
enum Configured {
    Capabilities(Arc<crate::capability::CapabilityBackend>),
    Backend(Arc<crate::backend::Backend>),
}
