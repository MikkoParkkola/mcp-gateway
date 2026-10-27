// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A listing's warm of a caller's cold per-user views (MIK-8962 SHARED.5).
//!
//! A backend that never opens a shared session has no shared catalogue to
//! show a caller whose own view is cold. Before `tools/list` is built, that
//! caller's own view of each such backend with a surfaced tool is
//! re-established through the checks a stored read runs, in the same order:
//! the account pre-pass and `claim_caller_view`, both through the caller's own
//! backend grant, before any credential is resolved or any backend is reached.

use super::MetaMcp;
use super::account_outcome::AccountWrites;
use super::scoped_backends::Unscoped;
use super::visibility::InvokeScope;

impl MetaMcp {
    /// Warm the caller's cold views of the surfaced tools' backends that
    /// refuse a shared session. Each won claim's fill runs as its own task,
    /// and the listing waits for all of them under one deadline measured from
    /// here: the longest fill bound among those backends. A fill still running
    /// then is left out of this listing, finishes on its own lease, and the
    /// caller hears `tools/list_changed` when its slot stores (MIK-8148).
    pub(crate) async fn warm_listing_views(
        &self,
        scope: InvokeScope<'_>,
        session_id: Option<&str>,
    ) {
        let surfaced = self.surfaced_state();
        // A config read only: which backends refuse a shared session. Whether
        // this caller may reach one is decided by the scoped checks below.
        let refused: Vec<_> = surfaced
            .tools
            .iter()
            .filter_map(|surfaced| {
                let backend = self
                    .backends
                    .get_for(Unscoped::Visibility, &surfaced.server)?;
                backend
                    .shared_slot_refused()
                    .then(|| ((surfaced.server.as_str(), surfaced.tool.as_str()), backend))
            })
            .collect();
        let Some(deadline) = refused
            .iter()
            .map(|(_, backend)| backend.tools_fill_bound())
            .max()
        else {
            return;
        };
        let targets: Vec<(&str, &str)> = refused.iter().map(|(target, _)| *target).collect();
        let warm = async {
            // A listing is not a call: a busy custody writes no transient
            // refusal record here.
            self.account_prepass(&targets, scope, session_id, AccountWrites::PermanentOnly)
                .await;
            let mut fills = Vec::new();
            for &(server, tool) in &targets {
                if let Some(fill) = self
                    .claim_caller_view(server, tool, scope, session_id)
                    .await
                {
                    fills.push(tokio::spawn(fill.run()));
                }
            }
            for fill in fills {
                let _ = fill.await;
            }
        };
        let _ = tokio::time::timeout(deadline, warm).await;
    }
}
