// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8377: whether the identity a stream was admitted under is still good,
//! judged at every decision from the fields MIK-8350 captured at attach.

use super::told::{DeadReason, LiveCtx, ViewSubject};

impl ViewSubject {
    /// Whether the identity the stream was admitted under is still good, or
    /// why not: the adapter assertion's window (MIK-8350), then the agent, the
    /// certificate and the trusted proxy (MIK-8377). A failed clause ends the
    /// stream; nothing here re-judges it with less identity.
    pub(crate) fn live(&self, ctx: &LiveCtx<'_>) -> Result<(), DeadReason> {
        if let Some(adapter) = &self.adapter
            && !adapter.live()
        {
            return Err(DeadReason::Adapter);
        }
        // The agent the held bearer validates as now must be the one the
        // stream attached as, and an agent-less stream never adopts one: the
        // judge reads the live agent's scopes, so a swap would widen the view.
        let same_agent = match (&self.oauth_agent, ctx.agent) {
            (None, None) => true,
            (Some(attached), Some(live)) => attached.client_id == live.claims.sub,
            _ => false,
        };
        if !same_agent {
            return Err(DeadReason::Agent);
        }
        // Valid while now < notAfter. An unreadable clock cannot show that.
        if let Some(not_after) = self.cert_not_after
            && !crate::clock::unix_secs().is_ok_and(|now| now < not_after)
        {
            return Err(DeadReason::Cert);
        }
        // Restart-only, so defence in depth: the bearer half is the
        // credential check that runs before this.
        if let Some(peer) = self.proxy_peer
            && !ctx.caller_identity.trusts_peer(peer)
        {
            return Err(DeadReason::Proxy);
        }
        Ok(())
    }
}
