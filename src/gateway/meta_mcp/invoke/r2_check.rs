// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! R2's pre-dispatch key check on the Meta-MCP route (MIK-7570.SCHEMA.1) and
//! its F13 cold-slot fill: the refusal, the miss hint pool, and the
//! accounting of a fill the slot's failsafe refused.

use serde_json::{Value, json};

use super::super::super::meta_mcp_helpers::did_you_mean;
use super::{BudgetOutcome, MetaMcp, dispatch_error_result};
use crate::gateway::recovery::MetaSurface;
use crate::security::http_diagnostics::is_upstream_unauthorized;
use crate::{Error, Result};

/// A miss on `tool`, with a "did you mean?" hint drawn from `candidates`
/// (names this caller could invoke, A3) when one is close enough. The
/// dispatch miss's wording; R2's text A (F13) keeps its own and appends the
/// same hint.
pub(super) fn miss_with_hint(
    server: &str,
    tool: &str,
    candidates: &[&str],
    fallback: &str,
) -> String {
    match did_you_mean(tool, candidates, 3, 3) {
        Some(hint) => format!("Tool '{tool}' not found on server '{server}'. {hint}"),
        None => format!("Tool '{tool}' not found on server '{server}'. {fallback}"),
    }
}

impl MetaMcp {
    /// MIK-7570.SCHEMA.1 (R2): the `isError` result refusing a call to an MCP
    /// backend whose arguments carry keys the tool's schema does not declare.
    ///
    /// Runs on the arguments as the caller sent them, before secret injection,
    /// so a gateway-injected credential is never mistaken for an invented key.
    /// Capabilities are skipped: their executor validates after injection.
    /// A cold slot is listed once as the caller, with `headers` (F13); `Err`
    /// is the slot's failsafe refusing that list.
    pub(super) async fn undeclared_key_refusal(
        &self,
        // The backend the call was judged on (MIK-7810), never a second lookup
        // by name: a reload between the two must not send this caller's
        // headers to a replacement.
        (server, backend): (&str, Option<&std::sync::Arc<crate::backend::Backend>>),
        tool: &str,
        arguments: &Value,
        identity_key: Option<&str>,
        headers: &[(String, String)],
        (scope, session_id): (super::super::InvokeScope<'_>, Option<&str>),
    ) -> Result<Option<Value>> {
        if self
            .get_capabilities()
            .is_some_and(|cap| server == cap.name && cap.has_capability(tool))
        {
            return Ok(None);
        }
        let Some(backend) = backend else {
            return Ok(None);
        };
        let text = backend
            .undeclared_key_refusal(identity_key, headers, tool, arguments)
            .await?;
        // F13 text A (the backend's complete list lacks the tool) is a miss.
        // It keeps the design's exact wording on both routes; on this route
        // only, the profile-scoped "did you mean?" hint the miss after
        // dispatch gave before is appended (amendment: text A plus an
        // optional hint, keeping the #555 / MIK-7518 suggestion contract).
        let text = text.map(|text| {
            if text != crate::backend::text_absent(tool) {
                return text;
            }
            let names = backend.get_cached_tool_names_for(identity_key);
            let candidates = self.miss_hint_pool(&names, server, (scope, session_id));
            match did_you_mean(tool, &candidates, 3, 3) {
                Some(hint) => format!("{text}. {hint}"),
                None => text,
            }
        });
        Ok(text
            .map(|text| json!({ "content": [{ "type": "text", "text": text }], "isError": true })))
    }

    /// The "did you mean?" pool for a miss on `server`: the `names` from this
    /// caller's slot that it could invoke (A3). The ONE pool source for every
    /// miss hint (the dispatch miss and R2's text A, F13), so a fix to what
    /// the pool admits reaches every site at once.
    pub(super) fn miss_hint_pool<'n>(
        &self,
        names: &'n [String],
        server: &str,
        (scope, session_id): (super::super::InvokeScope<'_>, Option<&str>),
    ) -> Vec<&'n str> {
        names
            .iter()
            .map(String::as_str)
            .filter(|name| self.may_invoke(server, name, scope, session_id).is_ok())
            .collect()
    }

    /// A cold-slot fill that failed, answered as a failed dispatch is. The
    /// list is this caller's first request, so a 401 on a managed credential
    /// forces its one refresh here (A11-c); otherwise a cold slot would never
    /// reach the dispatch that refreshes it. `Ok` is the accounted tool
    /// result and the error it answers; `Err` is a marked account refusal,
    /// for the caller's connect offer.
    pub(super) async fn answer_refused_fill(
        &self,
        (server, tool): (&str, &str),
        error: Error,
        managed: Option<&crate::personal_accounts::ManagedLease>,
        (checked_at, surface): (std::time::Instant, MetaSurface),
    ) -> std::result::Result<(Value, Error), Error> {
        let error = match managed {
            Some(managed) if is_upstream_unauthorized(&error) => {
                managed.after_upstream_401(error).await
            }
            _ => error,
        };
        let value = self.account_refused_fill(server, tool, &error, (checked_at, surface));
        if crate::personal_accounts::refusal::marked(&error).is_some() {
            return Err(error);
        }
        Ok((value, error))
    }

    /// [`Self::answer_refused_fill`] for a bridged round: the error text it
    /// is refused with. Every managed 401, refreshed and marked or not, is
    /// parked in `parked`, exactly as a dispatched round's is (A11-c).
    pub(super) async fn bridged_refused_fill(
        &self,
        at: (&str, &str),
        error: Error,
        managed: Option<&crate::personal_accounts::ManagedLease>,
        checked_at: std::time::Instant,
        parked: &parking_lot::Mutex<Option<Error>>,
    ) -> String {
        let parks = managed.is_some() && is_upstream_unauthorized(&error);
        // Only the error text is used; the hinted value is dropped, so its
        // surface is moot.
        let (Ok((_, error)) | Err(error)) = self
            .answer_refused_fill(
                at,
                error,
                managed,
                (checked_at, MetaSurface::Undiscoverable),
            )
            .await;
        let message = error.to_string();
        if parks || crate::personal_accounts::refusal::marked(&error).is_some() {
            *parked.lock() = Some(error);
        }
        message
    }

    /// Account a check-site fill the slot's failsafe refused, or that failed
    /// on transport under `closed` (F13, A3), exactly as `accounted_dispatch`
    /// accounts a dispatch refused or failed the same way: the
    /// invocation counter with `status="error"`, the latency histogram (the
    /// check's own elapsed time) and the error budget. Returns the tool
    /// result a refused dispatch answers with.
    pub(super) fn account_refused_fill(
        &self,
        server: &str,
        tool: &str,
        error: &Error,
        (started, surface): (std::time::Instant, MetaSurface),
    ) -> Value {
        telemetry_metrics::counter!(
            "mcp_tool_invocations_total",
            "server" => server.to_owned(),
            "status" => "error"
        )
        .increment(1);
        telemetry_metrics::histogram!(
            "mcp_tool_invocation_duration_seconds",
            "server" => server.to_owned()
        )
        .record(started.elapsed().as_secs_f64());
        self.record_error_budget(server, tool, BudgetOutcome::of_error(error));
        dispatch_error_result(error, tool, server, surface)
    }
}
