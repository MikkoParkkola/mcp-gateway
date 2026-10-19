// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A stored result is served only under the binding that produced it
//! (MIK-8407, MIK-8440).
//!
//! Every dispatch records the binding each step ran under: the account token
//! (`AccountStrategyRegistry::binding_token`, the descriptor id with the
//! fingerprint of the whole declared descriptor) or, on the direct route, a
//! forwarded passthrough credential's charged binding. A replay is judged
//! here, one comparison for every site: each recorded binding must equal the
//! binding the same step would dispatch under for this request NOW.
//! Otherwise the stored output was produced under another account or
//! credential, and it is refused. It is never re-run: the key's one
//! execution is settled, and a second would send the call twice.

use crate::gateway::meta_mcp::admission::StepBinding;

/// Why a stored result is not served. Typed, so each kind keeps one text and
/// one code wherever it is answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// A recorded step ran under a binding other than the one it would run
    /// under now (an account re-bound, another forwarded credential).
    Rebound,
    /// A task row written before bindings were recorded: its provenance
    /// cannot be established (MIK-8407 design r4 E4).
    Legacy,
}

impl Refusal {
    /// The answer: `-32603`, not retryable, nothing sent. The text names
    /// the backend and never an account or a credential.
    pub(crate) fn error(self, server: &str) -> crate::Error {
        let text = match self {
            Self::Rebound => format!(
                "the stored result for backend '{server}' was produced under a different \
                 account or forwarded credential; it is not served"
            ),
            Self::Legacy => format!(
                "the stored result for backend '{server}' predates credential binding and is \
                 not served; re-run the call with a new idempotency key"
            ),
        };
        crate::Error::json_rpc(-32603, text)
    }
}

/// Judge `recorded` against `current`, the binding each `(server, tool)`
/// would dispatch under now. The first step whose recorded binding differs
/// is refused; a step recorded under two bindings always is, as one current
/// binding cannot equal both.
pub(crate) fn judge(
    recorded: &[StepBinding],
    current: impl Fn(&str, &str) -> Option<String>,
) -> crate::Result<()> {
    match recorded
        .iter()
        .find(|(server, tool, binding)| current(server, tool) != *binding)
    {
        Some((server, ..)) => Err(Refusal::Rebound.error(server)),
        None => Ok(()),
    }
}

/// The binding token a stored result records for account `descriptor_id`
/// and is judged against: `<id>#<fingerprint>`, or `<id>#` for an id no
/// descriptor declares, which equals no declared token. The ONE formatter for
/// both the recorded and the current side.
pub(crate) fn binding_token(
    registry: &crate::identity_propagation::AccountStrategyRegistry,
    descriptor_id: &str,
) -> String {
    let fingerprint = registry
        .declared(descriptor_id)
        .map(|declared| declared.fingerprint)
        .unwrap_or_default();
    format!("{descriptor_id}#{fingerprint}")
}

impl super::MetaMcp {
    /// The account token `(server, tool)` dispatches under for this view now:
    /// the same lookup the account judgement uses, formatted by the one
    /// formatter the recording side used (MIK-8407).
    pub(super) fn current_binding(
        &self,
        view: &super::scoped_backends::ScopedBackends<'_>,
        server: &str,
        tool: &str,
    ) -> Option<String> {
        self.target_account(view, server, tool)
            .map(|account| binding_token(&self.account_strategies, &account.0))
    }

    /// [`judge`] for a meta-route replay: each recorded step against the
    /// account it would run under for `view` now.
    pub(super) fn judge_bindings(
        &self,
        view: &super::scoped_backends::ScopedBackends<'_>,
        recorded: &[StepBinding],
    ) -> crate::Result<()> {
        judge(recorded, |server, tool| {
            self.current_binding(view, server, tool)
        })
    }
}

#[cfg(test)]
mod tests;
