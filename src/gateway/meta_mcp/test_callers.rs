// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test-only caller contexts and the anonymous discovery wrappers.

use serde_json::Value;

use super::{MetaMcp, MetaMcpCallerContext};
use crate::Result;

/// A caller context for the discovery entry points, in tests.
///
/// `list_tools` and `search_tools` take one since MIK-7334.CATALOGUE.1: the
/// catalogue they serve depends on who is asking, which is the whole mode. This
/// builds the anonymous case — no verified identity, no credential principal —
/// which on a multi-user gateway is the caller §4.6 row 2 of the design says
/// must see an identity-bound backend omitted.
/// Test-only discovery wrappers that supply the anonymous caller.
///
/// The discovery entry points take a caller since MIK-7334.CATALOGUE.1. Most
/// existing cases are about workflow state, ranking or authorization, where the
/// caller is not the variable under test, so they call these rather than
/// spelling a context each time. Named `_anon` so a case that DOES depend on who
/// is asking cannot reach one by accident.
impl MetaMcp {
    pub(in crate::gateway) async fn list_tools_anon(
        &self,
        args: &Value,
        session_id: Option<&str>,
    ) -> Result<Value> {
        self.list_tools(args, session_id, &anonymous_caller()).await
    }

    pub(in crate::gateway) async fn search_tools_anon(
        &self,
        args: &Value,
        session_id: Option<&str>,
    ) -> Result<Value> {
        self.search_tools(args, session_id, &anonymous_caller())
            .await
    }

    pub(in crate::gateway) async fn code_mode_search_anon(
        &self,
        args: &Value,
        session_id: Option<&str>,
    ) -> Result<Value> {
        self.code_mode_search(args, session_id, &anonymous_caller())
            .await
    }
}

pub(in crate::gateway) fn anonymous_caller() -> MetaMcpCallerContext<'static> {
    // `RetryFields` is borrowed by the context, so a test-local value would not
    // outlive the call. One shared empty set is correct here: these callers are
    // not retrying anything.
    static RETRY: std::sync::OnceLock<crate::protocol::mrtr::RetryFields> =
        std::sync::OnceLock::new();
    let retry = RETRY.get_or_init(crate::protocol::mrtr::RetryFields::default);
    MetaMcpCallerContext {
        task: None,
        execution: None,
        signing: None,
        is_modern: true,
        protocol_revision: None,
        credential_principal: None,
        authentication: crate::gateway::meta_mcp::Authentication::Anonymous,
        authorizer: &crate::gateway::authz::AllowAll,
        api_key_name: None,
        agent_id: None,
        agent_declared: None,
        grant_subject: None,
        verified_identity: None,
        is_admin: false,
        input_capabilities: crate::protocol::meta::Declared::NONE,
        confirmation: crate::gateway::destructive_confirmation::ConfirmationChannel::Unavailable,
        retry,
        era: crate::protocol::meta::Era::Modern,
        channel: &crate::gateway::input_bridge::NoClientChannel,
    }
}

/// The same context, carrying a verified end-user identity.
///
/// This is the caller the per-caller catalogue mode exists for: one that can
/// resolve a per-user credential for an identity-bound backend and therefore
/// has its own slot, its own fetch and its own catalogue.
pub(in crate::gateway) fn identified_caller(
    identity: &crate::key_server::oidc::VerifiedIdentity,
) -> MetaMcpCallerContext<'_> {
    MetaMcpCallerContext {
        credential_principal: Some("a-validated-bearer-token-digest"),
        verified_identity: Some(identity),
        ..anonymous_caller()
    }
}
