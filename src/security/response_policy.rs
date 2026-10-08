// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Server-owned correlation shared by response security and transport adapters.
//! This module is available when the optional Firewall feature is disabled too.

use serde::Serialize;

/// Authenticated routing target; never reconstructed from returned tool text.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(crate) struct ResponsePolicyTarget {
    pub server: String,
    pub tool: String,
}

/// Internal response admission requires at least one server-bound policy target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(feature = "firewall"), allow(dead_code))]
pub(crate) struct InvalidResponseTargets;

/// Existing audit labels attached by the server dispatch boundary.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ResponseCorrelation<'a> {
    pub session_id: &'a str,
    pub caller: &'a str,
    pub external_server: &'a str,
    pub external_tool: &'a str,
    /// The caller's verified grant subject, when one resolved (MIK-7938): the
    /// delivery record names it as the invocation record does.
    pub(crate) subject: Option<&'a crate::identity_grants::GrantSubject>,
}

/// Distinguishes a served result from an internally consumed legacy question.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(not(feature = "firewall"), allow(dead_code))]
pub(crate) enum ResponseArtifactKind {
    FinalResponse,
    BridgeChallenge,
    /// The `data` of an MCP event before its first delivery (MIK-7630).
    EventPayload,
    /// The params of a notification a backend streamed during a call
    /// (MIK-8161).
    Notification,
}

/// A backend question must retain the meaning bound to its answer and state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(feature = "firewall"), allow(dead_code))]
pub(crate) enum ResponseMutationPolicy {
    Redact,
    Immutable,
    PreserveInputRequired,
}

/// The members of an interim answer the client is asked (`inputRequests`) and
/// hands back (`requestState`): a finding in either refuses, never rewrites.
pub(crate) const INTERIM_MEMBERS: [&str; 2] = ["inputRequests", "requestState"];

impl ResponseMutationPolicy {
    /// The policy for a result part: an interim answer keeps its question and
    /// handle whole, anything else is redacted in place.
    #[cfg_attr(not(feature = "firewall"), allow(dead_code))]
    pub(crate) fn for_result(result: &serde_json::Value) -> Self {
        if INTERIM_MEMBERS
            .iter()
            .any(|member| result.get(member).is_some())
        {
            Self::PreserveInputRequired
        } else {
            Self::Redact
        }
    }
}
