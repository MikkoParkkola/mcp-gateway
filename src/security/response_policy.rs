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
    /// Where the target came from; never written to the audit row.
    #[serde(skip)]
    pub(crate) origin: TargetOrigin,
}

impl ResponsePolicyTarget {
    /// The backend the call was routed to.
    pub(crate) fn routed(server: &str, tool: &str) -> Self {
        Self {
            server: server.to_owned(),
            tool: tool.to_owned(),
            origin: TargetOrigin::Routed,
        }
    }
}

/// Where a [`ResponsePolicyTarget`] came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum TargetOrigin {
    /// The backend the call was routed to.
    Routed,
    /// An answer no one backend can be named for (discovery, a notification,
    /// a target-less meta answer): `server` is the `gateway` label, and the
    /// scan judges it as every registered backend could have sent it.
    NoBackend,
    /// One of those backends, added by `MetaMcp::expand_targets` for rule
    /// matching only: the audit row lists the targets the call had.
    #[cfg_attr(not(feature = "firewall"), allow(dead_code))]
    Expanded,
}

/// The API key a call was authenticated with, for a firewall rule's `keys`
/// scope. `NotKnown` is a surface that carries no key: a rule there resolves to
/// the strongest outcome over every key it could have been.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyOf<'a> {
    /// Authenticated with this API key.
    Key(&'a str),
    /// Known to carry no API key (stdio, an anonymous or non-key caller).
    NoKey,
    /// The key is not carried here.
    NotKnown,
}

impl<'a> KeyOf<'a> {
    /// From a caller whose credential is known: its proven API key name
    /// (`AuthenticatedClient::api_key_identity`), or none.
    pub(crate) fn of_client(api_key: Option<&'a str>) -> Self {
        api_key.map_or(Self::NoKey, Self::Key)
    }

    /// From an authenticated caller: its proven API key name, or no key.
    #[cfg_attr(not(feature = "firewall"), allow(dead_code))]
    pub(crate) fn of_caller(client: Option<&'a crate::gateway::auth::AuthenticatedClient>) -> Self {
        Self::of_client(
            client.and_then(crate::gateway::auth::AuthenticatedClient::api_key_identity),
        )
    }
}

/// The backend a firewall rule's `servers` scope is judged against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(feature = "firewall"), allow(dead_code))]
pub(crate) enum ServerOf<'a> {
    /// The backend's registry name.
    Backend(&'a str),
    /// No backend: matches no `servers` glob.
    NoBackend,
}

#[cfg_attr(not(feature = "firewall"), allow(dead_code))]
impl<'a> ServerOf<'a> {
    /// The name records and per-backend guards key on: the backend, or the
    /// `gateway` label for none.
    pub(crate) const fn label(self) -> &'a str {
        match self {
            Self::Backend(name) => name,
            Self::NoBackend => "gateway",
        }
    }
}

/// What a firewall rule is matched against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(feature = "firewall"), allow(dead_code))]
pub(crate) struct RuleTarget<'a> {
    pub(crate) server: ServerOf<'a>,
    pub(crate) tool: &'a str,
    pub(crate) key: KeyOf<'a>,
}

#[cfg_attr(not(feature = "firewall"), allow(dead_code))]
impl<'a> RuleTarget<'a> {
    /// A call routed to `server`'s `tool` by `client` (its API key, or none).
    pub(crate) fn routed(
        server: &'a str,
        tool: &'a str,
        client: Option<&'a crate::gateway::auth::AuthenticatedClient>,
    ) -> Self {
        Self {
            server: ServerOf::Backend(server),
            tool,
            key: KeyOf::of_caller(client),
        }
    }
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
    /// The trace of the invocation the delivered answer belongs to, so its
    /// delivery record joins that invocation's record. `None`
    /// where no single invocation produced the answer (a notification, a
    /// plan) or the correlation only labels a scan.
    pub(crate) trace_id: Option<&'a str>,
    /// The API key the caller authenticated with, for a firewall rule's
    /// `keys` scope. Only the firewall reads it; `NotKnown` where this
    /// surface carries no proven key.
    #[cfg_attr(not(feature = "firewall"), allow(dead_code))]
    pub(crate) key: KeyOf<'a>,
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
