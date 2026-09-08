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
pub(crate) struct InvalidResponseTargets;

/// Existing audit labels attached by the server dispatch boundary.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ResponseCorrelation<'a> {
    pub session_id: &'a str,
    pub caller: &'a str,
    pub external_server: &'a str,
    pub external_tool: &'a str,
}

/// Distinguishes a served result from an internally consumed legacy question.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ResponseArtifactKind {
    FinalResponse,
    BridgeChallenge,
}

/// A backend question must retain the meaning bound to its answer and state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResponseMutationPolicy {
    Redact,
    Immutable,
    PreserveInputRequired,
}
