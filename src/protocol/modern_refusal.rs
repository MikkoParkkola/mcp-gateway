// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The refusals a MODERN (2026-07-28) request faces from its body alone
//! (MIK-8368). `/mcp` calls all of them; stdio calls [`removed_method_refusal`],
//! so a removed method earns one answer on either transport. Checks that read an
//! HTTP header (the served revision header, duplicate headers, the
//! header-against-body mirror) are not here: stdio carries no headers. The
//! unserved-revision and undeclared-capability refusals are body-only but stay
//! HTTP-only: a stdio batch runs its items with modern serving off
//! (`StdioClient::modern`), so sharing them would refuse every modern call in
//! a batch.
//!
//! The callers call these only for a `Modern` request shape, so a legacy or
//! malformed request is refused (or not) by its own caller, exactly as before.

use super::meta::{MODERN_VERSIONS, REMOVED_IN_2026_07_28, RequestFields, required_capability};
use super::{JsonRpcResponse, RequestId};

/// Which body-only refusal [`modern_method_refusal`] made, so a caller can map
/// it to its own status. HTTP answers a missing capability 400 and a removed
/// method 404; stdio has no status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModernRefusal {
    /// A method the client needs a capability for and did not declare.
    MissingCapability,
    /// A method the 2026-07-28 revision removed.
    Removed,
}

/// The answer to a protocol version this build cannot serve.
///
/// The client is told which revisions it could retry on rather than left to
/// guess. Shared by the POST classifier, stdio and the `GET /mcp` era gate so
/// they cannot give one client two different answers.
#[must_use]
pub fn unsupported_version_error(
    id: Option<RequestId>,
    version: &str,
    modern_enabled: bool,
) -> JsonRpcResponse {
    let supported: &[&str] = if modern_enabled { MODERN_VERSIONS } else { &[] };
    JsonRpcResponse::error_with_data(
        id,
        super::era::UNSUPPORTED_PROTOCOL_VERSION,
        format!("unsupported protocol version '{version}'"),
        serde_json::json!({ "supportedVersions": supported }),
    )
}

/// A modern request naming a revision this build does not serve, or serves with
/// modern support switched off. `None` admits.
#[must_use]
pub fn unsupported_modern_version(
    id: Option<&RequestId>,
    fields: &RequestFields,
    modern_enabled: bool,
) -> Option<JsonRpcResponse> {
    (!modern_enabled || !MODERN_VERSIONS.contains(&fields.protocol_version.as_str()))
        .then(|| unsupported_version_error(id.cloned(), &fields.protocol_version, modern_enabled))
}

/// A method the request needs a capability for and did not declare (-32021), or
/// one the revision removed (-32601), in that order. The two method sets are
/// disjoint, so the order is not observable. `None` admits.
#[must_use]
pub fn modern_method_refusal(
    id: Option<&RequestId>,
    fields: &RequestFields,
    method: &str,
) -> Option<(JsonRpcResponse, ModernRefusal)> {
    if let Some(capability) = required_capability(method)
        && !fields.declares_capability(capability)
    {
        let mut rpc = JsonRpcResponse::error(
            id.cloned(),
            super::era::MISSING_REQUIRED_CLIENT_CAPABILITY,
            format!("client did not declare the '{capability}' capability"),
        );
        if let Some(ref mut error) = rpc.error {
            error.data = Some(serde_json::json!({ "requiredCapabilities": [capability] }));
        }
        return Some((rpc, ModernRefusal::MissingCapability));
    }
    removed_method_refusal(id, method).map(|rpc| (rpc, ModernRefusal::Removed))
}

/// The refusal for a method this revision removed. Methods outside the list get
/// `None`.
#[must_use]
pub fn removed_method_refusal(id: Option<&RequestId>, method: &str) -> Option<JsonRpcResponse> {
    REMOVED_IN_2026_07_28.contains(&method).then(|| {
        JsonRpcResponse::error(
            id.cloned(),
            super::era::METHOD_NOT_FOUND_CODE,
            format!("method '{method}' was removed in MCP 2026-07-28"),
        )
    })
}
