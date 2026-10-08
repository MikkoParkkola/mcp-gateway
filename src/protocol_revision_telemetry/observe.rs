// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Process-wide observation entry points over the shared registry.

use std::collections::BTreeMap;

use serde_json::Value;

use super::{
    CacheScope, ListFilters, META_CLIENT_INFO, META_PROTOCOL_VERSION, SessionAttribution, Snapshot,
    ToolsListShadow, Transport, UNATTRIBUTED_CLIENT, client_info_name, client_label, global,
    public_over_filtered, request_meta_value, requested_revision, revision_label,
};
// Only the zero-registration loop in `register_metrics` reads these.
#[cfg(feature = "metrics")]
use super::{
    MEASURED_CLIENTS, MEASURED_REVISIONS, MEASURED_TRANSPORTS, OTHER_REVISION, cache_scope_decision,
};
use crate::protocol::extensions::ExtensionSet;

/// Record the revision a session's handshake answered.
///
/// Called from the one site where negotiation happens, so the stored value is
/// the one the client was told -- never a second derivation of it.
pub fn bind_session_revision(session_id: Option<&str>, negotiated: &'static str) {
    let Some(session_id) = session_id else {
        return;
    };
    global()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .bind_negotiated_revision(session_id, negotiated);
}

/// The revision this session's handshake answered, if it has had one.
///
/// `None` before any `initialize`, which is what lets the observation record
/// report `absent`/`none` for a message that arrives first rather than
/// fabricating a revision for it.
#[must_use]
pub fn session_negotiated_revision(session_id: Option<&str>) -> Option<&'static str> {
    global()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .session_attribution(session_id)
        .and_then(|item| item.negotiated_revision)
}

/// Record one parsed inbound JSON-RPC request.
///
/// Metric labels and remembered legacy attribution are bounded. Session IDs are
/// reduced to hashes and retained only for a fixed-capacity cache.
pub fn observe_inbound_request(
    request: &Value,
    params: Option<&Value>,
    method: &str,
    protocol_header: Option<&str>,
    session_id: Option<&str>,
    transport: Transport,
) {
    if method.starts_with("notifications/") {
        return;
    }
    let initialize_params = (method == "initialize").then_some(params).flatten();
    let explicit_requested = request_meta_value(request, params, META_PROTOCOL_VERSION)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| requested_revision(initialize_params, None))
        .or_else(|| protocol_header.map(str::trim).map(str::to_string))
        .filter(|value| !value.is_empty());
    // MIK-6704: label only — attributes the observation, gates nothing.
    let explicit_client = client_info_name(request_meta_value(request, params, META_CLIENT_INFO))
        .or_else(|| client_info_name(initialize_params.and_then(|p| p.get("clientInfo"))))
        .unwrap_or_else(|| UNATTRIBUTED_CLIENT.to_string());

    let mut reg = global()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let previous = (transport == Transport::Stdio)
        .then(|| reg.session_attribution(session_id))
        .flatten();
    let requested_label = revision_label(explicit_requested.as_deref())
        .or_else(|| previous.and_then(|item| item.requested_revision));
    let client = if explicit_client == UNATTRIBUTED_CLIENT {
        previous.map_or(UNATTRIBUTED_CLIENT, |item| item.client)
    } else {
        client_label(&explicit_client)
    };
    if transport == Transport::Stdio
        && method == "initialize"
        && let Some(session_id) = session_id
    {
        reg.bind_session(
            session_id,
            SessionAttribution {
                requested_revision: requested_label,
                client,
                // A second `initialize` on one session re-asks; until it is
                // answered the session is still served under the last answer.
                negotiated_revision: previous.and_then(|item| item.negotiated_revision),
            },
        );
    }
    reg.observe_request(requested_label, client, transport);
    drop(reg);
    emit_request_metrics(requested_label, client, transport);
    tracing::debug!(
        requested_revision = requested_label.unwrap_or("unattributed"),
        client,
        transport = transport.as_str(),
        "mcp728.u1 inbound request observation"
    );
}

/// Record the extensions a client negotiated for one `tools/call`.
///
/// The gateway advertises its own set through `server/discover`; this is the
/// other half of that exchange — what clients actually declare back. Without
/// it the adoption question behind MIK-7311 has no production measurement, and
/// `ExtensionSet::from_capabilities` has no production caller at all.
///
/// Measurement only. It gates nothing: the 4.0.0 task model is knowingly short
/// of the extension specification, so refusing or diverting a call on the
/// strength of this set would enforce a contract the gateway does not yet keep.
pub fn observe_client_extensions(extensions: &ExtensionSet) {
    if extensions.is_empty() {
        return;
    }
    let mut reg = global()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for extension in extensions.iter() {
        reg.observe_extension(extension);
        tracing::debug!(
            extension = extension.id(),
            "mcp728.u1 client extension negotiated"
        );
    }
}

/// Extension adoption observed by this process, by identifier.
#[must_use]
pub fn extension_adoption() -> BTreeMap<String, u64> {
    global()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .extension_adoption()
}

/// Shadow-log one `tools/list` on the process registry.
pub fn observe_tools_list(filters: ListFilters) -> ToolsListShadow {
    let mut reg = global()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let shadow = reg.shadow_tools_list(filters);
    drop(reg);
    emit_tools_list_metrics(filters, shadow.would_emit_cache_scope);
    tracing::debug!(
        principal = shadow.principal,
        profile = shadow.profile,
        session = shadow.session,
        request = shadow.request,
        would_emit_cache_scope = shadow.would_emit_cache_scope.as_str(),
        public_over_filtered = public_over_filtered(filters, shadow.would_emit_cache_scope),
        "mcp728.u1 tools/list cacheScope shadow"
    );
    shadow
}

fn emit_tools_list_metrics(filters: ListFilters, scope: CacheScope) {
    let _ = (filters, scope);
    #[cfg(feature = "metrics")]
    telemetry_metrics::counter!(
        "mcp_tools_list_cache_scope_shadow_total",
        "principal" => if filters.principal { "true" } else { "false" },
        "profile" => if filters.profile { "true" } else { "false" },
        "session" => if filters.session { "true" } else { "false" },
        "request" => if filters.request { "true" } else { "false" },
        "would_emit_cache_scope" => scope.as_str()
    )
    .increment(1);
}

/// Register every bounded protocol-revision and list-shadow metric series at zero.
///
/// Call this after installing the recorder and before taking the baseline scrape
/// for a measurement window. Zero registration prevents an unused revision or
/// client family from disappearing from `increase()` queries.
pub fn register_metrics() {
    #[cfg(feature = "metrics")]
    {
        for revision in MEASURED_REVISIONS
            .iter()
            .copied()
            .chain(std::iter::once(OTHER_REVISION))
        {
            for client in MEASURED_CLIENTS {
                for transport in MEASURED_TRANSPORTS {
                    telemetry_metrics::counter!(
                        "mcp_protocol_revision_observations_total",
                        "requested_revision" => revision,
                        "client" => *client,
                        "transport" => transport.as_str()
                    )
                    .increment(0);
                }
            }
        }

        for client in MEASURED_CLIENTS {
            for transport in MEASURED_TRANSPORTS {
                telemetry_metrics::counter!(
                    "mcp_protocol_revision_unattributed_observations_total",
                    "client" => *client,
                    "transport" => transport.as_str()
                )
                .increment(0);
            }
        }

        for principal in [false, true] {
            for profile in [false, true] {
                for session in [false, true] {
                    for request in [false, true] {
                        let filters = ListFilters {
                            principal,
                            profile,
                            session,
                            request,
                        };
                        let scope = cache_scope_decision(filters);
                        telemetry_metrics::counter!(
                            "mcp_tools_list_cache_scope_shadow_total",
                            "principal" => principal.to_string(),
                            "profile" => profile.to_string(),
                            "session" => session.to_string(),
                            "request" => request.to_string(),
                            "would_emit_cache_scope" => scope.as_str()
                        )
                        .increment(0);
                    }
                }
            }
        }
    }
}

/// Process snapshot for the measurement table.
pub fn global_snapshot() -> Snapshot {
    global()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .snapshot()
}

/// Process count for one `tools/list` filter combination.
pub fn global_shadow_count(filters: ListFilters) -> u64 {
    global()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .shadow_count(filters)
}

fn emit_request_metrics(
    requested_revision: Option<&'static str>,
    client: &'static str,
    transport: Transport,
) {
    let _ = (requested_revision, client, transport);
    #[cfg(feature = "metrics")]
    {
        if let Some(rev) = requested_revision {
            telemetry_metrics::counter!(
                "mcp_protocol_revision_observations_total",
                "requested_revision" => rev,
                "client" => client,
                "transport" => transport.as_str()
            )
            .increment(1);
        } else {
            telemetry_metrics::counter!(
                "mcp_protocol_revision_unattributed_observations_total",
                "client" => client,
                "transport" => transport.as_str()
            )
            .increment(1);
        }
    }
}
