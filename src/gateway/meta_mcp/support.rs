// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Standalone helpers for `MetaMcp`.
//!
//! Contains idempotency key resolution, tag collection, Code Mode result
//! conversion, and response augmentation. The playbook step invoker lives in
//! `playbook_invoker.rs`.

use serde_json::{Value, json};

use crate::idempotency::IdempotencyCache;

use super::MetaMcp;
use crate::gateway::meta_mcp::MetaMcpCallerContext;

// ============================================================================
// Idempotency
// ============================================================================

/// Whether the caller presented and validated a credential.
///
/// Carried explicitly on every caller context, never inferred from the
/// credential principal: the live HTTP anonymous caller carries `Some("")`, and
/// an auth-off task worker carries the non-empty `AUTH_DISABLED_TASK_OWNER`, so
/// a digest says nothing reliable about whether anyone authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Authentication {
    Authenticated,
    Anonymous,
}

impl Authentication {
    /// Read from `AuthenticatedClient::authenticated`. No client at all is
    /// anonymous: nothing was presented.
    pub(crate) fn of(client: Option<&crate::gateway::auth::AuthenticatedClient>) -> Self {
        if client.is_some_and(|client| client.authenticated) {
            Self::Authenticated
        } else {
            Self::Anonymous
        }
    }
}

/// Who the response cache and the retry key belong to.
///
/// A tri-state rather than `Option<String>` so the fail-closed case cannot be
/// dropped by accident: `Anonymous` is the one namespace every caller without
/// a credential shares, and `Unresolved` is an authenticated caller no arm
/// could name. The key helpers below take this by reference and hold the
/// exhaustive match, so no call site unwraps it to a string of its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum CachePrincipal {
    Caller(String),
    Anonymous,
    Unresolved,
}

/// `projection_key_suffix`, scoped to the playbook step this dispatch runs
/// in, if any (MIK-8341): `|step:N` lands after the length-prefixed client
/// key, so each step of a keyed run gets its own entry (no 409 between steps)
/// while a retry of the same step inside the run still meets its stored answer
/// (ADR-012). A client key that spells `|step:N` cannot collide: the length
/// prefix covers only the client's text. Reads the playbook engine's own step
/// label, never Code Mode's, whose steps carry no key.
pub(super) fn step_scoped(projection_key_suffix: &str) -> String {
    match crate::playbook::current_step() {
        Some(label) => format!("|step:{label}{projection_key_suffix}"),
        None => projection_key_suffix.to_owned(),
    }
}

/// Build the idempotency key for a `gateway_invoke` call.
///
/// `client_key` is the key the client sent in `params._meta`; there is no other
/// source. A call without one is not protected, and that is the correct
/// outcome: a key the client never chose cannot express which repeats are
/// deliberate, so deriving one from `(server, tool, arguments)` made an
/// identical second call — a retry the user asked for — silently return the
/// first result instead of running.
///
/// The suffixes are the ADR-008 INV-3 binding. They stay part of the key so one
/// caller's stored result is never served to another under the same client key.
///
/// The client key is LENGTH-PREFIXED because it is the one attacker-chosen
/// segment: appended raw, a caller could simply spell another caller's suffix
/// inside its own key and derive that caller's entry (MIK-7408). The length
/// says where the client's bytes stop, so no choice of key can reach across
/// the boundary into a segment the gateway derives.
///
/// Returns `None` when no idempotency cache is configured, when the client
/// sent no key, or when the principal is `Unresolved`. `route` labels the
/// skip counter (`meta` or `direct`).
pub(super) fn idempotency_key_for(
    client_key: Option<&str>,
    projection_key_suffix: &str,
    principal: &CachePrincipal,
    idem_cache: Option<&std::sync::Arc<IdempotencyCache>>,
    route: &'static str,
) -> Option<String> {
    idem_cache?;
    let key = client_key?;
    let Some(identity_suffix) = retry_identity_suffix(principal) else {
        // Fail closed (A0 D4): never read or write the shared key space. The
        // call proceeds unguarded, like one that sent no key.
        tracing::warn!(
            route,
            "Idempotency guard skipped: unresolved caller principal"
        );
        telemetry_metrics::counter!(
            "mcp_idempotency_guard_skipped_total",
            "reason" => "unresolved_principal",
            "route" => route
        )
        .increment(1);
        return None;
    };
    let len = key.len();
    Some(format!(
        "{len}:{key}{projection_key_suffix}{identity_suffix}"
    ))
}

/// The retry de-duplication suffix: WHO a stored idempotency entry belongs to.
///
/// Exactly the principal the response cache keys on (`caller_cache_principal`),
/// so a caller the response cache tells apart can never share a retry entry.
/// Empty for `Anonymous`, the one pooled namespace; `None` for `Unresolved`,
/// which must never fall back to that namespace.
pub(super) fn retry_identity_suffix(principal: &CachePrincipal) -> Option<String> {
    match principal {
        CachePrincipal::Caller(principal) => Some(format!("|{principal}")),
        CachePrincipal::Anonymous => Some(String::new()),
        CachePrincipal::Unresolved => None,
    }
}

/// Count and log one response-cache bypass for an `Unresolved` caller (A0 D4).
/// Called once per call the cache would otherwise have served, so the read and
/// the write that both skip do not count twice. `route` mirrors the
/// idempotency skip counter's label.
pub(super) fn note_cache_bypass(principal: &CachePrincipal, route: &'static str) {
    if *principal == CachePrincipal::Unresolved {
        tracing::warn!(
            route,
            "Response cache bypassed: unresolved caller principal"
        );
        telemetry_metrics::counter!(
            "mcp_cache_bypass_total",
            "reason" => "unresolved_principal",
            "route" => route
        )
        .increment(1);
    }
}

/// Who the response cache keys on, namespaced by the evidence it came from.
///
/// One tagged, length-prefixed namespace per source, so two different kinds of
/// principal cannot collide by spelling: an identity-propagation
/// `cache_binding`, else the verified OIDC actor, else the caller's own
/// `GrantSubject` (authority + subject). The `GrantSubject` arm is what
/// separates two callers on a deployment that derives identity from trusted
/// headers, mTLS or an OAuth agent and runs with identity propagation off and
/// no OIDC — the shipped default, where every caller previously keyed as
/// `None` and shared one entry.
///
/// Last, for an authenticated caller only, the credential digest
/// (`AuthenticatedClient::principal`, a digest of the validated secret, never
/// the operator-chosen key name): two API keys, or the admin bearer, stop
/// sharing one entry. An authenticated caller no arm names is `Unresolved`;
/// only an anonymous one joins the pooled namespace.
///
/// The binding is copied opaquely, never re-hashed and never trimmed: it is
/// already the resolver's digest, and the same string is what the capability
/// executor copies into the inner key.
pub(super) fn caller_cache_principal(
    cache_binding: Option<&str>,
    verified_identity: Option<&crate::key_server::oidc::VerifiedIdentity>,
    grant_subject: Option<&crate::identity_grants::GrantSubject>,
    credential_principal: Option<&str>,
    authentication: Authentication,
) -> CachePrincipal {
    if let Some(binding) = cache_binding {
        return CachePrincipal::Caller(format!("idp:{}:{binding}", binding.len()));
    }
    if let Some(actor) =
        verified_identity.map(crate::key_server::oidc::VerifiedIdentity::stable_actor_id)
    {
        return CachePrincipal::Caller(format!("oidc:{}:{actor}", actor.len()));
    }
    if let Some(subject) = grant_subject {
        return CachePrincipal::Caller(format!(
            "grant:{}:{}:{}:{}",
            subject.authority.len(),
            subject.authority,
            subject.subject.len(),
            subject.subject
        ));
    }
    match (
        authentication,
        crate::gateway::auth::authenticated_principal(
            authentication == Authentication::Authenticated,
            credential_principal,
        ),
    ) {
        (Authentication::Anonymous, _) => CachePrincipal::Anonymous,
        (Authentication::Authenticated, Some(digest)) => {
            CachePrincipal::Caller(format!("cred:{}:{digest}", digest.len()))
        }
        (Authentication::Authenticated, None) => CachePrincipal::Unresolved,
    }
}

/// What a continuation binds a caller with no verified identity to (MIK-8078,
/// lead ruling A): the principal the idempotency guard keys that caller's
/// calls on, from the same [`caller_cache_principal`], so the two can never
/// name one caller two ways. A caller the guard cannot name binds to nothing
/// (`Credential(None)`), and no continuation is minted for it.
pub(super) fn key_binding<'a>(
    (cache_binding, grant_subject): (Option<&str>, Option<&crate::identity_grants::GrantSubject>),
    credential_principal: Option<&str>,
    authentication: Authentication,
) -> crate::protocol::mrtr::PrincipalSource<'a> {
    // Every input the guard reads but the verified identity, which binds
    // first, as its own scheme: a propagated identity or a proven subject
    // behind one shared key stays its own caller here, as in the guard.
    let principal = caller_cache_principal(
        cache_binding,
        None,
        grant_subject,
        credential_principal,
        authentication,
    );
    match principal {
        CachePrincipal::Caller(principal) => crate::protocol::mrtr::PrincipalSource::Key(principal),
        CachePrincipal::Anonymous | CachePrincipal::Unresolved => {
            crate::protocol::mrtr::PrincipalSource::Credential(None)
        }
    }
}

/// The owner key an authenticated caller's MCP child is named by when nothing
/// else names it (MIK-7825): `credential:<principal>`, the string a task records
/// as its owner (`handlers::tasks::session_owner_key`). A live request carries
/// the bare principal (hex, or a fixed label: never a colon); a background
/// task's rebuilt caller carries that recorded owner, already prefixed. Both
/// map to one key, so a call and the task it starts reach one child.
///
/// `None` unless the request authenticated: with authentication off the
/// principal is a gateway constant, not a caller.
pub(super) fn credential_owner(caller: &super::MetaMcpCallerContext<'_>) -> Option<String> {
    let principal = crate::gateway::auth::authenticated_principal(
        caller.authentication == Authentication::Authenticated,
        caller.credential_principal,
    )?;
    let prefix = crate::gateway::auth::CREDENTIAL_OWNER_PREFIX;
    Some(if principal.starts_with(prefix) {
        principal.to_owned()
    } else {
        format!("{prefix}{principal}")
    })
}

/// The principal a caller owns its keyed calls by when it has no routed task
/// owner: its credential (never text carrying the reserved local-operator
/// prefix), else its proven subject. One function for the meta route and the
/// direct route (MIK-8154), so the two cannot spell one caller apart.
pub(super) fn credential_or_subject_owner<'a>(
    credential_principal: Option<&'a str>,
    grant_subject: Option<&crate::identity_grants::GrantSubject>,
    caller_key: Option<&'a str>,
) -> Option<&'a str> {
    credential_principal
        .filter(|text| !text.is_empty() && !text.starts_with(super::LOCAL_OPERATOR_PREFIX))
        .or_else(|| proven_subject_owner(grant_subject, caller_key))
}

/// The execution principal a keyed call is admitted under (MIK-8382
/// UNIFY.1a′): the routed admission owner (verified identity, agent, proven
/// subject or credential, as `route_owners` resolves it; the pooled
/// anonymous owner is none), else [`credential_or_subject_owner`]. The ONE
/// definition the intake check and admission share, so the intake cannot
/// refuse a caller admission would admit.
pub(super) fn execution_principal<'a>(
    owner: super::AdmissionOwner<'a>,
    credential_principal: Option<&'a str>,
    grant_subject: Option<&crate::identity_grants::GrantSubject>,
    caller_key: Option<&'a str>,
) -> Option<&'a str> {
    owner
        .principal()
        .or_else(|| credential_or_subject_owner(credential_principal, grant_subject, caller_key))
}

/// The refusal of a keyed call with no execution principal, -32003. Its text
/// is written here only, so the intake and admission answer it alike.
pub(super) fn no_execution_principal() -> crate::Error {
    crate::Error::json_rpc(-32003, "A verified execution principal is required")
}

/// The intake check (MIK-8382 UNIFY.1a′): a keyed `tools/call` with an id
/// from a caller with no execution principal is refused here, before any
/// backend lookup, tool judgement or backend work, so its answer is one for
/// every tool and backend name. `None` lets the request go on.
pub(crate) fn intake_refusal(
    request: &serde_json::Value,
    owner: super::AdmissionOwner<'_>,
    credential_principal: Option<&str>,
    grant_subject: Option<&crate::identity_grants::GrantSubject>,
    caller_key: Option<&str>,
) -> Option<crate::Error> {
    (crate::protocol::mrtr::intake_requires_principal(request)
        && execution_principal(owner, credential_principal, grant_subject, caller_key).is_none())
    .then(no_execution_principal)
}

/// The proven subject a caller with no credential owns its keyed calls by
/// (MIK-7688): an OAuth agent (its client id) or a client certificate (its
/// SAN URI, else its CN), as the router's `caller_key` encodes them. Never a
/// header identity, and never a certificate naming no subject: its
/// `caller_key` is then no subject key.
fn proven_subject_owner<'a>(
    grant_subject: Option<&crate::identity_grants::GrantSubject>,
    caller_key: Option<&'a str>,
) -> Option<&'a str> {
    let authority = grant_subject?.authority.as_str();
    if !matches!(authority, "agent_oauth" | "mtls") {
        return None;
    }
    caller_key.filter(|key| key.starts_with("subject:"))
}

/// Build the response-cache key for a `gateway_invoke` call.
///
/// One function rather than the expression repeated at the read and the write:
/// a key derived in two places is a key that can be derived two ways, and a
/// write that lands under a key no read computes is a cache that never hits
/// while looking exactly like one that does.
///
/// The retry discriminator is the MRTR.10 binding. A retry reuses the original
/// call's arguments, so without it two continuations answering the same gate
/// differently share one entry and the first answer is served for the second.
///
/// `context` is forwarded, not consumed here: the routing profile, protocol
/// revision and policy generation belong to the key the cache layer derives,
/// so this passes them down rather than mixing a discriminator of its own.
///
/// `None` for an `Unresolved` principal: no key means no `get` and no `set`.
pub(super) fn response_cache_key_for(
    server: &str,
    tool: &str,
    arguments: &Value,
    projection_key_suffix: &str,
    principal: &CachePrincipal,
    retry: &crate::protocol::mrtr::RetryFields,
    context: crate::cache::KeyContext<'_>,
) -> Option<String> {
    let principal = match principal {
        CachePrincipal::Caller(principal) => Some(principal.as_str()),
        CachePrincipal::Anonymous => None,
        CachePrincipal::Unresolved => return None,
    };
    let base = crate::cache::ResponseCache::response_key(
        server,
        tool,
        arguments,
        projection_key_suffix,
        principal,
        context,
    );
    Some(format!("{base}{}", retry.key_discriminator()))
}

// ============================================================================
// Tag collection
// ============================================================================

/// Extract keyword tags from a tool's description into `out`.
///
/// Tags are parsed from the `[keywords: tag1, tag2, ...]` suffix appended by
/// `CapabilityDefinition::to_mcp_tool()`. Tags are lowercased and hyphen-split
/// parts are also collected so both "entity-discovery" and "entity" are indexed.
pub(super) fn collect_tool_tags(tool: &crate::protocol::Tool, out: &mut Vec<String>) {
    let Some(desc) = tool.description.as_deref() else {
        return;
    };
    let Some(kw_start) = desc.find("[keywords:") else {
        return;
    };
    let section = &desc[kw_start..];
    let inner = section
        .trim_start_matches("[keywords:")
        .trim_end_matches(']');
    for tag in inner.split(',') {
        let tag = tag.trim().to_lowercase();
        if !tag.is_empty() {
            // Also push hyphen-split parts (e.g. "entity-discovery" → "entity", "discovery")
            for part in tag.split('-') {
                let part = part.trim();
                if !part.is_empty() {
                    out.push(part.to_string());
                }
            }
            out.push(tag);
        }
    }
}

/// Tag collector for Code Mode search (alias; delegates to the existing implementation).
///
/// Exists so that `code_mode_search` can call a descriptively named function without
/// duplicating the tag-parsing logic from `collect_tool_tags`.
pub(super) fn collect_tool_tags_for_code_mode(tool: &crate::protocol::Tool, out: &mut Vec<String>) {
    collect_tool_tags(tool, out);
}

// ============================================================================
// Code Mode JSON conversion
// ============================================================================

/// Convert a Code Mode search result JSON object into a [`crate::ranking::SearchResult`].
///
/// Code Mode matches use `"tool": "server:name"` format; this function splits
/// on the first `:` to recover server and `tool_name` for the ranker.
pub(super) fn json_to_code_mode_search_result(v: &Value) -> Option<crate::ranking::SearchResult> {
    use crate::gateway::meta_mcp_helpers::parse_code_mode_tool_ref;
    let tool_ref = v.get("tool")?.as_str()?;
    let description = v.get("description")?.as_str().unwrap_or("").to_string();
    let (tool_name, server_opt) = parse_code_mode_tool_ref(tool_ref);
    let server = server_opt?.to_string();
    let mut result = crate::ranking::SearchResult::new(server, tool_name, description);
    result.signals = crate::ranking::RankingSignals::from_json(v);
    Some(result)
}

/// Reconstruct ranked Code Mode results from ranked `SearchResult` objects.
///
/// After ranking, the schema must be re-fetched from the original matches list
/// (the ranker only carries name/description/score). This function rebuilds each
/// match JSON by looking up the original entry by its `"tool"` field.
pub(super) fn ranked_results_to_code_mode_json(
    ranked: Vec<crate::ranking::SearchResult>,
    explain: bool,
    originals: &[Value],
) -> Vec<Value> {
    ranked
        .into_iter()
        .filter_map(|r| {
            let tool_ref = format!("{}:{}", r.server, r.tool);
            // Find the original entry to preserve the schema field
            originals
                .iter()
                .find(|v| v.get("tool").and_then(Value::as_str) == Some(&tool_ref))
                .cloned()
                .map(|mut value| {
                    if let Value::Object(ref mut map) = value {
                        map.insert("score".to_string(), json!(r.score));
                        if explain {
                            map.insert(
                                "ranking".to_string(),
                                crate::gateway::search_disclosure::ranking_debug_object(&r),
                            );
                        }
                    }
                    value
                })
        })
        .collect()
}

/// Signals that are the same for every tool in every response.
///
/// Measured 2026-07-31 on a live `gateway_search` call: 13 of 16 signals were
/// the constant `1.0`. A signal that never varies distinguishes nothing — it is
/// scoring-engine diagnostics shipped to a consumer that cannot act on it, on
/// the repository whose stated value proposition is token savings.
const CONSTANT_SIGNALS: &[&str] = &[
    "cost_efficiency",
    "freshness",
    "grant",
    "latency",
    "organization_preference",
    "permission_fit",
    "policy_fit",
    "risk",
    "runtime_health",
    "safety",
    "success_rate",
    "trust",
    "user_preference",
];

/// Drop the signals that carry no information.
///
/// Named rather than a value test, deliberately. Dropping every field that
/// happens to equal `1.0` would drop a real score sitting at its maximum —
/// `relevance` does that legitimately — and the caller would lose the one
/// number that told it something. The list is what was measured, not what a
/// heuristic guessed.
#[must_use]
pub fn prune_constant_signals(ranking: &Value) -> Value {
    let mut pruned = ranking.clone();
    if let Some(signals) = pruned.get_mut("signals").and_then(Value::as_object_mut) {
        signals.retain(|name, _| !CONSTANT_SIGNALS.contains(&name.as_str()));
    }
    pruned
}

// ============================================================================
// Response augmentation
// ============================================================================

/// MIK-7939: the gateway wrote `path` of an invoke result; a relay receipt
/// leaves it out.
fn note_written(path: &'static [&'static str], result: &Value) {
    use super::invoke::gateway_writes::{Layer, note};
    note(Layer::Value, path, result);
}

/// Attach `_predicted_next` to an invoke result when predictions are available.
///
/// If `predictions` is empty the original `result` is returned unchanged,
/// preserving the zero-cost fast path for sessions without enough history.
pub(super) fn augment_with_predictions(mut result: Value, predictions: Vec<Value>) -> Value {
    if predictions.is_empty() {
        return result;
    }
    super::invoke::gateway_writes::insert_noted(
        super::invoke::gateway_writes::Layer::Value,
        &["_predicted_next"],
        &mut result,
        Value::Array(predictions),
    );
    result
}

/// Attach `_trace_id` to an invoke result so callers can correlate gateway logs
/// with backend logs.
///
/// The `_trace_id` is always inserted; this function never returns the original
/// `result` unmodified (the contract guarantees the field is present).
pub(super) fn augment_with_trace(mut result: Value, trace_id: &str) -> Value {
    if let Value::Object(ref mut map) = result {
        map.insert("_trace_id".to_string(), json!(trace_id));
    }
    note_written(&["_trace_id"], &result);
    result
}

/// Opaque, non-reversible reference to an auth-context label.
///
/// The gateway's `api_key_name` is a config-chosen label, not a credential, but
/// the receipt contract stores only a *reference* — never a raw identifier — so
/// nothing sensitive can ever reach the `_meta` channel (CWE-532, rung 1.5).
fn auth_context_ref_hash(name: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(name.as_bytes());
    format!("sha256:{}", hex::encode(&digest[..8]))
}

/// Stamp a signed runtime provenance receipt into `result._meta.provenance`
/// (MIK-6905, rung 1.2/1.4).
///
/// Additive only: the receipt lands under the MCP `_meta` channel and no tool
/// content is touched. Facts observed at the gateway — backend, tool, auth-ref,
/// cache outcome, backend success — are recorded and signed; nothing is
/// inferred (rung 1.4).
///
/// Also returns the [`SignedResultProvenance`] alongside the stamped value —
/// this is the same object embedded in `_meta.provenance`, returned again so
/// the caller (`maybe_stamp_provenance`, MIK-6908 rung 3.1) can hand it to the
/// shadow claim-capture sink without re-deriving or re-parsing it out of the
/// JSON it was just serialized into.
#[allow(
    clippy::too_many_arguments,
    reason = "one receipt's facts, each passed as observed"
)]
pub(super) fn augment_with_provenance(
    mut result: Value,
    signer: &crate::attestation::signer::BnautAttestationSigner,
    backend_id: &str,
    tool: &str,
    api_key_name: Option<&str>,
    cache: crate::trust::CacheOutcome,
    backend_ok: bool,
    observed_at: String,
) -> (Value, crate::trust::SignedResultProvenance) {
    use crate::trust::RuntimeProvenanceReceipt;

    let mut receipt =
        RuntimeProvenanceReceipt::observed(backend_id, tool, observed_at, cache, backend_ok);
    if let Some(name) = api_key_name {
        receipt = receipt.with_auth_context_ref(auth_context_ref_hash(name));
    }
    // Option A ground truth (MIK-6914): when a per-backend extractor recognises
    // this `(backend, tool)` and can read a genuine authoritative count from the
    // result, record it as the observed `row_count`. Every unrecognised backend
    // returns `None`, so the receipt keeps the honest "not observed" floor and
    // no count is ever fabricated (the MIK-5854 stop-line).
    if let Some(row_count) = crate::trust::extract_row_count(backend_id, tool, &result, backend_ok)
    {
        receipt = receipt.with_row_count(row_count);
    }
    // Join key: the active call's trace_id (also returned to the client as
    // `result._trace_id`), so the receipt is self-joinable to the agent's claim.
    // Absent on paths with no trace scope (e.g. direct backend route).
    if let Some(trace_id) = crate::gateway::trace::current() {
        receipt = receipt.with_call_id(trace_id);
    }
    let signed_receipt = receipt.sign(signer);
    let prov_value = serde_json::to_value(&signed_receipt).unwrap_or(Value::Null);

    if let Value::Object(ref mut map) = result {
        let meta = map
            .entry("_meta")
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
        if let Value::Object(meta_map) = meta {
            meta_map.insert("provenance".to_string(), prov_value);
        }
    }
    note_written(&["_meta", "provenance"], &result);
    (result, signed_receipt)
}

/// Remove a backend-supplied `_meta.provenance` receipt from `result`.
///
/// The gateway authors provenance receipts only when stamping is enabled. With
/// stamping OFF, any `_meta.provenance` present was injected by the backend, and
/// a naive reader could mistake a backend-forged receipt for a gateway-signed
/// one (MIK-6909). Stripping it on the off path closes that spoofing surface so
/// the `_meta.provenance` channel means "gateway-authored" or nothing.
///
/// Honest backends never set this key, so the common case is a no-op and the
/// "byte-identical with the feature off" guarantee still holds. Only the
/// `provenance` key is removed — other `_meta` entries (e.g. cache keys) are
/// preserved — and an `_meta` object left empty by the removal is dropped so no
/// stray `{}` appears where the backend sent none.
pub(super) fn strip_backend_provenance(mut result: Value) -> Value {
    if let Value::Object(ref mut map) = result
        && let Some(Value::Object(meta_map)) = map.get_mut("_meta")
        && meta_map.remove("provenance").is_some()
        && meta_map.is_empty()
    {
        map.remove("_meta");
    }
    result
}

#[path = "playbook_invoker.rs"]
mod playbook_invoker;
pub(super) use playbook_invoker::MetaMcpInvoker;
#[cfg(test)]
use playbook_invoker::internal_invoke_args;
pub(crate) use playbook_invoker::{
    STEP_NOT_PERMITTED, STEP_NOT_PERMITTED_CODE, STEP_NOT_PERMITTED_STATUS, step_not_permitted,
};

#[cfg(test)]
#[path = "support_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "idempotency_caller_scope_tests.rs"]
mod idempotency_caller_scope_tests;

#[cfg(test)]
#[path = "retry_input_tests.rs"]
mod retry_input_tests;

#[cfg(test)]
#[path = "cache_principal_tests.rs"]
mod cache_principal_tests;

#[cfg(test)]
#[path = "proven_owner_tests.rs"]
mod proven_owner_tests;
