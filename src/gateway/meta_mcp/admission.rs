// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Request-owned synchronous admission and secured HTTP settlement.

use parking_lot::Mutex;
use serde_json::{Value, json};

use crate::idempotency::admission::{Admission, Lease, Mode, Refusal, Request};
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::security::audit::AuditOutcome;
use crate::{Error, Result};

use super::MetaMcp;
use super::effects::{Effect, meta_tool_effect};

#[path = "admission_plan.rs"]
mod plan;

/// Borrowed by inner dispatches, owned by the outer request future. Dropping the
/// future drops its one lease, including after a transport cancellation.
pub(crate) struct SyncLease {
    state: Mutex<(Lease, bool)>,
    playbook: Option<crate::playbook::PlaybookDefinition>,
    /// The invocation record's facts about this execution, kept for a replay.
    audit: Mutex<Option<ReplayAudit>>,
}

impl SyncLease {
    /// The same immutable definition supplied both preflight and fingerprinting.
    pub(super) fn playbook_definition(&self) -> Option<&crate::playbook::PlaybookDefinition> {
        self.playbook.as_ref()
    }

    /// #2472: what this execution's invocation record said, so a replay of
    /// it is recorded the same way. The last invocation under the lease wins.
    pub(crate) fn note_audit(&self, audit: ReplayAudit) {
        *self.audit.lock() = Some(audit);
    }

    pub(crate) fn mark_dispatched(&self) {
        let mut state = self.state.lock();
        state.0.mark_dispatched();
        state.1 = true;
    }

    /// The HTTP owner calls this only after the existing response security
    /// pipeline. No backend value can settle admission on its own.
    #[cfg(test)]
    pub(crate) fn complete_secured(self, response: &JsonRpcResponse) {
        self.complete_delivery(response, None);
    }

    pub(crate) fn complete_delivery(
        self,
        response: &JsonRpcResponse,
        signing: Option<&super::signing::SigningInvocationContext>,
    ) {
        let (lease, dispatched) = self.state.into_inner();
        let audit = self.audit.into_inner();
        if !dispatched
            || response.result.as_ref().is_some_and(|result| {
                crate::protocol::mrtr::InputRequired::claims_input_required(result)
            })
        {
            return;
        }
        // Transport correlation never belongs to retained operation state.
        let mut secured = response.to_value_lossy();
        secured["id"] = Value::Null;
        // Only the private external signing origin can identify gateway metadata.
        // Backend business fields on other routes are never stripped by shape.
        if signing.is_some_and(super::signing::SigningInvocationContext::owns_signature)
            && let Some(result) = secured.get_mut("result").and_then(Value::as_object_mut)
        {
            result.remove("_signature");
        }
        // A link binds one delivery's nonce and time; a replay mints its own.
        if let Some(result) = secured.get_mut("result") {
            crate::security::signature_chain::strip_chain(result);
        }
        // A chained backend's upstream links answered this request's nonce, so
        // its replay is never linked (inc3 R8).
        let chain = match response.chain_source {
            _ if response.chain_upstream.is_some() => StoredChain::ChainedBackend,
            crate::protocol::ChainSource::Backend => StoredChain::Backend,
            _ => StoredChain::NotEligible,
        };
        let stored = StoredDelivery {
            response: secured,
            chain,
            audit,
        };
        lease.complete_secured(&serde_json::to_value(stored).unwrap_or(Value::Null));
    }
}

/// What a sync admission stores: the secured response plus its server-owned
/// chain eligibility, which the response's own serialization never carries.
#[derive(serde::Serialize, serde::Deserialize)]
struct StoredDelivery {
    response: Value,
    /// Absent in records written before the chain existed: never eligible.
    #[serde(default)]
    chain: StoredChain,
    /// Absent in records written before #2472, and for calls that wrote no
    /// invocation record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    audit: Option<ReplayAudit>,
}

/// #2472: the first execution's invocation-record outcome and response hash,
/// stored server-side beside its secured response. The response a replay
/// delivers is the wrapped, post-delivery form, so neither can be derived
/// from it: a wrapped tool error reads as a success.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct ReplayAudit {
    outcome: StoredOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    response_hash: Option<String>,
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum StoredOutcome {
    Ok,
    ToolError,
    Denied(i32),
    Invalid(i32),
    Error(i32),
}

impl ReplayAudit {
    pub(crate) fn new(outcome: AuditOutcome, response_hash: Option<String>) -> Self {
        let outcome = match outcome {
            AuditOutcome::Ok => StoredOutcome::Ok,
            AuditOutcome::ToolError => StoredOutcome::ToolError,
            AuditOutcome::Denied(code) => StoredOutcome::Denied(code),
            AuditOutcome::Invalid(code) => StoredOutcome::Invalid(code),
            AuditOutcome::Error(code) => StoredOutcome::Error(code),
        };
        Self {
            outcome,
            response_hash,
        }
    }

    pub(crate) fn outcome(&self) -> AuditOutcome {
        match self.outcome {
            StoredOutcome::Ok => AuditOutcome::Ok,
            StoredOutcome::ToolError => AuditOutcome::ToolError,
            StoredOutcome::Denied(code) => AuditOutcome::Denied(code),
            StoredOutcome::Invalid(code) => AuditOutcome::Invalid(code),
            StoredOutcome::Error(code) => AuditOutcome::Error(code),
        }
    }

    pub(crate) fn response_hash(&self) -> Option<&str> {
        self.response_hash.as_deref()
    }
}

#[derive(serde::Serialize, serde::Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum StoredChain {
    Backend,
    /// A chained backend's result (inc3 R8): its upstream links answered
    /// another request's nonce, so a replay is never linked.
    ChainedBackend,
    #[default]
    NotEligible,
}

/// Decode a stored delivery; a bare response is a record from before the
/// envelope and replays without a link.
fn stored_response(bytes: &[u8]) -> Option<(JsonRpcResponse, Option<ReplayAudit>)> {
    if let Ok(stored) = serde_json::from_slice::<StoredDelivery>(bytes) {
        let mut response: JsonRpcResponse = serde_json::from_value(stored.response).ok()?;
        if stored.chain == StoredChain::Backend {
            response.chain_source = crate::protocol::ChainSource::Replay;
        }
        return Some((response, stored.audit));
    }
    serde_json::from_slice(bytes)
        .ok()
        .map(|response| (response, None))
}

pub(crate) enum SyncAdmission {
    Unprotected,
    Owned(SyncLease),
    /// A completed execution's secured response, and its record facts.
    Replay(JsonRpcResponse, Option<ReplayAudit>),
}

/// Gateway controls have the same meaning at both external execution routes.
pub(crate) fn execution_arguments(arguments: &mut Value) -> bool {
    let full = arguments
        .get("_full")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if let Some(object) = arguments.as_object_mut() {
        object.remove("_full");
        object.remove("_claim");
    }
    full
}

impl MetaMcp {
    pub(crate) fn read_only_target(&self, server: &str, tool: &str) -> bool {
        if let Some(context) = self.reload_context() {
            context
                .live_config
                .get()
                .idempotency
                .is_read_only(server, tool)
        } else {
            self.idempotency_config.read().is_read_only(server, tool)
        }
    }

    /// Authorization and ordinary argument sanitization precede this call.
    /// Only validated identity objects and credential principals reach it.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn admit_sync(
        &self,
        is_modern: bool,
        verified_identity: Option<&crate::key_server::oidc::VerifiedIdentity>,
        credential_principal: Option<&str>,
        retry: &crate::protocol::mrtr::RetryFields,
        server: &str,
        tool: &str,
        arguments: &Value,
        representation: impl FnOnce() -> Value,
        request_id: &RequestId,
    ) -> Result<SyncAdmission> {
        self.admit_operation(
            is_modern,
            verified_identity,
            credential_principal,
            retry,
            || {
                json!({
                    "kind": "backend", "server": server, "tool": tool, "arguments": arguments,
                    "retry": retry.key_discriminator(),
                })
            },
            representation,
            self.read_only_target(server, tool),
            (server, tool),
            request_id,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn admit_operation(
        &self,
        is_modern: bool,
        verified_identity: Option<&crate::key_server::oidc::VerifiedIdentity>,
        credential_principal: Option<&str>,
        retry: &crate::protocol::mrtr::RetryFields,
        // A THUNK, not a value. Building the operation envelope deep-copies
        // `arguments`, and the two early returns below discard it: a call with
        // no idempotency key resolves to `Unprotected` without ever reading it.
        // Paying for that copy before the branch that decides whether it is
        // needed is what this parameter exists to avoid (NFR.WORKLOAD.1).
        operation: impl FnOnce() -> Value,
        // A thunk for the same reason: the unkeyed path never reads it (#613).
        representation: impl FnOnce() -> Value,
        read_only: bool,
        // (backend, tool) for the un-keyed warn only; never an identity.
        target: (&str, &str),
        request_id: &RequestId,
    ) -> Result<SyncAdmission> {
        if retry.is_malformed() {
            return Err(Error::json_rpc(
                -32602,
                "Malformed execution retry metadata",
            ));
        }
        let Some(key) = retry.idempotency_key.as_deref() else {
            // A call carrying no key cannot be recognised as a re-issue, so a
            // refusal protects nothing; it is admitted unprotected, as legacy
            // frames always were. `required` restores the refusal for
            // deployments whose modern clients all send keys (F10, ADR-012).
            if is_modern
                && !read_only
                && *self.unkeyed.mode.read() == crate::config::IdempotencyKeyMode::Required
            {
                return Err(Error::json_rpc(
                    -32602,
                    format!(
                        "An explicit idempotency key is required: set _meta \"{}\" \
                         (server.idempotency_key: required)",
                        crate::protocol::mrtr::IDEMPOTENCY_KEY_META
                    ),
                ));
            }
            self.record_unkeyed(is_modern, read_only, target);
            return Ok(SyncAdmission::Unprotected);
        };
        let principal = verified_identity
            .map(crate::key_server::oidc::VerifiedIdentity::stable_actor_id)
            .or_else(|| {
                credential_principal
                    .filter(|value| !value.is_empty())
                    .map(str::to_owned)
            })
            .ok_or_else(|| Error::json_rpc(-32003, "A verified execution principal is required"))?;
        let operation = operation();
        let representation = representation();
        let request = Request {
            principal: &principal,
            key,
            operation: &operation,
            representation: &representation,
            mode: Mode::Sync,
        };
        let round = retry.key_discriminator();
        let admission = if round.is_empty() {
            self.execution_admission().admit(request)
        } else {
            self.execution_admission().admit_round(request, &round)
        };
        match admission {
            Ok(Admission::Owned(lease)) => Ok(SyncAdmission::Owned(SyncLease {
                state: Mutex::new((lease, false)),
                playbook: None,
                audit: Mutex::new(None),
            })),
            Ok(Admission::Replay(bytes)) => {
                let (mut response, audit) = stored_response(&bytes).ok_or_else(|| {
                    Error::json_rpc(409, "Secured execution result is unavailable")
                })?;
                response.id = Some(request_id.clone());
                Ok(SyncAdmission::Replay(response, audit))
            }
            Ok(Admission::InFlight) => {
                Err(Error::json_rpc(409, "Execution is already in progress"))
            }
            Ok(Admission::Unavailable) => Err(Error::json_rpc(
                409,
                "Secured execution result is unavailable",
            )),
            Err(Refusal::Mismatch) => Err(Error::json_rpc(
                409,
                "Idempotency key belongs to another execution or representation",
            )),
            Err(Refusal::InvalidIdentity | Refusal::MetadataTooLarge) => Err(Error::json_rpc(
                -32602,
                "Invalid execution admission metadata",
            )),
            Err(Refusal::Capacity | Refusal::ExpiryOverflow) => Err(Error::json_rpc(
                -32000,
                "Execution admission is unavailable",
            )),
        }
    }

    /// The policy a retained result must pass before it is served: the
    /// invocation policy of a `gateway_invoke` or surfaced-tool target (#2445).
    /// Returns the target, if the call names one.
    fn check_target_policy<'v>(
        &'v self,
        caller: &super::MetaMcpCallerContext<'_>,
        tool_name: &'v str,
        arguments: &'v Value,
        session: Option<&str>,
    ) -> Result<Option<(&'v str, &'v str, Value)>> {
        let target = if tool_name == "gateway_invoke" {
            let server =
                crate::gateway::meta_mcp_helpers::extract_required_str(arguments, "server")?;
            let tool = crate::gateway::meta_mcp_helpers::extract_required_str(arguments, "tool")?;
            Some((
                server,
                tool,
                crate::gateway::meta_mcp_helpers::parse_tool_arguments(arguments)?,
            ))
        } else {
            self.surfaced_tool_server(tool_name)
                .map(|server| (server, tool_name, arguments.clone()))
        };
        if let Some((server, tool, operation_arguments)) = &target {
            let (server, tool) = (*server, *tool);
            if !caller
                .signing
                .is_some_and(|context| context.prepared_for(server, tool))
            {
                // `gateway_invoke` already arrives as a policy envelope, and it
                // carries fields the synthesized one cannot reconstruct — the
                // attestation token among them. Rebuilding it here dropped the
                // token before enforcement could see it, so a correctly signed
                // call was refused as unattested. A surfaced tool has no such
                // envelope, so that branch still synthesizes one.
                let synthesized;
                let envelope = if tool_name == "gateway_invoke" {
                    arguments
                } else {
                    synthesized = named_tool_envelope(server, tool, operation_arguments, caller);
                    &synthesized
                };
                if tool_name != "gateway_invoke"
                    && let Some(absent) = self.withheld_surfaced(server, tool, caller, session)
                {
                    return Err(absent);
                }
                self.check_invocation_policy(envelope, session, caller)?;
            }
        }
        Ok(target)
    }

    /// #2450: a task-augmented call skips `admit_meta_sync`, but its durable
    /// admission can answer a repeat from the stored task, so the same policy
    /// runs first: the target's invocation policy, else the keyed plan check.
    pub(crate) fn check_task_admission_policy(
        &self,
        caller: &super::MetaMcpCallerContext<'_>,
        tool_name: &str,
        arguments: &Value,
        session: Option<&str>,
    ) -> Result<()> {
        if self
            .check_target_policy(caller, tool_name, arguments, session)?
            .is_none()
        {
            self.authorize_execution_plan(caller, tool_name, arguments, session)?;
        }
        Ok(())
    }

    /// Protect one outer logical meta invocation, including all its inner steps.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn admit_meta_sync(
        &self,
        caller: &super::MetaMcpCallerContext<'_>,
        tool_name: &str,
        arguments: &Value,
        session: Option<&str>,
        id: &RequestId,
    ) -> Result<SyncAdmission> {
        let is_modern = caller.is_modern;
        // These operations cannot execute on a sessionless protocol. Preserve
        // their protocol refusal before asking for or reserving a retry key.
        if is_modern {
            match tool_name {
                "gateway_set_profile" => {
                    return Err(Error::Protocol(super::NO_SESSION_FOR_PROFILE.to_string()));
                }
                "gateway_set_state" => {
                    return Err(Error::Protocol(super::NO_SESSION_FOR_STATE.to_string()));
                }
                _ => {}
            }
        }
        let verified_identity = caller.verified_identity;
        // The key owner, not a display principal: for stdio it is the reserved
        // owner value (MIK-7272.OWNER.3), never `STDIO_CREDENTIAL_PRINCIPAL`.
        let owner_principal = caller.owner_principal();
        let retry = caller.retry;
        // The arm the dispatch will use, so a retry's representation names it.
        let arm_key = caller.experiment_key(session);
        if let Some((server, tool, mut operation_arguments)) =
            self.check_target_policy(caller, tool_name, arguments, session)?
        {
            let full = execution_arguments(&mut operation_arguments);
            return self.admit_sync(
                is_modern,
                verified_identity,
                owner_principal,
                retry,
                server,
                tool,
                &operation_arguments,
                || self.meta_representation(tool_name, full, session, arm_key),
                id,
            );
        }
        // These compiled discovery/reporting tools do not execute external work.
        // Backend annotations and operator target strings cannot add built-ins.
        let read_only = meta_tool_effect(tool_name) == Effect::ReadOnly;
        // A retained result is still protected by today's authorization. Plan
        // loading and every target check precede lookup, including mismatches.
        let playbook = self.authorize_execution_plan(caller, tool_name, arguments, session)?;
        let mut operation = json!({"kind": "gateway", "tool": tool_name,
            "arguments": arguments, "retry": retry.key_discriminator()});
        if let Some(definition) = &playbook {
            let value = serde_json::to_value(definition)
                .map_err(|_| Error::json_rpc(-32603, "Invalid playbook definition"))?;
            // Keep the bounded admission envelope independent of plan size.
            operation["playbook"] = json!(crate::hashing::canonical_json_sha256(&value));
        }
        let mut admission = self.admit_operation(
            is_modern,
            verified_identity,
            owner_principal,
            retry,
            // Already built above, because the playbook digest folds into it.
            // Handed over as a thunk to match the parameter; the saving on this
            // path is the callee's, not the caller's.
            || operation,
            || self.meta_representation(tool_name, false, session, arm_key),
            read_only,
            ("gateway", tool_name),
            id,
        )?;
        if let SyncAdmission::Owned(lease) = &mut admission {
            lease.playbook = playbook;
        }
        Ok(admission)
    }

    pub(crate) fn meta_representation(
        &self,
        tool_name: &str,
        full: bool,
        session: Option<&str>,
        // `MetaMcpCallerContext::experiment_key`: the arm keys on the caller (G4).
        arm_key: Option<&str>,
    ) -> Value {
        // `gateway_set_profile` changes the profile it would be bound to, so a
        // bound retry never matches its own stored result. Its output depends
        // on the target profile, which the operation already carries, and on
        // the session it names, so it is bound to that session instead.
        let profile = if tool_name == "gateway_set_profile" {
            json!({"session": super::session_key(session)})
        } else {
            self.active_profile(session).describe()
        };
        let mut representation = json!({
            "route": "meta", "tool": tool_name, "full": full,
            "projection": format!("{:?}", self.projection_mode),
            "profile": profile,
            "arm": crate::projection::projection_key_suffix(self.projection_mode, arm_key),
        });
        // State is session-local. Keep the active-profile binding above, and
        // additionally prevent one session from replaying another's result.
        if tool_name == "gateway_set_state" {
            representation["session"] = json!(super::session_key(session));
        }
        representation
    }

    /// Validate the six management branches before their first possible effect.
    /// Existing dispatch methods still own their validation and error wording.
    pub(super) fn mark_management_dispatch(
        &self,
        tool: &str,
        arguments: &Value,
        session: Option<&str>,
        execution: &SyncLease,
    ) -> Result<()> {
        use crate::gateway::meta_mcp_helpers::extract_required_str;
        match tool {
            "gateway_kill_server" | "gateway_revive_server" => {
                extract_required_str(arguments, "server")?;
            }
            "gateway_set_state" => {
                extract_required_str(arguments, "state")?;
                if super::session_key(session).is_none() {
                    return Err(Error::Protocol(super::NO_SESSION_FOR_STATE.to_string()));
                }
            }
            "gateway_set_profile" => {
                let name = extract_required_str(arguments, "profile")?;
                if super::session_key(session).is_none() {
                    return Err(Error::Protocol(super::NO_SESSION_FOR_PROFILE.to_string()));
                }
                if !self.profile_registry.contains(name) {
                    return Err(Error::Protocol("Unknown routing profile".into()));
                }
            }
            "gateway_reload_config" => {
                if self.get_reload_context().is_none() {
                    return Err(Error::json_rpc(
                        -32603,
                        "Config reload is not enabled on this gateway",
                    ));
                }
            }
            "gateway_reload_capabilities" => {
                if self.get_capabilities().is_none() {
                    return Err(Error::json_rpc(
                        -32603,
                        "Capability backend is not enabled on this gateway",
                    ));
                }
            }
            _ => return Ok(()),
        }
        execution.mark_dispatched();
        Ok(())
    }
}

/// `server.idempotency_key`, restart-scoped like the rest of `server`, and the
/// last warn time per (backend, tool) for un-keyed admissions.
#[derive(Default)]
pub(crate) struct UnkeyedPolicy {
    mode: parking_lot::RwLock<crate::config::IdempotencyKeyMode>,
    warned: Mutex<WarnedAt>,
}

impl MetaMcp {
    pub(crate) fn set_idempotency_key_mode(&self, mode: crate::config::IdempotencyKeyMode) {
        *self.unkeyed.mode.write() = mode;
    }

    /// Count every un-keyed admission, and warn about a MODERN one at most once
    /// per (backend, tool) per [`UNKEYED_WARN_INTERVAL`]. Labels carry no identity.
    fn record_unkeyed(&self, is_modern: bool, read_only: bool, (server, tool): (&str, &str)) {
        telemetry_metrics::counter!(
            "mcp_unkeyed_calls_total",
            "era" => if is_modern { "modern" } else { "legacy" },
            "gateway_read_only" => if read_only { "true" } else { "false" }
        )
        .increment(1);
        let now = std::time::Instant::now();
        if !is_modern || !first_warn(&mut self.unkeyed.warned.lock(), server, tool, now) {
            return;
        }
        tracing::warn!(
            backend = server,
            tool,
            gateway_read_only = read_only,
            "modern tools/call admitted without an idempotency key: a re-issue after a \
             broken stream may execute twice; set server.idempotency_key: required once \
             clients send _meta \"io.mcp-gateway/idempotency-key\""
        );
    }
}

/// Whether (server, tool) is due a warn at `now`, recording it if so. `now` is
/// a parameter so the eviction order can be tested without sleeping.
fn first_warn(warned: &mut WarnedAt, server: &str, tool: &str, now: std::time::Instant) -> bool {
    let key = (server.to_owned(), tool.to_owned());
    if warned
        .get(&key)
        .is_some_and(|last| now.duration_since(*last) < UNKEYED_WARN_INTERVAL)
    {
        return false;
    }
    // `gateway_invoke` names come from caller arguments: bound the map. Expired
    // entries go first; a map still full of live ones loses its oldest.
    if warned.len() >= UNKEYED_WARN_CAP {
        warned.retain(|_, last| now.duration_since(*last) < UNKEYED_WARN_INTERVAL);
    }
    if warned.len() >= UNKEYED_WARN_CAP
        && let Some(oldest) = warned
            .iter()
            .min_by_key(|(_, last)| **last)
            .map(|(k, _)| k.clone())
    {
        warned.remove(&oldest);
    }
    warned.insert(key, now);
    true
}

const UNKEYED_WARN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(600);
const UNKEYED_WARN_CAP: usize = 1024;

type WarnedAt = std::collections::HashMap<(String, String), std::time::Instant>;

#[cfg(test)]
#[path = "admission_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "admission_round_tests.rs"]
mod round_tests;

/// The policy envelope for a backend tool called by its own name.
///
/// Such a call has no `attestation` argument, so its token rides in
/// `params._meta["io.mcp-gateway/attestation"]`, parsed into `caller.retry`.
/// Admission and the invoke funnel both check an envelope built here, so the
/// two checks of one call see the same token (MIK-7570.ATTEST.1).
pub(super) fn named_tool_envelope(
    server: &str,
    tool: &str,
    arguments: &Value,
    caller: &super::MetaMcpCallerContext<'_>,
) -> Value {
    let mut envelope = json!({"server": server, "tool": tool, "arguments": arguments});
    if let Some(token) = &caller.retry.attestation {
        envelope["attestation"] = json!(token);
    }
    envelope
}
