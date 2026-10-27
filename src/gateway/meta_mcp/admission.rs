// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Request-owned synchronous admission and secured HTTP settlement.

use crate::error::rpc_codes::{INTERNAL_ERROR, INVALID_PARAMS};
use parking_lot::Mutex;
use serde_json::{Value, json};

use crate::idempotency::admission::{Admission, Lease, Mode, Refusal, Request, Settlement};
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::{Error, Result};

use super::MetaMcp;
use super::effects::{Effect, meta_tool_effect};
use super::warn_limit::{WarnedAt, first_warn};

#[path = "admission_plan.rs"]
mod plan;
#[path = "admission_replay.rs"]
mod replay;
pub(crate) use replay::{ReplayFacts, ReplayOrigin, ReplayTarget};
#[path = "admission_era.rs"]
mod era;
#[path = "admission_operation.rs"]
mod operation;
pub(crate) use operation::{OPERATION_DEFINING_META, operation_arguments};
#[path = "admission_stored.rs"]
mod stored;
use era::{refuse_another_era, shaped_for_request};
pub(crate) use stored::{ReplayAudit, StepBinding, note_distinct};
use stored::{StoredChain, StoredDelivery, stored_response};

/// Borrowed by inner dispatches, owned by the outer request future. Dropping the
/// future drops its one lease, including after a transport cancellation.
pub(crate) struct SyncLease {
    /// The lease and how many dispatches marked it: a composite marks once
    /// per step.
    state: Mutex<(Lease, u32)>,
    playbook: Option<crate::playbook::PlaybookDefinition>,
    /// The invocation record's facts about this execution, kept for a replay.
    audit: Mutex<Option<ReplayAudit>>,
    /// The steps this execution was served (sent, or answered from a stored
    /// or cached result), kept for a replay (#3872 FIX 1).
    steps: Mutex<Vec<(String, String)>>,
    /// The binding each step ran under (MIK-8407), kept for a replay.
    bindings: Mutex<Vec<stored::StepBinding>>,
    /// MIK-8747: the era its stored delivery is shaped for (meta path only).
    era: Option<crate::protocol::meta::Era>,
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

    /// Note the step `(server, tool)` this execution was served, once.
    pub(crate) fn note_step(&self, (server, tool): (&str, &str)) {
        let mut steps = self.steps.lock();
        if !steps.iter().any(|(s, t)| s == server && t == tool) {
            steps.push((server.to_owned(), tool.to_owned()));
        }
    }

    /// Note the binding `(server, tool)` is dispatched under, once per
    /// distinct binding: a step seen under two can match no single current
    /// one, so its replay refuses (MIK-8407).
    pub(crate) fn note_binding(&self, (server, tool): (&str, &str), binding: Option<&str>) {
        stored::note_distinct(&mut self.bindings.lock(), (server, tool), binding);
    }

    /// The steps noted so far, for the invoke stage rows (MIK-8488).
    #[cfg(test)]
    pub(crate) fn served_steps_for_test(&self) -> Vec<(String, String)> {
        self.steps.lock().clone()
    }

    pub(crate) fn mark_dispatched(&self) {
        let mut state = self.state.lock();
        state.0.mark_dispatched();
        state.1 = state.1.saturating_add(1);
    }

    /// A dispatch this lease marked was refused before the backend acted (a
    /// relay caught mid-exchange): unmark it, unless an earlier step of the
    /// same execution did act, whose protection stays.
    pub(crate) fn withdraw_dispatch(&self) {
        let mut state = self.state.lock();
        state.1 = state.1.saturating_sub(1);
        if state.1 == 0 {
            state.0.dispatched = false;
        }
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
    ) -> bool {
        let read = crate::security::tenant_reads::in_read_scope()
            .then(|| crate::security::tenant_reads::noted().unwrap_or_default());
        let writes = crate::gateway::gateway_writes::recorded();
        self.complete_delivery_read(response, signing, (read, writes))
    }

    /// [`Self::complete_delivery`] for a caller past its read scope: `read` is
    /// what the scope noted (`None` when no scope was open) and `writes` what
    /// the gateway wrote into the response (MIK-7991). The stdio route settles
    /// after its judge, outside the scope (MIK-7920). `true` when the
    /// delivery was retained, so a replay can serve it (`MIK-8408` E1: only
    /// a retained plan delivery's receipts are captured).
    pub(crate) fn complete_delivery_read(
        self,
        response: &JsonRpcResponse,
        signing: Option<&super::signing::SigningInvocationContext>,
        (read, writes): (
            Option<crate::security::tenant_reads::ReadAttribution>,
            crate::gateway::gateway_writes::WriteRecord,
        ),
    ) -> bool {
        let era = self.era;
        let (lease, dispatches) = self.state.into_inner();
        let audit = self.audit.into_inner();
        let steps = self.steps.into_inner();
        let bindings = self.bindings.into_inner();
        if dispatches == 0
            || response.result.as_ref().is_some_and(|result| {
                crate::protocol::mrtr::InputRequired::claims_input_required(result)
            })
        {
            super::invoke::relay::cancel_replay_capture();
            return false;
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
            read,
            writes,
            dispatched: Some(steps),
            era,
            bindings,
        };
        let retained = lease.complete_secured(&serde_json::to_value(stored).unwrap_or(Value::Null))
            == Settlement::Retained;
        if !retained {
            super::invoke::relay::cancel_replay_capture();
        }
        retained
    }
}

// MIK-8154 L0: the operation the last keyed admission on this thread keyed,
// so a row can compare what two routes admit for one target.
#[cfg(test)]
thread_local! {
    static LAST_OPERATION: std::cell::RefCell<Option<Value>> = const { std::cell::RefCell::new(None) };
}

/// Take the operation the last keyed admission on this thread built (L0).
#[cfg(test)]
pub(crate) fn take_last_operation() -> Option<Value> {
    LAST_OPERATION.with(|last| last.borrow_mut().take())
}

pub(crate) enum SyncAdmission {
    Unprotected,
    Owned(SyncLease),
    /// A completed execution's secured response, its record facts, and the
    /// single-call target it was admitted for (MIK-8392 STORED.2: the
    /// target-branch target, else a continuation retry's origin, else `None`
    /// for a plan; it steers the route-stage deferral), and the steps it
    /// dispatched (`None` in a record that predates the list, MIK-8361),
    /// which a plan replay proves live before it is served (MIK-8406), and
    /// the binding each step ran under, judged before serving (MIK-8407).
    Replay(
        JsonRpcResponse,
        Option<ReplayAudit>,
        Option<ReplayTarget>,
        Option<Vec<(String, String)>>,
        Vec<stored::StepBinding>,
    ),
}

/// The refusal of a key reused for another execution or representation. It
/// is also how admission tells a reused key from a key in flight for a
/// withheld step (MIK-8361 ruling A); `admission_tests::
/// sub4_replay_current_policy_code_mode_revocation` fails if a reworded
/// mismatch stops matching it.
const KEY_MISMATCH: &str = "Idempotency key belongs to another execution or representation";

/// The gateway's own directives inside a tool's arguments: read and removed
/// here, so the sanitize step refuses a dirty key that cleans to one
/// (MIK-8378 ENV.2) from this one list.
pub(crate) const EXECUTION_DIRECTIVES: [&str; 2] = ["_full", "_claim"];

/// Gateway controls have the same meaning at both external execution routes.
pub(crate) fn execution_arguments(arguments: &mut Value) -> bool {
    let full = arguments
        .get("_full")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if let Some(object) = arguments.as_object_mut() {
        for directive in EXECUTION_DIRECTIVES {
            object.remove(directive);
        }
    }
    full
}

/// [`execution_arguments`] on a possibly borrowed value: it is copied only
/// when there is a control key to strip (MIK-8014).
pub(super) fn execution_arguments_cow(arguments: &mut std::borrow::Cow<'_, Value>) -> bool {
    if EXECUTION_DIRECTIVES
        .iter()
        .any(|directive| arguments.get(directive).is_some())
    {
        return execution_arguments(arguments.to_mut());
    }
    false
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
            || {
                Ok(Some(ReplayTarget {
                    server: server.to_owned(),
                    tool: tool.to_owned(),
                    origin: ReplayOrigin::Named,
                }))
            },
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
        // The replay's single-call target, read only when the store yields
        // one (MIK-8392 STORED.2). A thunk for the same reason as the two
        // above: the plan branch reads a continuation origin through it, and
        // anything but a replay must not pay for that read, let alone answer
        // it. An error fails the admission, so an unreadable origin is never
        // served stored (E1).
        replay_target: impl FnOnce() -> Result<Option<ReplayTarget>>,
    ) -> Result<SyncAdmission> {
        if retry.is_malformed() {
            return Err(Error::json_rpc(
                INVALID_PARAMS,
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
                    INVALID_PARAMS,
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
            .ok_or_else(super::support::no_execution_principal)?;
        let operation = operation();
        #[cfg(test)]
        LAST_OPERATION.with(|last| *last.borrow_mut() = Some(operation.clone()));
        // `MIK-8408` F1: the stored entry's replay key for this request,
        // with the round below folded in at the note. Only a relay-active
        // delivery captures or stages receipts, so only then is it taken.
        let replay_key = self
            .relay_active()
            .then(|| super::invoke::relay::sync_replay_key(&principal, key, &operation));
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
            Ok(Admission::Owned(lease)) => {
                super::invoke::relay::note_sync_capture_key(replay_key.as_ref(), &round);
                Ok(SyncAdmission::Owned(SyncLease {
                    state: Mutex::new((lease, 0)),
                    playbook: None,
                    audit: Mutex::new(None),
                    steps: Mutex::new(Vec::new()),
                    bindings: Mutex::new(Vec::new()),
                    era: None,
                }))
            }
            Ok(Admission::Replay(bytes)) => {
                super::invoke::relay::note_sync_lookup_key(replay_key.as_ref(), &round);
                // Read before the store is decoded: an unreadable origin
                // fails the admission without touching the retained bytes it
                // must never serve (E1).
                let single_target = replay_target()?;
                refuse_another_era(&bytes, is_modern)?;
                let (mut response, audit) = stored_response(&bytes).ok_or_else(|| {
                    Error::json_rpc(409, "Secured execution result is unavailable")
                })?;
                response.id = Some(request_id.clone());
                Ok(SyncAdmission::Replay(
                    response,
                    audit,
                    single_target,
                    stored::dispatched_steps(&bytes),
                    stored::stored_bindings(&bytes),
                ))
            }
            Ok(Admission::InFlight) => {
                Err(Error::json_rpc(409, "Execution is already in progress"))
            }
            Ok(Admission::Unavailable) => Err(Error::json_rpc(
                409,
                "Secured execution result is unavailable",
            )),
            Ok(Admission::Sealed) => Err(Error::json_rpc(
                409,
                crate::idempotency::admission::SEALED_MESSAGE,
            )),
            Err(Refusal::Mismatch) => Err(Error::json_rpc(409, KEY_MISMATCH)),
            Err(Refusal::InvalidIdentity | Refusal::MetadataTooLarge) => Err(Error::json_rpc(
                INVALID_PARAMS,
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
    ) -> Result<Option<(&'v str, &'v str, std::borrow::Cow<'v, Value>)>> {
        let target = if tool_name == "gateway_invoke" {
            let server =
                crate::gateway::meta_mcp_helpers::extract_required_str(arguments, "server")?;
            let tool = crate::gateway::meta_mcp_helpers::extract_required_str(arguments, "tool")?;
            Some((
                server,
                tool,
                crate::gateway::meta_mcp_helpers::parse_tool_arguments_cow(arguments)?,
            ))
        } else {
            // A name withheld from this caller has no target here: it takes
            // the absent-name path (MIK-8340).
            self.surfaced_for(tool_name, caller.scope(), session)
                .visible_server()
                .map(|server| (server, tool_name, std::borrow::Cow::Borrowed(arguments)))
        };
        if let Some((server, tool, operation_arguments)) = &target {
            let (server, tool) = (*server, *tool);
            if caller
                .signing
                .is_some_and(|context| context.prepared_for(server, tool))
            {
                // Signing ran the policy before the route stage could record
                // this request's verdict (stdio): refuse a withheld name here.
                super::visible::memo::refuse_withheld(server, tool)?;
            } else {
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
                self.check_invocation_policy(envelope, session, caller)?;
            }
        }
        Ok(target)
    }

    /// Protect one outer logical meta invocation, including its inner steps.
    #[allow(clippy::too_many_arguments)] // The nonce wrapper: `signing::admit_meta_sync`.
    pub(crate) fn admit_meta_sync_unrefunded(
        &self,
        owner: super::AdmissionOwner<'_>,
        caller: &super::MetaMcpCallerContext<'_>,
        tool_name: &str,
        arguments: &Value,
        session: Option<&str>,
        id: &RequestId,
    ) -> Result<SyncAdmission> {
        // One admission authority per key, for every transport: a task is
        // admitted durably under `Mode::Task` by its handoff (a lease too would
        // self-mismatch). Signing admission owns its own calls, and a signed
        // call was authorized when signing prepared it.
        if caller.awaits_signing_admission() {
            return Ok(SyncAdmission::Unprotected);
        }
        // A task passes the policy the synchronous call passes below (the
        // target's invocation policy, else the keyed plan check), here, before
        // a task or its key exists; its worker checks again at dispatch
        // (MIK-8315). A repeat is answered from the stored task only after it.
        if caller.task.is_some() {
            if self
                .check_target_policy(caller, tool_name, arguments, session)?
                .is_none()
            {
                // A withheld step is the task worker's gate's, as a missing
                // step is; a repeat re-checks its stored targets (ruling A).
                self.authorize_execution_plan(caller, tool_name, arguments, session)?;
            }
            return Ok(SyncAdmission::Unprotected);
        }
        caller.retry.refuse_on_playbook_run(tool_name)?; // MIK-8341: before any reservation
        // These operations cannot execute on a sessionless protocol. Preserve
        // their protocol refusal before asking for or reserving a retry key.
        if caller.is_modern {
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
        // The key owner, spelled as task admission spells it (MIK-8193): one
        // store, one identity per caller. For stdio it is the reserved owner
        // value (MIK-7272.OWNER.3), never `STDIO_CREDENTIAL_PRINCIPAL`.
        // No task owner (a certificate or agent alone): its proven subject.
        let owner_principal = caller.execution_principal(owner);
        let retry = caller.retry;
        // The arm the dispatch will use, so a retry's representation names it.
        let arm_key = caller.experiment_key();
        if let Some((server, tool, mut operation_arguments)) =
            self.check_target_policy(caller, tool_name, arguments, session)?
        {
            let full = execution_arguments_cow(&mut operation_arguments);
            return self
                .admit_sync(
                    caller.is_modern,
                    verified_identity,
                    owner_principal,
                    retry,
                    server,
                    tool,
                    &operation_arguments,
                    || self.meta_representation(tool_name, full, session, arm_key),
                    id,
                )
                .map(|admission| shaped_for_request(admission, caller.is_modern));
        }
        // These compiled discovery/reporting tools do not execute external work.
        // Backend annotations and operator target strings cannot add built-ins.
        let read_only = meta_tool_effect(tool_name) == Effect::ReadOnly;
        // MIK-8392 STORED.2 E8: see `hidden_name_unprotected`.
        if self.hidden_name_unprotected(tool_name, retry, (verified_identity, owner_principal)) {
            return Ok(SyncAdmission::Unprotected);
        }
        // A retained result is still protected by today's authorization. Plan
        // loading and every target check precede lookup, including mismatches.
        let (playbook, withheld) =
            self.authorize_execution_plan(caller, tool_name, arguments, session)?;
        let mut operation = json!({"kind": "gateway", "tool": tool_name,
            "arguments": operation_arguments(arguments, OPERATION_DEFINING_META),
            "retry": retry.key_discriminator()});
        if let Some(definition) = &playbook {
            let value = serde_json::to_value(definition)
                .map_err(|_| Error::json_rpc(INTERNAL_ERROR, "Invalid playbook definition"))?;
            // Keep the bounded admission envelope independent of plan size.
            operation["playbook"] = json!(crate::hashing::canonical_json_sha256(&value));
        }
        let admission = self.admit_operation(
            caller.is_modern,
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
            || self.replay_origin_target(tool_name, retry),
        );
        // A replay meets a withheld step's current refusal only where the
        // first run dispatched that step, as SUB.4 pins it: its holder held
        // access then. A step the first run answered as missing never ran, so
        // its replay is the stored answer, as a missing step's is; a record
        // with no step list counts every step as run (#3872 FIX 1). A key
        // reused with other arguments is a mismatch, not a replay: the
        // mismatch a missing step gets. A fresh call goes on to the step's
        // gate, and any other admission answer is the one a missing step
        // gets, never the step's reason (ruling A).
        let ran = match &admission {
            Ok(SyncAdmission::Replay(_, _, _, dispatched, _)) => Some(dispatched),
            _ => None,
        };
        if let Some(dispatched) = ran
            && let Some(refusal) = stored::refusal_to_meet(dispatched.as_deref(), withheld)
        {
            return Err(crate::gateway::delivery_facts::refused(refusal));
        }
        let mut admission = admission?;
        if let SyncAdmission::Owned(lease) = &mut admission {
            lease.playbook = playbook;
        }
        Ok(shaped_for_request(admission, caller.is_modern))
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
                        INTERNAL_ERROR,
                        "Config reload is not enabled on this gateway",
                    ));
                }
            }
            "gateway_reload_capabilities" => {
                if self.get_capabilities().is_none() {
                    return Err(Error::json_rpc(
                        INTERNAL_ERROR,
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
    /// per (backend, tool) per [`super::warn_limit::WARN_INTERVAL`]. Labels carry no identity.
    fn record_unkeyed(&self, is_modern: bool, read_only: bool, (server, tool): (&str, &str)) {
        super::warn_limit::count_unkeyed(is_modern, read_only);
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

#[cfg(test)]
#[path = "admission_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "admission_round_tests.rs"]
mod round_tests;

#[cfg(test)]
#[path = "admission_withheld_tests.rs"]
mod withheld_tests;

#[cfg(all(test, feature = "metrics"))]
#[path = "unkeyed_metric_tests.rs"]
mod unkeyed_metric_tests;

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
