// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Request-owned synchronous admission and secured HTTP settlement.

use parking_lot::Mutex;
use serde_json::{Value, json};

use crate::idempotency::admission::{Admission, Lease, Mode, Refusal, Request};
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::{Error, Result};

use super::MetaMcp;

#[path = "admission_plan.rs"]
mod plan;

/// Borrowed by inner dispatches, owned by the outer request future. Dropping the
/// future drops its one lease, including after a transport cancellation.
pub(crate) struct SyncLease {
    state: Mutex<(Lease, bool)>,
    playbook: Option<crate::playbook::PlaybookDefinition>,
}

impl SyncLease {
    /// The same immutable definition supplied both preflight and fingerprinting.
    pub(super) fn playbook_definition(&self) -> Option<&crate::playbook::PlaybookDefinition> {
        self.playbook.as_ref()
    }

    pub(crate) fn mark_dispatched(&self) {
        let mut state = self.state.lock();
        state.0.mark_dispatched();
        state.1 = true;
    }

    /// The HTTP owner calls this only after the existing response security
    /// pipeline. No backend value can settle admission on its own.
    pub(crate) fn complete_secured(self, response: &JsonRpcResponse) {
        self.complete_delivery(response, None);
    }

    pub(crate) fn complete_delivery(
        self,
        response: &JsonRpcResponse,
        signing: Option<&super::signing::SigningInvocationContext>,
    ) {
        let (lease, dispatched) = self.state.into_inner();
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
        lease.complete_secured(&secured);
    }
}

pub(crate) enum SyncAdmission {
    Unprotected,
    Owned(SyncLease),
    Replay(JsonRpcResponse),
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
        representation: &Value,
        request_id: &RequestId,
    ) -> Result<SyncAdmission> {
        let operation = json!({
            "kind": "backend", "server": server, "tool": tool, "arguments": arguments,
            "retry": retry.key_discriminator(),
        });
        self.admit_operation(
            is_modern,
            verified_identity,
            credential_principal,
            retry,
            &operation,
            representation,
            self.read_only_target(server, tool),
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
        operation: &Value,
        representation: &Value,
        read_only: bool,
        request_id: &RequestId,
    ) -> Result<SyncAdmission> {
        if retry.is_malformed() {
            return Err(Error::json_rpc(
                -32602,
                "Malformed execution retry metadata",
            ));
        }
        let Some(key) = retry.idempotency_key.as_deref() else {
            return if !is_modern || read_only {
                Ok(SyncAdmission::Unprotected)
            } else {
                Err(Error::json_rpc(
                    -32602,
                    "An explicit idempotency key is required",
                ))
            };
        };
        let principal = verified_identity
            .map(crate::key_server::oidc::VerifiedIdentity::stable_actor_id)
            .or_else(|| {
                credential_principal
                    .filter(|value| !value.is_empty())
                    .map(str::to_owned)
            })
            .ok_or_else(|| Error::json_rpc(-32003, "A verified execution principal is required"))?;
        let request = Request {
            principal: &principal,
            key,
            operation,
            representation,
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
            })),
            Ok(Admission::Replay(bytes)) => {
                let mut response: JsonRpcResponse = serde_json::from_slice(&bytes)
                    .map_err(|_| Error::json_rpc(409, "Secured execution result is unavailable"))?;
                response.id = Some(request_id.clone());
                Ok(SyncAdmission::Replay(response))
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
        let credential_principal = caller.credential_principal;
        let retry = caller.retry;
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
        if let Some((server, tool, mut operation_arguments)) = target {
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
                    synthesized =
                        json!({"server": server, "tool": tool, "arguments": operation_arguments});
                    &synthesized
                };
                self.check_invocation_policy(envelope, session, caller)?;
            }
            let full = execution_arguments(&mut operation_arguments);
            return self.admit_sync(
                is_modern,
                verified_identity,
                credential_principal,
                retry,
                server,
                tool,
                &operation_arguments,
                &self.meta_representation(tool_name, full, session),
                id,
            );
        }
        // These compiled discovery/reporting tools do not execute external work.
        // Backend annotations and operator target strings cannot add built-ins.
        let read_only = matches!(
            tool_name,
            "gateway_search"
                | "gateway_list_servers"
                | "gateway_list_tools"
                | "gateway_search_tools"
                | "gateway_get_stats"
                | "gateway_cost_report"
                | "gateway_webhook_status"
                | "gateway_list_disabled_capabilities"
                | "gateway_get_profile"
                | "gateway_list_profiles"
        );
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
            credential_principal,
            retry,
            &operation,
            &self.meta_representation(tool_name, false, session),
            read_only,
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
    ) -> Value {
        json!({
            "route": "meta", "tool": tool_name, "full": full,
            "projection": format!("{:?}", self.projection_mode),
            "profile": self.active_profile(session).describe(),
            "arm": crate::projection::projection_key_suffix(self.projection_mode, session),
        })
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

#[cfg(test)]
#[path = "admission_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "admission_round_tests.rs"]
mod round_tests;
