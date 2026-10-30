// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! R2's undeclared-key check on the direct route (MIK-7570.SCHEMA.1), with
//! F13's fetch of the caller's own catalogue when its slot is cold.

use crate::gateway::meta_mcp::invoke::egress::Egressed;
use axum::http::StatusCode;
use serde_json::{Value, json};

use super::super::helpers::build_http_response;
use super::BackendRejection;
use super::direct_failure::DirectFailure;
use crate::backend::{CatalogueVerdict, Lens};
use crate::gateway::meta_mcp::response_security::error_response_preserving_status;
use crate::gateway::meta_mcp::visible::absent::absent_name;
use crate::protocol::{JsonRpcResponse, RequestId};

/// The caller's slot binding and the headers it propagates upstream; a cold
/// slot is listed with exactly these, so the list is fetched as the caller.
pub(super) type CallerSlot<'a> = (Option<&'a str>, &'a crate::transport::LentCredential);

/// The gateway's answer to a name the caller's catalogue lacks, on the
/// direct route: -32601 under its preserved status (MIK-8356, MIK-8361).
pub(super) fn absent_response(id: &RequestId, tool: &str) -> BackendRejection {
    let response = error_response_preserving_status(id.clone(), &absent_name(tool));
    build_http_response(&Egressed::gateway_own(response), StatusCode::OK)
}

/// [`key_refusal`] for a name the caller may not see: answered as a name the
/// catalogue lacks, under no caller's credential, so nothing is filled.
pub(super) async fn withheld_refusal(
    backend: &crate::backend::Backend,
    failed: &DirectFailure<'_>,
    params: &Value,
    id: &RequestId,
) -> Option<BackendRejection> {
    let none = crate::transport::LentCredential::default();
    key_refusal(
        backend,
        ((None, &none), failed),
        params,
        (id, Lens::Withheld),
    )
    .await
}

/// The rejection for a `tools/call` R2 refuses, or `None` to proceed.
///
/// A refusal is a tool result, not a 403, so a model can correct the call;
/// the early return drops the idempotency reservation unsettled. When the
/// slot's failsafe refuses the cold-slot list, or under `closed` the list
/// fails on transport (F13, A3), the call is answered by the same
/// [`DirectFailure`] a failed dispatch is: client failure recorded, error
/// logged, a 401 on a managed credential refreshed once (A11-c). It gets no
/// reservation: no `tools/call` left the gateway, so the dropped reservation
/// releases.
///
/// Under [`Lens::Withheld`] (MIK-8361: the caller's policy hides the tool,
/// judged before any credential) the call is answered exactly as a name the
/// catalogue lacks, never forwarded, and with no credential: on a per-user
/// backend at once (-32601, no fill), on a shared one from the shared slot.
pub(super) async fn key_refusal(
    backend: &crate::backend::Backend,
    ((identity_key, headers), failed): (CallerSlot<'_>, &DirectFailure<'_>),
    params: &Value,
    (id, lens): (&RequestId, Lens),
) -> Option<BackendRejection> {
    let tool = params.get("name").and_then(Value::as_str).unwrap_or("");
    let arguments = params.get("arguments").unwrap_or(&Value::Null);
    let call = crate::gateway::meta_mcp::invoke::dispatch_guards::BackendCall {
        server: &backend.name,
        tool,
        session_id: None,
        api_key_name: None,
        cost_key: None,
        trace_id: tool,
        caller_key: None,
    };
    // MIK-8356: on a per-user backend, a tool this caller's own catalogue
    // withholds or lacks answers as an absent name (-32601), whatever the
    // argument-key mode; the argument keys are judged only after.
    let absent = || absent_response(id, tool);
    if backend.keeps_per_user_catalogues() {
        if lens == Lens::Withheld {
            return Some(absent());
        }
        let verdict = backend
            .catalogue_verdict(identity_key, headers.clone(), tool)
            .await;
        // The check may have filled the caller's slot: index it, whatever the
        // verdict; an unfilled slot is never recorded (MIK-8356).
        let proof = crate::identity_propagation::CallerProof::new(
            failed.identity,
            crate::identity_propagation::CallerProvenance::classify(
                failed.client.map(|client| client.principal.storage_form()),
            ),
        );
        failed
            .state
            .meta_mcp
            .remember_caller_slot(backend, proof, identity_key);
        match verdict {
            // A withheld entry (descriptor, schema) is the gateway refusing the
            // call, as the meta gate records it; a lacked name is not.
            Ok(CatalogueVerdict::Withholds) => {
                crate::gateway::delivery_facts::raise(
                    crate::gateway::delivery_facts::ResponseEffect::Refused,
                );
                return Some(absent());
            }
            Ok(CatalogueVerdict::Lacks) => return Some(absent()),
            Ok(CatalogueVerdict::Offers | CatalogueVerdict::Unknown) => {}
            Err(e) => return Some(failed.clone().answer((None, None), e, &call).await),
        }
    }
    // A shared catalogue's withheld entry (descriptor, schema) takes the
    // lacked name's path too; a policy-withheld name is judged without the
    // caller's credential, which is not resolved for it.
    // The gateway's own static headers, for the shared slot's gate: no
    // caller's credential, so nothing to check.
    let gate = crate::transport::LentCredential::unchecked(backend.gate_headers());
    let (slot, lens) = match lens {
        Lens::Withheld => ((None, gate), Lens::Withheld),
        Lens::Catalogue => {
            // Under `off` no call lists the catalogue: judged from what is held.
            let verdict = if backend.checks_membership() {
                backend
                    .catalogue_verdict(identity_key, headers.clone(), tool)
                    .await
            } else {
                Ok(backend.held_verdict(identity_key, tool))
            };
            match verdict {
                Ok(CatalogueVerdict::Withholds) => {
                    // As above: the withheld entry is refused, answered absent.
                    crate::gateway::delivery_facts::raise(
                        crate::gateway::delivery_facts::ResponseEffect::Refused,
                    );
                    ((identity_key, headers.clone()), Lens::Withheld)
                }
                _ => ((identity_key, headers.clone()), Lens::Catalogue),
            }
        }
    };
    let checked = backend.catalogue_refusal(slot, tool, arguments, lens);
    match checked.await {
        Ok(None) => None,
        Ok(Some(crate::backend::KeyAnswer { kind, text })) => {
            if kind.refuses() {
                crate::gateway::delivery_facts::raise(
                    crate::gateway::delivery_facts::ResponseEffect::Refused,
                );
            }
            let result = json!({ "content": [{ "type": "text", "text": text }], "isError": true });
            let mut response = JsonRpcResponse::success(id.clone(), result);
            // The text lists the backend's own parameter names, which no
            // dispatch gate read: it meets the content checks here.
            let screen = (
                &call,
                crate::gateway::meta_mcp::invoke::egress::ContentChecks::Here,
            );
            super::super::direct_guards::scan_direct_egress(
                failed.state,
                screen,
                failed.client,
                &mut response,
            );
            Some(build_http_response(&Egressed::of(response), StatusCode::OK))
        }
        Err(e) => Some(failed.clone().answer((None, None), e, &call).await),
    }
}
