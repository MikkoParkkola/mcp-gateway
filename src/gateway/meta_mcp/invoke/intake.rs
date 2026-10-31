// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The intake stages of `invoke_tool_traced` (MIK-8488): who calls, then what
//! the call asks for.
//!
//! Moved verbatim from the orchestrator. Each stage takes a named input that
//! holds exactly what it reads, and returns a named output the stages below
//! build on.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use serde_json::Value;

use super::gateway_writes;
use super::projection::extract_client_claim;
use super::stored_proof::TracedOutcome;
use crate::Result;
use crate::gateway::meta_mcp::{MetaMcp, MetaMcpCallerContext};
use crate::gateway::meta_mcp_helpers::{extract_required_str, parse_tool_arguments};
use crate::gateway::recovery::MetaSurface;
use crate::identity_propagation::CallerProof;
use crate::key_server::oidc::VerifiedIdentity;
use crate::routing_profile::RoutingProfile;
use crate::trust::ClientClaim;

/// The invoked step, borrowed from the call's arguments. The one group B1
/// shares: every holder reads both fields in full.
#[derive(Clone, Copy)]
pub(super) struct Step<'a> {
    pub(super) server: &'a str,
    pub(super) tool: &'a str,
}

/// What S1 proved about the caller: the identity facts the later stages read.
pub(super) struct CallerFacts<'a> {
    pub(super) api_key_name: Option<&'a str>,
    pub(super) verified_identity: Option<&'a VerifiedIdentity>,
    pub(super) caller_proof: CallerProof<'a>,
    pub(super) credential_owner: Option<String>,
    pub(super) surface: MetaSurface,
}

/// S1's input: exactly what the intake reads.
pub(super) struct IntakeIn<'a, 'c> {
    pub(super) args: &'a Value,
    pub(super) session_id: Option<&'a str>,
    pub(super) caller: &'a MetaMcpCallerContext<'c>,
}

/// S1's output: the step, the caller facts, and the epoch the call is
/// authorized in.
pub(super) struct Intake<'a, 'c> {
    pub(super) step: Step<'a>,
    pub(super) facts: CallerFacts<'c>,
    pub(super) policy_epoch: u64,
    pub(super) writes_mark: gateway_writes::Mark,
}

/// S2's input: exactly what the directives read. Every field is a borrow or
/// a copy, so the stage takes it by value without consuming anything.
#[derive(Clone, Copy)]
pub(super) struct DirectivesIn<'a, 'c> {
    pub(super) args: &'a Value,
    pub(super) session_id: Option<&'a str>,
    pub(super) caller: &'a MetaMcpCallerContext<'c>,
    pub(super) trace_id: &'a str,
    pub(super) step: Step<'a>,
}

/// S2's output: the stripped arguments and the keys the stages below build on.
pub(super) struct Directives<'a> {
    pub(super) arguments: Value,
    pub(super) want_full: bool,
    pub(super) client_claim: Option<ClientClaim>,
    pub(super) arm_key: Option<&'a str>,
    pub(super) projection_key_suffix: String,
    pub(super) profile: Arc<RoutingProfile>,
    pub(super) tool_key: String,
}

impl MetaMcp {
    /// S1, the intake: the caller's identity facts, the epoch the call is
    /// authorized in, and the gate's answer when it gives one.
    #[forbid(unused_variables)]
    pub(super) async fn intake<'a, 'c>(
        &self,
        input: IntakeIn<'a, 'c>,
    ) -> Result<std::ops::ControlFlow<TracedOutcome, Intake<'a, 'c>>> {
        // Unpacked once, here, so the context travels whole across the call
        // boundary for the same reason `invoke_tool` takes it whole: no call
        // site can pass an authorizer without the identity it authorizes.
        let IntakeIn {
            args,
            session_id,
            caller,
        } = input;
        let api_key_name = caller.api_key_name;
        let verified_identity = caller.verified_identity;
        let provenance = caller.provenance();
        let caller_proof = CallerProof::new(verified_identity, provenance);
        // Names an MCP child when nothing above does (MIK-7825).
        let credential_owner = super::super::support::credential_owner(caller);
        // The meta-tools this caller can see, for its recovery hints (MIK-7974).
        let surface = self.hint_surface(caller);

        // Capture once, before any authorization input is read. A bump after
        // this strands the insert under the epoch this call was authorized
        // in. A second load at the write site is the 4.g race.
        let policy_epoch = self.policy_epoch.load(Ordering::Acquire);
        // MIK-7991: this call's own gateway writes start here, apart from an
        // earlier plan step's in the same delivery; stored with its answer.
        let writes_mark = gateway_writes::mark();

        let server = extract_required_str(args, "server")?;
        let tool = extract_required_str(args, "tool")?;
        if let Some(answer) = self.gated(args, (server, tool), caller, session_id).await {
            return answer
                .map(TracedOutcome::Live)
                .map(std::ops::ControlFlow::Break);
        }
        Ok(std::ops::ControlFlow::Continue(Intake {
            step: Step { server, tool },
            facts: CallerFacts {
                api_key_name,
                verified_identity,
                caller_proof,
                credential_owner,
                surface,
            },
            policy_epoch,
            writes_mark,
        }))
    }

    /// S2, the directives: the call's arguments with the gateway directives
    /// stripped, and the keys the idempotency and cache stages build on.
    #[forbid(unused_variables)]
    pub(super) fn directives<'a>(&self, input: DirectivesIn<'a, '_>) -> Result<Directives<'a>> {
        let DirectivesIn {
            args,
            session_id,
            caller,
            trace_id,
            step: Step { server, tool },
        } = input;
        let mut arguments = parse_tool_arguments(args).inspect_err(|_| {
            super::audit::note_pre_send(crate::gateway::meta_mcp::dispatch_log::PreSend::Refused);
        })?;
        // `_full` (opt out of response projection, MIK-3533) and `_claim` (the
        // MIK-6914 Option B claim-under-test) are gateway directives, not
        // upstream parameters. Both are stripped BEFORE the argument hash and
        // idempotency key are computed, so toggling one cannot bypass
        // idempotency or fragment the cache, and neither reaches a backend.
        //
        // The claim is read first, because the shared strip removes it too.
        // It is untrusted client input bound to this call's `trace_id`,
        // threaded to the provenance chokepoint and (with capture enabled)
        // recorded as the claim under scrutiny; never the ground-truth leg.
        let client_claim = extract_client_claim(&mut arguments, trace_id);
        // The one strip both routes use (MIK-8663): it reads `_full` and
        // removes every listed directive.
        let want_full = crate::gateway::meta_mcp::admission::execution_arguments(&mut arguments);

        // MIK-5877: in `experimental` mode the projected (treatment) and raw
        // (control) arms must NOT share response-cache / idempotency entries, or
        // one arm's shape would be served to the other (the key is otherwise
        // just server:tool:hash(args)). Suffix both keys with the arm so each
        // arm is isolated while still deduping within itself — preserving
        // idempotency's double-execution protection per arm. `off`/`on` add no
        // suffix, so their keys are byte-identical to before.
        // G4: the arm keys on the caller, never on the "" every modern caller
        // shares; a keyless caller gets the control arm and is not counted.
        let arm_key = caller.experiment_key();
        let projection_key_suffix =
            crate::projection::projection_key_suffix(self.projection_mode, arm_key);

        tracing::Span::current().record("trace_id", trace_id);

        let profile = self.active_profile(session_id);

        let tool_key = format!("{server}:{tool}");
        Ok(Directives {
            arguments,
            want_full,
            client_claim,
            arm_key,
            projection_key_suffix,
            profile,
            tool_key,
        })
    }
}
