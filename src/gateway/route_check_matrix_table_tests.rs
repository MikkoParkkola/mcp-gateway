// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The route x check table on the release line at 0028fb249, from the
//! re-verified route-check matrix (b3 note r4, seats grok + gpt). One arm per
//! stage, then one arm per answer for that stage, each with its evidence.

use super::{Expect, MethodKind, Na, Route, Stage, Ticket};

/// What `stage` does on `route` for `method` today. No wildcard arm: every
/// (route, stage) pair is decided here, so a new variant fails to compile.
pub(crate) const fn expect(method: MethodKind, route: Route, stage: Stage) -> Expect {
    use Expect::{Applies, ExpectedGap, NotApplicable};
    use Route::{Direct, Invoke, Stdio, Surfaced, TaskSubmit, TaskWorker};
    match method {
        MethodKind::ToolsCall => match stage {
            // The stateful check_request (dispatch_tools_call.rs,
            // backend_handlers.rs:120; stdio's route stage,
            // stdio_route_stage.rs, P3). Stated parity limit (lead ruling,
            // P3): stdio admits the signing nonce before its route stage, so a
            // bad nonce stays cheap to refuse (MIK-7377.SIGNING.5 row 40), and
            // gives it back when the route stage refuses. A call with both a
            // bad nonce and a blocked argument therefore answers the nonce
            // error on stdio and the firewall error on /mcp.
            Stage::RouteFirewall => match route {
                Invoke | Surfaced | Direct | TaskSubmit | Stdio => Applies,
                TaskWorker => NotApplicable(Na::DecidedAtSubmit),
            },
            // Every meta send passes it (invoke.rs:428); the direct route's
            // tools/call takes its permit after redeem (MIK-8351, which took
            // MIK-8154.SAN.3); a task submit sends nothing.
            Stage::ChokepointRescan => match route {
                Invoke | Surfaced | TaskWorker | Stdio | Direct => Applies,
                TaskSubmit => NotApplicable(Na::NoBackendSend),
            },
            // One sanitize step honouring the flag on every route (MIK-8154
            // SAN.1): /mcp intake (dispatch_intake.rs), stdio
            // `prepare_signing` and the direct route's `read_envelope`.
            Stage::Sanitize => match route {
                Invoke | Surfaced | TaskSubmit | Stdio | Direct => Applies,
                TaskWorker => NotApplicable(Na::DecidedAtSubmit),
            },
            // Grants and the admin rule fire only for the capability provider
            // (server == capabilities.name, meta_mcp/visibility.rs).
            Stage::Authorize => match route {
                // A task submit passes the sync call's policy at admission
                // (admit_meta_sync, MIK-8315); its worker checks again.
                Invoke | Surfaced | TaskSubmit | TaskWorker | Stdio => Applies,
                Direct => NotApplicable(Na::NotCapabilityProvider),
            },
            // Response-time on every sending route; /mcp legacy calls get
            // Declared::NONE as the direct route does (parity).
            Stage::MrtrUndeclared => match route {
                Invoke | Surfaced | Direct | TaskWorker | Stdio => Applies,
                TaskSubmit => NotApplicable(Na::NoBackendSend),
            },
            // X14 decides task-augmented surfaced calls only
            // (task_confirmation.rs:164, UPGRADING-4.0.md X14 section). A plain
            // surfaced call carries no task member; its task form is R4a.
            Stage::TaskConfirm => match route {
                Invoke | Direct => NotApplicable(Na::NotSurfacedName),
                Surfaced => NotApplicable(Na::NoTaskMember),
                TaskSubmit | Stdio => Applies,
                TaskWorker => NotApplicable(Na::DecidedAtSubmit),
            },
            // The store's replay (invoke.rs:291, direct_dispatch.rs:111).
            Stage::Idempotency => match route {
                Invoke | Surfaced | Direct | TaskSubmit | Stdio => Applies,
                TaskWorker => NotApplicable(Na::DecidedAtSubmit),
            },
            // admit_meta_sync at dispatch_tools_call.rs and stdio_dispatch.rs;
            // the direct route's 7b, `direct_route_admission`, at
            // direct_idempotency.rs (MIK-8154.LEASE.1); tasks skip it.
            Stage::Lease => match route {
                Invoke | Surfaced | Stdio | Direct => Applies,
                TaskSubmit | TaskWorker => NotApplicable(Na::DecidedAtSubmit),
            },
            // An admission refusal of a call without task intent gives the
            // nonce back on /mcp and stdio (MIK-8150, `signing::admit_meta_sync`),
            // as the direct route does (direct_dispatch.rs:313-316). A relay
            // refusal and any task call's refusal still keep it until every
            // effect marks the execution (MIK-8353).
            Stage::NonceGiveBack => match route {
                Invoke | TaskSubmit => ExpectedGap(Ticket::Mik8353),
                Surfaced | Stdio | Direct => Applies,
                TaskWorker => NotApplicable(Na::TransportHasNoNonce),
            },
            // A surfaced-name call keeps its chain source (MIK-8159).
            Stage::ChainLink => match route {
                Invoke | Surfaced | Direct | Stdio => Applies,
                TaskSubmit => NotApplicable(Na::NoBackendSend),
                TaskWorker => NotApplicable(Na::TaskSettlementNotLinked),
            },
            // Every sending route through scan_egress.
            Stage::ResponseFirewall => match route {
                Invoke | Surfaced | Direct | TaskWorker | Stdio => Applies,
                TaskSubmit => NotApplicable(Na::NoBackendSend),
            },
        },
    }
}
