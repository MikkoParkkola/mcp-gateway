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
            // The stateful check_request (dispatch_tools_call.rs:232,
            // backend_handlers.rs:120); absent on stdio (stdio_dispatch.rs:394-559).
            Stage::RouteFirewall => match route {
                Invoke | Surfaced | Direct | TaskSubmit => Applies,
                TaskWorker => NotApplicable(Na::DecidedAtSubmit),
                Stdio => ExpectedGap(Ticket::Mik8149),
            },
            // Every meta send passes it (invoke.rs:428); the direct route never
            // reaches it (MIK-8154.SAN.3); a task submit sends nothing.
            Stage::ChokepointRescan => match route {
                Invoke | Surfaced | TaskWorker | Stdio => Applies,
                Direct => ExpectedGap(Ticket::Mik8154),
                TaskSubmit => NotApplicable(Na::NoBackendSend),
            },
            // /mcp honours the flag (dispatch_intake.rs:355); the direct route
            // sanitizes whatever it says (backend_handlers.rs:171-175); stdio
            // never sanitizes.
            Stage::Sanitize => match route {
                Invoke | Surfaced | TaskSubmit => Applies,
                Direct => ExpectedGap(Ticket::Mik8154),
                TaskWorker => NotApplicable(Na::DecidedAtSubmit),
                Stdio => ExpectedGap(Ticket::Mik8149),
            },
            // Grants and the admin rule fire only for the capability provider
            // (server == capabilities.name, meta_mcp/visibility.rs).
            Stage::Authorize => match route {
                Invoke | Surfaced | TaskWorker | Stdio => Applies,
                // The submit path runs neither check (dispatch_tools_call.rs:380);
                // the worker does (policy.rs:98, chokepoint.rs:129).
                TaskSubmit => ExpectedGap(Ticket::Mik8315),
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
                TaskSubmit => Applies,
                TaskWorker => NotApplicable(Na::DecidedAtSubmit),
                Stdio => ExpectedGap(Ticket::Mik8160),
            },
            // The store's replay (invoke.rs:291, direct_dispatch.rs:111).
            Stage::Idempotency => match route {
                Invoke | Surfaced | Direct | TaskSubmit | Stdio => Applies,
                TaskWorker => NotApplicable(Na::DecidedAtSubmit),
            },
            // admit_meta_sync only at dispatch_tools_call.rs:503 and
            // stdio_dispatch.rs:522; tasks skip it (admission.rs:523).
            Stage::Lease => match route {
                Invoke | Surfaced | Stdio => Applies,
                Direct => ExpectedGap(Ticket::Mik8154),
                TaskSubmit | TaskWorker => NotApplicable(Na::DecidedAtSubmit),
            },
            // An admit_meta_sync, relay or task-admission refusal keeps the
            // nonce (MIK-8150 NONCE.1/.3/.6); the direct route gives it back
            // (direct_dispatch.rs:313-316).
            Stage::NonceGiveBack => match route {
                Invoke | Surfaced | Stdio | TaskSubmit => ExpectedGap(Ticket::Mik8150),
                Direct => Applies,
                TaskWorker => NotApplicable(Na::TransportHasNoNonce),
            },
            // A surfaced-name call drops the chain source (call_dispatch.rs:135-136).
            Stage::ChainLink => match route {
                Invoke | Direct | Stdio => Applies,
                Surfaced => ExpectedGap(Ticket::Mik8159),
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
