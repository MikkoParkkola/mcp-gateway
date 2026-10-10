// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The route x check table on the release line at 0028fb249, from the
//! re-verified route-check matrix (b3 note r3, seats grok + gpt).

use super::{Expect, MethodKind, Na, Route, Stage, Ticket};

/// What `stage` does on `route` for `method` today. No wildcard arm: every
/// (route, stage) pair is decided here, so a new variant fails to compile.
pub(crate) const fn expect(method: MethodKind, route: Route, stage: Stage) -> Expect {
    use Expect::{Applies, ExpectedGap, NotApplicable};
    use Route::{Direct, Invoke, Stdio, Surfaced, TaskSubmit, TaskWorker};
    use Stage::{
        Authorize, ChainLink, ChokepointRescan, Idempotency, Lease, MrtrUndeclared,
        NonceGiveBack, ResponseFirewall, RouteFirewall, Sanitize, TaskConfirm,
    };
    match method {
        MethodKind::ToolsCall => match (route, stage) {
            // RouteFirewall: the stateful `check_request` (dispatch_tools_call.rs:232,
            // backend_handlers.rs:120); absent on stdio (stdio_dispatch.rs:394-559).
            (Invoke | Surfaced | Direct | TaskSubmit, RouteFirewall) => Applies,
            (TaskWorker, RouteFirewall) => NotApplicable(Na::DecidedAtSubmit),
            (Stdio, RouteFirewall) => ExpectedGap(Ticket::Mik8149),

            // ChokepointRescan: every meta send (invoke.rs:428); the direct route
            // never reaches it (MIK-8154.SAN.3); task submit sends nothing.
            (Invoke | Surfaced | TaskWorker | Stdio, ChokepointRescan) => Applies,
            (Direct, ChokepointRescan) => ExpectedGap(Ticket::Mik8154),
            (TaskSubmit, ChokepointRescan) => NotApplicable(Na::NoBackendSend),

            // Sanitize: `/mcp` honours the flag (dispatch_intake.rs:355); the direct
            // route sanitizes whatever it says (backend_handlers.rs:171-175);
            // stdio never sanitizes.
            (Invoke | Surfaced | TaskSubmit, Sanitize) => Applies,
            (Direct, Sanitize) => ExpectedGap(Ticket::Mik8154),
            (TaskWorker, Sanitize) => NotApplicable(Na::DecidedAtSubmit),
            (Stdio, Sanitize) => ExpectedGap(Ticket::Mik8149),

            // Authorize: grants and the admin rule fire only for the capability
            // provider (`server == capabilities.name`, meta_mcp/visibility.rs).
            (Invoke | Surfaced | TaskSubmit | TaskWorker | Stdio, Authorize) => Applies,
            (Direct, Authorize) => NotApplicable(Na::NotCapabilityProvider),

            // MrtrUndeclared: response-time on every sending route; `/mcp` legacy
            // calls get `Declared::NONE` as the direct route does (parity).
            (Invoke | Surfaced | Direct | TaskWorker | Stdio, MrtrUndeclared) => Applies,
            (TaskSubmit, MrtrUndeclared) => NotApplicable(Na::NoBackendSend),

            // TaskConfirm (X14): surfaced tools only (task_confirmation.rs:164).
            (Invoke | Direct, TaskConfirm) => NotApplicable(Na::NotSurfacedName),
            (Surfaced | TaskSubmit, TaskConfirm) => Applies,
            (TaskWorker, TaskConfirm) => NotApplicable(Na::DecidedAtSubmit),
            (Stdio, TaskConfirm) => ExpectedGap(Ticket::Mik8160),

            // Idempotency: the store's replay (invoke.rs:291, direct_dispatch.rs:111).
            (Invoke | Surfaced | Direct | TaskSubmit | Stdio, Idempotency) => Applies,
            (TaskWorker, Idempotency) => NotApplicable(Na::DecidedAtSubmit),

            // Lease: `admit_meta_sync` only at dispatch_tools_call.rs:503 and
            // stdio_dispatch.rs:522; tasks skip it (admission.rs:523).
            (Invoke | Surfaced | Stdio, Lease) => Applies,
            (Direct, Lease) => ExpectedGap(Ticket::Mik8154),
            (TaskSubmit | TaskWorker, Lease) => NotApplicable(Na::DecidedAtSubmit),

            // NonceGiveBack: an `admit_meta_sync` or relay refusal keeps the nonce
            // (MIK-8150 NONCE.1/NONCE.3); the direct route gives it back
            // (direct_dispatch.rs:313-316).
            (Invoke | Surfaced | Stdio, NonceGiveBack) => ExpectedGap(Ticket::Mik8150),
            (Direct | TaskSubmit, NonceGiveBack) => Applies,
            (TaskWorker, NonceGiveBack) => NotApplicable(Na::TransportHasNoNonce),

            // ChainLink: a surfaced-name call drops the chain source
            // (call_dispatch.rs:135-136, MIK-8159).
            (Invoke | Direct | Stdio, ChainLink) => Applies,
            (Surfaced, ChainLink) => ExpectedGap(Ticket::Mik8159),
            (TaskSubmit, ChainLink) => NotApplicable(Na::NoBackendSend),
            (TaskWorker, ChainLink) => NotApplicable(Na::TaskSettlementNotLinked),

            // ResponseFirewall: every route through `scan_egress`.
            (Invoke | Surfaced | Direct | TaskWorker | Stdio, ResponseFirewall) => Applies,
            (TaskSubmit, ResponseFirewall) => NotApplicable(Na::NoBackendSend),
        },
    }
}
