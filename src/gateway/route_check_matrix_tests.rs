// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The route x check matrix (MIK-8137 family route-check-parity, b3).
//!
//! One table states, for every entry route of a backend `tools/call` and
//! every check stage, what applies today. `ExpectedGap` rows name the ticket
//! that closes them and assert the gap still exists, so the PR that closes a
//! gap turns its row red until the row says `Applies`. `expect` is a match
//! with no wildcard arm: a new route or stage without a row does not compile.

/// The method a row is about. Only `tools/call` is in the matrix today; a
/// later variant extends the same match.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MethodKind {
    ToolsCall,
}

/// The entry routes a backend `tools/call` can arrive on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Route {
    /// R1: `/mcp` `tools/call gateway_invoke`.
    Invoke,
    /// R2: `/mcp` `tools/call <surfaced name>`.
    Surfaced,
    /// R3: `/mcp/{name}`.
    Direct,
    /// R4a: a task-augmented `tools/call` submit on `/mcp`.
    TaskSubmit,
    /// R4b: the task worker running that call.
    TaskWorker,
    /// R5: the stdio transport.
    Stdio,
}

/// The check stages, in the frozen design's order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stage {
    /// The stateful route-layer request scan (`Firewall::check_request`).
    RouteFirewall,
    /// The stateless dispatch-time rescan (`invoke/chokepoint.rs`).
    ChokepointRescan,
    /// Input sanitization, honouring `security.sanitize_input`.
    Sanitize,
    /// Identity grants and the admin-capability rule.
    Authorize,
    /// The MRTR.9 gate on undeclared backend questions.
    MrtrUndeclared,
    /// X14, the task-admission destructive gate.
    TaskConfirm,
    /// The idempotency store's replay.
    Idempotency,
    /// The execution lease's in-flight refusal.
    Lease,
    /// A refusal after nonce admission gives the signing nonce back.
    NonceGiveBack,
    /// The chain origin link on the answer.
    ChainLink,
    /// The response firewall.
    ResponseFirewall,
}

/// Why a stage cannot apply on a route. Closed: a new reason is a design
/// decision, not free text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Na {
    /// The route answers without sending anything to a backend.
    NoBackendSend,
    /// The route's request carries no task member, and X14 governs only
    /// task-augmented calls.
    NoTaskMember,
    /// The route has no signing nonce of its own.
    TransportHasNoNonce,
    /// The task submit already decided this stage for the worker.
    DecidedAtSubmit,
    /// X14 covers surfaced tools only (UPGRADING-4.0.md, X14 section).
    NotSurfacedName,
    /// A task settlement is not chain-linked.
    TaskSettlementNotLinked,
    /// Grants and the admin rule fire only for the capability provider,
    /// which is never a direct-route backend.
    NotCapabilityProvider,
}

/// The ticket that closes an expected gap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Ticket {
    Mik8149,
    Mik8150,
    Mik8154,
    Mik8159,
    Mik8160,
}

/// What a (method, route, stage) row asserts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Expect {
    Applies,
    NotApplicable(Na),
    ExpectedGap(Ticket),
}

impl Route {
    pub(crate) const ALL: [Self; 6] = [
        Self::Invoke,
        Self::Surfaced,
        Self::Direct,
        Self::TaskSubmit,
        Self::TaskWorker,
        Self::Stdio,
    ];

    /// Exhaustive: a new variant without an index does not compile.
    pub(crate) const fn index(self) -> usize {
        match self {
            Self::Invoke => 0,
            Self::Surfaced => 1,
            Self::Direct => 2,
            Self::TaskSubmit => 3,
            Self::TaskWorker => 4,
            Self::Stdio => 5,
        }
    }
}

impl Stage {
    pub(crate) const ALL: [Self; 11] = [
        Self::RouteFirewall,
        Self::ChokepointRescan,
        Self::Sanitize,
        Self::Authorize,
        Self::MrtrUndeclared,
        Self::TaskConfirm,
        Self::Idempotency,
        Self::Lease,
        Self::NonceGiveBack,
        Self::ChainLink,
        Self::ResponseFirewall,
    ];

    /// Exhaustive: a new variant without an index does not compile.
    pub(crate) const fn index(self) -> usize {
        match self {
            Self::RouteFirewall => 0,
            Self::ChokepointRescan => 1,
            Self::Sanitize => 2,
            Self::Authorize => 3,
            Self::MrtrUndeclared => 4,
            Self::TaskConfirm => 5,
            Self::Idempotency => 6,
            Self::Lease => 7,
            Self::NonceGiveBack => 8,
            Self::ChainLink => 9,
            Self::ResponseFirewall => 10,
        }
    }
}

#[path = "route_check_matrix_table.rs"]
mod table;
pub(crate) use table::expect;
#[cfg(feature = "firewall")]
#[path = "route_check_matrix_rows.rs"]
mod rows;

/// `ALL` lists every variant exactly once: each index in `0..N` is hit once.
/// A length check alone would pass a list that repeats one variant and
/// misses another.
#[test]
fn every_route_and_stage_is_listed_exactly_once() {
    let mut routes = [0u8; Route::ALL.len()];
    for route in Route::ALL {
        routes[route.index()] += 1;
    }
    assert!(routes.iter().all(|&n| n == 1), "Route::ALL: {routes:?}");
    let mut stages = [0u8; Stage::ALL.len()];
    for stage in Stage::ALL {
        stages[stage.index()] += 1;
    }
    assert!(stages.iter().all(|&n| n == 1), "Stage::ALL: {stages:?}");
}

/// Every gap names its ticket, and the table answers every pair.
#[test]
fn the_table_answers_every_route_and_stage() {
    let mut gaps = 0;
    for route in Route::ALL {
        for stage in Stage::ALL {
            if let Expect::ExpectedGap(_) = expect(MethodKind::ToolsCall, route, stage) {
                gaps += 1;
            }
        }
    }
    // Today's gaps on 0028fb249: R1/R2/R5 nonce, R2 chain link, R3 rescan,
    // sanitize and lease, R5 route firewall, sanitize and X14.
    assert_eq!(gaps, 10, "the gap count moved: update the table and this pin");
}

/// The cells a live row in `rows` drives (route, stage). Kept beside the
/// table so a new row and its listing land together.
const DRIVEN: &[(Route, Stage)] = &[
    (Route::Invoke, Stage::RouteFirewall),
    (Route::Surfaced, Stage::RouteFirewall),
    (Route::Direct, Stage::RouteFirewall),
    (Route::Stdio, Stage::RouteFirewall),
    (Route::Invoke, Stage::ChokepointRescan),
    (Route::Direct, Stage::ChokepointRescan),
    (Route::Stdio, Stage::ChokepointRescan),
    (Route::Invoke, Stage::Sanitize),
    (Route::Direct, Stage::Sanitize),
    (Route::Stdio, Stage::Sanitize),
    (Route::Invoke, Stage::MrtrUndeclared),
    (Route::Direct, Stage::MrtrUndeclared),
    (Route::Stdio, Stage::MrtrUndeclared),
    (Route::TaskSubmit, Stage::TaskConfirm),
    (Route::Stdio, Stage::TaskConfirm),
    (Route::Invoke, Stage::Lease),
    (Route::Direct, Stage::Lease),
    (Route::Invoke, Stage::NonceGiveBack),
    (Route::Direct, Stage::NonceGiveBack),
    (Route::Invoke, Stage::ChainLink),
    (Route::Surfaced, Stage::ChainLink),
    (Route::Direct, Stage::ChainLink),
    (Route::Stdio, Stage::ChainLink),
    (Route::Invoke, Stage::ResponseFirewall),
    (Route::Direct, Stage::ResponseFirewall),
    (Route::Stdio, Stage::ResponseFirewall),
];

/// Cells the table states but no live row drives yet, each with the reason
/// and where it gets driven. Visible on purpose: an undriven cell is a claim
/// without a regression net, so it is named rather than silently skipped.
const UNDRIVEN: &[(Route, Stage, &str)] = &[
    (Route::Invoke, Stage::Authorize, "needs a capability-provider fixture; v4.0.1 N2 follow-up"),
    (Route::Invoke, Stage::Idempotency, "needs the outer-admission eviction helper; v4.0.1 N2 follow-up"),
    (Route::Surfaced, Stage::ChokepointRescan, "R1 drives the same code path; v4.0.1 N2 follow-up"),
    (Route::Surfaced, Stage::Sanitize, "R1 drives the same intake; v4.0.1 N2 follow-up"),
    (Route::Surfaced, Stage::Authorize, "needs a capability-provider fixture; v4.0.1 N2 follow-up"),
    (Route::Surfaced, Stage::MrtrUndeclared, "R1 drives the same gate; v4.0.1 N2 follow-up"),
    (Route::Surfaced, Stage::Idempotency, "needs the outer-admission eviction helper; v4.0.1 N2 follow-up"),
    (Route::Surfaced, Stage::Lease, "R1 drives the same admit_meta_sync; v4.0.1 N2 follow-up"),
    (Route::Surfaced, Stage::NonceGiveBack, "gap MIK-8150: driven red-first by MIK-8150.NONCE.4"),
    (Route::Surfaced, Stage::ResponseFirewall, "R1 drives the same egress; v4.0.1 N2 follow-up"),
    (Route::Direct, Stage::Idempotency, "needs the outer-admission eviction helper; v4.0.1 N2 follow-up"),
    (Route::TaskSubmit, Stage::RouteFirewall, "needs a task-submit driver per stage; v4.0.1 N2 follow-up"),
    (Route::TaskSubmit, Stage::Sanitize, "needs a task-submit driver per stage; v4.0.1 N2 follow-up"),
    (Route::TaskSubmit, Stage::Authorize, "needs a capability-provider fixture; v4.0.1 N2 follow-up"),
    (Route::TaskSubmit, Stage::Idempotency, "needs the outer-admission eviction helper; v4.0.1 N2 follow-up"),
    (Route::TaskSubmit, Stage::NonceGiveBack, "needs a signed task-submit driver; v4.0.1 N2 follow-up"),
    (Route::TaskWorker, Stage::ChokepointRescan, "needs a task-worker driver; v4.0.1 N2 follow-up"),
    (Route::TaskWorker, Stage::Authorize, "needs a task-worker driver; v4.0.1 N2 follow-up"),
    (Route::TaskWorker, Stage::MrtrUndeclared, "needs a task-worker driver; v4.0.1 N2 follow-up"),
    (Route::TaskWorker, Stage::ResponseFirewall, "needs a task-worker driver; v4.0.1 N2 follow-up"),
    (Route::Stdio, Stage::Authorize, "needs a capability-provider fixture; v4.0.1 N2 follow-up"),
    (Route::Stdio, Stage::Idempotency, "needs the outer-admission eviction helper; v4.0.1 N2 follow-up"),
    (Route::Stdio, Stage::Lease, "needs a held stdio backend; v4.0.1 N2 follow-up"),
    (Route::Stdio, Stage::NonceGiveBack, "gap MIK-8150: driven red-first by MIK-8150.NONCE.5"),
];

/// Every cell the table says Applies or ExpectedGap is either driven by a
/// live row or listed in `UNDRIVEN`, never both and never neither; no
/// NotApplicable cell is listed. A new row that forgets `DRIVEN`, or a table
/// change that strands a cell, fails here.
#[test]
fn every_stated_cell_is_driven_or_named_undriven() {
    let driven = |r, s| DRIVEN.iter().any(|&(dr, ds)| dr == r && ds == s);
    let undriven = |r, s| UNDRIVEN.iter().any(|&(ur, us, _)| ur == r && us == s);
    let mut missing = Vec::new();
    for route in Route::ALL {
        for stage in Stage::ALL {
            let stated = !matches!(
                expect(MethodKind::ToolsCall, route, stage),
                Expect::NotApplicable(_)
            );
            match (stated, driven(route, stage), undriven(route, stage)) {
                (true, true, false) | (true, false, true) | (false, false, false) => {}
                state => missing.push((route, stage, state)),
            }
        }
    }
    assert!(
        missing.is_empty(),
        "cells driven twice, stranded, or listed while NotApplicable \
         (route, stage, (stated, driven, undriven)): {missing:?}"
    );
}
