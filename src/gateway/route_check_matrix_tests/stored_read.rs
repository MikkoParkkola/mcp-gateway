// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The task-read matrix (MIK-8392). A stored task read hands a caller the
//! output of a call made earlier, so it must judge the target as a live call
//! would: against the caller's account and the caller's own view. One row per
//! (read route, stage); `expect` has no wildcard arm, so a new route or stage
//! without a row does not compile. The `ExpectedGap` row names the ticket
//! that closes it, and the gap pin turns red when it closes.

use super::{Expect, Ticket};

/// The routes that read a stored task.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReadRoute {
    /// `tasks/get` on `/mcp`.
    HttpGet,
    /// `tasks/get` on the stdio transport.
    StdioGet,
    /// The task-status notification frame on an HTTP stream.
    HttpFrame,
    /// A stdio task-status frame.
    StdioFrame,
    /// A repeated task-augmented `tools/call` with the same key.
    RepeatedCall,
    /// `tasks/update`.
    Update,
    /// `tasks/cancel`.
    Cancel,
}

/// What a stored read judges before it hands out the output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReadStage {
    /// The caller's per-user account for the target is still live (not
    /// revoked, not waiting on a connect offer).
    AccountView,
    /// The caller's own view of the target (its slot, the listing, the
    /// descriptor policy) still offers the tool.
    CallerView,
}

/// Why a stage cannot apply on a read route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReadNa {
    /// The route answers with a gateway-authored acknowledgement that carries
    /// no stored output (rows T6, T7 pin it).
    GatewayAuthoredAck,
    /// stdio has no task-status subscribers, so no frame is ever sent.
    NoStdioSubscribers,
}

/// What a (route, stage) row asserts. `Expect::NotApplicable` carries the
/// tools/call reason type, so the read matrix states its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReadExpect {
    Stated(Expect),
    NotApplicable(ReadNa),
}

impl ReadRoute {
    pub(crate) const ALL: [Self; 7] = [
        Self::HttpGet,
        Self::StdioGet,
        Self::HttpFrame,
        Self::StdioFrame,
        Self::RepeatedCall,
        Self::Update,
        Self::Cancel,
    ];

    /// Exhaustive: a new variant without an index does not compile.
    const fn index(self) -> usize {
        match self {
            Self::HttpGet => 0,
            Self::StdioGet => 1,
            Self::HttpFrame => 2,
            Self::StdioFrame => 3,
            Self::RepeatedCall => 4,
            Self::Update => 5,
            Self::Cancel => 6,
        }
    }
}

impl ReadStage {
    pub(crate) const ALL: [Self; 2] = [Self::AccountView, Self::CallerView];

    /// Exhaustive: a new variant without an index does not compile.
    const fn index(self) -> usize {
        match self {
            Self::AccountView => 0,
            Self::CallerView => 1,
        }
    }
}

/// `ALL` lists every variant exactly once, so the checks below see them all.
#[test]
fn every_read_route_and_stage_is_listed_exactly_once() {
    let mut routes = [0u8; ReadRoute::ALL.len()];
    for route in ReadRoute::ALL {
        routes[route.index()] += 1;
    }
    assert!(routes.iter().all(|&n| n == 1), "ReadRoute::ALL: {routes:?}");
    let mut stages = [0u8; ReadStage::ALL.len()];
    for stage in ReadStage::ALL {
        stages[stage.index()] += 1;
    }
    assert!(stages.iter().all(|&n| n == 1), "ReadStage::ALL: {stages:?}");
}

pub(crate) const fn expect(route: ReadRoute, stage: ReadStage) -> ReadExpect {
    use ReadExpect::{NotApplicable, Stated};
    use ReadRoute::{Cancel, HttpFrame, HttpGet, RepeatedCall, StdioFrame, StdioGet, Update};
    use ReadStage::{AccountView, CallerView};
    match (route, stage) {
        // The repeat is a live tools/call: the live admission judges the
        // caller's view first. Its account step is STORED.2's site 5.
        (HttpGet | StdioGet | HttpFrame, AccountView | CallerView) | (RepeatedCall, CallerView) => {
            Stated(Expect::Applies)
        }
        (RepeatedCall, AccountView) => Stated(Expect::ExpectedGap(Ticket::Mik8392)),
        (StdioFrame, AccountView | CallerView) => NotApplicable(ReadNa::NoStdioSubscribers),
        (Update | Cancel, AccountView | CallerView) => NotApplicable(ReadNa::GatewayAuthoredAck),
    }
}

/// Today's one gap: the repeated call's account step, closed by MIK-8392
/// STORED.2 (site 5, `defer_or_serve_existing`), which flips the row.
#[test]
fn the_read_table_has_one_named_gap() {
    let gaps: Vec<_> = ReadRoute::ALL
        .into_iter()
        .flat_map(|r| ReadStage::ALL.into_iter().map(move |s| (r, s)))
        .filter(|&(r, s)| matches!(expect(r, s), ReadExpect::Stated(Expect::ExpectedGap(_))))
        .collect();
    assert_eq!(
        gaps,
        [(ReadRoute::RepeatedCall, ReadStage::AccountView)],
        "the gap set moved: update the table and this pin"
    );
}

/// The row that drives each stated cell, or why none does. Rows live beside
/// the code they drive; a cell listed here with no row is named, not hidden.
const DRIVEN: &[(ReadRoute, ReadStage, &str)] = &[
    (
        ReadRoute::HttpGet,
        ReadStage::AccountView,
        "router::stored_read_account_tests T10, T10p, Ub, lease::{U1, C6, L4, L4b, L5, L2, N0}; \
         router::stored_read_capability_tests T11, U2",
    ),
    (
        ReadRoute::HttpGet,
        ReadStage::CallerView,
        "task_execution_adapter::stored_read_access T1, T9, T9c, T9d, T12, T16; \
         router::stored_read_slot_tests T8, T8t, C1, C1r, K1, lease::{C2-C8, R1, L1b, L3, T17}",
    ),
    (
        ReadRoute::StdioGet,
        ReadStage::AccountView,
        "UNDRIVEN: no stdio per-user account fixture; stdio tasks/get runs the same \
         prepare_stored_read and judge_stored_targets as HttpGet",
    ),
    (
        ReadRoute::StdioGet,
        ReadStage::CallerView,
        "server::tests::stored_read_stdio T2",
    ),
    (
        ReadRoute::HttpFrame,
        ReadStage::AccountView,
        "router::stored_read_account_tests T10pf (with N1)",
    ),
    (
        ReadRoute::HttpFrame,
        ReadStage::CallerView,
        "task_execution_adapter::stored_read_frames T3",
    ),
    (
        ReadRoute::RepeatedCall,
        ReadStage::CallerView,
        "task_execution_adapter::stored_read_access T5",
    ),
    (
        ReadRoute::RepeatedCall,
        ReadStage::AccountView,
        "gap MIK-8392 STORED.2: driven red-first by its site-5 rows",
    ),
];

/// Every stated cell is listed in `DRIVEN` exactly once, and no
/// `NotApplicable` cell is.
#[test]
fn every_stated_read_cell_is_listed_once() {
    let mut wrong = Vec::new();
    for route in ReadRoute::ALL {
        for stage in ReadStage::ALL {
            let stated = matches!(expect(route, stage), ReadExpect::Stated(_));
            let listed = DRIVEN
                .iter()
                .filter(|&&(r, s, _)| r == route && s == stage)
                .count();
            if listed != usize::from(stated) {
                wrong.push((route, stage, stated, listed));
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "(route, stage, stated, times listed): {wrong:?}"
    );
}
