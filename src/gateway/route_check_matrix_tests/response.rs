// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The response-stage matrix (MIK-8689). Every answer the gateway delivers
//! passes a tail of response stages, and some pairs must run in a fixed order
//! for the receipt, the signature and the delivery record to describe the
//! bytes the client gets. One cell per (route, case, era, pair); `expect`
//! has no wildcard arm, so a new route, case or pair without a cell does not
//! compile, and `pairs_consistent` makes a table that contradicts a route's
//! stage order fail to compile. Rows observe outcomes only (receipts,
//! signatures, delivery rows, resends); no stage carries a test hook.

use crate::protocol::meta::Era;

/// The routes an answer leaves by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RespRoute {
    /// `POST /mcp` (`router::handlers`, `finalize_routed`).
    Mcp,
    /// The stdio transport (`stdio_dispatch`, `judge_and_commit`).
    Stdio,
    /// `POST /mcp/{name}` (`direct_dispatch::finish_tail`, `direct_audit`).
    Direct,
    /// A task's stored result: the worker's seal and the recovered task.
    Task,
}

/// How the answer was produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RespCase {
    /// A backend call made for this request.
    Fresh,
    /// A response-cache hit.
    CacheHit,
    /// An idempotency-key replay of a stored answer.
    IdempotentReplay,
    /// A task's stored result (the `Task` route only).
    Task,
}

/// The response stages, named as the code names them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RespStage {
    /// The HMAC receipt mint (`augment_with_provenance`).
    ProvenanceStamp,
    /// The 2026-07-28 shaper (`shape_modern_response`).
    Shape,
    /// The egress firewall scan.
    Firewall,
    /// `clamp_delivered_scope` on the top-level `cacheScope`.
    ScopeClamp,
    /// The chain strip and origin link (`emit_origin_link`).
    OriginLink,
    /// The public receipt seal (`seal_public_provenance`).
    Seal,
    /// The message signature.
    Sign,
    /// The read judge (`outbound::answer`).
    Judge,
    /// The `response_delivery_attempt` record.
    DeliveryRecord,
    /// The relay receipt rebuilt from the final answer.
    RelayRebuild,
    /// The relay receipts committed for a delivered answer.
    RelayCommit,
}

/// The pairs the matrix states, as (before, after) through [`RespPair::stages`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RespPair {
    ShapeSeal,
    FirewallSeal,
    ClampLink,
    ClampSeal,
    StampSeal,
    SealSign,
    SignRecord,
    JudgeRecord,
    RecordCommit,
    JudgeCommit,
    /// The rebuild reads the final, signed bytes.
    SignRebuild,
    FirewallStamp,
    JudgeRebuild,
    StampShape,
    LinkSeal,
    SignJudge,
}

/// The ticket that closes a response gap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RespTicket {
    /// A direct idempotent replay is not resealed.
    Mik8705,
    /// Mcp and stdio fix the receipt's facts before the egress firewall.
    Mik8707,
}

/// Why a gap's order difference reaches no delivered outcome today. Closed
/// reasons; the order itself is pinned at source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Latent {
    /// The receipt's result facts are `row_count` and `backend_ok`. The only
    /// extractor arm reads GitHub's server-reported `total_count`
    /// (`trust/result_extractor.rs:55-80`), the redactor rewrites a matched
    /// span inside a string (`security/firewall/redactor.rs:182`), redaction
    /// never flips `isError`, and a Block replaces the whole answer, so the
    /// stamp-firewall order changes no delivered fact.
    NoExtractedFactRedactionChanges,
}

/// Why a pair's order cannot be read from any outcome. Closed reasons.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Invisible {
    /// The judge only replaces an answer, and both orders then leave no
    /// receipt (lead ruling; stdio and HTTP differ in code, MIK-8704).
    JudgeOnlyReplaces,
    /// The stamp's facts do not read the members the shaper writes.
    StampIgnoresShapedMembers,
    /// The seal writes only under `_meta`, which `content_digest` excludes.
    SealWritesOnlyExcludedMeta,
    /// `_signature` is no tenant-attribution key, so the judge reads nothing
    /// signing adds.
    JudgeReadsNothingSigningAdds,
}

/// Why a cell cannot occur.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RespNa {
    /// A legacy answer is never shaped.
    NoModernShapeOnLegacy,
    /// The direct route has no response cache.
    NoCacheOnDirect,
    /// A task settlement is not chain-linked.
    TaskHasNoOriginLink,
    /// The task case belongs to the `Task` route, and that route to it.
    TaskIsItsOwnRoute,
    /// A keyed replay on `/mcp` or stdio re-serves the stored, already sealed
    /// delivery (`router/handlers.rs:571`, `stdio_delivery.rs:83`, served by
    /// `admission.rs:394`): it mints and seals nothing. Pinned by
    /// `rows::r_replay_mcp_reserves_the_stored_delivery` (red-check record
    /// red-A1-record.md: the earlier re-stamp premise was wrong).
    ReplayReservesTheStoredDelivery,
    /// The stored task tail is the clamp and the seal over the worker's mint;
    /// the delivery stages run on the `tasks/get` route that reads it.
    TaskTailIsClampAndSeal,
}

/// What a cell asserts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RespExpect {
    Ordered,
    ExpectedGap(RespTicket),
    /// A real order difference no delivered outcome shows today; pinned by a
    /// source-order row so the fix, or a new extractor, flips a test.
    LatentGap(RespTicket, Latent),
    OrderInvisibleByOutcome(Invisible),
    NotApplicable(RespNa),
}

impl RespPair {
    pub(crate) const ALL: [Self; 16] = [
        Self::ShapeSeal,
        Self::FirewallSeal,
        Self::ClampLink,
        Self::ClampSeal,
        Self::StampSeal,
        Self::SealSign,
        Self::SignRecord,
        Self::JudgeRecord,
        Self::RecordCommit,
        Self::JudgeCommit,
        Self::SignRebuild,
        Self::FirewallStamp,
        Self::JudgeRebuild,
        Self::StampShape,
        Self::LinkSeal,
        Self::SignJudge,
    ];

    /// (before, after). Exhaustive: a new pair names its stages here.
    pub(crate) const fn stages(self) -> (RespStage, RespStage) {
        use RespStage::{
            DeliveryRecord, Firewall, Judge, OriginLink, ProvenanceStamp, RelayCommit,
            RelayRebuild, ScopeClamp, Seal, Shape, Sign,
        };
        match self {
            Self::ShapeSeal => (Shape, Seal),
            Self::FirewallSeal => (Firewall, Seal),
            Self::ClampLink => (ScopeClamp, OriginLink),
            Self::ClampSeal => (ScopeClamp, Seal),
            Self::StampSeal => (ProvenanceStamp, Seal),
            Self::SealSign => (Seal, Sign),
            Self::SignRecord => (Sign, DeliveryRecord),
            Self::JudgeRecord => (Judge, DeliveryRecord),
            Self::RecordCommit => (DeliveryRecord, RelayCommit),
            Self::JudgeCommit => (Judge, RelayCommit),
            Self::SignRebuild => (Sign, RelayRebuild),
            Self::FirewallStamp => (Firewall, ProvenanceStamp),
            Self::JudgeRebuild => (Judge, RelayRebuild),
            Self::StampShape => (ProvenanceStamp, Shape),
            Self::LinkSeal => (OriginLink, Seal),
            Self::SignJudge => (Sign, Judge),
        }
    }
}

pub(crate) const ROUTES: [RespRoute; 4] = [
    RespRoute::Mcp,
    RespRoute::Stdio,
    RespRoute::Direct,
    RespRoute::Task,
];
pub(crate) const CASES: [RespCase; 4] = [
    RespCase::Fresh,
    RespCase::CacheHit,
    RespCase::IdempotentReplay,
    RespCase::Task,
];
pub(crate) const ERAS: [Era; 2] = [Era::Modern, Era::Legacy];

/// Each route's tail as the code runs it (verified at 407481d51:
/// ~/.claude/data/ratification-briefs/mik-8689/orders-verified.md).
pub(crate) const fn order(route: RespRoute) -> &'static [RespStage] {
    use RespStage::{
        DeliveryRecord, Firewall, Judge, OriginLink, ProvenanceStamp, RelayCommit, RelayRebuild,
        ScopeClamp, Seal, Shape, Sign,
    };
    match route {
        // router/handlers.rs:543-602, response_security.rs `finalize_routed`.
        RespRoute::Mcp => &[
            ProvenanceStamp,
            Shape,
            Firewall,
            ScopeClamp,
            OriginLink,
            Seal,
            Sign,
            Judge,
            DeliveryRecord,
            RelayRebuild,
            RelayCommit,
        ],
        // stdio_dispatch.rs:176-216, stdio_delivery.rs `judge_and_commit`.
        RespRoute::Stdio => &[
            ProvenanceStamp,
            Shape,
            Firewall,
            ScopeClamp,
            OriginLink,
            Seal,
            Sign,
            RelayRebuild,
            Judge,
            DeliveryRecord,
            RelayCommit,
        ],
        // direct_dispatch.rs:525-625, backend_handlers.rs `sign_and_record`,
        // direct_audit.rs:218-272.
        RespRoute::Direct => &[
            Firewall,
            ProvenanceStamp,
            Shape,
            ScopeClamp,
            OriginLink,
            Seal,
            Sign,
            RelayRebuild,
            Judge,
            DeliveryRecord,
            RelayCommit,
        ],
        // input_round.rs:109-110, meta_mcp/upstream.rs:554-555.
        RespRoute::Task => &[ProvenanceStamp, ScopeClamp, Seal],
    }
}

/// What `pair` asserts on the cell (route, case, era).
pub(crate) const fn expect(
    route: RespRoute,
    case: RespCase,
    era: Era,
    pair: RespPair,
) -> RespExpect {
    use Invisible::{
        JudgeOnlyReplaces, JudgeReadsNothingSigningAdds, SealWritesOnlyExcludedMeta,
        StampIgnoresShapedMembers,
    };
    use RespCase::{CacheHit, Fresh, IdempotentReplay, Task as TaskCase};
    use RespExpect::{ExpectedGap, LatentGap, NotApplicable, OrderInvisibleByOutcome, Ordered};
    use RespPair::{
        ClampLink, ClampSeal, FirewallSeal, FirewallStamp, JudgeCommit, JudgeRebuild, JudgeRecord,
        LinkSeal, RecordCommit, SealSign, ShapeSeal, SignJudge, SignRebuild, SignRecord, StampSeal,
        StampShape,
    };
    use RespRoute::{Direct, Mcp, Stdio, Task};
    match (route, case, era, pair) {
        (Task, Fresh | CacheHit | IdempotentReplay, _, _)
        | (Mcp | Stdio | Direct, TaskCase, _, _) => NotApplicable(RespNa::TaskIsItsOwnRoute),
        (Task, TaskCase, _, ClampLink | LinkSeal) => NotApplicable(RespNa::TaskHasNoOriginLink),
        (
            Task,
            TaskCase,
            _,
            ShapeSeal | FirewallSeal | SealSign | SignRecord | JudgeRecord | RecordCommit
            | JudgeCommit | SignRebuild | FirewallStamp | JudgeRebuild | StampShape | SignJudge,
        ) => NotApplicable(RespNa::TaskTailIsClampAndSeal),
        (Direct, CacheHit, _, _) => NotApplicable(RespNa::NoCacheOnDirect),
        (_, _, Era::Legacy, ShapeSeal | StampShape) => NotApplicable(RespNa::NoModernShapeOnLegacy),
        // A replay runs the tail on the stored, already sealed bytes: no mint,
        // so nothing is sealed or linked anew (lead ruling, MIK-8689 phase C).
        (
            Mcp | Stdio | Direct,
            IdempotentReplay,
            _,
            ShapeSeal | FirewallSeal | ClampSeal | SealSign | ClampLink,
        ) => NotApplicable(RespNa::ReplayReservesTheStoredDelivery),
        (Direct, IdempotentReplay, _, StampSeal) => ExpectedGap(RespTicket::Mik8705),
        (Mcp | Stdio, IdempotentReplay, _, StampSeal) => {
            NotApplicable(RespNa::ReplayReservesTheStoredDelivery)
        }
        (Mcp | Stdio, _, _, FirewallStamp) => {
            LatentGap(RespTicket::Mik8707, Latent::NoExtractedFactRedactionChanges)
        }
        (_, _, _, JudgeRebuild) => OrderInvisibleByOutcome(JudgeOnlyReplaces),
        (_, _, _, StampShape) => OrderInvisibleByOutcome(StampIgnoresShapedMembers),
        (_, _, _, LinkSeal) => OrderInvisibleByOutcome(SealWritesOnlyExcludedMeta),
        (_, _, _, SignJudge) => OrderInvisibleByOutcome(JudgeReadsNothingSigningAdds),
        (
            _,
            _,
            _,
            ShapeSeal | FirewallSeal | ClampLink | ClampSeal | StampSeal | SealSign | SignRecord
            | JudgeRecord | RecordCommit | JudgeCommit | SignRebuild | FirewallStamp,
        ) => Ordered,
    }
}

/// Where `stage` sits in `route`'s tail.
const fn position(route: RespRoute, stage: RespStage) -> Option<usize> {
    let tail = order(route);
    let mut i = 0;
    while i < tail.len() {
        if tail[i] as u8 == stage as u8 {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// No route lists a stage twice, and every `Ordered` cell names two stages
/// its route runs, in that order.
const fn pairs_consistent() -> bool {
    let mut ri = 0;
    while ri < ROUTES.len() {
        let route = ROUTES[ri];
        let tail = order(route);
        let mut i = 0;
        while i < tail.len() {
            let mut j = i + 1;
            while j < tail.len() {
                if tail[i] as u8 == tail[j] as u8 {
                    return false;
                }
                j += 1;
            }
            i += 1;
        }
        let mut ci = 0;
        while ci < CASES.len() {
            let mut ei = 0;
            while ei < ERAS.len() {
                let mut pi = 0;
                while pi < RespPair::ALL.len() {
                    let pair = RespPair::ALL[pi];
                    if let RespExpect::Ordered = expect(route, CASES[ci], ERAS[ei], pair) {
                        let (before, after) = pair.stages();
                        match (position(route, before), position(route, after)) {
                            (Some(b), Some(a)) if b < a => {}
                            _ => return false,
                        }
                    }
                    pi += 1;
                }
                ei += 1;
            }
            ci += 1;
        }
        ri += 1;
    }
    true
}

const _: () = assert!(
    pairs_consistent(),
    "a stated order contradicts a route's tail"
);

/// Every cell, for the runtime checks.
fn cells() -> impl Iterator<Item = (RespRoute, RespCase, Era, RespPair)> {
    ROUTES.into_iter().flat_map(|route| {
        CASES.into_iter().flat_map(move |case| {
            ERAS.into_iter().flat_map(move |era| {
                RespPair::ALL
                    .into_iter()
                    .map(move |pair| (route, case, era, pair))
            })
        })
    })
}

/// `ALL` lists every pair exactly once.
#[test]
fn every_response_pair_is_listed_exactly_once() {
    for (i, a) in RespPair::ALL.iter().enumerate() {
        for b in &RespPair::ALL[i + 1..] {
            assert_ne!(a, b, "RespPair::ALL lists {a:?} twice");
        }
    }
}

/// The gap set is exactly MIK-8705, expected (a direct replay is not
/// resealed, both eras), and MIK-8707, latent (Mcp and stdio stamp before the
/// firewall, every case and era; no delivered fact differs today). A new,
/// closed or reclassified gap moves this pin.
#[test]
fn the_response_table_names_exactly_two_gaps() {
    let gaps: Vec<_> = cells()
        .filter_map(|cell| match expect(cell.0, cell.1, cell.2, cell.3) {
            RespExpect::ExpectedGap(ticket) => Some((ticket, false, cell)),
            RespExpect::LatentGap(ticket, _) => Some((ticket, true, cell)),
            _ => None,
        })
        .collect();
    let of = |t, latent| {
        gaps.iter()
            .filter(|(ticket, is_latent, _)| *ticket == t && *is_latent == latent)
            .count()
    };
    assert_eq!(of(RespTicket::Mik8705, false), 2, "{gaps:?}");
    assert_eq!(of(RespTicket::Mik8707, true), 12, "{gaps:?}");
    assert_eq!(gaps.len(), 14, "the gap set moved: {gaps:?}");
}

/// The order behind the MIK-8707 latent gap, pinned at source.
#[path = "response_source_order.rs"]
mod source_order;

#[cfg(feature = "firewall")]
#[path = "response_rows.rs"]
mod rows;

/// Which row drives a stated cell. A cell no row can drive gets an
/// `Undriven` variant with its reason when the first one appears (phase A2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Driven {
    /// The named row test(s).
    Row(&'static str),
    /// A route that runs the same function as another: a source-order `pin`
    /// that the route still delegates to it, and the `rows` that drive that
    /// function on the other route (lead ruling, MIK-8689 phase B).
    Shared {
        pin: &'static str,
        rows: &'static [&'static str],
    },
    /// The same pair on this route in another case or era, which runs the
    /// same tail: `pin` is the source-order row that keeps that true.
    SameAs {
        pin: &'static str,
        case: RespCase,
        era: Era,
    },
    /// The cell states nothing (`NotApplicable` or `OrderInvisibleByOutcome`).
    NotStated,
}

/// The pin behind an era twin: the tail takes no era or case.
const NO_CASE_OR_ERA: &str = "response::source_order::the_tail_takes_no_case_or_era";
/// The pin behind a replay or cache-hit twin: each reaches its route's tail.
const REACHES_THE_TAIL: &str = "response::source_order::replay_and_cache_hit_reach_the_tail";

/// Whether an answer of `case` on `route` runs that route's response tail.
/// A replay and a cache hit both do (`dispatch_tools_call.rs:721-727`,
/// `direct_idempotency.rs:141`, `stdio_dispatch.rs:681`, and the cache-hit
/// re-stamp at `invoke/pre_dispatch.rs:430`); a stored task is sealed at the
/// worker instead. Pinned by `source_order::replay_and_cache_hit_reach_the_tail`.
const fn reaches_tail(route: RespRoute, case: RespCase) -> bool {
    !matches!(route, RespRoute::Task) && !matches!(case, RespCase::Task)
}

/// Whether `expect` states an order to drive.
const fn stated(expect: RespExpect) -> bool {
    matches!(
        expect,
        RespExpect::Ordered | RespExpect::ExpectedGap(_) | RespExpect::LatentGap(..)
    )
}

/// Phase C's case and era twins (lead ruling): a replay or a cache hit runs
/// the Fresh tail on its own route, and the other era runs the same tail,
/// which takes no era.
const fn twin(case: RespCase, era: Era) -> Driven {
    match (case, era) {
        (RespCase::IdempotentReplay | RespCase::CacheHit, _) => Driven::SameAs {
            pin: REACHES_THE_TAIL,
            case: RespCase::Fresh,
            era,
        },
        (_, Era::Modern) => Driven::SameAs {
            pin: NO_CASE_OR_ERA,
            case,
            era: Era::Legacy,
        },
        (_, Era::Legacy) => Driven::SameAs {
            pin: NO_CASE_OR_ERA,
            case,
            era: Era::Modern,
        },
    }
}

/// The row behind every `Ordered`, `ExpectedGap` or `LatentGap` cell.
const fn driven(route: RespRoute, case: RespCase, era: Era, pair: RespPair) -> Driven {
    use RespCase::{CacheHit, Fresh, IdempotentReplay, Task as TaskCase};
    use RespPair::{
        ClampLink, ClampSeal, FirewallSeal, FirewallStamp, JudgeCommit, JudgeRecord, RecordCommit,
        SealSign, ShapeSeal, SignRebuild, SignRecord, StampSeal,
    };
    use RespRoute::{Direct, Mcp, Stdio, Task};
    match (route, case, era, pair) {
        _ if !stated(expect(route, case, era, pair)) => Driven::NotStated,
        // Phase C: a task's stored result is clamped, then sealed, at the
        // worker (input_round.rs:109-110), whatever era submitted it; the rows
        // drive a real task through `/mcp` (MIK-8398 R14, R19). The recovered
        // task (upstream.rs:554) is the same pair, pinned by MIK-8398's
        // `tasks_get_with_a_public_scope_is_sealed_as_delivered`.
        (Task, TaskCase, _, ClampSeal) => Driven::Row(
            "router::tests::task_execution_adapter::provenance_seal::a_worker_task_with_a_public_scope_is_sealed_as_delivered",
        ),
        (Task, TaskCase, _, StampSeal) => Driven::Row(
            "router::tests::task_execution_adapter::provenance_seal::a_task_run_by_the_worker_stores_a_sealed_result",
        ),
        (Stdio, Fresh, Era::Modern, ShapeSeal) => {
            Driven::Row("rows::stdio::r_shape_stdio_shape_precedes_seal")
        }
        // A seal needs a receipt minted in this request, so every sealed,
        // Bound clamp row also shows the stamp ran before the seal.
        (Stdio, Fresh, _, ClampSeal | StampSeal) => {
            Driven::Row("rows::stdio::r_clamp_stdio_scope_clamp_precedes_seal")
        }
        (Stdio, Fresh, _, FirewallSeal) => {
            Driven::Row("rows::stdio::r_fwseal_stdio_firewall_precedes_seal")
        }
        (Stdio, Fresh, _, SealSign | SignRecord) => Driven::Shared {
            pin: "response::source_order::stdio_finalizes_through_finalize_routed",
            rows: &[
                "rows::r_sign_seal_precedes_sign",
                "rows::r_recsign_sign_precedes_delivery_record",
            ],
        },
        (Stdio, Fresh, Era::Legacy, JudgeRecord) => Driven::Row(
            "server::signing_allocation_tests::stdio_tenant_reads::stdio_judged_read_is_one_record",
        ),
        (Stdio, Fresh, Era::Legacy, JudgeCommit) => Driven::Row(
            "server::signing_allocation_tests::collusion_stdio::stdio_judged_out_read_records_no_receipt",
        ),
        (Stdio, Fresh, Era::Legacy, RecordCommit) => Driven::Row(
            "server::signing_allocation_tests::collusion_stdio::stdio_audit_withheld_read_records_no_receipt",
        ),
        (Stdio, Fresh, Era::Legacy, SignRebuild) => Driven::Row(
            "server::signing_allocation_tests::collusion_stdio_delivered::a_stdio_answer_is_receipted_as_delivered",
        ),
        (Stdio, Fresh, Era::Legacy, ClampLink) => {
            Driven::Row("rows::stdio::r_link_stdio_scope_clamp_precedes_origin_link")
        }
        (Mcp | Direct, Fresh, Era::Modern, ShapeSeal) => {
            Driven::Row("rows::r_shape_shape_precedes_seal")
        }
        (Mcp | Direct, Fresh, _, ClampSeal | StampSeal) => {
            Driven::Row("rows::r_clamp_scope_clamp_precedes_seal")
        }
        (Mcp | Direct, Fresh, _, FirewallSeal) => {
            Driven::Row("rows::r_fwseal_firewall_precedes_seal")
        }
        (Mcp | Direct, Fresh, Era::Modern, SignRecord) => {
            Driven::Row("rows::r_recsign_sign_precedes_delivery_record")
        }
        (Mcp | Stdio, Fresh | CacheHit | IdempotentReplay, _, FirewallStamp)
        | (Direct, Fresh | IdempotentReplay, _, FirewallStamp) => {
            Driven::Row("response::source_order::stamp_and_egress_scan_order_is_pinned_at_source")
        }
        (Mcp | Direct, Fresh, Era::Legacy, ClampLink) => {
            Driven::Row("rows::r_link_scope_clamp_precedes_origin_link")
        }
        (Mcp | Direct, Fresh, Era::Modern, SealSign) => {
            Driven::Row("rows::r_sign_seal_precedes_sign")
        }
        (Mcp | Direct, Fresh, Era::Modern, SignRebuild) => {
            Driven::Row("rows::r_rebuild_relay_receipt_reflects_the_delivered_bytes")
        }
        (Mcp, Fresh, Era::Modern, RecordCommit) => {
            Driven::Row("rows::r_commit_delivery_record_precedes_relay_commit")
        }
        (Direct, Fresh, Era::Modern, RecordCommit) => Driven::Row(
            "router::collusion_direct_tests::verdict::a_read_record_failure_leaves_no_direct_receipt",
        ),
        (Mcp, Fresh, Era::Modern, JudgeCommit) => Driven::Row(
            "router::collusion_direct_tests::meta::meta_tenant_withheld_delivery_not_recorded",
        ),
        (Direct, Fresh, Era::Modern, JudgeCommit) => Driven::Row(
            "router::collusion_direct_tests::verdict::a_judged_out_direct_read_records_no_receipt",
        ),
        (Mcp, Fresh, Era::Modern, JudgeRecord) => Driven::Row(
            "router::tests::meta_firewall_verdict::caller_key::tenant_reads::a_judged_answer_is_one_record",
        ),
        (Direct, Fresh, Era::Legacy, JudgeRecord) => Driven::Row(
            "router::direct_audit_tests::response_judge::r_recjudge_direct_verdict_rides_the_delivery_record",
        ),
        (Direct, IdempotentReplay, _, StampSeal) => {
            Driven::Row("rows::r_replayseal_direct_replay_seal_gap")
        }
        _ => twin(case, era),
    }
}

/// Every stated cell resolves to a named row, directly or through a
/// `SameAs` twin, within two hops; a twin only from a case that reaches the
/// tail; and no cell that states nothing names a row.
#[test]
fn every_stated_response_cell_is_driven_or_explained() {
    let mut wrong = Vec::new();
    for cell in cells() {
        let (route, case, era, pair) = cell;
        let is_stated = stated(expect(route, case, era, pair));
        let mut at = (case, era);
        let mut resolved = false;
        for _ in 0..3 {
            match driven(route, at.0, at.1, pair) {
                Driven::Row(name) => {
                    resolved = !name.trim().is_empty();
                    break;
                }
                Driven::Shared { pin, rows } => {
                    resolved = !pin.trim().is_empty() && !rows.is_empty();
                    break;
                }
                Driven::SameAs {
                    pin,
                    case: to,
                    era: to_era,
                } => {
                    if pin.trim().is_empty() || !reaches_tail(route, at.0) {
                        break;
                    }
                    at = (to, to_era);
                }
                Driven::NotStated => break,
            }
        }
        if is_stated != resolved {
            wrong.push((cell, is_stated, resolved));
        }
    }
    assert!(
        wrong.is_empty(),
        "(cell, stated, resolves to a row): {wrong:?}"
    );
}
