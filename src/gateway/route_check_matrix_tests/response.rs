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
    /// (`trust/result_extractor.rs:55-80`), redaction never flips `isError`,
    /// and a Block replaces the whole answer. Since MIK-8745 and MIK-8772 a
    /// redaction inside a JSON string value or key keeps the text parseable,
    /// so the count survives the scan; for texts over 1 MiB the count can
    /// still be lost (MIK-8774).
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
    /// A replay's stored bytes are already clamped on every route: a stored
    /// delivery's result is serialized through the `cacheScope` clamp
    /// (`protocol/messages.rs:54`), and `/mcp` and stdio clamp before storing
    /// too. So a replay's clamp changes nothing before the fresh link it mints (the stored link
    /// is stripped: "a replay mints its own", `meta_mcp/admission.rs:147`).
    StoredBytesAlreadyClamped,
    /// Ingress removes a backend's own `_signature` (a gateway-only member),
    /// so the message signature overwrites nothing a receipt could hold, and
    /// a rebuild before or after signing digests the same backend text. The
    /// rebuild still leaves out the gateway's own signature, which signing
    /// notes: `rows::r_ownsig_the_gateway_signature_is_not_receipted`.
    IngressStripsBackendSignature,
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
    /// `admission.rs:394`): it mints no receipt, so nothing is stamped or
    /// sealed anew (`seal_receipt` seals only a receipt this request minted,
    /// `invoke/provenance_stamp.rs:181`). Pinned by
    /// `rows::r_replay_mcp_reserves_the_stored_delivery` (red-check record
    /// red-A1-record.md: the earlier re-stamp premise was wrong).
    ReplayReservesTheStoredDelivery,
    /// A keyed replay on Direct runs `finish_tail` over a stored delivery that
    /// was stored before the seal (`direct_idempotency.rs` `deliver_replay`),
    /// and it mints no receipt, so nothing is stamped or sealed (the stored
    /// receipt arrives unsealed: MIK-8705, `rows::r_replayseal_direct_replay_seal_gap`).
    ReplayMintsNoReceipt,
    /// The stored task tail is the clamp and the seal over the worker's mint;
    /// the delivery stages run on the `tasks/get` route that reads it.
    TaskTailIsClampAndSeal,
    /// The matrix drives `tools/call`, whose answer may not carry
    /// `cacheScope`: ingress removes a backend's copy, so the clamp has
    /// nothing to change there. On the direct route no cacheable method is
    /// linked or sealed (`finish_direct` links only `tools/call`, and only
    /// `tools/call` is sealed and signed), so no clamp order exists to state;
    /// `rows::r_clamp_read_delivers_private` keeps the clamp's own effect.
    IngressRemovesToolCallScope,
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

/// Each route's tail as the code runs it (verified against the code at
/// 407481d51).
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
        IngressStripsBackendSignature, JudgeOnlyReplaces, JudgeReadsNothingSigningAdds,
        SealWritesOnlyExcludedMeta, StampIgnoresShapedMembers, StoredBytesAlreadyClamped,
    };
    use RespCase::{CacheHit, Fresh, IdempotentReplay, Task as TaskCase};
    use RespExpect::{ExpectedGap, NotApplicable, OrderInvisibleByOutcome, Ordered};
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
        (Task, TaskCase, _, ClampSeal) => NotApplicable(RespNa::IngressRemovesToolCallScope),
        (Direct, CacheHit, _, _) => NotApplicable(RespNa::NoCacheOnDirect),
        (Mcp | Stdio | Direct, Fresh | CacheHit, _, ClampLink | ClampSeal) => {
            NotApplicable(RespNa::IngressRemovesToolCallScope)
        }
        (_, _, Era::Legacy, ShapeSeal | StampShape) => NotApplicable(RespNa::NoModernShapeOnLegacy),
        // On /mcp and stdio a replay runs the tail on the stored, already
        // sealed bytes: no mint, so nothing is sealed anew; it does mint a
        // fresh link, after a clamp that changes nothing (lead rulings, MIK-8689
        // phase C and R3). A replay from the other era is refused (MIK-8747),
        // so no stored answer is shaped for an era it was not stored in.
        // Every route's stored result is already clamped (its
        // serialization clamps), so no replay's clamp changes anything; Direct
        // stores before its seal and mints nothing to seal (delta check).
        (
            Mcp | Stdio,
            IdempotentReplay,
            _,
            ShapeSeal | FirewallSeal | ClampSeal | SealSign | StampSeal | FirewallStamp,
        ) => NotApplicable(RespNa::ReplayReservesTheStoredDelivery),
        (Mcp | Stdio | Direct, IdempotentReplay, _, ClampLink) => {
            OrderInvisibleByOutcome(StoredBytesAlreadyClamped)
        }
        (Direct, IdempotentReplay, _, StampSeal) => ExpectedGap(RespTicket::Mik8705),
        (
            Direct,
            IdempotentReplay,
            _,
            ShapeSeal | FirewallSeal | ClampSeal | SealSign | FirewallStamp,
        ) => NotApplicable(RespNa::ReplayMintsNoReceipt),
        (Mcp | Stdio, _, _, FirewallStamp) => AFTER_MIK_8745,
        (_, _, _, JudgeRebuild) => OrderInvisibleByOutcome(JudgeOnlyReplaces),
        (_, _, _, StampShape) => OrderInvisibleByOutcome(StampIgnoresShapedMembers),
        (_, _, _, LinkSeal) => OrderInvisibleByOutcome(SealWritesOnlyExcludedMeta),
        (_, _, _, SignJudge) => OrderInvisibleByOutcome(JudgeReadsNothingSigningAdds),
        (_, _, _, SignRebuild) => OrderInvisibleByOutcome(IngressStripsBackendSignature),
        (
            _,
            _,
            _,
            ShapeSeal | FirewallSeal | StampSeal | SealSign | SignRecord | JudgeRecord
            | RecordCommit | JudgeCommit | FirewallStamp,
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

/// The Mcp and stdio `FirewallStamp` cells since MIK-8745: the stamp still
/// precedes the scan there (MIK-8707), but no counted fact differs.
pub(crate) const AFTER_MIK_8745: RespExpect =
    RespExpect::LatentGap(RespTicket::Mik8707, Latent::NoExtractedFactRedactionChanges);

/// The gap set is exactly MIK-8705, expected (a direct replay is not
/// resealed, both eras), and MIK-8707, latent (Mcp and stdio stamp before the
/// egress scan, fresh and cache hit, both eras: [`AFTER_MIK_8745`]). A new,
/// closed or reclassified gap moves this pin.
#[test]
fn the_response_table_names_its_gaps() {
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
    assert_eq!(of(RespTicket::Mik8707, true), 8, "{gaps:?}");
    assert_eq!(gaps.len(), 10, "the gap set moved: {gaps:?}");
}

/// The order behind the MIK-8707 latent gap, pinned at source.
#[path = "response_source_order.rs"]
mod source_order;

#[cfg(feature = "firewall")]
#[path = "response_rows.rs"]
mod rows;

/// Which row drives each stated cell, and the checks that every cited row
/// exists and every stated cell is driven.
#[path = "response_driven.rs"]
mod driven;
