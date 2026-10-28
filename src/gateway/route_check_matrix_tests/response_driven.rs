// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The response matrix's coverage map (MIK-8689): which row drives each
//! stated cell of [`super::expect`], and the tests that every cited row is a
//! test in this tree and every stated cell resolves to one.

use super::{Invisible, RespCase, RespExpect, RespNa, RespPair, RespRoute, cells, expect};
use crate::protocol::meta::Era;

/// Which row drives a stated cell. A cell no row can drive gets an
/// `Undriven` variant with its reason when the first one appears (phase A2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Driven {
    /// The named row test.
    Row(&'static str),
    /// Several rows, each driving the pair at one of the route's sites.
    Rows(&'static [&'static str]),
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

/// The recovered task's seal row: a public scope is clamped, then the
/// receipt this request minted is sealed Bound to the delivered result.
const RECOVERED_TASK_SEALED: &str =
    "meta_mcp::tests::provenance_delivery::tasks_get_with_a_public_scope_is_sealed_as_delivered";
/// The pin behind an era twin: the tail takes no era or case.
const NO_CASE_OR_ERA: &str = "response::source_order::the_tail_takes_no_case_or_era";
/// The pin behind a replay or cache-hit twin: each reaches its route's tail.
const REACHES_THE_TAIL: &str = "response::source_order::replay_and_cache_hit_reach_the_tail";

/// Whether an answer of `case` on `route` runs that route's response tail.
/// A replay and a cache hit both do (`dispatch_tools_call.rs:721-727`,
/// `direct_idempotency.rs:141`, `stdio_dispatch.rs:681`, and the cache-hit
/// re-stamp at `invoke/pre_dispatch.rs:430`); a stored task is sealed at the
/// worker instead. Pinned by `source_order::replay_and_cache_hit_reach_the_tail`.
#[cfg(feature = "firewall")]
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
        FirewallSeal, FirewallStamp, JudgeCommit, JudgeRecord, RecordCommit, SealSign, ShapeSeal,
        SignRecord, StampSeal,
    };
    use RespRoute::{Direct, Mcp, Stdio, Task};
    if !stated(expect(route, case, era, pair)) {
        return Driven::NotStated;
    }
    if matches!(case, IdempotentReplay)
        && let Some(row) = replay_row(route, era, pair)
    {
        return row;
    }
    if matches!((route, case), (Stdio, Fresh))
        && let Some(row) = stdio_fresh_row(era, pair)
    {
        return row;
    }
    match (route, case, era, pair) {
        (Task, TaskCase, _, StampSeal) => Driven::Rows(&[
            "router::tests::task_execution_adapter::provenance_seal::a_task_run_by_the_worker_stores_a_sealed_result",
            RECOVERED_TASK_SEALED,
        ]),
        (Mcp | Direct, Fresh, Era::Modern, ShapeSeal) => {
            Driven::Row("rows::r_shape_shape_precedes_seal")
        }
        (Mcp | Direct, Fresh, _, StampSeal) => {
            Driven::Row("rows::r_stamp_seal_binds_the_delivered_bytes")
        }
        (Mcp | Direct, Fresh, _, FirewallSeal) => {
            Driven::Row("rows::r_fwseal_firewall_precedes_seal")
        }
        (Mcp | Direct, Fresh, Era::Modern, SignRecord) => {
            Driven::Row("rows::r_recsign_sign_precedes_delivery_record")
        }
        // The order is read at source; the row shows the scan keeps what the
        // stamp counted.
        (Mcp | Stdio, Fresh | CacheHit, _, FirewallStamp) => Driven::Shared {
            pin: "response::source_order::stamp_and_egress_scan_order_is_pinned_at_source",
            rows: &["rows::r_fwstamp_redaction_keeps_the_counted_text"],
        },
        (Direct, Fresh, _, FirewallStamp) => {
            Driven::Row("response::source_order::stamp_and_egress_scan_order_is_pinned_at_source")
        }
        (Mcp | Direct, Fresh, Era::Modern, SealSign) => {
            Driven::Row("rows::r_sign_seal_precedes_sign")
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
        _ => twin(case, era),
    }
}

/// The row behind a stated stdio `Fresh` cell (phase B), where stdio has
/// rows of its own.
const fn stdio_fresh_row(era: Era, pair: RespPair) -> Option<Driven> {
    use RespPair::{
        FirewallSeal, JudgeCommit, JudgeRecord, RecordCommit, SealSign, ShapeSeal, SignRecord,
        StampSeal,
    };
    Some(match (era, pair) {
        (Era::Modern, ShapeSeal) => Driven::Row("rows::stdio::r_shape_stdio_shape_precedes_seal"),
        // A seal needs a receipt minted in this request, so every sealed,
        // Bound clamp row also shows the stamp ran before the seal.
        (_, StampSeal) => Driven::Row("rows::stdio::r_stamp_stdio_seal_binds_the_delivered_bytes"),
        (_, FirewallSeal) => Driven::Row("rows::stdio::r_fwseal_stdio_firewall_precedes_seal"),
        (_, SealSign) => Driven::Shared {
            pin: "response::source_order::stdio_finalizes_through_finalize_routed",
            rows: &["rows::r_sign_seal_precedes_sign"],
        },
        // Stdio records outside `finalize_routed`, in `judge_and_commit`, so
        // its own row drives the pair (lead ruling R4).
        (Era::Legacy, SignRecord) => {
            Driven::Row("rows::stdio::r_recsign_stdio_sign_precedes_delivery_record")
        }
        (Era::Legacy, JudgeRecord) => Driven::Row(
            "server::signing_allocation_tests::stdio_tenant_reads::stdio_judged_read_is_one_record",
        ),
        (Era::Legacy, JudgeCommit) => Driven::Row(
            "server::signing_allocation_tests::collusion_stdio::stdio_judged_out_read_records_no_receipt",
        ),
        (Era::Legacy, RecordCommit) => Driven::Row(
            "server::signing_allocation_tests::collusion_stdio::stdio_audit_withheld_read_records_no_receipt",
        ),
        _ => return None,
    })
}

/// The row behind a stated `IdempotentReplay` cell that is not its Fresh twin.
const fn replay_row(route: RespRoute, era: Era, pair: RespPair) -> Option<Driven> {
    use RespPair::StampSeal;
    use RespRoute::Direct;
    Some(match (route, era, pair) {
        (Direct, _, StampSeal) => Driven::Row("rows::r_replayseal_direct_replay_seal_gap"),
        _ => return None,
    })
}

/// The rows that show an `OrderInvisibleByOutcome` reason holds, where a row
/// can. `StoredBytesAlreadyClamped` rests on a stored delivery's result being
/// serialized through the `cacheScope` clamp (`to_value_lossy` is
/// `serde_json::to_value` over `serialize_delivered_result`).
const fn invisible_pins(reason: Invisible) -> &'static [&'static str] {
    match reason {
        Invisible::StoredBytesAlreadyClamped => {
            &["protocol::cacheable::clamp_tests::every_non_private_scope_is_delivered_as_private"]
        }
        Invisible::IngressStripsBackendSignature => &[
            "protocol::reserved_members::tests::a_full_strip_removes_every_gateway_only_member_and_nothing_else",
            "rows::r_ownsig_the_gateway_signature_is_not_receipted",
        ],
        Invisible::JudgeOnlyReplaces
        | Invisible::StampIgnoresShapedMembers
        | Invisible::SealWritesOnlyExcludedMeta
        | Invisible::JudgeReadsNothingSigningAdds => &[],
    }
}

/// The rows that show a `NotApplicable` reason holds, where a row can.
const fn na_pins(reason: RespNa) -> &'static [&'static str] {
    match reason {
        RespNa::ReplayReservesTheStoredDelivery => &[
            "rows::r_replay_mcp_reserves_the_stored_delivery",
            "rows::stdio::r_replay_stdio_reserves_the_stored_delivery",
            "rows::r_erareplay_cross_era_replay_is_refused",
            "rows::stdio::r_erareplay_stdio_cross_era_replay_is_refused",
        ],
        RespNa::ReplayMintsNoReceipt => &["rows::r_replayseal_direct_replay_seal_gap"],
        RespNa::IngressRemovesToolCallScope => &[
            "rows::r_stamp_seal_binds_the_delivered_bytes",
            "rows::stdio::r_stamp_stdio_seal_binds_the_delivered_bytes",
            "rows::r_clamp_read_delivers_private",
            "router::tests::task_execution_adapter::provenance_seal::a_worker_task_with_a_public_scope_is_sealed_as_delivered",
        ],
        RespNa::NoModernShapeOnLegacy
        | RespNa::NoCacheOnDirect
        | RespNa::TaskHasNoOriginLink
        | RespNa::TaskIsItsOwnRoute
        | RespNa::TaskTailIsClampAndSeal => &[],
    }
}

/// Every test name `driven` gives for `driven`, pins included.
fn cited(driven: Driven) -> Vec<&'static str> {
    match driven {
        Driven::Row(name) => vec![name],
        Driven::Rows(names) => names.to_vec(),
        Driven::Shared { pin, rows } => std::iter::once(pin).chain(rows.iter().copied()).collect(),
        Driven::SameAs { pin, .. } => vec![pin],
        Driven::NotStated => Vec::new(),
    }
}

/// Every `.rs` file under `dir`, read.
fn sources_under(dir: &std::path::Path, out: &mut Vec<(std::path::PathBuf, String)>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("a directory entry").path();
        if path.is_dir() {
            sources_under(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            let text = std::fs::read_to_string(&path).unwrap_or_default();
            out.push((path, text));
        }
    }
}

/// Whether `text` defines `needle` (`fn <name>(`) under a `#[test]` or
/// `#[tokio::test]` attribute: the attribute, doc and blank lines directly
/// above the fn.
fn is_test_fn(text: &str, needle: &str) -> bool {
    text.match_indices(needle).any(|(at, _)| {
        let line_start = text[..at].rfind('\n').map_or(0, |n| n + 1);
        text[..line_start]
            .lines()
            .rev()
            .map(str::trim)
            .take_while(|line| line.starts_with("#[") || line.starts_with("///") || line.is_empty())
            .any(|line| line == "#[test]" || line.starts_with("#[tokio::test"))
    })
}

/// Every name the map cites is a test this tree defines: its last segment is
/// a `#[test]`/`#[tokio::test]` `fn` (in `response_rows.rs` or `response_source_order.rs` for the
/// matrix's own `rows::` and `source_order::` names), so a rename or a typo
/// fails here and not only in an external `--list` check. A `NotApplicable`
/// reason's rows ([`na_pins`]) are checked the same way.
#[test]
fn every_cited_response_row_is_a_test_in_the_tree() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    sources_under(&root, &mut files);
    let mut names = std::collections::BTreeSet::new();
    for (route, case, era, pair) in cells() {
        names.extend(cited(driven(route, case, era, pair)));
        match expect(route, case, era, pair) {
            RespExpect::NotApplicable(reason) => names.extend(na_pins(reason).iter().copied()),
            RespExpect::OrderInvisibleByOutcome(reason) => {
                names.extend(invisible_pins(reason).iter().copied());
            }
            _ => {}
        }
    }
    let mut missing = Vec::new();
    for name in &names {
        let seg = name.rsplit("::").next().unwrap_or(name);
        let needle = format!("fn {seg}(");
        let home = if name.starts_with("rows::") {
            Some("route_check_matrix_tests/response_rows.rs")
        } else if name.starts_with("response::source_order::") {
            Some("route_check_matrix_tests/response_source_order.rs")
        } else {
            None
        };
        let found = files.iter().any(|(path, text)| {
            home.is_none_or(|home| path.ends_with(home)) && is_test_fn(text, &needle)
        });
        if !found {
            missing.push(*name);
        }
    }
    assert!(
        missing.is_empty(),
        "cited rows with no test fn: {missing:?}"
    );
}

/// Every stated cell resolves to a named row, directly or through a
/// `SameAs` twin, within two hops; a twin only from a case that reaches the
/// tail; and no cell that states nothing names a row. The rows compile only
/// with `firewall` (`mod rows`), so coverage is claimed for that build.
#[cfg(feature = "firewall")]
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
                Driven::Rows(names) => {
                    resolved =
                        !names.is_empty() && names.iter().all(|name| !name.trim().is_empty());
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
