// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8382 UNIFY.1b (design d2 §3.7, rows E1-E3): a caller with no
//! principal on a required per-user backend keeps the missing name's answer
//! (-32601), and the server logs one WARN naming the backend and the missing
//! execution principal, limited per (backend, caller key). Listings and
//! names the caller merely lacks log nothing.
//!
//! A WARN is matched by content, not wording: a WARN line naming [`BACKEND`]
//! and "execution principal". Each row builds its gateways outside the
//! capture and runs its calls inside it, on one current-thread runtime, so a
//! parallel test cannot write into the capture.

use super::{BACKEND, Entry, Gateway, StatusCode, TOOL, call, call_as, gateway, json};
use crate::gateway::meta_mcp::slot_verdict_fixture::{CallerSlot, Warmth};
use axum::body::to_bytes;
use serde_json::Value;
use tower::ServiceExt;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a current-thread runtime builds")
}

/// The captured WARN lines that report a missing principal on [`BACKEND`].
fn lacked_warns(log: &str) -> usize {
    log.lines()
        .filter(|line| {
            line.contains("WARN") && line.contains(BACKEND) && line.contains("execution principal")
        })
        .count()
}

/// A no-principal caller's `tools/list` on the direct route, or a
/// `gateway_list_tools` / `gateway_search_tools` on `/mcp`: listings only.
async fn list_unidentified(gw: &Gateway, uri: &str, params: Value) -> StatusCode {
    let method = if uri == "/mcp" { "tools/call" } else { "tools/list" };
    let body = json!({"jsonrpc": "2.0", "id": 9, "method": method, "params": params});
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .expect("a static request builds");
    let response = gw
        .router
        .clone()
        .oneshot(request)
        .await
        .expect("the router is infallible");
    let status = response.status();
    let _ = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("an in-memory body reads");
    status
}

/// E1: on `gateway_invoke` and on the direct route, a no-principal call of
/// [`TOOL`] answers exactly as an identified caller's call of a name its
/// catalogue lacks (status and body, id aside), and logs exactly one WARN.
/// RED at base: the answer matches, but nothing is logged.
#[test]
fn e1_case_b_refusal_answers_absent_and_warns_once() {
    let rt = runtime();
    let mut cells = Vec::new();
    for entry in [Entry::Invoke, Entry::Direct] {
        let refused = rt.block_on(gateway(CallerSlot::Valid, Warmth::Warm, "other", false));
        let missing = rt.block_on(gateway(CallerSlot::Lacks, Warmth::Warm, "other", false));
        let (answer, log) = crate::test_log_capture::capture_warnings(|| {
            rt.block_on(call_as(&refused, entry, json!({"q": "x"}), false))
        });
        let twin = rt.block_on(call(&missing, entry, json!({"q": "x"})));
        if answer != twin || answer.1.pointer("/error/code") != Some(&json!(-32601)) {
            cells.push(format!("E1 {entry:?}: answered {answer:?}, missing twin {twin:?}"));
        }
        if lacked_warns(&log) != 1 {
            cells.push(format!(
                "E1 {entry:?}: {} WARNs, want 1:\n{log}",
                lacked_warns(&log)
            ));
        }
    }
    assert!(cells.is_empty(), "E1:\n{}", cells.join("\n"));
}

/// E2 CONTROL: no WARN where no call is refused for a missing principal.
/// An identified caller's call of a name its catalogue lacks; a name the
/// active profile withholds from an identified caller; and listings by a
/// no-principal caller (direct `tools/list`, `gateway_list_tools`,
/// `gateway_search_tools`), which judge the same backend but refuse no call.
/// Green at base only because no such WARN exists yet; it carries the
/// "WARN on listing paths" mutant after the fix.
#[test]
fn e2_no_warn_without_a_refused_call() {
    let rt = runtime();
    let lacks = rt.block_on(gateway(CallerSlot::Lacks, Warmth::Warm, "other", false));
    let withheld = rt.block_on(gateway(CallerSlot::Valid, Warmth::Warm, TOOL, false));
    let listed = rt.block_on(gateway(CallerSlot::Valid, Warmth::Warm, "other", false));
    let (statuses, log) = crate::test_log_capture::capture_warnings(|| {
        rt.block_on(async {
            for entry in [Entry::Invoke, Entry::Direct] {
                call(&lacks, entry, json!({"q": "x"})).await;
                call(&withheld, entry, json!({"q": "x"})).await;
            }
            [
                list_unidentified(&listed, &format!("/mcp/{BACKEND}"), json!({})).await,
                list_unidentified(
                    &listed,
                    "/mcp",
                    json!({"name": "gateway_list_tools", "arguments": {"server": BACKEND}}),
                )
                .await,
                list_unidentified(
                    &listed,
                    "/mcp",
                    json!({"name": "gateway_search_tools", "arguments": {"query": TOOL}}),
                )
                .await,
            ]
        })
    });
    // As each listing answers at the base: the direct `tools/list` of a
    // no-principal caller is refused by identity propagation (403), the
    // meta listings answer 200. None of them is a refused call.
    assert_eq!(
        statuses,
        [StatusCode::FORBIDDEN, StatusCode::OK, StatusCode::OK],
        "E2 premise: a listing answered differently"
    );
    assert_eq!(lacked_warns(&log), 0, "E2: a WARN without a refusal:\n{log}");
    assert_eq!(listed.dispatched(), 0, "E2: a listing dispatched");
}

/// E3: the same no-principal caller refused three times (twice on
/// `gateway_invoke`, once on the direct route) within the window logs one
/// WARN: the limiter keys on (backend, caller key), not on the entry or the
/// request. RED at base: nothing is logged.
#[test]
fn e3_one_warn_per_caller_within_the_window() {
    let rt = runtime();
    let gw = rt.block_on(gateway(CallerSlot::Valid, Warmth::Warm, "other", false));
    let ((), log) = crate::test_log_capture::capture_warnings(|| {
        rt.block_on(async {
            for entry in [Entry::Invoke, Entry::Invoke, Entry::Direct] {
                let (status, answer) = call_as(&gw, entry, json!({"q": "x"}), false).await;
                assert_eq!(
                    (status, answer.pointer("/error/code")),
                    (StatusCode::OK, Some(&json!(-32601))),
                    "E3 premise {entry:?}: not the absent answer: {answer}"
                );
            }
        });
    });
    assert_eq!(lacked_warns(&log), 1, "E3: want one WARN:\n{log}");
}
