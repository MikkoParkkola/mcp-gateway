// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8412: on `POST /mcp` the caller verdict runs before signing admission
//! (`dispatch_tools_call.rs`), so a refused signed call pays for it. What it
//! adds is measured as the difference between a per-user target (the verdict
//! reads custody) and a plain target (nothing to judge), the same refusal and
//! payload otherwise, and capped (ALLOC.2, lead ruling 2026-10-19).
//!
//! Why not the stdio caps (2 large, 8 KiB small, MIK-8400): those bound a
//! whole refusal after parse; this share is a fixed cost per refused call
//! with no payload term, the same at 1 and 3 MiB. The cap is on that share
//! and on its staying payload-independent; the pinned large count and how it
//! moved are at [`LARGE_ALLOCATIONS`]. HTTP intake's own cost is outside it
//! (the plain target pays it too).
//!
//! Custody work runs in `spawn_blocking`, off the request's thread, so the
//! rows meter every thread (`measure_async_process_wide`) inside an isolated
//! child process running only that row.

use axum::body::to_bytes;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::busy_nonce::signed_fixture_with;
use super::{BACKEND, KEY, TOOL, modern_meta};
use crate::gateway::alloc_meter::{
    LARGE_BYTES, Measured, isolate, measure_async, measure_async_process_wide,
};
use crate::security::sanitize::InputSanitizing;

/// Exactly this many more large allocations on the per-user target
/// (all threads; the lead's ruling keeps the count exact). Measured 3 at
/// first, 2 after merges #3954/#3965/#3974/#3973/#3977/#3956, 1 after #3976:
/// a change in either direction must be re-measured and re-ruled, not
/// absorbed.
const LARGE_ALLOCATIONS: u64 = 1;
/// At most this many more bytes in large allocations.
const LARGE_BUDGET: u64 = 16 * 1024;
/// At most this many more bytes in small allocations: measured 62,210 to
/// 62,260 B, most of it the custody read on the blocking pool.
const SMALL_BUDGET: u64 = 96 * 1024;
/// The share may differ by at most this much between 1 and 3 MiB.
///
/// 2 KiB (lead ruling 2026-10-27; was 1 KiB): the refused call's delivery
/// record now adds about 237 small allocations, and about one loaded run in
/// 30 puts a one-off ~1 KB on the first measured call (1,042 and 1,082 B
/// observed, the 3 MiB share identical both times), likely a buffer stepping
/// up its capacity in the record write. A payload copy would cost megabytes,
/// and `PLAIN_SLOPE_PER_MIB` pins that separately. Restoring 1 KiB waits on
/// finding and pre-sizing that buffer.
const SIZE_SLACK: u64 = 2 * 1024;
/// How much more the plain target's refusal may allocate per extra MiB of
/// payload. A payload copy in the shared verdict loop is paid by both targets
/// and so cancels out of the share; this bounds it on the plain target.
/// Measured 7,202,320 B per MiB (HTTP intake, MIK-8499); an upper bound, so
/// it stays valid as intake gets cheaper.
const PLAIN_SLOPE_PER_MIB: u64 = 7_600_000;
/// A refusal of an empty payload on the per-user target: its large
/// allocations are the boxed dispatch futures, which both targets pay, so
/// verdict state carried in them would not show in the share. Measured 9 /
/// 41,168 B (2026-10-19).
const FUTURE_LARGE: u64 = 10;
const FUTURE_BUDGET: u64 = 48 * 1024;

fn nested(target: usize) -> Value {
    let leaf = json!({"note": "n".repeat(512), "flags": [true, false, true],
        "ids": (0..16).collect::<Vec<u32>>()});
    let leaf_bytes = serde_json::to_vec(&leaf).expect("leaf").len();
    let branch = Value::Array((0..=target / leaf_bytes).map(|_| leaf.clone()).collect());
    json!({"folder": "inbox", "filter": {"nested": {"deep": {"batch": branch}}}})
}

fn body(target: Option<(&str, &str)>, nonce: Option<Value>, size: usize) -> bytes::Bytes {
    let (server, tool) = target.unwrap_or((BACKEND, TOOL));
    let mut arguments = json!({"server": server, "tool": tool, "arguments": nested(size)});
    if let Some(nonce) = nonce {
        arguments["nonce"] = nonce;
    }
    bytes::Bytes::from(
        json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {
            "name": "gateway_invoke", "arguments": arguments, "_meta": modern_meta()}})
        .to_string(),
    )
}

fn request(body: bytes::Bytes) -> axum::http::Request<axum::body::Body> {
    axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {KEY}"))
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", "gateway_invoke")
        .body(axum::body::Body::from(body))
        .expect("a request")
}

/// A plain backend with no account: the caller verdict has nothing to judge.
struct Plain;

#[async_trait::async_trait]
impl crate::transport::Transport for Plain {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        let id = crate::protocol::RequestId::Number(1);
        if method == "tools/list" {
            return Ok(crate::protocol::JsonRpcResponse::success(
                id,
                json!({"tools": [{"name": "echo", "inputSchema": {"type": "object"}}]}),
            ));
        }
        Ok(crate::protocol::JsonRpcResponse::success(
            id,
            json!({"content": [{"type": "text", "text": "ok"}], "isError": false}),
        ))
    }
    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        Ok(())
    }
    fn is_connected(&self) -> bool {
        true
    }
    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// The verdict's share of one refusal at `size`: per-user minus plain.
#[derive(Debug, Clone, Copy)]
struct Share {
    large: i128,
    large_bytes: i128,
    small_bytes: i128,
}

fn share(per_user: Measured, plain: Measured) -> Share {
    let small = |m: Measured| i128::from(m.bytes - m.large_bytes);
    Share {
        large: i128::from(per_user.large) - i128::from(plain.large),
        large_bytes: i128::from(per_user.large_bytes) - i128::from(plain.large_bytes),
        small_bytes: small(per_user) - small(plain),
    }
}

/// One refusal on `target`, metered from the request to the answer's bytes.
async fn refused(
    fx: &super::Fx,
    target: Option<(&str, &str)>,
    nonce: Option<Value>,
    size: usize,
) -> (Value, Measured) {
    refused_body(fx, body(target, nonce, size)).await
}

/// [`refused`] for a body built by the caller.
async fn refused_body(fx: &super::Fx, bytes: bytes::Bytes) -> (Value, Measured) {
    let req = request(bytes);
    let (reply, measured) = measure_async_process_wide(|| async {
        let response = fx.router.clone().oneshot(req).await.expect("an answer");
        to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("a body")
    })
    .await;
    (
        serde_json::from_slice(&reply).unwrap_or(Value::Null),
        measured,
    )
}

/// The two targets the share is the difference of: the per-user `BACKEND`
/// (`None`) and a plain backend with no account.
const TARGETS: [Option<(&str, &str)>; 2] = [None, Some(("plain", "echo"))];

/// The signed fixture with the plain backend registered beside it, both
/// targets warmed unmetered, and each nonce a replayed row reuses spent once.
async fn prepared(kind: &str, nonce: &impl Fn(&str) -> Option<Value>) -> super::Fx {
    prepared_with(kind, nonce, InputSanitizing::Off).await
}

/// [`prepared`] with `security.sanitize_input` as `sanitizing` says.
async fn prepared_with(
    kind: &str,
    nonce: &impl Fn(&str) -> Option<Value>,
    sanitizing: InputSanitizing,
) -> super::Fx {
    let fx = signed_fixture_with(sanitizing).await;
    let plain = std::sync::Arc::new(crate::backend::Backend::new(
        "plain",
        crate::config::BackendConfig::r2_off(),
        &crate::config::FailsafeConfig::default(),
        std::time::Duration::from_secs(300),
    ));
    plain.set_transport_for_test(std::sync::Arc::new(Plain));
    assert!(
        fx.gateway.backends().register(plain),
        "premise: plain registered"
    );
    for (i, target) in TARGETS.into_iter().enumerate() {
        drop(
            fx.router
                .clone()
                .oneshot(request(body(target, None, 0)))
                .await,
        );
        for size in [0usize, 1 << 20, 3 << 20] {
            if let Some(Value::String(n)) = nonce(&format!("{kind}-{i}-{size}")) {
                let response = fx
                    .router
                    .clone()
                    .oneshot(request(body(target, Some(json!(n)), 0)))
                    .await
                    .expect("an answer");
                let primed: Value = serde_json::from_slice(
                    &to_bytes(response.into_body(), usize::MAX)
                        .await
                        .expect("a body"),
                )
                .unwrap_or(Value::Null);
                assert!(
                    primed.get("error").is_none(),
                    "{kind}: premise, the priming call under {n} was served: {primed}"
                );
            }
        }
    }
    fx
}

/// ALLOC.1 + ALLOC.2 for one refusal kind: at 1 and 3 MiB the refusal's
/// error is pinned, the verdict is shown to run on the per-user target and
/// not on the plain one, and its share is within the cap and the same at
/// both sizes.
fn verdict_share_is_capped(kind: &str, nonce: impl Fn(&str) -> Option<Value>, expected: &str) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    rt.block_on(async {
        let fx = prepared(kind, &nonce).await;
        let (empty_reply, empty) = refused(&fx, None, nonce(&format!("{kind}-0-0")), 0).await;
        assert_eq!(
            empty_reply
                .pointer("/error/message")
                .and_then(Value::as_str),
            Some(expected),
            "{kind}: premise, the empty-payload call is the same refusal: {empty_reply}"
        );
        assert!(
            empty.large <= FUTURE_LARGE && empty.large_bytes <= FUTURE_BUDGET,
            "ALLOC.2 {kind}: an empty refusal's dispatch futures grew: {empty}, above \
             {FUTURE_LARGE} large / {FUTURE_BUDGET} B"
        );
        let mut shares = Vec::new();
        let mut plain_bytes = Vec::new();
        for size in [1usize << 20, 3 << 20] {
            let mut readings = Vec::new();
            for (i, target) in TARGETS.into_iter().enumerate() {
                let resolves = fx.gateway.resolves();
                let (reply, measured) =
                    refused(&fx, target, nonce(&format!("{kind}-{i}-{size}")), size).await;
                let lookups = fx.gateway.resolves() - resolves;
                assert_eq!(
                    reply.pointer("/error/message").and_then(Value::as_str),
                    Some(expected),
                    "{kind} {size}: the refusal changed: {reply}"
                );
                assert_eq!(
                    lookups > 0,
                    target.is_none(),
                    "{kind} {size}: premise, the verdict reads custody on the per-user target only"
                );
                readings.push(measured);
            }
            plain_bytes.push(readings[1].bytes);
            let share = share(readings[0], readings[1]);
            assert!(
                share.large >= 0 && share.large_bytes >= 0 && share.small_bytes >= 0,
                "ALLOC.2 {kind} {size}: the plain target cost more than the per-user one, \
                 so the baseline is wrong: {share:?}"
            );
            assert!(
                share.large == i128::from(LARGE_ALLOCATIONS)
                    && share.large_bytes <= i128::from(LARGE_BUDGET)
                    && share.small_bytes <= i128::from(SMALL_BUDGET),
                "ALLOC.2 {kind} {size}: the verdict's share {share:?} is not \
                 {LARGE_ALLOCATIONS} large within {LARGE_BUDGET} B and {SMALL_BUDGET} B small \
                 (per-user {}, plain {})",
                readings[0],
                readings[1]
            );
            shares.push(share);
        }
        let slope = plain_bytes[1].saturating_sub(plain_bytes[0]) / 2;
        assert!(
            slope <= PLAIN_SLOPE_PER_MIB,
            "ALLOC.2 {kind}: the plain target's refusal grew {slope} B per MiB of payload, \
             above {PLAIN_SLOPE_PER_MIB} (a payload copy on the shared path?)"
        );
        let total = |s: Share| s.large_bytes + s.small_bytes;
        assert!(
            total(shares[1]).abs_diff(total(shares[0])) <= u128::from(SIZE_SLACK)
                && shares[1].large == shares[0].large,
            "ALLOC.2 {kind}: the verdict's share grows with the payload: {shares:?}"
        );
    });
}

#[test]
fn a_missing_nonce_refusal_pays_a_capped_verdict_share() {
    if isolate(&test_path(
        "a_missing_nonce_refusal_pays_a_capped_verdict_share",
    )) {
        return;
    }
    verdict_share_is_capped(
        "missing",
        |_| None,
        "Nonce required when message signing is enforced",
    );
}

#[test]
fn a_malformed_nonce_refusal_pays_a_capped_verdict_share() {
    if isolate(&test_path(
        "a_malformed_nonce_refusal_pays_a_capped_verdict_share",
    )) {
        return;
    }
    verdict_share_is_capped("malformed", |_| Some(json!(42)), "Invalid signing nonce");
}

#[test]
fn a_replayed_nonce_refusal_pays_a_capped_verdict_share() {
    if isolate(&test_path(
        "a_replayed_nonce_refusal_pays_a_capped_verdict_share",
    )) {
        return;
    }
    verdict_share_is_capped(
        "replayed",
        |key| Some(json!(format!("http-8412-{key}"))),
        "Nonce replay detected",
    );
}

/// The meter is not blind on this path: a deep clone of the 1 MiB payload
/// made across an await costs at least its size, and one known allocation
/// reads as one large one, a blocking-pool thread's included.
#[test]
fn the_meter_sees_this_payload() {
    if isolate(&test_path("the_meter_sees_this_payload")) {
        return;
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    rt.block_on(async {
        let payload = nested(1 << 20);
        let (copy, measured) = measure_async(|| async {
            tokio::task::yield_now().await;
            payload.clone()
        })
        .await;
        assert!(measured.bytes >= 1 << 20, "positive control: {measured}");
        drop(copy);
        let (copy, wide) = measure_async_process_wide(|| async {
            tokio::task::yield_now().await;
            payload.clone()
        })
        .await;
        assert!(
            wide.bytes >= 1 << 20,
            "positive control, all threads: {wide}"
        );
        drop(copy);
        // Consecutive scopes start from zero.
        let ((), quiet) = measure_async_process_wide(|| async {}).await;
        assert!(
            quiet.bytes < wide.bytes / 100,
            "a scope did not reset: {quiet}"
        );
        // Start the blocking pool unmetered, so the reading is the
        // allocation and not the pool's first thread.
        tokio::task::spawn_blocking(|| ())
            .await
            .expect("the blocking pool starts");
        let (block, one) = measure_async_process_wide(|| async {
            tokio::task::spawn_blocking(|| Vec::<u8>::with_capacity(LARGE_BYTES))
                .await
                .expect("the blocking task")
        })
        .await;
        assert!(
            one.large >= 1 && one.large_bytes >= u64::try_from(LARGE_BYTES).expect("fits"),
            "the blocking pool's allocation is seen: {one}"
        );
        drop(block);
    });
}

/// A libtest filter for `name` in this module, from the crate root's children
/// down (`module_path!` names the crate itself first).
fn test_path(name: &str) -> String {
    let module = module_path!();
    let module = module
        .split_once("::")
        .map_or(module, |(_crate, rest)| rest);
    format!("{module}::{name}")
}

/// MIK-8499 INTAKE.2(a): what a refused call may cost beyond parsing its
/// body. Measured 46,792 B at both 1 and 3 MiB after the fix (it was
/// 3,216,360 B at 1 MiB, the `_meta` merge's copy of the arguments).
/// Lead-ruled 2026-10-20: 64 KiB fixed, tightened only on new evidence.
///
/// Raised to 96 KiB (lead ruling 2026-10-27): a refused `/mcp` call now
/// writes its delivery record. Measured 87,369 B at both 1 and 3 MiB, so the
/// cost stays fixed. The record write alone is 28,631 B across 237 calls,
/// none of 2 KiB or more (serializing and hashing the answer is 1,531 B of
/// it): many small allocations, no one buffer to shrink. Trimming that path
/// back under 64 KiB is tracked for 4.0.1. Margin: about 11 KB (98,304 B cap over 87,369 B measured); a
/// further raise needs its own breakdown.
const OVER_PARSE: u64 = 96 * 1024;
/// How much that excess may grow from 1 to 3 MiB: no payload term (measured
/// 0 B).
const OVER_PARSE_GROWTH: u64 = 1024;

/// MIK-8499 INTAKE.2(a): on this fixture (sanitizer off, firewall off, the
/// body in one chunk), a refused 1 and 3 MiB `gateway_invoke` costs its parse
/// plus a fixed cap, with no second term that grows with the payload. Red
/// before the fix: the meta-tool `_meta` merge cloned the whole argument tree
/// (about 3.2 MB per MiB, `merge_client_meta_ref`).
#[test]
fn a_refused_meta_call_costs_its_parse_plus_a_fixed_cap() {
    if isolate(&test_path(
        "a_refused_meta_call_costs_its_parse_plus_a_fixed_cap",
    )) {
        return;
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    rt.block_on(async {
        let fx = prepared("missing", &|_| None).await;
        let plain = Some(("plain", "echo"));
        // Warm the plain path unmetered, as the share rows do.
        let _ = refused(&fx, plain, None, 1 << 10).await;
        let mut over = Vec::new();
        for size in [1usize << 20, 3 << 20] {
            let bytes = body(plain, None, size);
            let (_, parse) = measure_async_process_wide(|| async {
                serde_json::from_slice::<Value>(&bytes).expect("the body is JSON")
            })
            .await;
            let (reply, refusal) = refused(&fx, plain, None, size).await;
            assert_eq!(
                reply.pointer("/error/message").and_then(Value::as_str),
                Some("Nonce required when message signing is enforced"),
                "INTAKE.2(a) {size}: premise, the same refusal: {reply}"
            );
            let excess = refusal.bytes.saturating_sub(parse.bytes);
            println!("INTAKE.2(a) size={size} parse={parse} refusal={refusal} over_parse={excess}");
            assert!(
                excess <= OVER_PARSE,
                "INTAKE.2(a) {size}: the refusal allocated {excess} B beyond its parse, above \
                 {OVER_PARSE} (parse {parse}, refusal {refusal})"
            );
            over.push(excess);
        }
        assert!(
            over[1].abs_diff(over[0]) <= OVER_PARSE_GROWTH,
            "INTAKE.2(a): the excess over parse grows with the payload: {over:?}"
        );
    });
}

/// MIK-8499 INTAKE.2(b): what the input sanitizer adds to a refused call.
/// Lead-ruled 2026-10-20: 64 KiB fixed, tightened only on new evidence.
const SANITIZER_SHARE: u64 = 64 * 1024;

/// MIK-8499 INTAKE.2(b): the input sanitizer's share of a refused 1 and 3 MiB
/// `gateway_invoke` (the same call with `security.sanitize_input` on minus
/// off, the production default being on) is a fixed cap, the same at both
/// sizes. Red before the fix: the sanitizer rebuilt the whole request, about
/// 9 MB at 1 MiB.
#[test]
fn a_refused_call_pays_no_payload_term_for_the_sanitizer() {
    if isolate(&test_path(
        "a_refused_call_pays_no_payload_term_for_the_sanitizer",
    )) {
        return;
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    rt.block_on(async {
        let plain = Some(("plain", "echo"));
        let mut cost = std::collections::HashMap::new();
        for sanitizing in [InputSanitizing::Off, InputSanitizing::On] {
            let fx = prepared_with("missing", &|_| None, sanitizing).await;
            let _ = refused(&fx, plain, None, 1 << 10).await;
            for size in [1usize << 20, 3 << 20] {
                let (reply, measured) = refused(&fx, plain, None, size).await;
                assert_eq!(
                    reply.pointer("/error/message").and_then(Value::as_str),
                    Some("Nonce required when message signing is enforced"),
                    "INTAKE.2(b) {sanitizing:?} {size}: premise, the same refusal: {reply}"
                );
                cost.insert((sanitizing == InputSanitizing::On, size), measured.bytes);
            }
        }
        let mut shares = Vec::new();
        for size in [1usize << 20, 3 << 20] {
            let share = cost[&(true, size)].saturating_sub(cost[&(false, size)]);
            println!("INTAKE.2(b) size={size} sanitizer_share={share}");
            assert!(
                share <= SANITIZER_SHARE,
                "INTAKE.2(b) {size}: the sanitizer added {share} B to a refused call, above \
                 {SANITIZER_SHARE} (on {}, off {})",
                cost[&(true, size)],
                cost[&(false, size)]
            );
            shares.push(share);
        }
        assert!(
            shares[1].abs_diff(shares[0]) <= SIZE_SLACK,
            "INTAKE.2(b): the sanitizer's share grows with the payload: {shares:?}"
        );
    });
}

/// [`body`] with one key to strip, `"k\u{1}ey"`, at the top of the backend
/// tool's own `arguments`, beside the bulk: business data, so validation
/// passes it and the sanitizer rewrites it (S9c).
fn dirty_key_body(target: Option<(&str, &str)>, size: usize) -> bytes::Bytes {
    let mut request: Value = serde_json::from_slice(&body(target, None, size)).expect("JSON");
    request["params"]["arguments"]["arguments"]["k\u{1}ey"] = json!(1);
    bytes::Bytes::from(request.to_string())
}

/// MIK-8499 INTAKE.2(b), a key to rewrite: one dirty key in a tool's
/// arguments does not buy a copy of everything beside it. The sanitizer's
/// share of the same refused 1 and 3 MiB call stays within the fixed cap.
/// Red before the move: the object holding the dirty key was rebuilt by the
/// copying walker, bulk and all.
#[test]
fn a_dirty_argument_key_buys_no_copy_of_the_payload() {
    if isolate(&test_path(
        "a_dirty_argument_key_buys_no_copy_of_the_payload",
    )) {
        return;
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    rt.block_on(async {
        let plain = Some(("plain", "echo"));
        let mut cost = std::collections::HashMap::new();
        for sanitizing in [InputSanitizing::Off, InputSanitizing::On] {
            let fx = prepared_with("missing", &|_| None, sanitizing).await;
            let _ = refused_body(&fx, dirty_key_body(plain, 1 << 10)).await;
            for size in [1usize << 20, 3 << 20] {
                let (reply, measured) = refused_body(&fx, dirty_key_body(plain, size)).await;
                assert_eq!(
                    reply.pointer("/error/message").and_then(Value::as_str),
                    Some("Nonce required when message signing is enforced"),
                    "dirty key {sanitizing:?} {size}: premise, the same refusal: {reply}"
                );
                cost.insert((sanitizing == InputSanitizing::On, size), measured.bytes);
            }
        }
        let mut shares = Vec::new();
        for size in [1usize << 20, 3 << 20] {
            let share = cost[&(true, size)].saturating_sub(cost[&(false, size)]);
            println!("INTAKE.2(b) dirty key size={size} sanitizer_share={share}");
            assert!(
                share <= SANITIZER_SHARE,
                "INTAKE.2(b) dirty key {size}: the sanitizer added {share} B to a refused call, \
                 above {SANITIZER_SHARE} (on {}, off {})",
                cost[&(true, size)],
                cost[&(false, size)]
            );
            shares.push(share);
        }
        assert!(
            shares[1].abs_diff(shares[0]) <= SIZE_SLACK,
            "INTAKE.2(b) dirty key: the sanitizer's share grows with the payload: {shares:?}"
        );
    });
}
