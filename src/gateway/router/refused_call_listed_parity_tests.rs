// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The parity rows again, for a withheld name the backend does list.
//!
//! The probe of the rows above, `gateway_invok`, is both denied to `k-deny`
//! and absent from the catalogue, so a gateway that let a withheld name skip
//! the firewall only when the backend lists it would still pass them. Here
//! the probe is `read`: listed by the backend and denied to `k-deny` by
//! name. Its missing twin is `k-std` calling `read` on a gateway whose
//! backend lists `note` and `gateway_invoke` but not `read`. Those are the
//! names `k-deny` can see on the first gateway, so both arms draw their
//! "did you mean?" hint from the same pool, and neither has a name close
//! enough to `read` to suggest.
//!
//! Each row builds one fresh gateway per arm. Both probes must get the
//! absent-name answer for `read`; then the visible call, and every effect
//! after it, must be the same on both arms. The controls in the rows above
//! already show what the visible call does on its own.

use super::*;

/// Listed by the backend, denied to `k-deny` by name.
const LISTED: &str = "read";

/// Text A for `read`, as both routes word it before any hint.
const READ_ABSENT: &str = "the backend does not list a tool named `read`";

#[derive(Clone, Copy)]
enum Route {
    Direct,
    Meta,
}

async fn send(route: Route, fx: &Fx, key: &str, tool: &str, args: Value) -> (StatusCode, Value) {
    match route {
        Route::Direct => post_direct(fx, BACKEND, key, tool, args, None, Some(SESSION)).await,
        Route::Meta => post_meta_invoke(fx, key, BACKEND, tool, args, None, Some(SESSION)).await,
    }
}

fn assert_read_absent(route: Route, status: StatusCode, body: &Value) {
    let text = json!({ "content": [{ "type": "text", "text": READ_ABSENT }], "isError": true });
    let expected = match route {
        Route::Direct => json!({ "jsonrpc": "2.0", "id": 1, "result": text }),
        Route::Meta => wrapped(&text),
    };
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, &expected, "{body}");
}

fn assert_visible_allowed(route: Route, status: StatusCode, body: &Value) {
    match route {
        Route::Direct => assert_allowed(status, body),
        Route::Meta => assert_meta_allowed(status, body),
    }
}

/// The two arms' visible answers are one answer, the meta route's
/// generated trace id aside.
fn assert_same_visible(
    route: Route,
    withheld: (StatusCode, &Value),
    missing: (StatusCode, &Value),
) {
    assert_eq!(
        missing.0, withheld.0,
        "missing {} withheld {}",
        missing.1, withheld.1
    );
    match route {
        Route::Direct => assert_eq!(missing.1, withheld.1),
        Route::Meta => assert_same_allowed(missing.1, withheld.1),
    }
}

/// The withheld arm and its missing twin, on fresh gateways built from
/// `build` with the listing that holds `read` and the one that does not.
async fn arms<F, Fut>(build: F) -> (Fx, Fx)
where
    F: Fn(Answer) -> Fut,
    Fut: std::future::Future<Output = Fx>,
{
    (
        build(Answer::WithNote).await,
        build(Answer::WithoutRead).await,
    )
}

async fn budget_pair(route: Route, limit: usize) {
    let dir = crate::test_dir_keep::kept_tempdir();
    let (withheld, missing) = arms(|answer| {
        fixture_firewalled_budget_built(
            answer,
            (dir.path().join(answer_log(answer)), limit),
            |meta| meta,
        )
    })
    .await;
    let (probe, body) = send(route, &withheld, WITHHELD_KEY, LISTED, json!({})).await;
    assert_read_absent(route, probe, &body);
    let (w_status, w_visible) = send(route, &withheld, WITHHELD_KEY, VISIBLE, json!({})).await;

    let (probe, body) = send(route, &missing, OPEN_KEY, LISTED, json!({})).await;
    assert_read_absent(route, probe, &body);
    let (m_status, m_visible) = send(route, &missing, OPEN_KEY, VISIBLE, json!({})).await;

    assert_same_visible(route, (w_status, &w_visible), (m_status, &m_visible));
    match (route, limit) {
        (Route::Direct, 1) => assert_budget_refused(w_status, &w_visible),
        (Route::Meta, 1) => assert_meta_budget_refused(w_status, &w_visible),
        _ => assert_visible_allowed(route, w_status, &w_visible),
    }
    // Nothing reaches the backend but an allowed visible call.
    assert_eq!(
        withheld.calls.load(Ordering::SeqCst),
        usize::from(limit > 1)
    );
    assert_eq!(
        missing.calls.load(Ordering::SeqCst),
        withheld.calls.load(Ordering::SeqCst)
    );
}

async fn tenant_pair(route: Route, limit: usize) {
    let (withheld, missing) = arms(|answer| fixture_firewalled_tenant(answer, limit)).await;
    let probe_args = || json!({ "tenant": "t1" });
    let visible_args = || json!({ "tenant": "t2" });
    let (probe, body) = send(route, &withheld, WITHHELD_KEY, LISTED, probe_args()).await;
    assert_read_absent(route, probe, &body);
    let (w_status, w_visible) = send(route, &withheld, WITHHELD_KEY, VISIBLE, visible_args()).await;

    let (probe, body) = send(route, &missing, OPEN_KEY, LISTED, probe_args()).await;
    assert_read_absent(route, probe, &body);
    let (m_status, m_visible) = send(route, &missing, OPEN_KEY, VISIBLE, visible_args()).await;

    assert_same_visible(route, (w_status, &w_visible), (m_status, &m_visible));
    match (route, limit) {
        (Route::Direct, 1) => assert_tenant_refused(w_status, &w_visible),
        (Route::Meta, 1) => assert_meta_tenant_refused(w_status, &w_visible),
        _ => assert_visible_allowed(route, w_status, &w_visible),
    }
    assert_eq!(
        withheld.calls.load(Ordering::SeqCst),
        usize::from(limit > 1)
    );
    assert_eq!(
        missing.calls.load(Ordering::SeqCst),
        withheld.calls.load(Ordering::SeqCst)
    );
}

/// Each arm's own audit file, so the two gateways never share one log.
fn answer_log(answer: Answer) -> &'static str {
    match answer {
        Answer::WithoutRead => "missing-audit.jsonl",
        _ => "withheld-audit.jsonl",
    }
}

async fn audit_pair(route: Route) {
    let dir = crate::test_dir_keep::kept_tempdir();
    let log = |answer| dir.path().join(answer_log(answer));
    let (withheld, missing) = arms(|answer| fixture_firewalled_audited(answer, log(answer))).await;

    let (probe, withheld_probe) = send(route, &withheld, WITHHELD_KEY, LISTED, json!({})).await;
    assert_read_absent(route, probe, &withheld_probe);
    let withheld_events = audit_events(&log(Answer::WithNote));
    let (status, body) = send(route, &withheld, WITHHELD_KEY, VISIBLE, json!({})).await;
    assert_visible_allowed(route, status, &body);

    let (probe, missing_probe) = send(route, &missing, OPEN_KEY, LISTED, json!({})).await;
    assert_read_absent(route, probe, &missing_probe);
    assert_eq!(missing_probe, withheld_probe);
    let missing_events = audit_events(&log(Answer::WithoutRead));
    let (status, body) = send(route, &missing, OPEN_KEY, VISIBLE, json!({})).await;
    assert_visible_allowed(route, status, &body);

    // One scan each way: the probe is charged as one request, and its absent
    // answer passes the response scan once.
    assert_eq!(withheld_events, ["request", "response"]);
    assert_eq!(missing_events, withheld_events);
    // Only each arm's visible call was sent on.
    assert_eq!(withheld.calls.load(Ordering::SeqCst), 1);
    assert_eq!(missing.calls.load(Ordering::SeqCst), 1);
}

/// The fixture has seeded `read` as a well-known name, so the step from
/// `read` to `note` may score as an anomaly. Which way it goes is the
/// detector's business: the claim here is that both arms take the same way,
/// with the same answer and the same change to the pair map.
async fn anomaly_pair(route: Route) {
    let (withheld, missing) = arms(fixture_firewalled_anomaly).await;

    let before = learned_pairs(&withheld);
    let (probe, body) = send(route, &withheld, WITHHELD_KEY, LISTED, json!({})).await;
    assert_read_absent(route, probe, &body);
    let (w_status, w_visible) = send(route, &withheld, WITHHELD_KEY, VISIBLE, json!({})).await;
    let withheld_deltas = pair_deltas(&before, &learned_pairs(&withheld));

    let before = learned_pairs(&missing);
    let (probe, body) = send(route, &missing, OPEN_KEY, LISTED, json!({})).await;
    assert_read_absent(route, probe, &body);
    let (m_status, m_visible) = send(route, &missing, OPEN_KEY, VISIBLE, json!({})).await;
    let missing_deltas = pair_deltas(&before, &learned_pairs(&missing));

    // A probe one arm skipped would differ here either way: blocked against
    // allowed if the step scores, a pair against none if it does not.
    assert_same_visible(route, (w_status, &w_visible), (m_status, &m_visible));
    assert_eq!(missing_deltas, withheld_deltas);
    assert_eq!(
        missing.calls.load(Ordering::SeqCst),
        withheld.calls.load(Ordering::SeqCst)
    );
}

#[tokio::test(flavor = "current_thread")]
async fn direct_listed_withheld_and_missing_spend_one_call_budget() {
    budget_pair(Route::Direct, 1).await;
}

#[tokio::test(flavor = "current_thread")]
async fn direct_listed_withheld_and_missing_do_not_spend_a_two_call_budget() {
    budget_pair(Route::Direct, 2).await;
}

#[tokio::test(flavor = "current_thread")]
async fn direct_listed_withheld_and_missing_write_the_same_probe_audit() {
    audit_pair(Route::Direct).await;
}

#[tokio::test(flavor = "current_thread")]
async fn direct_listed_withheld_and_missing_reach_a_second_tenant() {
    tenant_pair(Route::Direct, 1).await;
}

#[tokio::test(flavor = "current_thread")]
async fn direct_listed_withheld_and_missing_stay_inside_a_two_tenant_limit() {
    tenant_pair(Route::Direct, 2).await;
}

#[tokio::test(flavor = "current_thread")]
async fn direct_listed_withheld_and_missing_record_the_same_anomaly_step() {
    anomaly_pair(Route::Direct).await;
}

#[tokio::test(flavor = "current_thread")]
async fn meta_listed_withheld_and_missing_spend_one_call_budget() {
    budget_pair(Route::Meta, 1).await;
}

#[tokio::test(flavor = "current_thread")]
async fn meta_listed_withheld_and_missing_do_not_spend_a_two_call_budget() {
    budget_pair(Route::Meta, 2).await;
}

#[tokio::test(flavor = "current_thread")]
async fn meta_listed_withheld_and_missing_write_the_same_probe_audit() {
    audit_pair(Route::Meta).await;
}

#[tokio::test(flavor = "current_thread")]
async fn meta_listed_withheld_and_missing_reach_a_second_tenant() {
    tenant_pair(Route::Meta, 1).await;
}

#[tokio::test(flavor = "current_thread")]
async fn meta_listed_withheld_and_missing_stay_inside_a_two_tenant_limit() {
    tenant_pair(Route::Meta, 2).await;
}

#[tokio::test(flavor = "current_thread")]
async fn meta_listed_withheld_and_missing_record_the_same_anomaly_step() {
    anomaly_pair(Route::Meta).await;
}
