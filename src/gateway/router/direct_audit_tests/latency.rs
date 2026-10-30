// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Latency at the counting sites (test plan rows 19, 20, 23, 24, 25, 26b,
//! 27b, 29): one sample per counted call that reached a backend, none for a call
//! the gateway answered itself.

use std::time::Duration;

use super::counting::{attach, keyed_meta_invoke, meta_invoke, totals};
use super::*;
use crate::counters::{CounterStore, Window};
use crate::gateway::meta_mcp::invoke::send_timer::seam;

/// The injected send time every row uses, inside one bin.
const SEND: Duration = Duration::from_millis(7);

/// The latency slots `server` (all servers when `None`) holds over 24 hours.
fn points(store: &CounterStore, server: Option<&str>) -> Vec<crate::counters::LatPoint> {
    let now = crate::clock::unix_secs().expect("a readable clock");
    store
        .latency_series(server, Window::Day, false, now, &chrono::Local)
        .points
}

/// The one slot's `(calls, failed, timed_out)` and p95, panicking otherwise.
fn one_slot(store: &CounterStore, server: Option<&str>) -> ((u32, u32, u32), Option<u64>) {
    let points = points(store, server);
    let [point] = points.as_slice() else {
        panic!("one latency slot for {server:?}: {points:?}");
    };
    ((point.calls, point.failed, point.timed_out), point.v)
}

fn sent_bin_ms() -> u64 {
    crate::counters::latency_bin_ms(SEND)
}

/// Row 19: a meta call records one sample, on its server and on global,
/// with the send's own time.
#[tokio::test]
async fn meta_call_records_one_sample() {
    let fx = fixture(Setup {
        auth: Some(key_for_alpha(None)),
        ..Setup::default()
    })
    .await;
    let store = attach(&fx);
    seam::inject(SEND);
    let (status, answer) = post_to(
        &fx,
        "/mcp",
        &meta_invoke("alpha", "t", &json!({})),
        &Caller::Key,
    )
    .await;
    seam::clear();
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(
        one_slot(&store, Some("alpha")),
        ((1, 0, 0), Some(sent_bin_ms()))
    );
    assert_eq!(one_slot(&store, None), ((1, 0, 0), Some(sent_bin_ms())));
}

/// Row 20: a direct call records one sample.
#[tokio::test]
async fn direct_call_records_one_sample() {
    let fx = fixture(Setup::default()).await;
    let store = attach(&fx);
    seam::inject(SEND);
    let (status, body) = post(&fx, "alpha", &tools_call("t"), &Caller::Anonymous).await;
    seam::clear();
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        one_slot(&store, Some("alpha")),
        ((1, 0, 0), Some(sent_bin_ms()))
    );
}

/// Row 23: a call the gateway refused before any send is counted and never
/// timed.
#[tokio::test]
async fn a_refusal_before_the_send_records_no_sample() {
    let fx = fixture(Setup {
        auth: Some(key_for_alpha(None)),
        ..Setup::default()
    })
    .await;
    let store = attach(&fx);
    let _ = post_to(
        &fx,
        "/mcp",
        &meta_invoke("beta", "t", &json!({})),
        &Caller::Key,
    )
    .await;
    let _ = post(&fx, "beta", &tools_call("t"), &Caller::Key).await;
    assert!(
        points(&store, None).is_empty(),
        "{:?}",
        points(&store, None)
    );
}

/// Row 24: an idempotency replay is answered from the first execution and
/// records nothing more.
#[tokio::test]
async fn a_replay_records_no_second_sample() {
    let fx = fixture(Setup {
        auth: Some(key_for_alpha(None)),
        ..Setup::default()
    })
    .await;
    let store = attach(&fx);
    seam::inject(SEND);
    assert_eq!(keyed_meta_invoke(&fx, 1).await, StatusCode::OK);
    assert_eq!(keyed_meta_invoke(&fx, 2).await, StatusCode::OK);
    seam::clear();
    assert_eq!(one_slot(&store, None).0, (1, 0, 0));
}

/// Row 25: a backend timeout records one sample, timed out; another failure
/// after the send records one, failed.
#[tokio::test]
async fn a_backend_timeout_records_timed_out() {
    for (fail, expected) in [
        (
            (|| crate::Error::BackendTimeout("slow".into())) as fn() -> crate::Error,
            (1, 0, 1),
        ),
        (|| crate::Error::Transport("reset".into()), (1, 1, 0)),
    ] {
        let fx = fixture(Setup {
            backend_fail: Some(fail),
            ..Setup::default()
        })
        .await;
        let store = attach(&fx);
        seam::inject(SEND);
        let _ = post(&fx, "alpha", &tools_call("t"), &Caller::Anonymous).await;
        seam::clear();
        assert_eq!(one_slot(&store, Some("alpha")).0, expected);
    }
}

/// Row 26b: a tool's `isError` result is an answer from the backend.
#[tokio::test]
async fn a_tool_error_result_is_answered() {
    let fx = fixture(Setup {
        reply: Some(json!({"content": [{"type": "text", "text": "no"}], "isError": true})),
        ..Setup::default()
    })
    .await;
    let store = attach(&fx);
    seam::inject(SEND);
    let _ = post(&fx, "alpha", &tools_call("t"), &Caller::Anonymous).await;
    seam::clear();
    assert_eq!(one_slot(&store, Some("alpha")).0, (1, 0, 0));
}

/// Row 29: a direct request other than `tools/call` is not counted, so it
/// records no sample.
#[tokio::test]
async fn an_uncounted_request_records_nothing() {
    let fx = fixture(Setup::default()).await;
    let store = attach(&fx);
    let body =
        json!({"jsonrpc": "2.0", "id": 9, "method": "resources/list", "params": {}}).to_string();
    seam::inject(SEND);
    let _ = post(&fx, "alpha", &body, &Caller::Anonymous).await;
    seam::clear();
    assert!(
        points(&store, None).is_empty(),
        "{:?}",
        points(&store, None)
    );
}

/// Row 27b: the whole call is dropped while its send waits on the backend
/// (the client went away). Nothing finished, so nothing records: no count and
/// no sample.
#[tokio::test]
async fn a_dropped_call_records_nothing() {
    let fx = fixture(Setup {
        extras: &[Extra::HangCall],
        ..Setup::default()
    })
    .await;
    let store = attach(&fx);
    seam::inject(SEND);
    let body = tools_call("t");
    // Boxed, so the drop below ends the call itself, not a pin of it.
    let mut call = Box::pin(post(&fx, "alpha", &body, &Caller::Anonymous));
    // Wait on the event: `alpha` took the call. The 30 s bound is a hang
    // guard; `alpha` answers nothing, so the call cannot answer first.
    let sent = tokio::time::timeout(Duration::from_secs(30), async {
        while fx.calls.load(Ordering::SeqCst) < 1 {
            tokio::task::yield_now().await;
        }
    });
    tokio::select! {
        biased;
        answered = &mut call => panic!("a hung backend answered: {answered:?}"),
        sent = sent => assert!(sent.is_ok(), "alpha was never sent the call"),
    }
    drop(call);
    seam::clear();
    assert_eq!(totals(&store), [0; 5]);
    assert!(points(&store, None).is_empty(), "{:?}", points(&store, None));
}
