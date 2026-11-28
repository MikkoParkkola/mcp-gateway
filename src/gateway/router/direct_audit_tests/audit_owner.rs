// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The record a response-firewall refusal leaves (P4 (1), (2)): one call,
//! one block, one firewall catch and no error on the counters; with a log,
//! exactly one record, `denied` with the refusal's code and no response hash,
//! naming the call. On the meta route the scan decides after the dispatch has
//! ended, so the same row also proves a late refusal still reaches the record.

use super::counting::{attach, meta_invoke, totals};
use super::*;

/// [calls, blocks, errors, firewall catches, cache hits] after one refusal.
const ONE_FIREWALL_REFUSAL: [u64; 5] = [1, 1, 0, 1, 0];

/// What the refusal answers with and records: `INVALID_REQUEST`.
const REFUSAL_CODE: i64 = -32600;

/// Every way one route and log setting departs from the expected record.
async fn departures(route: &str, log: Log) -> Vec<String> {
    let logged = matches!(log, Log::On);
    let fx = fixture(Setup {
        log,
        tenant_limit: Some(0),
        response_rules: Some(BLOCK_T_RULES),
        reply: Some(takeover_reply()),
        ..Setup::default()
    })
    .await;
    let store = attach(&fx);
    if route == "meta" {
        let call = meta_invoke("alpha", "t", &json!({}));
        let _ = post_to(&fx, "/mcp", &call, &Caller::Anonymous).await;
    } else {
        let _ = post(&fx, "alpha", &tools_call("t"), &Caller::Anonymous).await;
    }
    let case = format!("{route}, log {}", if logged { "on" } else { "off" });
    let mut wrong = Vec::new();
    let counted = totals(&store);
    if counted != ONE_FIREWALL_REFUSAL {
        wrong.push(format!(
            "{case}: counters {counted:?}, want {ONE_FIREWALL_REFUSAL:?}"
        ));
    }
    if !logged {
        return wrong;
    }
    let records = invocations(&fx);
    let [record] = records.as_slice() else {
        wrong.push(format!("{case}: {} records, want 1", records.len()));
        return wrong;
    };
    for (field, want) in [
        ("outcome", json!("denied")),
        ("error_code", json!(REFUSAL_CODE)),
        ("server", json!("alpha")),
        ("tool", json!("t")),
    ] {
        if record[field] != want {
            wrong.push(format!("{case}: {field} = {}, want {want}", record[field]));
        }
    }
    if record.get("response_hash").is_some() {
        wrong.push(format!("{case}: a refused answer carries a response_hash"));
    }
    wrong
}

#[tokio::test]
async fn p4_1_a_refused_answer_is_one_denial_on_both_routes_with_and_without_a_log() {
    let mut wrong = Vec::new();
    for route in ["meta", "direct"] {
        for log in [Log::On, Log::Off] {
            wrong.extend(departures(route, log).await);
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// One meta call under `setup`: exactly one invocation record, of `class`,
/// and the counters moved by exactly `counts`.
async fn once(case: &str, setup: Setup, class: &str, counts: [u64; 5]) -> Vec<String> {
    let fx = fixture(setup).await;
    let store = attach(&fx);
    let call = meta_invoke("alpha", "t", &json!({}));
    let _ = post_to(&fx, "/mcp", &call, &Caller::Anonymous).await;
    let mut wrong = Vec::new();
    let counted = totals(&store);
    if counted != counts {
        wrong.push(format!("{case}: counters {counted:?}, want {counts:?}"));
    }
    let records = invocations(&fx);
    match records.as_slice() {
        [record] if record["outcome"] == class => {}
        [record] => wrong.push(format!(
            "{case}: outcome {}, want {class}",
            record["outcome"]
        )),
        _ => wrong.push(format!("{case}: {} records, want exactly 1", records.len())),
    }
    wrong
}

/// P4 (3), the commit points today's code can reach without a hook: a
/// delivered answer, a backend's own error and a transport failure each leave
/// exactly one record with today's class and today's counts, so moving the
/// record behind finalize cannot lose or double one.
#[tokio::test]
async fn p4_3_each_finished_meta_call_writes_exactly_one_record() {
    let mut wrong = Vec::new();
    wrong.extend(once("delivered", Setup::default(), "ok", [1, 0, 0, 0, 0]).await);
    let backend_error = Setup {
        backend_error: Some(-32010),
        ..Setup::default()
    };
    wrong.extend(once("backend error", backend_error, "error", [1, 0, 1, 0, 0]).await);
    let transport = Setup {
        backend_fail: Some(|| crate::Error::Transport("the peer went away".into())),
        ..Setup::default()
    };
    wrong.extend(once("transport failure", transport, "error", [1, 0, 1, 0, 0]).await);
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// P4 (3), a delivered meta answer's record keeps its success response hash.
#[tokio::test]
async fn p4_3_a_delivered_meta_answer_keeps_its_response_hash() {
    let fx = fixture(Setup::default()).await;
    let call = meta_invoke("alpha", "t", &json!({}));
    let _ = post_to(&fx, "/mcp", &call, &Caller::Anonymous).await;
    let records = invocations(&fx);
    let [record] = records.as_slice() else {
        panic!("{} records, want 1", records.len());
    };
    let hash = record["response_hash"].as_str().unwrap_or_default();
    assert!(hash.starts_with("sha256:"), "{record}");
}

/// P4 (3), a failed invocation append on `/mcp`: fail-closed withholds the
/// answer (-32005, no result), fail-open delivers it; each with no record
/// and today's counts.
#[tokio::test]
async fn p4_3_a_failed_meta_append_keeps_both_failure_policies() {
    let mut wrong = Vec::new();
    for fail_closed in [true, false] {
        let fx = fixture(Setup {
            fail_closed,
            ..Setup::default()
        })
        .await;
        let store = attach(&fx);
        fx.log.set_append_failure_for_test(true);
        let call = meta_invoke("alpha", "t", &json!({}));
        let (_, answer) = post_to(&fx, "/mcp", &call, &Caller::Anonymous).await;
        let withheld = answer["error"]["code"] == -32005 && answer.get("result").is_none();
        let case = if fail_closed {
            "fail-closed"
        } else {
            "fail-open"
        };
        if withheld != fail_closed {
            wrong.push(format!("{case}: answer {answer}"));
        }
        let counted = totals(&store);
        if counted != [1, 0, 0, 0, 0] {
            wrong.push(format!(
                "{case}: counters {counted:?}, want [1, 0, 0, 0, 0]"
            ));
        }
        let records = invocations(&fx).len();
        if records != 0 {
            wrong.push(format!("{case}: {records} records, want 0"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// P4 (3), drop of an abandoned request: a `/mcp` call dropped after its
/// record was built and before its commit (the client went away) still
/// writes exactly one record, through the handed-off job, with today's class
/// and counts.
#[tokio::test]
async fn p4_3_an_abandoned_meta_request_writes_its_record_once() {
    use std::sync::atomic::Ordering;
    let fx = fixture(Setup::default()).await;
    let store = attach(&fx);
    let jobs = std::sync::Arc::clone(&fx.state.meta_mcp.audit_jobs);
    jobs.seams.hold_commit.store(true, Ordering::SeqCst);
    let call = meta_invoke("alpha", "t", &json!({}));
    {
        let request = post_to(&fx, "/mcp", &call, &Caller::Anonymous);
        tokio::pin!(request);
        tokio::select! {
            _ = &mut request => panic!("the request answered past its parked commit"),
            () = jobs.seams.parked.notified() => {}
        }
    }
    let open = jobs.drain(std::time::Duration::from_secs(30)).await;
    assert_eq!(open, 0, "the handed-off write did not end");
    assert_eq!(
        totals(&store),
        [1, 0, 0, 0, 0],
        "counted once, as delivered"
    );
    let records = invocations(&fx);
    let [record] = records.as_slice() else {
        panic!("{} records, want exactly 1", records.len());
    };
    assert_eq!(record["outcome"], "ok", "{record}");
}

/// P4 (3), the client-cancel return: a `/mcp` call its caller cancels while
/// the backend holds it is answered -32800 and leaves today's record and
/// counts (its dispatch never finished, so it built no record).
#[tokio::test]
async fn p4_3_a_cancelled_meta_call_keeps_todays_record_and_counts() {
    use std::sync::atomic::Ordering;
    let fx = fixture(Setup {
        // A keyed caller: an anonymous call has no owner to cancel it by.
        auth: Some(key_for_alpha(None)),
        extras: &[Extra::GateCall],
        ..Setup::default()
    })
    .await;
    let store = attach(&fx);
    let call = meta_invoke("alpha", "t", &json!({}));
    let request = post_to(&fx, "/mcp", &call, &Caller::Key);
    tokio::pin!(request);
    let held = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            tokio::select! {
                _ = &mut request => panic!("premise: the backend holds the call"),
                () = tokio::time::sleep(std::time::Duration::from_millis(5)) => {
                    if fx.calls.load(Ordering::SeqCst) > 0 {
                        break;
                    }
                }
            }
        }
    });
    held.await.expect("premise: the backend receives the call");
    let cancel = json!({"jsonrpc": "2.0", "method": "notifications/cancelled",
                        "params": {"requestId": 5}})
    .to_string();
    let ((_, answer), _) = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        tokio::join!(&mut request, post_to(&fx, "/mcp", &cancel, &Caller::Key))
    })
    .await
    .expect("the cancel ends the held call");
    assert_eq!(answer["error"]["code"], json!(-32800), "{answer}");
    assert_eq!(
        totals(&store),
        [0, 0, 0, 0, 0],
        "a cancelled call counts nothing"
    );
    assert_eq!(
        invocations(&fx).len(),
        0,
        "a cancelled call writes no record"
    );
}

/// P4 (3), cancellation while the append is in flight: a `/mcp` call dropped
/// after finalize handed its record to the audit job, while that job is still
/// held, leaves exactly one complete record once the job runs, counted once.
#[tokio::test]
async fn p4_3_a_request_dropped_mid_append_still_lands_one_record() {
    use std::sync::atomic::Ordering;
    use std::time::Duration;
    let fx = fixture(Setup::default()).await;
    let store = attach(&fx);
    let jobs = std::sync::Arc::clone(&fx.state.meta_mcp.audit_jobs);
    jobs.seams.gate_jobs.store(true, Ordering::SeqCst);
    let call = meta_invoke("alpha", "t", &json!({}));
    {
        let request = post_to(&fx, "/mcp", &call, &Caller::Anonymous);
        tokio::pin!(request);
        let handed = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                tokio::select! {
                    _ = &mut request => panic!("the request answered before its record's job ran"),
                    () = tokio::time::sleep(Duration::from_millis(5)) => {
                        if jobs.drain(Duration::ZERO).await > 0 {
                            break;
                        }
                    }
                }
            }
        });
        handed.await.expect("the record's job starts");
    }
    jobs.seams.open_gate();
    assert_eq!(
        jobs.drain(Duration::from_secs(30)).await,
        0,
        "the job did not end"
    );
    assert_eq!(
        totals(&store),
        [1, 0, 0, 0, 0],
        "counted once, as delivered"
    );
    let records = invocations(&fx);
    let [record] = records.as_slice() else {
        panic!("{} records, want exactly 1", records.len());
    };
    assert_eq!(record["outcome"], "ok", "{record}");
}

/// P4 (3), the anonymous side of the client-cancel return: an anonymous
/// `/mcp` caller has no owner to cancel by, so its `notifications/cancelled`
/// is dropped (as specced: inflight_calls.rs, "A caller with neither is never
/// registered"); the held call completes and writes its one record.
#[tokio::test]
async fn p4_3_an_anonymous_cancel_is_dropped_and_the_call_records_once() {
    use std::sync::atomic::Ordering;
    use std::time::Duration;
    let fx = fixture(Setup {
        extras: &[Extra::GateCall],
        ..Setup::default()
    })
    .await;
    let store = attach(&fx);
    let call = meta_invoke("alpha", "t", &json!({}));
    let request = post_to(&fx, "/mcp", &call, &Caller::Anonymous);
    tokio::pin!(request);
    let held = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            tokio::select! {
                _ = &mut request => panic!("premise: the backend holds the call"),
                () = tokio::time::sleep(Duration::from_millis(5)) => {
                    if fx.calls.load(Ordering::SeqCst) > 0 {
                        break;
                    }
                }
            }
        }
    });
    held.await.expect("premise: the backend receives the call");
    let cancel = json!({"jsonrpc": "2.0", "method": "notifications/cancelled",
                        "params": {"requestId": 5}})
    .to_string();
    let _ = post_to(&fx, "/mcp", &cancel, &Caller::Anonymous).await;
    fx.gate.as_ref().expect("a gated fixture").notify_one();
    let (_, answer) = tokio::time::timeout(Duration::from_secs(30), &mut request)
        .await
        .expect("the released call answers");
    assert!(
        answer.get("result").is_some(),
        "the call completed: {answer}"
    );
    assert_eq!(
        totals(&store),
        [1, 0, 0, 0, 0],
        "counted once, as delivered"
    );
    let records = invocations(&fx);
    let [record] = records.as_slice() else {
        panic!("{} records, want exactly 1", records.len());
    };
    assert_eq!(record["outcome"], "ok", "{record}");
}
