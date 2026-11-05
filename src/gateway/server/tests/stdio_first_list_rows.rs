// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-9309 rows: the first modern stdio list's wait, its bound, its once
//! flag and cancellation. Fixtures in [`super::stdio_first_list`].

use std::time::Duration;

use serde_json::json;

use super::stdio_first_list::{
    ARRIVAL, AT_ONCE, TOOL, answer_within, assert_unasked_none, holds, modern,
    modern_during_warm_up,
};

/// A meta tool every list holds.
const META: &str = "gateway_list_servers";

/// R1 (FIRST.1): the first modern list during warm-up holds the surfaced
/// tool once the fill lands, and nothing is sent unasked.
#[tokio::test]
async fn r1_a_modern_first_list_during_warm_up_holds_the_filled_tool() {
    let (mut serve, held) = modern_during_warm_up(None).await;
    serve.send(&modern(2, "tools/list")).await;
    let mut seen = Vec::new();
    let early = answer_within(&mut serve, 2, AT_ONCE, &mut seen).await;
    held.release.send(true).expect("the backend is serving");
    let first = match early {
        Some(answer) => answer,
        None => answer_within(&mut serve, 2, ARRIVAL, &mut seen)
            .await
            .expect("the first list answers once the fill lands"),
    };
    assert!(
        holds(&first, TOOL),
        "a modern stdio client's first tools/list during warm-up lacked {TOOL}: {first}"
    );
    if let Some(frame) = serve.next(AT_ONCE).await {
        seen.push(frame);
    }
    assert_unasked_none(&seen);
    serve.close().await;
}

/// R2, R3, R2b: a fill that outlasts the bound (backend timeout 2 s, so the
/// bound is 3 s) answers with what the list has, never an error; a second
/// list does not wait again; released later, a relist shows the tool, and
/// nothing is sent unasked throughout.
#[tokio::test]
async fn r2_an_expired_first_wait_answers_with_what_it_has_and_a_relist_heals() {
    let (mut serve, held) = modern_during_warm_up(Some("2s")).await;
    let mut seen = Vec::new();
    let started = std::time::Instant::now();
    serve.send(&modern(2, "tools/list")).await;
    let first = answer_within(&mut serve, 2, ARRIVAL, &mut seen)
        .await
        .expect("an expired wait still answers");
    let waited = started.elapsed();
    assert!(
        first.get("error").is_none(),
        "an expired wait answered an error: {first}"
    );
    assert!(holds(&first, META) && !holds(&first, TOOL), "{first}");
    assert!(
        waited >= Duration::from_secs(1),
        "the first list did not wait: {waited:?}"
    );
    assert!(
        waited < Duration::from_secs(15),
        "not bounded by the fill bound: {waited:?}"
    );

    serve.send(&modern(3, "tools/list")).await;
    answer_within(&mut serve, 3, AT_ONCE, &mut seen)
        .await
        .expect("a second list does not wait again");

    held.release.send(true).expect("the backend is serving");
    let by = tokio::time::Instant::now() + Duration::from_secs(40);
    let mut id = 4;
    loop {
        serve.send(&modern(id, "tools/list")).await;
        let reply = answer_within(&mut serve, id, ARRIVAL, &mut seen)
            .await
            .expect("a relist answers");
        if holds(&reply, TOOL) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < by,
            "the fill never healed the list"
        );
        id += 1;
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert_unasked_none(&seen);
    serve.close().await;
}

/// R3b: a first list cancelled mid-wait leaves the flag armed: the retry
/// waits too, and holds the tool once released.
#[tokio::test]
async fn r3b_a_cancelled_first_list_leaves_the_wait_armed() {
    let (mut serve, held) = modern_during_warm_up(None).await;
    let mut seen = Vec::new();
    serve.send(&modern(2, "tools/list")).await;
    assert!(
        answer_within(&mut serve, 2, AT_ONCE, &mut seen)
            .await
            .is_none(),
        "premise: the first list waits while the backend is held"
    );
    serve
        .send(
            &json!({"jsonrpc": "2.0", "method": "notifications/cancelled",
            "params": {"requestId": 2}}),
        )
        .await;
    serve.send(&modern(3, "tools/list")).await;
    let early = answer_within(&mut serve, 3, AT_ONCE, &mut seen).await;
    assert!(
        early.is_none(),
        "the retry after a cancel did not wait: {early:?}"
    );
    held.release.send(true).expect("the backend is serving");
    let retry = answer_within(&mut serve, 3, ARRIVAL, &mut seen)
        .await
        .expect("the retry answers once the fill lands");
    assert!(holds(&retry, TOOL), "{retry}");
    assert!(
        seen.iter().all(|frame| frame["id"] != json!(2)),
        "the cancelled list was answered: {seen:?}"
    );
    serve.close().await;
}

/// R13: two first lists sent together both wait on the one fill and both
/// hold the tool.
#[tokio::test]
async fn r13_overlapping_first_lists_both_hold_the_tool() {
    let (mut serve, held) = modern_during_warm_up(None).await;
    let mut seen = Vec::new();
    serve.send(&modern(2, "tools/list")).await;
    serve.send(&modern(3, "tools/list")).await;
    assert!(
        answer_within(&mut serve, 2, AT_ONCE, &mut seen)
            .await
            .is_none(),
        "the first list did not wait"
    );
    held.release.send(true).expect("the backend is serving");
    for id in [2, 3] {
        let answer = match seen.iter().position(|frame| frame["id"] == json!(id)) {
            Some(at) => seen.remove(at),
            None => answer_within(&mut serve, id, ARRIVAL, &mut seen)
                .await
                .expect("each list answers"),
        };
        assert!(holds(&answer, TOOL), "list {id}: {answer}");
    }
    serve.close().await;
}
