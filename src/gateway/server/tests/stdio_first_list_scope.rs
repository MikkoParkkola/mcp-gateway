// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-9309 rows: who the first-list wait applies to and what it fills.
//! Fixtures in [`super::stdio_first_list`].

use std::sync::atomic::Ordering;

use serde_json::json;

use super::stdio_first_list::{
    ARRIVAL, AT_ONCE, TOOL, answer_within, asked, entry, held_backend, holds, modern,
    modern_during_warm_up, start,
};
use super::stdio_list_changed::legacy;

/// R4: a legacy session's list during a held warm-up answers at once: it is
/// told of the change instead (the MIK-8278 rows).
#[tokio::test]
async fn r4_a_legacy_first_list_does_not_wait() {
    let held = held_backend(&[TOOL]).await;
    let mut serve = start(&entry("held", &held, None), &[("held", TOOL)], "").await;
    asked(&held, 1).await;
    legacy(&mut serve, true).await;
    serve
        .send(&json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}))
        .await;
    let answer = answer_within(&mut serve, 2, AT_ONCE, &mut Vec::new())
        .await
        .expect("a legacy first list waited");
    assert!(answer["result"]["tools"].is_array(), "{answer}");
    serve.close().await;
}

/// R7: in Code Mode surfaced tools are never listed, so nothing is waited for.
#[tokio::test]
async fn r7_code_mode_does_not_wait() {
    let held = held_backend(&[TOOL]).await;
    let extra = "code_mode:\n  enabled: true\n";
    let mut serve = start(&entry("held", &held, None), &[("held", TOOL)], extra).await;
    asked(&held, 1).await;
    serve.send(&modern(1, "server/discover")).await;
    serve.reply(1, &mut Vec::new()).await;
    serve.send(&modern(2, "tools/list")).await;
    let answer = answer_within(&mut serve, 2, AT_ONCE, &mut Vec::new())
        .await
        .expect("a Code Mode first list waited");
    assert!(answer["result"]["tools"].is_array(), "{answer}");
    serve.close().await;
}

/// R9: two surfaced tools on one backend wait on its one fill: the backend is
/// asked once, and the first answer holds both.
#[tokio::test]
async fn r9_two_surfaced_tools_on_one_backend_share_its_fill() {
    const SECOND: &str = "firstlist_second";
    let held = held_backend(&[TOOL, SECOND]).await;
    let surfaced = [("held", TOOL), ("held", SECOND)];
    let mut serve = start(&entry("held", &held, None), &surfaced, "").await;
    asked(&held, 1).await;
    serve.send(&modern(1, "server/discover")).await;
    serve.reply(1, &mut Vec::new()).await;
    serve.send(&modern(2, "tools/list")).await;
    let mut seen = Vec::new();
    let early = answer_within(&mut serve, 2, AT_ONCE, &mut seen).await;
    assert_eq!(
        held.lists.load(Ordering::SeqCst),
        1,
        "the list fetched the backend's tools again instead of joining the fill"
    );
    held.release.send(true).expect("the backend is serving");
    let first = match early {
        Some(answer) => answer,
        None => answer_within(&mut serve, 2, ARRIVAL, &mut seen)
            .await
            .expect("the first list answers"),
    };
    assert!(holds(&first, TOOL) && holds(&first, SECOND), "{first}");
    serve.close().await;
}

/// R10: a surfaced backend left off the warm-start list is filled by the
/// first list itself, and its answer holds the tool.
#[tokio::test]
async fn r10_a_backend_off_the_warm_start_list_is_filled_by_the_first_list() {
    let (held, idle) = (
        held_backend(&[TOOL]).await,
        held_backend(&["idle_tool"]).await,
    );
    idle.release
        .send(true)
        .expect("the idle backend is serving");
    let backends = entry("held", &held, None) + &entry("idle", &idle, None);
    let extra = "  warm_start:\n    - idle\n";
    let mut serve = start(&backends, &[("held", TOOL)], extra).await;
    asked(&idle, 1).await;
    assert_eq!(
        held.lists.load(Ordering::SeqCst),
        0,
        "premise: warm-up left the held backend alone"
    );
    serve.send(&modern(1, "server/discover")).await;
    serve.reply(1, &mut Vec::new()).await;
    serve.send(&modern(2, "tools/list")).await;
    let mut seen = Vec::new();
    let early = answer_within(&mut serve, 2, AT_ONCE, &mut seen).await;
    held.release.send(true).expect("the backend is serving");
    let first = match early {
        Some(answer) => answer,
        None => answer_within(&mut serve, 2, ARRIVAL, &mut seen)
            .await
            .expect("the first list answers"),
    };
    assert!(
        holds(&first, TOOL),
        "the first list did not fill {TOOL}: {first}"
    );
    serve.close().await;
}

/// R12: EOF while the first list waits ends the session within its bound.
#[tokio::test]
async fn r12_eof_during_the_first_wait_ends_the_session() {
    let (mut serve, _held) = modern_during_warm_up(None).await;
    serve.send(&modern(2, "tools/list")).await;
    assert!(
        answer_within(&mut serve, 2, AT_ONCE, &mut Vec::new())
            .await
            .is_none(),
        "premise: the first list is waiting when stdin closes"
    );
    // `close` asserts the session returns Ok within its arrival bound.
    serve.close().await;
}

/// R15: a surfaced tool the session's routing profile excludes is never
/// shown, so its cold backend is not waited for: the first list answers at
/// once while that backend is held.
#[tokio::test]
async fn r15_a_tool_the_profile_excludes_is_not_waited_for() {
    let held = held_backend(&[TOOL]).await;
    let extra = "routing_profiles:\n  narrow:\n    description: \"no held\"\n    deny_backends: [\"held\"]\ndefault_routing_profile: narrow\n";
    let mut serve = start(&entry("held", &held, None), &[("held", TOOL)], extra).await;
    asked(&held, 1).await;
    serve.send(&modern(1, "server/discover")).await;
    serve.reply(1, &mut Vec::new()).await;
    serve.send(&modern(2, "tools/list")).await;
    let answer = answer_within(&mut serve, 2, AT_ONCE, &mut Vec::new()).await;
    assert!(
        answer.is_some(),
        "a first list waited for a tool its profile excludes"
    );
    serve.close().await;
}

/// R16: a modern `tools/list` inside a batch does not take the first-list
/// wait (batches run outside a ticket): it answers at once while the
/// surfaced backend is held.
#[tokio::test]
async fn r16_a_batched_first_list_does_not_wait() {
    let (mut serve, _held) = modern_during_warm_up(None).await;
    serve.send(&json!([modern(2, "tools/list")])).await;
    let frame = serve
        .next(AT_ONCE)
        .await
        .expect("a batched first list waited");
    let answers = frame
        .as_array()
        .unwrap_or_else(|| panic!("not a batch answer: {frame}"));
    assert!(
        answers
            .iter()
            .any(|answer| answer["id"] == json!(2) && answer["result"]["tools"].is_array()),
        "{frame}"
    );
    serve.close().await;
}
