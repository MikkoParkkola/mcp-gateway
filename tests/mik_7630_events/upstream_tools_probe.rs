// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Probe (throwaway, never merged): runs the MIK-8007 session-end row 120
//! times (4 lanes of 30) with every `tools/list` the gateway sends logged with its caller.
//! It prints the log of the first round that sees a list after the notice
//! was served, plus one clean round to compare against, then fails if any
//! round saw one.

use super::*;

const TOOLS_CHANGED: &str = "notifications/tools/list_changed";
const ROUNDS_PER_LANE: usize = 30;

fn lists(peer: &HttpPeer) -> usize {
    peer.frames("tools/list")
        .iter()
        .map(|f| f["id"].to_string())
        .collect::<std::collections::BTreeSet<_>>()
        .len()
}

/// The probe's own lines and the gateway frames of each backtrace.
fn probe_lines(logs: &str) -> String {
    logs.lines()
        .filter(|l| l.contains("PROBE") || l.contains("mcp_gateway::"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// One run of the row: the count when the owed notice was served, the count
/// at the end, the peer's list ids in arrival order, and the gateway log.
async fn round() -> (usize, usize, Vec<String>, String) {
    let dir = tempfile::tempdir().expect("tempdir");
    let receiver = Receiver::start(dir.path()).await;
    let peer = HttpPeer::start(Era::Modern).await;
    let cfg = upstream_config(dir.path(), http_backend(&peer), &[]);
    let gw =
        super::delivery::start_cfg_env(dir.path(), &receiver, cfg, &[("RUST_LOG", "info")]).await;
    let name = event("tools_changed");
    let _tools = sub(&gw, ALICE, &name, &receiver, json!({})).await;
    eventually("the listen asks for tools", || {
        peer.open_listens()
            .iter()
            .any(|f| f["notifications"]["toolsListChanged"] == true)
    })
    .await;
    let lists_before = lists(&peer);
    peer.hang_tools_list();
    peer.push(TOOLS_CHANGED, json!({}));
    eventually("the first refill reached the backend", || {
        lists(&peer) > lists_before
    })
    .await;
    peer.push(TOOLS_CHANGED, json!({}));
    tokio::time::sleep(Duration::from_secs(1)).await;
    peer.drop_streams();
    tokio::time::sleep(QUIET).await;
    peer.release_tools_list();
    eventually("the owed notice was served after the session ended", || {
        lists(&peer) > lists_before + 1
    })
    .await;
    let served = lists(&peer);
    peer.drop_streams();
    eventually("the backend is listened to again", || {
        !peer.open_listens().is_empty()
    })
    .await;
    tokio::time::sleep(QUIET).await;
    let ids = peer
        .frames("tools/list")
        .iter()
        .map(|f| f["id"].to_string())
        .collect();
    (served, lists(&peer), ids, gw.all_logs())
}

/// One lane of rounds, run beside the others to fit the job's time limit.
async fn lane(lane: usize) -> Vec<(String, usize, usize, Vec<String>, String)> {
    let mut out = Vec::new();
    for n in 0..ROUNDS_PER_LANE {
        let (served, after, ids, logs) = round().await;
        out.push((format!("{lane}.{n}"), served, after, ids, logs));
    }
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn probe_who_sends_the_extra_tools_list() {
    let (a, b, c, d) = tokio::join!(lane(0), lane(1), lane(2), lane(3));
    let mut clean_shown = false;
    let mut extra = 0usize;
    for (n, served, after, ids, logs) in a.into_iter().chain(b).chain(c).chain(d) {
        let show = after != served || !clean_shown;
        if show {
            println!(
                "===== PROBE round {n}: served {served}, after {after}, list ids {ids:?}\n{}\n===== end round {n}",
                probe_lines(&logs)
            );
            clean_shown |= after == served;
        }
        if after != served {
            extra += 1;
        }
    }
    println!("PROBE summary: {extra} of {} rounds saw a list after the served notice", 4 * ROUNDS_PER_LANE);
    assert_eq!(
        extra, 0,
        "rounds with an extra tools/list (see the PROBE output)"
    );
}
