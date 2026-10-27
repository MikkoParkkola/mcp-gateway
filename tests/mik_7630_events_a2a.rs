// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7630.SOURCE.1 P4: upstream events from an A2A backend. A2A carries no
//! MCP notifications, so the listener re-reads the backend's tools view
//! through the calls' discovery path at the snapshot interval and announces
//! `tools_changed` when the translated tool changed at all. The resource and
//! prompt kinds are refused `-32014 a2a_no_such_capability` (lead Q2).
//!
//! Before P4, `tools_changed` on A2A is accepted but has no listener, so A2
//! and A3 go red at their first expected event; A1 goes red on the reason
//! (`a2a_transport`).
#![cfg(all(unix, feature = "a2a"))]

#[path = "mik_7630_events/delivery.rs"]
#[allow(dead_code, reason = "shared helpers; each binary uses a subset")]
mod delivery;
#[path = "mik_7630_events/gateway.rs"]
#[allow(dead_code, reason = "shared harness; each binary uses a subset")]
mod gateway;
#[path = "mik_7630_events/receiver.rs"]
#[allow(dead_code, reason = "shared receiver; each binary uses a subset")]
mod receiver;
#[path = "mik_7630_events/sse_peer.rs"]
#[allow(dead_code, reason = "mock peer; each row uses a subset")]
mod sse_peer;
#[path = "mik_7630_events/upstream_sub.rs"]
#[allow(dead_code, reason = "shared helpers; each binary uses a subset")]
mod upstream_sub;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::http::StatusCode;
use axum::response::IntoResponse;
use delivery::{DEADLINE, records, start_cfg, wait_until};
use gateway::{ALICE, Gateway, error};
use receiver::{Receiver, whsec};
use serde_json::{Value, json};
use upstream_sub::{delivered, expect_events, sub, sub_params, unsub, upstream_config};

/// Several snapshot intervals at the 1 s cache TTL the rows configure.
const INTERVALS: Duration = Duration::from_secs(5);

/// An A2A agent whose card a row can change or make fail.
struct Agent {
    card: Arc<Mutex<Value>>,
    failing: Arc<AtomicBool>,
    fetches: Arc<AtomicUsize>,
    url: String,
}

impl Agent {
    async fn start() -> Self {
        let card = Arc::new(Mutex::new(Value::Null));
        let failing = Arc::new(AtomicBool::new(false));
        let fetches = Arc::new(AtomicUsize::new(0));
        let (c, f, n) = (card.clone(), failing.clone(), fetches.clone());
        let app = axum::Router::new().route(
            "/.well-known/agent-card.json",
            axum::routing::get(move || {
                let (c, f, n) = (c.clone(), f.clone(), n.clone());
                async move {
                    n.fetch_add(1, Ordering::SeqCst);
                    if f.load(Ordering::SeqCst) {
                        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    }
                    axum::Json(c.lock().expect("card").clone()).into_response()
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind agent");
        let url = format!("http://{}", listener.local_addr().expect("address"));
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let agent = Self {
            card,
            failing,
            fetches,
            url,
        };
        agent.set(|_| {});
        agent
    }

    /// Change the card in place (`edit` gets the whole card).
    fn set(&self, edit: impl FnOnce(&mut Value)) {
        let mut card = self.card.lock().expect("card");
        if card.is_null() {
            *card = json!({
                "name": "Agent",
                "description": "Answers questions.",
                "version": "1.0.0",
                "supportedInterfaces": [{"url": format!("{}/a2a", self.url),
                    "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}],
                "capabilities": {},
                "defaultInputModes": ["text/plain"],
                "defaultOutputModes": ["text/plain"],
                "skills": [{"id": "answer", "name": "Answer",
                    "description": "Answers a question", "tags": ["qa"]}],
            });
        }
        edit(&mut card);
    }

    fn fetches(&self) -> usize {
        self.fetches.load(Ordering::SeqCst)
    }
}

/// A gateway whose backend `x` is `agent`, re-read every second.
async fn start(dir: &std::path::Path, receiver: &Receiver, agent: &Agent) -> Gateway {
    let mut cfg = upstream_config(dir, json!({"a2a_url": agent.url}), &[]);
    cfg["meta_mcp"]["cache_ttl"] = json!("1s");
    start_cfg(dir, receiver, cfg).await
}

const TOOLS: &str = "backend.x.tools_changed";

/// Wait until the agent has served `n` more card reads than `from`.
async fn polled(agent: &Agent, from: usize, n: usize) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while agent.fetches() < from + n {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the listener did not poll the card {n} times (fetches {})",
            agent.fetches()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// The baseline after a subscribe: the backend starts lazily, and the F24
/// drain announces its first stored tool list as a change, as it does for
/// every backend that starts after a `tools_changed` subscription. Three
/// polls settle it; at most that one announcement is allowed.
async fn first_fill(agent: &Agent, receiver: &Receiver, id: &str) -> usize {
    polled(agent, agent.fetches(), 3).await;
    // timing: precondition
    tokio::time::sleep(Duration::from_secs(2)).await;
    let base = delivered(receiver, id, TOOLS).len();
    assert!(base <= 1, "at most the first fill is announced, got {base}");
    base
}

/// The delivered `tools_changed` count once it has held still for 2 s, so no
/// event still in flight is counted after it.
async fn settled_count(receiver: &Receiver, id: &str) -> usize {
    let mut last = delivered(receiver, id, TOOLS).len();
    loop {
        // timing: precondition
        tokio::time::sleep(Duration::from_secs(2)).await;
        let now = delivered(receiver, id, TOOLS).len();
        if now == last {
            return now;
        }
        last = now;
    }
}

/// A1: the resource and prompt kinds are refused with the capability reason.
#[tokio::test]
async fn a1_a2a_resource_and_prompt_kinds_are_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let receiver = Receiver::start(dir.path()).await;
    let agent = Agent::start().await;
    let gw = start(dir.path(), &receiver, &agent).await;
    for kind in ["resource_updated", "resources_changed", "prompts_changed"] {
        let name = format!("backend.x.{kind}");
        let answer = gw
            .rpc(
                Some(ALICE),
                "events/subscribe",
                sub_params(&name, &receiver.localhost_url(), &whsec(32), json!({})),
            )
            .await;
        let err = error(&answer);
        assert_eq!(err["code"], -32014, "{name}: typed refusal, got {answer}");
        assert_eq!(
            err["data"],
            json!({"feature": "backendEvents", "value": name, "reason": "a2a_no_such_capability"}),
            "{name}: the refusal names the reason"
        );
    }
    let names = gw.event_names(Some(ALICE), None).await;
    assert!(
        names.contains(&TOOLS.to_owned()),
        "tools_changed is offered: {names:?}"
    );
    assert!(
        !names
            .iter()
            .any(|n| n.starts_with("backend.x.resource") || n.starts_with("backend.x.prompts")),
        "the refused kinds are not offered: {names:?}"
    );
}

/// A2 + A4: a changed card is one event; an unchanged card, polled, is none.
#[tokio::test]
async fn a2_a_changed_card_announces_tools_changed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let receiver = Receiver::start(dir.path()).await;
    let agent = Agent::start().await;
    let gw = start(dir.path(), &receiver, &agent).await;
    let id = sub(&gw, ALICE, TOOLS, &receiver, json!({})).await;
    let base = first_fill(&agent, &receiver, &id).await;
    // A4: three more polls of an unchanged card announce nothing.
    polled(&agent, agent.fetches(), 3).await;
    assert_eq!(
        delivered(&receiver, &id, TOOLS).len(),
        base,
        "an unchanged card is quiet"
    );
    // A2: a changed skill description changes the translated tool.
    agent.set(|card| card["skills"][0]["description"] = json!("Answers two questions"));
    expect_events(&receiver, &id, TOOLS, base + 1).await;
}

/// A3: a change outside the description (the card's name, which becomes the
/// tool's title) is also announced: the whole tool is compared.
#[tokio::test]
async fn a3_any_translated_field_counts() {
    let dir = tempfile::tempdir().expect("tempdir");
    let receiver = Receiver::start(dir.path()).await;
    let agent = Agent::start().await;
    let gw = start(dir.path(), &receiver, &agent).await;
    let id = sub(&gw, ALICE, TOOLS, &receiver, json!({})).await;
    let base = first_fill(&agent, &receiver, &id).await;
    agent.set(|card| card["name"] = json!("Renamed Agent"));
    expect_events(&receiver, &id, TOOLS, base + 1).await;
}

/// A5: failed reads are not absence. Recovery to the same card is quiet;
/// a card changed across the failure is announced once, judged against the
/// pre-failure baseline.
#[tokio::test]
async fn a5_a_failed_read_keeps_the_baseline() {
    let dir = tempfile::tempdir().expect("tempdir");
    let receiver = Receiver::start(dir.path()).await;
    let agent = Agent::start().await;
    let gw = start(dir.path(), &receiver, &agent).await;
    let id = sub(&gw, ALICE, TOOLS, &receiver, json!({})).await;
    let base = first_fill(&agent, &receiver, &id).await;
    agent.failing.store(true, Ordering::SeqCst);
    polled(&agent, agent.fetches(), 2).await;
    agent.failing.store(false, Ordering::SeqCst);
    polled(&agent, agent.fetches(), 2).await;
    // timing: absence
    tokio::time::sleep(INTERVALS).await;
    assert_eq!(
        delivered(&receiver, &id, TOOLS).len(),
        base,
        "same card after failure: quiet"
    );
    agent.failing.store(true, Ordering::SeqCst);
    polled(&agent, agent.fetches(), 2).await;
    agent.set(|card| card["description"] = json!("Answers questions, now in Dutch."));
    agent.failing.store(false, Ordering::SeqCst);
    expect_events(&receiver, &id, TOOLS, base + 1).await;
}

/// A6: the poll runs on the snapshot schedule. With a zero cache TTL the
/// 1 s floor holds: over 5 s a handful of card reads, not a busy loop.
#[tokio::test]
async fn a6_the_poll_keeps_the_one_second_floor() {
    let dir = tempfile::tempdir().expect("tempdir");
    let receiver = Receiver::start(dir.path()).await;
    let agent = Agent::start().await;
    let mut cfg = upstream_config(dir.path(), json!({"a2a_url": agent.url}), &[]);
    cfg["meta_mcp"]["cache_ttl"] = json!("0s");
    let gw = start_cfg(dir.path(), &receiver, cfg).await;
    let id = sub(&gw, ALICE, TOOLS, &receiver, json!({})).await;
    let _ = first_fill(&agent, &receiver, &id).await;
    let from = agent.fetches();
    // timing: absence
    tokio::time::sleep(Duration::from_secs(5)).await;
    let polls = agent.fetches() - from;
    assert!(
        (3..=8).contains(&polls),
        "about one read a second over 5 s, got {polls}; the bounds allow CI \
         scheduling jitter (one tick early or late) and the backend's own health \
         ping, while a busy loop would read hundreds"
    );
}

/// A9: the last unsubscribe stops the poll.
#[tokio::test]
async fn a9_the_poll_stops_with_the_last_subscriber() {
    let dir = tempfile::tempdir().expect("tempdir");
    let receiver = Receiver::start(dir.path()).await;
    let agent = Agent::start().await;
    let gw = start(dir.path(), &receiver, &agent).await;
    let id = sub(&gw, ALICE, TOOLS, &receiver, json!({})).await;
    let _ = first_fill(&agent, &receiver, &id).await;
    unsub(&gw, ALICE, TOOLS, &receiver, json!({})).await;
    // timing: precondition
    tokio::time::sleep(Duration::from_secs(3)).await;
    let after = agent.fetches();
    // timing: absence
    tokio::time::sleep(INTERVALS).await;
    // A running poll reads about once a second (A6), so ~5 here; the
    // backend's own health check may still ping (a card read) once.
    let more = agent.fetches() - after;
    assert!(
        more <= 1,
        "the poll stopped once nobody listens; {more} reads in 5 s. One is allowed: the \
         backend's own health check pings with a card read"
    );
}

/// A7 (MIK-8835.A2A.2, design B3'): a reload turns backend `x` from a legacy
/// SSE backend into an A2A agent. Its resource subscription is withdrawn (A2A
/// has no resources), and its `tools_changed` subscription is kept and polled.
#[tokio::test]
async fn a7_a_reload_from_mcp_to_a2a_keeps_only_tools_changed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let receiver = Receiver::start(dir.path()).await;
    let sse = sse_peer::SsePeer::start().await;
    let agent = Agent::start().await;
    let mut cfg = upstream_config(
        dir.path(),
        json!({"http_url": sse.url, "streamable_http": false}),
        &[],
    );
    cfg["meta_mcp"]["cache_ttl"] = json!("1s");
    let mut gw = start_cfg(dir.path(), &receiver, cfg).await;
    sub(
        &gw,
        ALICE,
        "backend.x.resource_updated",
        &receiver,
        json!({"uri": sse_peer::URI_A}),
    )
    .await;
    let id = sub(&gw, ALICE, TOOLS, &receiver, json!({})).await;
    assert_eq!(records(dir.path(), "subs").len(), 2, "control: both stored");

    let mut next = gw.config().clone();
    next["backends"]["x"] = json!({"a2a_url": agent.url});
    gw.rewrite_config(next);
    assert!(
        wait_until(DEADLINE, || records(dir.path(), "subs").len() == 1).await,
        "the resource subscription is withdrawn on the reload: {}",
        gw.stall_report()
    );
    // The reload replaced `x`'s tools (the SSE peer's `echo`, then the
    // agent's tool), which is itself announced, alongside any first fill; so
    // this baseline is at least one event, not the at-most-one of
    // `first_fill`.
    polled(&agent, agent.fetches(), 3).await;
    let base = settled_count(&receiver, &id).await;
    assert!(base >= 1, "the reload's tool change is announced");
    agent.set(|card| card["name"] = json!("Reloaded Agent"));
    expect_events(&receiver, &id, TOOLS, base + 1).await;
}

/// A10: `x` is an A2A agent reached with the caller's identity. Its
/// `tools_changed` is refused per subscriber (a per-user listener has no read
/// of its own to poll the card with), and nothing polls it. A reload drops the
/// identity propagation: the agent is then shared, a subscription is
/// accepted, its card is polled, and a change is delivered.
#[tokio::test]
async fn a10_a_reload_to_a_shared_a2a_backend_revives_tools_changed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let receiver = Receiver::start(dir.path()).await;
    let agent = Agent::start().await;
    let mut cfg = upstream_config(
        dir.path(),
        json!({"a2a_url": agent.url, "identity_propagation": {"strategy": "passthrough",
            "audience": "https://idp.example", "session_mode": "per_user"}}),
        &[],
    );
    cfg["meta_mcp"]["cache_ttl"] = json!("1s");
    let mut gw = start_cfg(dir.path(), &receiver, cfg).await;
    let refused = gw
        .rpc(
            Some(ALICE),
            "events/subscribe",
            sub_params(TOOLS, &receiver.localhost_url(), &whsec(32), json!({})),
        )
        .await;
    assert!(
        error(&refused)["code"].is_i64(),
        "an identity-bound agent's tools_changed is refused: {refused}"
    );
    let held = agent.fetches();
    // timing: absence
    tokio::time::sleep(INTERVALS).await;
    assert_eq!(
        agent.fetches(),
        held,
        "control: an identity-bound agent is never polled"
    );

    let mut next = gw.config().clone();
    next["backends"]["x"] = json!({"a2a_url": agent.url});
    gw.rewrite_config(next);
    // The reload lands asynchronously: subscribe once it has.
    let deadline = tokio::time::Instant::now() + DEADLINE;
    let id = loop {
        let answer = gw
            .rpc(
                Some(ALICE),
                "events/subscribe",
                sub_params(TOOLS, &receiver.localhost_url(), &whsec(32), json!({})),
            )
            .await;
        if let Some(id) = answer["result"]["id"].as_str() {
            break id.to_owned();
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the shared agent accepts the subscription: {answer}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    let base = first_fill(&agent, &receiver, &id).await;
    agent.set(|card| card["name"] = json!("Shared Agent"));
    expect_events(&receiver, &id, TOOLS, base + 1).await;
}
