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
#[path = "mik_7630_events/upstream_sub.rs"]
#[allow(dead_code, reason = "shared helpers; each binary uses a subset")]
mod upstream_sub;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::http::StatusCode;
use axum::response::IntoResponse;
use delivery::start_cfg;
use gateway::{ALICE, Gateway, error};
use receiver::{Receiver, whsec};
use serde_json::{Value, json};
use upstream_sub::{delivered, expect_events, sub, sub_params, upstream_config};

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
    tokio::time::sleep(Duration::from_secs(2)).await;
    let base = delivered(receiver, id, TOOLS).len();
    assert!(base <= 1, "at most the first fill is announced, got {base}");
    base
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
