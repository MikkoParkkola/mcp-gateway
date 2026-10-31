// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Capability calls under a root rule, end to end (I6, R43): a capability's
//! argument template rewrites the path after any check, so the call is
//! refused before the executor runs; and a capability backend sharing a
//! config backend's name is refused as ambiguous, never sent to either.
//! Batch 5f.

use std::sync::Arc;

use serde_json::{Value, json};

use super::allowed_root_routes::{Routes, Setup};
use crate::capability::{CapabilityBackend, CapabilityExecutor};

/// A capability backend `name` with one CLI capability `read_file` that,
/// if it ever ran, would append to `ran`.
fn capabilities(name: &str, ran: &std::path::Path) -> Arc<CapabilityBackend> {
    let yaml = format!(
        "name: read_file\ndescription: Read a file.\nproviders:\n  primary:\n    service: cli\n    \
         config:\n      command: sh\n      args: [\"-c\", \"echo ran >> {}\"]\n",
        ran.display()
    );
    let definition = crate::capability::parse_capability(&yaml).expect("the capability parses");
    let caps = Arc::new(CapabilityBackend::new(
        name,
        Arc::new(CapabilityExecutor::new()),
    ));
    caps.register_capability(definition)
        .expect("the capability registers");
    caps
}

fn invoke(server: &str, path: &str) -> Value {
    json!({"name": "gateway_invoke", "arguments": {
        "server": server, "tool": "read_file", "arguments": {"path": path}}})
}

/// I6: a CLI capability under a root rule is `capability_not_checkable`,
/// even for an inside path, and its executor never runs. Control: the
/// config backend's inside call passes.
#[tokio::test]
async fn i6_capability_calls_are_refused_before_the_executor() {
    let routes = Routes::build(Setup {
        servers: "\"*\"",
        ..Setup::default()
    })
    .await;
    let ran = routes.dir.path().join("ran.log");
    routes.meta.set_capabilities(capabilities("caps", &ran));
    let inside = routes.path("safe/f");
    let answer = routes
        .post("/mcp", "tools/call", invoke("caps", &inside))
        .await;
    let text = answer.to_string();
    assert!(text.contains("capability_not_checkable"), "I6: {text}");
    assert!(!ran.exists(), "I6: the executor ran");
    let answer = routes
        .post("/mcp", "tools/call", invoke("fs", &inside))
        .await;
    assert!(answer.get("error").is_none(), "I6 control: {answer}");
}

/// R43: with a capability backend attached under the config backend's name
/// `fs`, a covered call is refused `ambiguous_backend` with the shared
/// envelope (code -32001, reason, server, routes) and reaches neither route.
/// Control: before the capability is attached the call reaches `fs`.
#[tokio::test]
async fn r43_a_name_both_routes_answer_is_ambiguous() {
    let routes = Routes::new().await;
    let inside = routes.path("safe/f");
    let answer = routes
        .post("/mcp", "tools/call", invoke("fs", &inside))
        .await;
    assert!(answer.get("error").is_none(), "R43 control: {answer}");
    let before = routes.received();

    let ran = routes.dir.path().join("ran.log");
    routes.meta.set_capabilities(capabilities("fs", &ran));
    let answer = routes
        .post("/mcp", "tools/call", invoke("fs", &inside))
        .await;
    let error = &answer["error"];
    assert_eq!(error["code"], json!(-32001), "R43: {answer}");
    assert_eq!(
        error["data"]["reason"],
        json!("ambiguous_backend"),
        "R43: {answer}"
    );
    assert_eq!(error["data"]["server"], json!("fs"), "R43: {answer}");
    assert_eq!(
        error["data"]["routes"],
        json!(["backend", "capability"]),
        "R43: {answer}"
    );
    // The one call site refuses every such name clash at resolve, before any
    // rule is looked at, so no rule is named (lead ruling 2026-10-29).
    assert!(
        error["data"].get("rule").is_none(),
        "R43: the name-clash check names no rule: {answer}"
    );
    assert_eq!(
        routes.received(),
        before,
        "R43: the config backend got the call"
    );
    assert!(!ran.exists(), "R43: the capability ran");
}

/// R43b (design d2): under the same clash the direct route `/mcp/fs` is
/// judged as the config backend it sends to: an inside call reaches only
/// that backend, and an outside call is refused before either runs.
#[tokio::test]
async fn r43b_the_direct_route_under_a_clash_judges_the_config_backend() {
    let routes = Routes::new().await;
    let ran = routes.dir.path().join("ran.log");
    routes.meta.set_capabilities(capabilities("fs", &ran));
    let before = routes.received();

    let inside = json!({"name": "read_file", "arguments": {"path": routes.path("safe/f")}});
    let answer = routes.post("/mcp/fs", "tools/call", inside).await;
    assert!(answer.get("error").is_none(), "R43b inside: {answer}");
    let after_inside = routes.received();
    assert_ne!(after_inside, before, "R43b: the config backend got no call");

    let outside = json!({"name": "read_file", "arguments": {"path": routes.path("outside/f")}});
    let answer = routes.post("/mcp/fs", "tools/call", outside).await;
    assert!(answer.get("error").is_some(), "R43b outside: {answer}");
    assert_eq!(
        routes.received(),
        after_inside,
        "R43b: the outside call reached the config backend"
    );
    assert!(!ran.exists(), "R43b: the capability ran");
}
