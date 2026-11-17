// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Map tools' rows through `gateway_invoke`: a paced refusal (RL16) and
//! attribution on the gateway exit (AT4, AT4b, AT5, AT7, AT9), over the
//! `.test`-hostname harness (`crate::capability::maps_harness`).

use std::sync::Arc;

use serde_json::{Value, json};

use super::MetaMcp;
use super::grant_decision_audit_tests::{api_key, context};
use crate::backend::BackendRegistry;
use crate::capability::maps_harness::{Names, Reply, Stub, executor};
use crate::capability::{CapabilityBackend, CapabilityDefinition};
use crate::protocol::RequestId;

const CAPS: &str = "maps_caps";
const OSM: &str = "© OpenStreetMap contributors";

/// A gateway serving `caps` from one capability backend.
fn gateway(caps: Vec<CapabilityDefinition>) -> MetaMcp {
    let backend = Arc::new(CapabilityBackend::new(
        CAPS,
        Arc::new(executor(Names::default())),
    ));
    for c in caps {
        backend.register_capability(c).expect("registered");
    }
    let meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    meta.set_capabilities(backend);
    meta
}

/// One `gateway_invoke` of `tool`, as the JSON the caller receives.
async fn invoke(meta: &MetaMcp, tool: &str, arguments: Value) -> Value {
    let who = api_key("alice");
    let response = Box::pin(meta.handle_tools_call(
        RequestId::Number(1),
        "gateway_invoke",
        json!({ "server": CAPS, "tool": tool, "arguments": arguments }),
        Some("maps-session"),
        context(&who),
    ))
    .await;
    serde_json::to_value(&response).expect("serialises")
}

/// The caller's two channels. `gateway_invoke` answers with one text item
/// holding the backend's tool result as JSON (beside the gateway's
/// `_context_integrity` and `_trace_id`) and no outer `structuredContent`, so
/// the channels are that tool result's text content, parsed, and its
/// `structuredContent`.
fn channels(response: &Value) -> (Value, Value) {
    let outer = response["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("outer text: {response}"));
    let tool: Value =
        serde_json::from_str(outer).unwrap_or_else(|_| panic!("tool result is JSON: {outer}"));
    let text = tool["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("tool text: {tool}"));
    let parsed = serde_json::from_str(text).unwrap_or_else(|_| panic!("text is JSON: {text}"));
    (parsed, tool["structuredContent"].clone())
}

/// A REST capability on `url` with `output` as its output schema and the
/// provider-level `extra` and top-level `top` lines.
fn cap(name: &str, url: &str, top: &str, output: &str, extra: &str) -> CapabilityDefinition {
    let yaml = format!(
        "fulcrum: \"1.0\"\nname: {name}\ndescription: d\n{top}schema:\n  input:\n    type: object\n    \
         properties:\n      q:\n        type: string\n  output:\n{output}providers:\n  primary:\n    \
         service: rest\n{extra}    config:\n      endpoint: {url}\n      method: GET\n"
    );
    crate::capability::parse_capability(&yaml).expect("capability")
}

/// An object output schema with `fields` (each a string) and `attribution`.
fn object_output(fields: &[&str]) -> String {
    let mut out = String::from("    type: object\n    properties:\n");
    for f in fields.iter().chain(["attribution"].iter()) {
        out.push_str(&format!("      {f}:\n        type: string\n"));
    }
    out
}

// ── RL16: a paced refusal through gateway_invoke ─────────────────────

#[tokio::test]
async fn rl16_a_paced_refusal_reaches_the_caller_verbatim() {
    let stub = Stub::start(Reply::json(r#"{"name":"n"}"#)).await;
    let meta = gateway(vec![cap(
        "rl16",
        &stub.url("rl16.test", "/s"),
        "",
        &object_output(&["name"]),
        "    rate_limit:\n      interval_ms: 30000\n",
    )]);
    invoke(&meta, "rl16", json!({ "q": "a" })).await;
    let refused = invoke(&meta, "rl16", json!({ "q": "b" })).await;
    let text = refused.to_string();
    assert!(
        text.contains(
            "Rate limit exceeded for backend 'rl16.test: one request per 30000 ms; retry after "
        ),
        "the refusal text reaches the caller: {refused}"
    );
    assert_eq!(stub.count(), 1);
}

// ── AT: attribution on the gateway exit ──────────────────────────────

fn attributed() -> String {
    format!("attribution: \"{OSM}\"\n")
}

#[tokio::test]
async fn at4b_attribution_without_a_transform_in_both_channels_with_and_without_full() {
    let stub = Stub::start(Reply::json(r#"{"name":"Helsinki"}"#)).await;
    let meta = gateway(vec![cap(
        "at4b",
        &stub.url("at4b.test", "/s"),
        &attributed(),
        &object_output(&["name"]),
        "",
    )]);
    for full in [false, true] {
        let mut args = json!({ "q": format!("full-{full}") });
        if full {
            args["_full"] = json!(true);
        }
        let response = invoke(&meta, "at4b", args).await;
        let (text, structured) = channels(&response);
        let want = json!({ "name": "Helsinki", "attribution": OSM });
        assert_eq!(text, want, "_full {full}: text");
        assert_eq!(structured, want, "_full {full}: structuredContent");
    }
}

#[tokio::test]
async fn at5_a_projecting_transform_keeps_the_attribution_and_drops_the_rest() {
    let stub = Stub::start(Reply::json(r#"{"name":"Helsinki","osm_id":"42"}"#)).await;
    let meta = gateway(vec![cap(
        "at5",
        &stub.url("at5.test", "/s"),
        &format!("{}response_transform:\n  project: [name]\n", attributed()),
        &object_output(&["name", "osm_id"]),
        "",
    )]);
    let (text, structured) = channels(&invoke(&meta, "at5", json!({ "q": "a" })).await);
    for (channel, v) in [("text", &text), ("structuredContent", &structured)] {
        assert_eq!(v["name"], "Helsinki", "{channel}: the kept field");
        assert_eq!(v["attribution"], OSM, "{channel}: the attribution");
        assert!(
            v.get("osm_id").is_none(),
            "{channel}: the dropped field is gone: {v}"
        );
    }
}

/// An array answer wrapped as `{results, attribution}`.
fn array_output() -> String {
    "    type: object\n    properties:\n      results:\n        type: array\n      attribution:\n        type: string\n"
        .to_owned()
}

#[tokio::test]
async fn at7_an_array_is_wrapped_once_on_both_exits() {
    let stub = Stub::start(Reply::json(r#"[{"name":"a"},{"name":"b"}]"#)).await;
    let definition = cap(
        "at7",
        &stub.url("at7.test", "/s"),
        &attributed(),
        &array_output(),
        "",
    );
    let meta = gateway(vec![definition]);
    let want = json!({ "results": [{ "name": "a" }, { "name": "b" }], "attribution": OSM });
    let (text, structured) = channels(&invoke(&meta, "at7", json!({ "q": "a" })).await);
    assert_eq!(text, want, "gateway text: wrapped once");
    assert_eq!(structured, want, "gateway structuredContent: wrapped once");
}

#[tokio::test]
async fn at7_a_string_is_wrapped_once_on_both_exits() {
    let stub = Stub::start(Reply::json(r#""a plain answer""#)).await;
    let meta = gateway(vec![cap(
        "at7s",
        &stub.url("at7s.test", "/s"),
        &attributed(),
        "    type: object\n    properties:\n      results:\n        type: string\n      attribution:\n        type: string\n",
        "",
    )]);
    let want = json!({ "results": "a plain answer", "attribution": OSM });
    let (text, structured) = channels(&invoke(&meta, "at7s", json!({ "q": "a" })).await);
    assert_eq!(text, want);
    assert_eq!(structured, want);
}
