// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Attribution rows (AT) on the direct exit (`CapabilityBackend::call_tool`, whose
//! successful result is built by `build_success_tool_result`), over the
//! `.test`-hostname harness.

use std::sync::Arc;

use serde_json::{Value, json};

use crate::capability::maps_harness::{Names, Reply, Stub, executor};
use crate::capability::{CapabilityBackend, CapabilityDefinition};
use crate::protocol::ToolsCallResult;

const OSM: &str = "© OpenStreetMap contributors";

/// A REST capability on `url` declaring the OSM attribution, with `output`
/// as its output schema; cached when `cached`.
fn cap(name: &str, url: &str, output: &str, cached: bool) -> CapabilityDefinition {
    let cache = if cached {
        "metadata:\n  read_only: true\ncache:\n  strategy: exact\n  ttl: 600\n"
    } else {
        ""
    };
    let yaml = format!(
        "fulcrum: \"1.0\"\nname: {name}\ndescription: d\nattribution: \"{OSM}\"\n{cache}schema:\n  \
         input:\n    type: object\n    properties:\n      q:\n        type: string\n  output:\n{output}\
         providers:\n  primary:\n    service: rest\n    config:\n      endpoint: {url}\n      \
         method: GET\n"
    );
    crate::capability::parse_capability(&yaml).expect("capability")
}

fn backend(caps: Vec<CapabilityDefinition>) -> CapabilityBackend {
    let backend = CapabilityBackend::new("maps", Arc::new(executor(Names::default())));
    for c in caps {
        backend.register_capability(c).expect("registered");
    }
    backend
}

/// The text content parsed as JSON, and `structuredContent`.
fn channels(result: &ToolsCallResult) -> (Value, Value) {
    let value = serde_json::to_value(result).expect("json");
    let text = value["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("text: {value}"));
    let parsed = serde_json::from_str(text).unwrap_or_else(|_| panic!("text is JSON: {text}"));
    (parsed, value["structuredContent"].clone())
}

fn object_output(fields: &[&str]) -> String {
    use std::fmt::Write as _;
    fields.iter().chain(["attribution"].iter()).fold(
        String::from("    type: object\n    properties:\n"),
        |mut out, f| {
            let _ = write!(out, "      {f}:\n        type: string\n");
            out
        },
    )
}

fn wrapped_output(results_type: &str) -> String {
    format!(
        "    type: object\n    properties:\n      results:\n        type: {results_type}\n      \
         attribution:\n        type: string\n"
    )
}

async fn both(answer: &str, host: &str, output: &str) -> (Value, Value) {
    let stub = Stub::start(Reply::json(answer)).await;
    let b = backend(vec![cap("at", &stub.url(host, "/s"), output, false)]);
    let result = b
        .call_tool("at", json!({ "q": "a" }))
        .await
        .expect("result");
    channels(&result)
}

#[tokio::test]
async fn at1_an_object_gains_the_attribution_and_keeps_its_keys() {
    let (text, structured) = both(
        r#"{"name":"Helsinki","osm_id":"42"}"#,
        "at1.test",
        &object_output(&["name", "osm_id"]),
    )
    .await;
    let want = json!({ "name": "Helsinki", "osm_id": "42", "attribution": OSM });
    assert_eq!(text, want);
    assert_eq!(structured, want);
}

#[tokio::test]
async fn at2_an_array_is_wrapped_with_the_attribution() {
    let (text, structured) = both(
        r#"[{"name":"a"},{"name":"b"}]"#,
        "at2.test",
        &wrapped_output("array"),
    )
    .await;
    let want = json!({ "results": [{ "name": "a" }, { "name": "b" }], "attribution": OSM });
    assert_eq!(text, want);
    assert_eq!(structured, want);
}

#[tokio::test]
async fn at2b_a_string_and_a_number_are_wrapped() {
    let (text, structured) = both(r#""plain""#, "at2b-s.test", &wrapped_output("string")).await;
    let want = json!({ "results": "plain", "attribution": OSM });
    assert_eq!((text, structured), (want.clone(), want));
    let (text, structured) = both("7", "at2b-n.test", &wrapped_output("number")).await;
    let want = json!({ "results": 7, "attribution": OSM });
    assert_eq!((text, structured), (want.clone(), want));
}

#[tokio::test]
async fn at3_a_provider_field_named_attribution_is_overwritten() {
    let (text, structured) = both(
        r#"{"name":"n","attribution":"someone else"}"#,
        "at3.test",
        &object_output(&["name"]),
    )
    .await;
    assert_eq!(text["attribution"], OSM);
    assert_eq!(structured["attribution"], OSM);
}

#[tokio::test]
async fn at6_a_cache_hit_carries_the_attribution() {
    let stub = Stub::start(Reply::json(r#"{"name":"n"}"#)).await;
    let definition = cap(
        "at6",
        &stub.url("at6.test", "/s"),
        &object_output(&["name"]),
        true,
    );
    assert!(definition.is_cacheable(), "premise: cacheable");
    let b = backend(vec![definition]);
    b.call_tool("at6", json!({ "q": "a" }))
        .await
        .expect("stored");
    let hit = b.call_tool("at6", json!({ "q": "a" })).await.expect("hit");
    assert_eq!(stub.count(), 1, "premise: the second call was a cache hit");
    let (text, structured) = channels(&hit);
    assert_eq!(text["attribution"], OSM);
    assert_eq!(structured["attribution"], OSM);
}

#[tokio::test]
async fn at11_a_failed_call_carries_no_attribution() {
    let stub = Stub::start(Reply::status(500)).await;
    let b = backend(vec![cap(
        "at11",
        &stub.url("at11.test", "/s"),
        &object_output(&["name"]),
        false,
    )]);
    match b.call_tool("at11", json!({ "q": "a" })).await {
        Err(e) => assert!(
            !e.to_string().contains(OSM),
            "no attribution on an error: {e}"
        ),
        Ok(result) => {
            assert!(result.is_error, "a 500 is an error result");
            let text = serde_json::to_string(&result).expect("json");
            assert!(!text.contains(OSM), "no attribution on an error: {text}");
        }
    }
    // Control: a 200 carries it (red until attribution lands).
    let (text, _) = both(r#"{"name":"n"}"#, "at11-ok.test", &object_output(&["name"])).await;
    assert_eq!(text["attribution"], OSM);
}
