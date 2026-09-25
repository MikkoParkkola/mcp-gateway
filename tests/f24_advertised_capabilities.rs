// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! F24: every change-notification capability the gateway advertises is one it
//! delivers.
//!
//! Drives the shipped binary on all four surfaces that report capabilities:
//! HTTP `initialize`, HTTP `server/discover`, stdio `initialize` and stdio
//! `server/discover`. The expected flags are written here, never read from
//! production, and every flag a surface reports as true must name the probe
//! that proves its notification arrives (`DELIVERY_PROBES`). Turning a flag on
//! without a producer and a probe fails `every_advertised_flag_has_a_delivery_probe`.

#[path = "common/signing_gateway.rs"]
pub mod signing_gateway;

use std::process::Stdio;
use std::time::Duration;

use serde_json::{Value, json};
use signing_gateway::HttpGateway;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

const TIMEOUT: Duration = Duration::from_secs(30);

/// The four change flags, as `(object, field)` in the capabilities document.
const FLAGS: [(&str, &str); 4] = [
    ("tools", "listChanged"),
    ("resources", "subscribe"),
    ("resources", "listChanged"),
    ("prompts", "listChanged"),
];

/// Expected value of each flag in `FLAGS` order, per surface.
const HTTP_EXPECTED: [bool; 4] = [true, false, false, false];
const STDIO_EXPECTED: [bool; 4] = [false, false, false, false];

/// Flag -> the test in `f24_tools_changed_delivery.rs` that fires its producer
/// and watches the notification arrive. A flag advertised true anywhere must
/// appear here.
pub const DELIVERY_PROBES: &[(&str, &str)] = &[(
    "tools.listChanged",
    "f24_tools_changed_delivery::every_tool_set_change_reaches_both_eras_once",
)];

fn flags(capabilities: &Value) -> [bool; 4] {
    FLAGS.map(|(object, field)| capabilities[object][field].as_bool().unwrap_or(false))
}

fn config() -> Value {
    json!({ "server": { "host": "127.0.0.1", "modern_protocol": true } })
}

fn initialize_body() -> Value {
    json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": { "name": "f24", "version": "1" }
        }
    })
}

fn discover_body() -> Value {
    json!({ "jsonrpc": "2.0", "id": 2, "method": "server/discover", "params": {} })
}

async fn http_capabilities(gateway: &HttpGateway, body: Value) -> Value {
    let response: Value = gateway
        .client
        .post(format!("{}/mcp", gateway.url))
        .json(&body)
        .send()
        .await
        .expect("HTTP request")
        .json()
        .await
        .expect("JSON body");
    response["result"]["capabilities"].clone()
}

/// `initialize` then `server/discover` over one `serve --stdio` process.
async fn stdio_capabilities() -> (Value, Value) {
    let dir = tempfile::tempdir().expect("tempdir");
    let config_path = dir.path().join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(
        &config_path,
        serde_yaml::to_string(&config()).expect("yaml"),
    )
    .expect("config");
    let mut command = signing_gateway::child_command(dir.path(), &config_path);
    let mut child = command
        .arg("--stdio")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn serve --stdio");
    let mut stdin = child.stdin.take().expect("stdin");
    let mut lines = BufReader::new(child.stdout.take().expect("stdout")).lines();

    let mut answers = Vec::new();
    for body in [initialize_body(), discover_body()] {
        let mut frame = serde_json::to_vec(&body).expect("frame");
        frame.push(b'\n');
        stdin.write_all(&frame).await.expect("write");
        stdin.flush().await.expect("flush");
        let id = body["id"].clone();
        let answer = tokio::time::timeout(TIMEOUT, async {
            loop {
                let line = lines.next_line().await.expect("read").expect("open stdout");
                let value: Value = serde_json::from_str(&line).expect("JSON line");
                if value["id"] == id {
                    return value;
                }
            }
        })
        .await
        .expect("stdio answer in time");
        answers.push(answer["result"]["capabilities"].clone());
    }
    drop(stdin);
    let _ = child.kill().await;
    let discover = answers.pop().expect("discover");
    (answers.pop().expect("initialize"), discover)
}

#[tokio::test]
async fn each_surface_advertises_only_what_it_delivers() {
    let gateway = HttpGateway::start(config()).await;
    let http_initialize = http_capabilities(&gateway, initialize_body()).await;
    let http_discover = http_capabilities(&gateway, discover_body()).await;
    let (stdio_initialize, stdio_discover) = stdio_capabilities().await;

    for (surface, capabilities, expected) in [
        ("HTTP initialize", &http_initialize, HTTP_EXPECTED),
        ("HTTP server/discover", &http_discover, HTTP_EXPECTED),
        ("stdio initialize", &stdio_initialize, STDIO_EXPECTED),
        ("stdio server/discover", &stdio_discover, STDIO_EXPECTED),
    ] {
        assert!(
            capabilities.is_object(),
            "{surface} returned no capabilities: {capabilities}"
        );
        assert_eq!(
            flags(capabilities),
            expected,
            "{surface}: flags {FLAGS:?} must be {expected:?}; got {capabilities}"
        );
    }
}

#[test]
fn every_advertised_flag_has_a_delivery_probe() {
    for (index, (object, field)) in FLAGS.iter().enumerate() {
        if HTTP_EXPECTED[index] || STDIO_EXPECTED[index] {
            let flag = format!("{object}.{field}");
            assert!(
                DELIVERY_PROBES.iter().any(|(name, _)| *name == flag),
                "{flag} is advertised, no delivery probe"
            );
        }
    }
}
