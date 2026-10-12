// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! F24: `tools.listChanged: true` is delivered for every change to the tool set.
//!
//! One shipped HTTP gateway, one listener per era: a 2026 `subscriptions/listen`
//! stream and a 2025 GET session stream. Each action changes the tool set
//! through a different production path (config reload adding, modifying and
//! removing a backend; a capability file appearing; the admin UI adding,
//! removing and reviving a backend), and each must reach both listeners
//! exactly once. The UI calls need an admin, so auth is on with a bearer.

#[path = "common/signing_gateway.rs"]
pub mod signing_gateway;

use std::time::Duration;

use serde_json::{Value, json};
use signing_gateway::{BackendFixture, HttpGateway};

/// How long an expected event may take. A hang bound only: the wait ends when
/// the event arrives, and under full-suite load the reload, the re-listing and
/// both deliveries can outrun 20 s (MIK-8252).
const ARRIVAL: Duration = Duration::from_secs(120);
/// How long a step that expects no event watches for one. Load can only hide
/// an event here, never fail a correct run.
const ABSENCE: Duration = Duration::from_secs(20);
const QUIET: Duration = Duration::from_millis(1500);
const LIST_CHANGED: &str = "notifications/tools/list_changed";
const BEARER: &str = "f24-delivery-admin-token-0123456789";

const CAPABILITY: &str = r#"fulcrum: "1.0"
name: f24_probe
description: F24 probe capability
schema:
  input:
    type: object
    properties: {}
providers:
  primary:
    service: rest
    config:
      base_url: https://api.github.com
      path: /zen
      method: GET
"#;

/// A byte stream of SSE, read as `data:` JSON events.
struct Events {
    response: reqwest::Response,
    buffer: String,
}

impl Events {
    /// The next event, or `None` if nothing arrives within `wait`.
    async fn next(&mut self, wait: Duration) -> Option<Value> {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            if let Some(end) = self.buffer.find("\n\n") {
                let block: String = self.buffer.drain(..end + 2).collect();
                if let Some(data) = block.lines().find_map(|l| l.strip_prefix("data:"))
                    && let Ok(value) = serde_json::from_str(data.trim())
                {
                    return Some(value);
                }
                continue;
            }
            let chunk = tokio::time::timeout_at(deadline, self.response.chunk())
                .await
                .ok()?
                .expect("stream read")?;
            self.buffer.push_str(&String::from_utf8_lossy(&chunk));
        }
    }

    /// Count `tools/list_changed` events: up to `ARRIVAL` for each of the
    /// `expected` ones, then until the stream has been quiet for `QUIET`, or
    /// for `ABSENCE` when none is expected.
    async fn count_list_changed(&mut self, expected: usize) -> usize {
        let mut count = 0;
        loop {
            let wait = match count {
                n if n < expected => ARRIVAL,
                0 => ABSENCE,
                _ => QUIET,
            };
            match self.next(wait).await {
                Some(event) if event["method"] == LIST_CHANGED => count += 1,
                Some(_) => {}
                None => return count,
            }
        }
    }
}

async fn modern_listen(gateway: &HttpGateway) -> Events {
    let body = json!({
        "jsonrpc": "2.0", "id": "f24-listen", "method": "subscriptions/listen",
        "params": {
            "notifications": { "toolsListChanged": true },
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {}
            }
        }
    });
    let response = gateway
        .client
        .post(format!("{}/mcp", gateway.url))
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "subscriptions/listen")
        .header("accept", "application/json, text/event-stream")
        .json(&body)
        .timeout(Duration::from_secs(600))
        .send()
        .await
        .expect("listen request");
    assert!(
        response.status().is_success(),
        "listen refused: {}",
        response.status()
    );
    let mut events = Events {
        response,
        buffer: String::new(),
    };
    events
        .next(ARRIVAL)
        .await
        .expect("the listen ack opens the stream");
    events
}

async fn legacy_stream(gateway: &HttpGateway) -> Events {
    let session = gateway.initialize().await;
    let response = gateway
        .client
        .get(format!("{}/mcp", gateway.url))
        .header("mcp-session-id", session)
        .header("accept", "text/event-stream")
        .timeout(Duration::from_secs(600))
        .send()
        .await
        .expect("GET stream");
    assert!(
        response.status().is_success(),
        "GET stream refused: {}",
        response.status()
    );
    Events {
        response,
        buffer: String::new(),
    }
}

/// Both listeners, opened only after the boot warm-up settled, with anything
/// already queued drained.
///
/// The boot warm-up's first fill announces once (MIK-8127). A listener opened
/// before it while the other opened after read (2,1) on a slow Windows runner
/// (#3620). The wait matches the message text only: the log formatter colours
/// field names with ANSI codes, so "backend=alpha" is not a literal substring
/// on every platform. alpha is the only backend at boot.
async fn listeners_after_boot(gateway: &HttpGateway) -> (Events, Events) {
    let settled = std::time::Instant::now() + Duration::from_secs(60);
    while !gateway.logs().contains("Warm-started + tools cached") {
        assert!(
            std::time::Instant::now() < settled,
            "alpha's boot warm-up never settled; logs: {}",
            gateway.logs()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let mut modern = modern_listen(gateway).await;
    let mut legacy = legacy_stream(gateway).await;
    let _ = (
        modern.count_list_changed(0).await,
        legacy.count_list_changed(0).await,
    );
    (modern, legacy)
}

fn write_config(gateway: &HttpGateway, config: &Value) {
    mcp_gateway::gateway::test_helpers::write_owner_only(
        gateway.config_path(),
        serde_yaml::to_string(config).expect("yaml"),
    )
    .expect("rewrite config");
}

fn drop_backend(config: &mut Value, name: &str) {
    config["backends"]
        .as_object_mut()
        .expect("map")
        .remove(name);
}

#[tokio::test]
async fn every_tool_set_change_reaches_both_eras_once() {
    let alpha = BackendFixture::start(json!({"content": []})).await;
    let beta = BackendFixture::start(json!({"content": []})).await;
    let caps = tempfile::tempdir().expect("capability dir");
    let mut config = json!({
        "server": { "host": "127.0.0.1", "modern_protocol": true },
        "auth": { "enabled": true, "bearer_token": BEARER },
        "security": { "transparency_log": {
            "enabled": true, "path": caps.path().join("audit").join("log.jsonl")
        } },
        "capabilities": { "enabled": true, "directories": [caps.path().join("caps")] },
        "backends": { "alpha": { "http_url": alpha.url, "streamable_http": true } }
    });
    std::fs::create_dir_all(caps.path().join("caps")).expect("capability dir");
    std::fs::create_dir_all(caps.path().join("audit")).expect("audit dir");
    let mut gateway = HttpGateway::start(config.clone()).await;
    gateway.client = admin_client();
    // Copy the file's port into the rewrite so a reload never sees a port
    // change. The harness writes 0 and reads the bound port from the banner
    // (#2513); 0 in both files keeps the live listener.
    config["server"]["port"] = serde_yaml::from_str::<Value>(
        &std::fs::read_to_string(gateway.config_path()).expect("config"),
    )
    .expect("yaml")["server"]["port"]
        .clone();
    let (mut modern, mut legacy) = listeners_after_boot(&gateway).await;

    // MIK-8127: one announcement per change of the tool set discovery shows,
    // never per backend event, so a step that leaves it unchanged expects none.
    let mut expect = async |action: &str, expected: usize| {
        let (m, l) = (
            modern.count_list_changed(expected).await,
            legacy.count_list_changed(expected).await,
        );
        assert_eq!(
            (m, l),
            (expected, expected),
            "{action}: tools/list_changed must reach the 2026 listener and the 2025 \
             stream {expected} time(s) each; logs: {}",
            gateway.logs()
        );
    };

    config["backends"]["beta"] = json!({ "http_url": beta.url, "streamable_http": true });
    write_config(&gateway, &config);
    expect("config reload adds a backend", 1).await;

    config["backends"]["beta"]["description"] = json!("modified");
    write_config(&gateway, &config);
    // The backend's own description is not part of any tool, and its
    // replacement lists the same tool, so discovery shows the same set.
    expect("config reload modifies a backend", 0).await;

    drop_backend(&mut config, "beta");
    write_config(&gateway, &config);
    expect("config reload removes a backend", 1).await;

    // A backend that never lists a tool adds nothing discovery shows, and
    // removing it takes nothing away.
    config["backends"]["delta"] =
        json!({ "http_url": "http://127.0.0.1:1/mcp", "streamable_http": true });
    write_config(&gateway, &config);
    expect("config reload adds a backend that never lists tools", 0).await;
    drop_backend(&mut config, "delta");
    write_config(&gateway, &config);
    expect("config reload removes a backend that never listed tools", 0).await;

    std::fs::write(caps.path().join("caps").join("f24_probe.yaml"), CAPABILITY)
        .expect("capability");
    expect("a capability file appears", 1).await;

    // The admin UI writes the config and reloads; the reload is what announces,
    // so a second, direct announce would reach each listener twice.
    let added = ui(
        &gateway,
        reqwest::Method::POST,
        "/ui/api/backends",
        Some(json!({ "name": "gamma", "url": beta.url })),
    )
    .await;
    assert_eq!(
        added,
        reqwest::StatusCode::CREATED,
        "UI add: {}",
        gateway.logs()
    );
    expect("the admin UI adds a backend", 1).await;

    let removed = ui(
        &gateway,
        reqwest::Method::DELETE,
        "/ui/api/backends/gamma",
        None,
    )
    .await;
    assert_eq!(
        removed,
        reqwest::StatusCode::NO_CONTENT,
        "UI remove: {}",
        gateway.logs()
    );
    expect("the admin UI removes a backend", 1).await;

    let revived = ui(
        &gateway,
        reqwest::Method::POST,
        "/ui/api/backends/alpha/revive",
        None,
    )
    .await;
    assert_eq!(
        revived,
        reqwest::StatusCode::OK,
        "UI revive: {}",
        gateway.logs()
    );
    // The rebuilt backend lists the same tool: nothing changed for discovery.
    expect("the admin UI revives a backend", 0).await;
}

/// A client that presents the admin bearer on every request.
fn admin_client() -> reqwest::Client {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::AUTHORIZATION,
        format!("Bearer {BEARER}").parse().expect("header"),
    );
    reqwest::Client::builder()
        .default_headers(headers)
        .timeout(Duration::from_secs(30))
        .build()
        .expect("client")
}

async fn ui(
    gateway: &HttpGateway,
    method: reqwest::Method,
    path: &str,
    body: Option<Value>,
) -> reqwest::StatusCode {
    let mut request = gateway
        .client
        .request(method, format!("{}{path}", gateway.url));
    if let Some(body) = body {
        request = request.json(&body);
    }
    request.send().await.expect("UI request").status()
}
