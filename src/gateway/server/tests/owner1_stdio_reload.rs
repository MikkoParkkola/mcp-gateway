// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7272.OWNER.1, the two reload branches with their context installed:
//! only the stdio serve loop installs a reload context and a capability
//! backend, so these rows drive `Gateway::run_stdio_on` over in-memory pipes.
//!
//! Test plan: `docs/design/2026-09-30-sub4-stdio-owner-test-plan.md` (I2,
//! T1.8 and T1.10). Each row makes the second keyed call distinguishable from
//! a re-execution: the file on disk changes between the calls, and a third,
//! unkeyed call proves the change is visible to a real reload.

use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, Lines};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::config::Config;
use crate::gateway::Gateway;

/// Bound on every wait for a response that must arrive.
const ARRIVAL: Duration = Duration::from_secs(20);

/// A capability the second step adds: a copy of
/// `capabilities/entertainment/musicbrainz_search.yaml`, renamed. Inline
/// because a packaged-crate build need not ship `capabilities/`.
const CAPABILITY: &str = r#"fulcrum: "1.0"
name: owner1_probe
description: Search music metadata from MusicBrainz - the open music encyclopedia. Find artists, albums, tracks, and recordings. Free, no API key required.

schema:
  input:
    type: object
    properties:
      query:
        type: string
        description: Search query
        examples:
          - "radiohead"
          - "abbey road beatles"
      type:
        type: string
        description: Entity type to search
        default: artist
        enum: [artist, release, recording, work, label]
      limit:
        type: integer
        description: Maximum results
        default: 10
    required:
      - query
  output:
    type: object
    properties:
      count:
        type: integer
      artists:
        type: array
        items:
          type: object
          properties:
            id:
              type: string
            name:
              type: string
            country:
              type: string
            type:
              type: string
            score:
              type: integer

providers:
  primary:
    service: rest
    cost_per_call: 0
    timeout: 15
    config:
      base_url: https://musicbrainz.org
      path: /ws/2/{type}
      method: GET
      headers:
        User-Agent: "MCPGateway/1.0"
        Accept: "application/json"
      params:
        query: "{query}"
        limit: "{limit}"
        fmt: "json"

cache:
  strategy: exact
  ttl: 86400

auth:
  required: false
  type: none

metadata:
  category: entertainment
  tags:
    - music
    - artists
    - albums
    - musicbrainz
    - free
  cost_category: free
  execution_time: fast
  read_only: true
  rate_limit: 1 req/sec
  docs: https://musicbrainz.org/doc/MusicBrainz_API
"#;

struct Serve {
    client: DuplexStream,
    replies: Lines<BufReader<DuplexStream>>,
    task: JoinHandle<()>,
    dir: tempfile::TempDir,
}

impl Serve {
    fn config_path(&self) -> std::path::PathBuf {
        self.dir.path().join("gateway.yaml")
    }

    fn capabilities_dir(&self) -> std::path::PathBuf {
        self.dir.path().join("caps")
    }

    async fn send(&mut self, frame: &Value) {
        let mut line = serde_json::to_vec(frame).expect("a frame serialises");
        line.push(b'\n');
        self.client
            .write_all(&line)
            .await
            .expect("stdin accepts the frame");
    }

    /// The next frame that answers `id`; anything else is skipped.
    async fn reply(&mut self, id: u64) -> Value {
        timeout(ARRIVAL, async {
            loop {
                let line = self
                    .replies
                    .next_line()
                    .await
                    .expect("stdout is readable")
                    .expect("the loop answers before closing");
                let frame: Value = serde_json::from_str(&line).expect("stdout carries JSON");
                if frame["id"] == json!(id) {
                    return frame;
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("no reply for id {id} within {ARRIVAL:?}"))
    }

    async fn call(&mut self, id: u64, tool: &str, key: Option<&str>) -> Value {
        let mut frame = json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": {"name": tool, "arguments": {}}});
        if let Some(key) = key {
            frame["params"]["_meta"] = json!({(crate::protocol::mrtr::IDEMPOTENCY_KEY_META): key});
        }
        self.send(&frame).await;
        self.reply(id).await
    }

    async fn close(self) {
        drop(self.client);
        drop(timeout(ARRIVAL, self.task).await);
    }
}

fn base_yaml(capabilities_dir: &std::path::Path) -> String {
    format!(
        "capabilities:\n  enabled: true\n  name: capabilities\n  directories:\n    - {}\n",
        capabilities_dir.display()
    )
}

/// A gateway serving stdio from a config file, as `run_stdio` would, after the
/// `initialize` handshake.
async fn serve() -> Serve {
    let dir = tempfile::tempdir().expect("tempdir");
    let caps = dir.path().join("caps");
    std::fs::create_dir(&caps).expect("capabilities directory");
    let path = dir.path().join("gateway.yaml");
    crate::gateway::test_helpers::write_owner_only(&path, base_yaml(&caps)).expect("write config");
    let config = Config::load(Some(&path)).expect("config loads");
    let gateway = Gateway::new_with_path(config, Some(path))
        .await
        .expect("gateway boots")
        .with_data_dir(dir.path().join("data"));
    let (client, input) = tokio::io::duplex(64 * 1024);
    let (output, stdout) = tokio::io::duplex(64 * 1024);
    let task = tokio::spawn(async move {
        drop(gateway.run_stdio_on(input, output, None).await);
    });
    let mut serve = Serve {
        client,
        replies: BufReader::new(stdout).lines(),
        task,
        dir,
    };
    serve
        .send(
            &json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "owner1", "version": "0"}}}),
        )
        .await;
    serve.reply(0).await;
    serve
}

/// The JSON a successful meta-tool call returned as its text content.
fn result_json(response: &Value) -> Value {
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("a successful tool call returns text: {response}"));
    serde_json::from_str(text).unwrap_or_else(|_| panic!("the text is JSON: {text}"))
}

/// T1.8. A keyed config reload replays its first result even after the file
/// changed; an unkeyed reload then sees the change, so the replay was a replay.
#[tokio::test]
async fn reload_config_over_the_serve_loop_replays() {
    let mut serve = serve().await;
    let first = serve
        .call(1, "gateway_reload_config", Some("reload-key"))
        .await;
    assert!(first.get("error").is_none(), "{first}");

    let edited = format!(
        "{}backends:\n  late:\n    http_url: \"http://127.0.0.1:9/\"\n    streamable_http: true\n",
        base_yaml(&serve.capabilities_dir())
    );
    crate::gateway::test_helpers::write_owner_only(&serve.config_path(), edited)
        .expect("rewrite config");

    let replay = serve
        .call(2, "gateway_reload_config", Some("reload-key"))
        .await;
    assert_eq!(
        result_json(&first),
        result_json(&replay),
        "the keyed reload must replay, not reload again"
    );
    let fresh = serve.call(3, "gateway_reload_config", None).await;
    assert_ne!(
        result_json(&fresh),
        result_json(&first),
        "an unkeyed reload must see the edited file: {fresh}"
    );
    serve.close().await;
}

/// T1.10. A keyed capability reload replays its first count after a file was
/// added; an unkeyed reload then counts it.
#[tokio::test]
async fn reload_capabilities_over_the_serve_loop_replays() {
    let mut serve = serve().await;
    let first = serve
        .call(1, "gateway_reload_capabilities", Some("capabilities-key"))
        .await;
    let before = result_json(&first)["total_capabilities"].clone();

    std::fs::write(
        serve.capabilities_dir().join("owner1_probe.yaml"),
        CAPABILITY,
    )
    .expect("add a capability");

    let replay = serve
        .call(2, "gateway_reload_capabilities", Some("capabilities-key"))
        .await;
    assert_eq!(
        result_json(&replay)["total_capabilities"],
        before,
        "the keyed reload must replay its first count"
    );
    let fresh = serve.call(3, "gateway_reload_capabilities", None).await;
    assert_ne!(
        result_json(&fresh)["total_capabilities"],
        before,
        "an unkeyed reload must count the added capability: {fresh}"
    );
    serve.close().await;
}
