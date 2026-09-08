// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! SUB4.SYNC.CACHE.1 and STDIO.OWNER.1: real process/transport falsifiers.
//! Continuation transfer, Task recovery and the other stdio security rows are
//! separate acceptance cases; these tests cannot supply their evidence.

#[path = "common/signing_gateway.rs"]
mod signing_gateway;

use std::process::Stdio;
use std::time::Duration;

use serde_json::{Value, json};
use signing_gateway::{BACKEND, BackendFixture, HttpGateway, TOOL, child_command, fixture_config};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::process::{Child, ChildStdin, ChildStdout};

const KEY: &str = "io.mcp-gateway/idempotency-key";
const VERSION: &str = "io.modelcontextprotocol/protocolVersion";
const CAPS: &str = "io.modelcontextprotocol/clientCapabilities";
const CREDENTIAL: &str = "sub4-lifecycle-synthetic-credential";
const IO_TIMEOUT: Duration = Duration::from_secs(15);

fn result(label: &str) -> Value {
    json!({"content":[{"type":"text","text":label}],"isError":false})
}

fn config(backend: &BackendFixture) -> Value {
    let mut config = fixture_config(&backend.url);
    config["security"]["message_signing"] = json!({"enabled":false});
    config["cache"] = json!({"enabled":false});
    config
}

fn call(id: &str, modern: bool, key: Option<&str>) -> Value {
    let mut call = json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{
        "name":"gateway_invoke","arguments":{"server":BACKEND,"tool":TOOL,
        "arguments":{"business":"identical-on-every-attempt"}}
    }});
    if modern {
        call["params"]["_meta"] = json!({(VERSION):"2026-07-28",(CAPS):{}});
    }
    if let Some(key) = key {
        call["params"]["_meta"][KEY] = json!(key);
    }
    call
}

fn assert_result(response: &Value, id: &str, label: &str) {
    assert_eq!(response["id"], id, "current correlation: {response}");
    assert!(
        response.get("error").is_none(),
        "successful control: {response}"
    );
    assert!(
        response["result"].to_string().contains(label),
        "expected backend artifact {label}: {response}"
    );
}

async fn http_call(gateway: &HttpGateway, request: Value) -> Value {
    let response = gateway
        .client
        .post(format!("{}/mcp", gateway.url))
        .bearer_auth(CREDENTIAL)
        .header("mcp-protocol-version", "2025-06-18")
        .json(&request)
        .send()
        .await
        .expect("real HTTP request");
    let status = response.status();
    let body: Value = response.json().await.expect("complete HTTP JSON response");
    assert!(status.is_success(), "{status}: {body}; {}", gateway.logs());
    body
}

/// SUB4.SYNC.CACHE.1: the ordinary cache is proved hot before key A, key B and
/// admission replay are distinguished using identical business arguments.
#[tokio::test]
async fn sub4_sync_cache_meta_independent_keys_dispatch_despite_hot_response_cache() {
    let backend = BackendFixture::start(result("cache-warm-effect-1")).await;
    let mut config = config(&backend);
    config["cache"] = json!({"enabled":true,"default_ttl":"1h"});
    config["auth"] = json!({"enabled":true,"public_paths":["/health"],
        "api_keys":[{"key":CREDENTIAL,"name":"lifecycle-owner","rate_limit":0,"backends":["*"]}]});
    let gateway = HttpGateway::start(config).await;
    let warm = http_call(&gateway, call("warm", false, None)).await;
    assert_result(&warm, "warm", "cache-warm-effect-1");
    assert_eq!(backend.calls().len(), 1);
    backend.set_result(result("independent-a-effect-2"));
    let hit = http_call(&gateway, call("warm-hit", false, None)).await;
    assert_result(&hit, "warm-hit", "cache-warm-effect-1");
    assert_eq!(
        backend.calls().len(),
        1,
        "ordinary response cache really hit"
    );

    let first = http_call(&gateway, call("key-a", false, Some("protected-a"))).await;
    assert_eq!(
        backend.calls().len(),
        2,
        "key A owns independent work despite the hot ordinary cache: {first}"
    );
    assert_result(&first, "key-a", "independent-a-effect-2");
    backend.set_result(result("independent-b-effect-3"));
    let second = http_call(&gateway, call("key-b", false, Some("protected-b"))).await;
    assert_eq!(
        backend.calls().len(),
        3,
        "changing only explicit key starts independent work: {second}"
    );
    assert_result(&second, "key-b", "independent-b-effect-3");
    let replay = http_call(&gateway, call("key-a-replay", false, Some("protected-a"))).await;
    assert_result(&replay, "key-a-replay", "independent-a-effect-2");
    assert!(!replay.to_string().contains("independent-b-effect-3"));
    assert_eq!(backend.calls().len(), 3, "same-key replay cannot dispatch");
    let ordinary = http_call(&gateway, call("ordinary-latest", false, None)).await;
    assert_result(&ordinary, "ordinary-latest", "independent-b-effect-3");
    assert_eq!(
        backend.calls().len(),
        3,
        "ordinary cache retains B while admission retains A"
    );
}

struct StdioGateway {
    child: Child,
    directory: TempDir,
    input: ChildStdin,
    output: Lines<BufReader<ChildStdout>>,
}

impl StdioGateway {
    async fn start(config: Value) -> Self {
        let directory = tempfile::tempdir().expect("private stdio gateway directory");
        let path = directory.path().join("gateway.yaml");
        std::fs::write(&path, serde_yaml::to_string(&config).unwrap()).unwrap();
        let log = std::fs::File::create(directory.path().join("stderr.log")).unwrap();
        let mut child = child_command(directory.path(), &path)
            .arg("--stdio")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(log))
            .spawn()
            .expect("real stdio gateway process");
        let input = child.stdin.take().unwrap();
        let output = BufReader::new(child.stdout.take().unwrap()).lines();
        let mut gateway = Self {
            child,
            directory,
            input,
            output,
        };
        let initialized = gateway.call(json!({"jsonrpc":"2.0","id":"initialize","method":"initialize",
            "params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"sub4-lifecycle","version":"test"}}})).await;
        assert!(
            initialized.get("result").is_some(),
            "stdio initialize: {initialized}"
        );
        gateway
    }

    async fn call(&mut self, request: Value) -> Value {
        let mut encoded = serde_json::to_vec(&request).unwrap();
        encoded.push(b'\n');
        tokio::time::timeout(IO_TIMEOUT, self.input.write_all(&encoded))
            .await
            .expect("bounded stdio write")
            .expect("complete stdio write");
        let answer = tokio::time::timeout(IO_TIMEOUT, async {
            loop {
                let line = self
                    .output
                    .next_line()
                    .await
                    .expect("read stdio frame")
                    .expect("gateway remains alive");
                let response: Value = serde_json::from_str(&line).expect("JSON-RPC stdout only");
                if response.get("id") == request.get("id") {
                    return response;
                }
            }
        })
        .await;
        answer.unwrap_or_else(|error| {
            panic!(
                "bounded stdio response: {error}; {}",
                std::fs::read_to_string(self.directory.path().join("stderr.log"))
                    .unwrap_or_default()
            )
        })
    }

    async fn stop(mut self) {
        self.child.kill().await.expect("terminate owned gateway");
        self.child.wait().await.expect("join owned gateway");
    }
}

/// MIK-7272.SUB4.STDIO.OWNER.1: actual transport supplies local execution
/// authority; request metadata supplies only an operation key, never identity.
#[tokio::test]
async fn sub4_stdio_owner_modern_keyed_write_and_cross_era_replay() {
    let backend = BackendFixture::start(result("stdio-owned-effect-1")).await;
    let mut gateway = StdioGateway::start(config(&backend)).await;
    let first = gateway
        .call(call("modern-owner", true, Some("local-operation")))
        .await;
    assert_result(&first, "modern-owner", "stdio-owned-effect-1");
    assert_eq!(backend.calls().len(), 1);
    backend.set_result(result("must-not-be-another-effect"));
    for (id, modern) in [("modern-replay", true), ("legacy-replay", false)] {
        let replay = gateway
            .call(call(id, modern, Some("local-operation")))
            .await;
        assert_result(&replay, id, "stdio-owned-effect-1");
        assert_eq!(backend.calls().len(), 1, "one same-realm owner across eras");
    }
    gateway.stop().await;
}

/// MIK-7272.SUB4.STDIO.OWNER.1: modern refusal and legacy repeat controls use
/// the same configured mutating target, without trusting its backend annotation.
#[tokio::test]
async fn sub4_stdio_owner_missing_key_refuses_and_legacy_unkeyed_repeats() {
    let backend = BackendFixture::start(result("legacy-effect-1")).await;
    let mut gateway = StdioGateway::start(config(&backend)).await;
    let missing = gateway.call(call("modern-missing", true, None)).await;
    assert_eq!(
        missing["error"]["code"], -32602,
        "modern missing key: {missing}"
    );
    assert_eq!(backend.calls().len(), 0, "refusal precedes backend effects");
    for (id, label, count) in [
        ("legacy-one", "legacy-effect-1", 1),
        ("legacy-two", "legacy-effect-2", 2),
    ] {
        backend.set_result(result(label));
        let allowed = gateway.call(call(id, false, None)).await;
        assert_result(&allowed, id, label);
        assert_eq!(
            backend.calls().len(),
            count,
            "legacy unkeyed repeats remain intentional"
        );
    }
    gateway.stop().await;
}
