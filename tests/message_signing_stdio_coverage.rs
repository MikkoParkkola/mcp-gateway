// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Production `serve --stdio` tools/call and JSON-RPC batch signing coverage.

#[path = "common/signing_gateway.rs"]
pub mod signing_gateway;

use std::collections::HashSet;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};
use signing_gateway::{BACKEND, BackendFixture, KEY, TOOL, child_command, fixture_config, invoke};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::process::{Child, ChildStdin, ChildStdout};

const KEY_ID: &str = "signing-test-current";
const SENTINEL: &str = "stdio-signing-backend-echo";
const IO_TIMEOUT: Duration = Duration::from_secs(30);

struct StdioGateway {
    child: Child,
    _directory: tempfile::TempDir,
    input: Option<ChildStdin>,
    output: Lines<BufReader<ChildStdout>>,
    child_pid: u32,
    profile_dir: Option<PathBuf>,
    prior_profiles: HashSet<PathBuf>,
}

impl StdioGateway {
    async fn start(config: Value) -> Self {
        let directory = tempfile::tempdir().expect("stdio gateway directory");
        let config_path = directory.path().join("gateway.yaml");
        write_yaml(&config_path, &config);
        let (profile_dir, prior_profiles) = snapshot_profile_dir();
        let mut command = child_command(directory.path(), &config_path);
        command
            .arg("--stdio")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        let mut child = command.spawn().expect("real stdio gateway process");
        let child_pid = child.id().expect("child pid after spawn");
        let input = child.stdin.take().expect("gateway stdin");
        let output = BufReader::new(child.stdout.take().expect("gateway stdout")).lines();
        let mut gateway = Self {
            child,
            _directory: directory,
            input: Some(input),
            output,
            child_pid,
            profile_dir,
            prior_profiles,
        };
        let initialized = gateway
            .call(json!({
                "jsonrpc": "2.0", "id": "stdio-signing-initialize", "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18", "capabilities": {},
                    "clientInfo": {"name": "signing-stdio-coverage", "version": "test"}
                }
            }))
            .await;
        assert!(
            initialized.get("result").is_some(),
            "stdio initialize fixture: {initialized}"
        );
        gateway
    }

    async fn call(&mut self, request: Value) -> Value {
        self.call_raw(request).await.0
    }

    async fn call_raw(&mut self, request: Value) -> (Value, String) {
        self.write_frame(&request).await;
        let wanted = request["id"].clone();
        tokio::time::timeout(IO_TIMEOUT, async {
            loop {
                let line = self.next_line().await;
                let frame: Value =
                    serde_json::from_str(&line).expect("stdout contains JSON-RPC, not logs");
                if frame.get("id") == Some(&wanted) {
                    return (frame, line);
                }
                assert!(
                    frame.get("id").is_none(),
                    "unexpected correlated frame: {frame}"
                );
            }
        })
        .await
        .expect("bounded matching stdio response")
    }

    async fn call_batch(&mut self, requests: &[Value]) -> Vec<Value> {
        let wanted: HashSet<Value> = requests.iter().map(|r| r["id"].clone()).collect();
        assert_eq!(wanted.len(), 2, "batch uses two distinct ids");
        self.write_frame(&Value::Array(requests.to_vec())).await;
        tokio::time::timeout(IO_TIMEOUT, async {
            loop {
                let line = self.next_line().await;
                let frame: Value =
                    serde_json::from_str(&line).expect("stdout contains JSON-RPC, not logs");
                match &frame {
                    Value::Array(members) => {
                        let ids: HashSet<Value> = members.iter().map(|m| m["id"].clone()).collect();
                        assert_eq!(ids, wanted, "batch ids must match both requests: {frame}");
                        assert_eq!(members.len(), 2, "batch must deliver two members: {frame}");
                        return members.clone();
                    }
                    Value::Object(_) if frame.get("id").is_none() => {}
                    _ => panic!("unexpected stdio frame while awaiting batch: {frame}"),
                }
            }
        })
        .await
        .expect("bounded matching stdio batch response")
    }

    async fn write_frame(&mut self, value: &Value) {
        let mut bytes = serde_json::to_vec(value).expect("serialize stdio request");
        bytes.push(b'\n');
        let input = self.input.as_mut().expect("stdin still open");
        tokio::time::timeout(IO_TIMEOUT, input.write_all(&bytes))
            .await
            .expect("bounded stdio write")
            .expect("write request");
    }

    async fn next_line(&mut self) -> String {
        self.output
            .next_line()
            .await
            .expect("read complete stdio frame")
            .expect("gateway remains alive")
    }

    async fn finish(mut self) {
        drop(self.input.take());
        let status = tokio::time::timeout(IO_TIMEOUT, self.child.wait())
            .await
            .expect("bounded successful stdio EOF exit")
            .expect("wait for stdio child");
        assert!(
            status.success(),
            "stdio child must exit successfully after stdin EOF, got {status}"
        );
        eprintln!(
            "SIGNING_COVERAGE_CHILD pid={} binary={} normal_exit={}",
            self.child_pid,
            env!("CARGO_BIN_EXE_mcp-gateway"),
            status.success()
        );
        assert_child_profile(
            self.profile_dir.as_ref(),
            &self.prior_profiles,
            self.child_pid,
        );
    }
}

#[tokio::test]
async fn stdio_enabled_nonce_replay_then_fresh_batch_is_signed() {
    let backend = BackendFixture::start(backend_result()).await;
    let mut gateway = StdioGateway::start(fixture_config(&backend.url)).await;
    let first_id = "stdio-echo-1";
    let first_nonce = "stdio-nonce-replay-1";
    let first = gateway
        .call(invoke(json!(first_id), json!(first_nonce), json!({})))
        .await;
    assert_invoke_sentinel(&first, SENTINEL);
    verify_signed_wire(&first, first_id, json!(first_nonce)).await;
    assert_eq!(backend.calls().len(), 1);

    let replay = gateway
        .call(invoke(
            json!("stdio-echo-replay"),
            json!(first_nonce),
            json!({}),
        ))
        .await;
    assert_eq!(
        replay["error"]["code"], -32001,
        "same-nonce replay must be refused: {replay}"
    );
    assert_eq!(
        backend.calls().len(),
        1,
        "replay must not reach the backend"
    );

    let batch_a = invoke(
        json!("stdio-echo-batch-a"),
        json!("stdio-nonce-batch-a"),
        json!({}),
    );
    let batch_b = invoke(
        json!("stdio-echo-batch-b"),
        json!("stdio-nonce-batch-b"),
        json!({}),
    );
    let members = gateway
        .call_batch(&[batch_a.clone(), batch_b.clone()])
        .await;
    let by_id = |id: &str| {
        members
            .iter()
            .find(|m| m["id"] == id)
            .cloned()
            .unwrap_or_else(|| panic!("missing batch member {id}: {members:?}"))
    };
    let a = by_id("stdio-echo-batch-a");
    let b = by_id("stdio-echo-batch-b");
    assert_invoke_sentinel(&a, SENTINEL);
    assert_invoke_sentinel(&b, SENTINEL);
    verify_signed_wire(&a, "stdio-echo-batch-a", json!("stdio-nonce-batch-a")).await;
    verify_signed_wire(&b, "stdio-echo-batch-b", json!("stdio-nonce-batch-b")).await;
    assert_eq!(backend.calls().len(), 3);

    gateway.finish().await;
}

#[tokio::test]
async fn stdio_enabled_optional_nonce_omitted_is_signed() {
    let backend = BackendFixture::start(backend_result()).await;
    let mut config = fixture_config(&backend.url);
    config["security"]["message_signing"]["require_nonce"] = json!(false);
    let mut gateway = StdioGateway::start(config).await;
    let request = json!({"jsonrpc": "2.0", "id": "stdio-echo-optional", "method": "tools/call",
    "params": {"name": "gateway_invoke", "arguments": {
        "server": BACKEND, "tool": TOOL, "arguments": {}
    }}});
    let response = gateway.call(request).await;
    assert_invoke_sentinel(&response, SENTINEL);
    verify_signed_wire(&response, "stdio-echo-optional", Value::Null).await;
    assert_eq!(backend.calls().len(), 1);
    gateway.finish().await;
}

fn write_yaml(path: &Path, config: &Value) {
    std::fs::write(path, serde_yaml::to_string(config).expect("config YAML"))
        .expect("write gateway config");
}

fn backend_result() -> Value {
    json!({"content": [{"type": "text", "text": SENTINEL}]})
}

fn wrapped_payload(response: &Value) -> Value {
    serde_json::from_str(
        response["result"]["content"][0]["text"]
            .as_str()
            .expect("wrapped gateway_invoke text"),
    )
    .expect("inner backend payload JSON")
}

fn assert_invoke_sentinel(response: &Value, sentinel: &str) {
    assert!(
        response.get("error").is_none(),
        "signed invoke error: {response}"
    );
    assert_eq!(response["result"]["isError"], false, "{response}");
    assert_eq!(
        wrapped_payload(response)["content"],
        backend_result()["content"],
        "{response}"
    );
    assert_eq!(
        wrapped_payload(response)["content"][0]["text"],
        sentinel,
        "{response}"
    );
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_secs()
}

fn verifier_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/common/signing_verifier.mjs")
}

async fn verify_signed_wire(response: &Value, request_id: &str, nonce: Value) {
    let wire = serde_json::to_string(response).expect("serialize delivered wire object");
    let mut child = tokio::process::Command::new("node")
        .arg(verifier_path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("node is required for the independent signing oracle");
    let mut stdin = child.stdin.take().expect("verifier stdin");
    stdin
        .write_all(
            json!({
                "wire": wire,
                "options": {
                    "key": KEY,
                    "keyId": KEY_ID,
                    "expectedId": {"kind": "string", "value": request_id},
                    "expectedNonce": nonce,
                    "now": now_unix()
                }
            })
            .to_string()
            .as_bytes(),
        )
        .await
        .expect("write verifier stdin");
    drop(stdin);
    let output = tokio::time::timeout(IO_TIMEOUT, child.wait_with_output())
        .await
        .expect("bounded node oracle")
        .expect("node oracle process");
    assert!(
        output.status.success(),
        "oracle failed status={} stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn snapshot_profile_dir() -> (Option<PathBuf>, HashSet<PathBuf>) {
    let Some(raw) = std::env::var_os("LLVM_PROFILE_FILE") else {
        return (None, HashSet::new());
    };
    let pattern = PathBuf::from(&raw);
    let pattern_text = pattern.to_string_lossy();
    assert!(
        pattern_text.contains("%p"),
        "LLVM_PROFILE_FILE must include %p for child attribution: {pattern_text}"
    );
    let dir = pattern
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    (Some(dir.clone()), existing_profraw(&dir))
}

fn existing_profraw(dir: &Path) -> HashSet<PathBuf> {
    let mut paths = HashSet::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return paths;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension() == Some(OsStr::new("profraw")) {
            paths.insert(path);
        }
    }
    paths
}

fn assert_child_profile(dir: Option<&PathBuf>, prior: &HashSet<PathBuf>, pid: u32) {
    let Some(dir) = dir else {
        return;
    };
    let pid_token = pid.to_string();
    let created = existing_profraw(dir)
        .into_iter()
        .filter(|path| !prior.contains(path))
        .filter(|path| {
            path.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|name| {
                    name.split(|c: char| !c.is_ascii_digit())
                        .any(|token| token == pid_token)
                })
        })
        .collect::<Vec<_>>();
    let nonempty = created
        .iter()
        .any(|path| std::fs::metadata(path).is_ok_and(|m| m.len() > 0));
    assert!(
        nonempty,
        "expected nonempty child profraw containing pid {pid} in {} after EOF exit; found {created:?}",
        dir.display()
    );
}

#[tokio::test]
async fn stdio_followup_policy_error_does_not_consume_nonce() {
    let backend = BackendFixture::start(backend_result()).await;
    let mut gateway = StdioGateway::start(fixture_config(&backend.url)).await;
    let nonce = json!("stdio-nonce-policy-refuse");
    let mut refused = invoke(json!("stdio-policy-bad-tool"), nonce.clone(), json!({}));
    refused["params"]["arguments"]["tool"] = json!("bad/tool");
    let response = gateway.call(refused).await;
    assert_eq!(response["id"], "stdio-policy-bad-tool");
    assert_eq!(response["error"]["code"], -32600);
    assert_eq!(
        response["error"]["message"],
        "Tool name 'bad/tool' contains disallowed character '/' (only [A-Za-z0-9_-] is permitted)"
    );
    assert!(response.get("result").is_none());
    assert_eq!(backend.calls().len(), 0);

    let honest = gateway
        .call(invoke(
            json!("stdio-policy-honest"),
            nonce.clone(),
            json!({}),
        ))
        .await;
    assert_invoke_sentinel(&honest, SENTINEL);
    verify_signed_wire(&honest, "stdio-policy-honest", nonce.clone()).await;
    assert_eq!(backend.calls().len(), 1);

    let replay = gateway
        .call(invoke(json!("stdio-policy-replay"), nonce, json!({})))
        .await;
    assert_eq!(replay["error"]["code"], -32001);
    assert_eq!(backend.calls().len(), 1);
    gateway.finish().await;
}

#[tokio::test]
async fn stdio_followup_client_meta_precedence_is_visible_at_backend() {
    let backend = BackendFixture::start(backend_result()).await;
    let mut gateway = StdioGateway::start(fixture_config(&backend.url)).await;
    let payload = json!({"echo": "metadata-payload"});
    let trace_a = "00-11111111111111111111111111111111-2222222222222222-01";
    let trace_b = "00-33333333333333333333333333333333-4444444444444444-01";
    let outer_meta = json!({
        "traceparent": trace_a,
        "prompt_cache_key": "outer-signing-meta",
        "client_only": "must-not-forward"
    });

    let mut outer_only = invoke(
        json!("stdio-meta-outer"),
        json!("stdio-nonce-meta-outer"),
        payload.clone(),
    );
    outer_only["params"]["_meta"] = outer_meta.clone();
    let outer_response = gateway.call(outer_only).await;
    assert_invoke_sentinel(&outer_response, SENTINEL);
    verify_signed_wire(
        &outer_response,
        "stdio-meta-outer",
        json!("stdio-nonce-meta-outer"),
    )
    .await;
    assert_eq!(backend.calls().len(), 1);
    assert_eq!(
        backend.calls()[0]["params"]["_meta"],
        json!({"traceparent": trace_a, "prompt_cache_key": "outer-signing-meta"})
    );
    assert_eq!(backend.calls()[0]["params"]["arguments"], payload);

    let mut inner_wins = invoke(
        json!("stdio-meta-inner"),
        json!("stdio-nonce-meta-inner"),
        payload.clone(),
    );
    inner_wins["params"]["_meta"] = outer_meta.clone();
    inner_wins["params"]["arguments"]["_meta"] = json!({
        "traceparent": trace_b,
        "prompt_cache_key": "inner-signing-meta",
        "client_only": "also-not-forward"
    });
    let inner_response = gateway.call(inner_wins).await;
    assert_invoke_sentinel(&inner_response, SENTINEL);
    verify_signed_wire(
        &inner_response,
        "stdio-meta-inner",
        json!("stdio-nonce-meta-inner"),
    )
    .await;
    assert_eq!(backend.calls().len(), 2);
    assert_eq!(
        backend.calls()[1]["params"]["_meta"],
        json!({"traceparent": trace_b, "prompt_cache_key": "inner-signing-meta"})
    );
    assert_eq!(backend.calls()[1]["params"]["arguments"], payload);

    let mut present_null = invoke(
        json!("stdio-meta-null"),
        json!("stdio-nonce-meta-null"),
        payload.clone(),
    );
    present_null["params"]["_meta"] = outer_meta;
    present_null["params"]["arguments"]["_meta"] = Value::Null;
    let null_response = gateway.call(present_null).await;
    assert_invoke_sentinel(&null_response, SENTINEL);
    verify_signed_wire(
        &null_response,
        "stdio-meta-null",
        json!("stdio-nonce-meta-null"),
    )
    .await;
    assert_eq!(backend.calls().len(), 3);
    let null_meta = &backend.calls()[2]["params"]["_meta"];
    assert!(null_meta.get("traceparent").is_none());
    assert_ne!(
        null_meta.get("prompt_cache_key"),
        Some(&json!("outer-signing-meta"))
    );
    assert_eq!(backend.calls()[2]["params"]["arguments"], payload);
    gateway.finish().await;
}
