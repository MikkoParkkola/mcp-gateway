// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! SIGNING.2: production `serve --stdio` must wire reload context (and LiveEnv).
//!
//! Current stdio omits `set_reload_context`; HTTP already has it. These tests
//! speak the public CLI/MCP surface only so an unwired process is semantic RED.

#[path = "common/signing_gateway.rs"]
pub mod signing_gateway;

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};
use signing_gateway::{BACKEND, BackendFixture, KEY, child_command, fixture_config, invoke};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::process::{Child, ChildStdin, ChildStdout};

const KEY_ID: &str = "signing-test-current";
const PREVIOUS: &str = "signing-test-previous-key-0123456789abcdef";
const ROTATED: &str = "signing-test-rotated-key-0123456789abcdef";
const ROTATED_PREV: &str = "signing-test-rotated-prev-0123456789abcdef";
const A_SENTINEL: &str = "stdio-reload-backend-a";
const B_SENTINEL: &str = "stdio-reload-backend-b";
const NOT_ENABLED: &str = "Config reload is not enabled on this gateway";
const IO_TIMEOUT: Duration = Duration::from_secs(30);

struct StdioGateway {
    _child: Child,
    _directory: tempfile::TempDir,
    config_path: PathBuf,
    input: ChildStdin,
    output: Lines<BufReader<ChildStdout>>,
}

impl StdioGateway {
    async fn start(config: Value) -> Self {
        let directory = tempfile::tempdir().expect("stdio gateway directory");
        let config_path = directory.path().join("gateway.yaml");
        write_yaml(&config_path, &config);
        let mut command = child_command(directory.path(), &config_path);
        command
            .arg("--stdio")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        let mut child = command.spawn().expect("real stdio gateway process");
        let input = child.stdin.take().expect("gateway stdin");
        let output = BufReader::new(child.stdout.take().expect("gateway stdout")).lines();
        let mut gateway = Self {
            _child: child,
            _directory: directory,
            config_path,
            input,
            output,
        };
        let initialized = gateway
            .call(json!({
                "jsonrpc": "2.0", "id": "stdio-initialize", "method": "initialize", "params": {
                    "protocolVersion": "2025-06-18", "capabilities": {},
                    "clientInfo": {"name": "signing-stdio-reload", "version": "test"}
                }
            }))
            .await;
        assert!(
            initialized.get("result").is_some(),
            "stdio initialize fixture: {initialized}"
        );
        gateway
    }

    fn write_config(&self, config: &Value) {
        write_yaml(&self.config_path, config);
    }

    async fn call(&mut self, request: Value) -> Value {
        self.call_raw(request).await.0
    }

    async fn call_raw(&mut self, request: Value) -> (Value, String) {
        let mut bytes = serde_json::to_vec(&request).expect("serialize stdio request");
        bytes.push(b'\n');
        tokio::time::timeout(IO_TIMEOUT, self.input.write_all(&bytes))
            .await
            .expect("bounded stdio write")
            .expect("write request");
        let wanted = request["id"].clone();
        tokio::time::timeout(IO_TIMEOUT, async {
            loop {
                let line = self
                    .output
                    .next_line()
                    .await
                    .expect("read complete stdio frame")
                    .expect("gateway remains alive");
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
}

fn write_yaml(path: &Path, config: &Value) {
    std::fs::write(path, serde_yaml::to_string(config).expect("config YAML"))
        .expect("write gateway config");
}

fn backend_result(sentinel: &str) -> Value {
    json!({"content": [{"type": "text", "text": sentinel}]})
}

fn with_previous(mut config: Value) -> Value {
    config["security"]["message_signing"]["previous_secret"] = json!(PREVIOUS);
    config
}

fn reload_request(id: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {
        "name": "gateway_reload_config", "arguments": {}
    }})
}

fn wrapped_payload(response: &Value) -> Value {
    serde_json::from_str(
        response["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_else(|| panic!("expected wrapped JSON text: {response}")),
    )
    .unwrap_or_else(|error| panic!("wrapped JSON text: {error}; {response}"))
}

fn assert_invoke_sentinel(response: &Value, sentinel: &str) {
    assert!(
        response.get("error").is_none(),
        "signed invoke error: {response}"
    );
    assert_eq!(response["result"]["isError"], false, "{response}");
    assert_eq!(
        wrapped_payload(response)["content"],
        backend_result(sentinel)["content"],
        "{response}"
    );
}

fn assert_reload_applied(response: &Value) -> Value {
    if let Some(error) = response.get("error") {
        panic!("stdio reload must apply (unwired context returns {NOT_ENABLED:?}): {error}");
    }
    assert_eq!(response["result"]["isError"], false, "{response}");
    let payload = wrapped_payload(response);
    assert_eq!(payload["status"], "ok", "{payload}");
    assert_eq!(payload["restart_required"], false, "{payload}");
    payload
}

fn assert_backend_modified(payload: &Value) {
    let changes = payload["changes"].to_string();
    assert!(
        changes.contains(BACKEND),
        "reload must report a meaningful modified backend, got {changes}"
    );
}

fn assert_restart_refusal(response: &Value, leaked: &[&str]) {
    let error = response
        .get("error")
        .unwrap_or_else(|| panic!("signing reload must JSON-RPC refuse, got {response}"));
    assert_eq!(error["code"], -32603, "{error}");
    let message = error["message"]
        .as_str()
        .unwrap_or_else(|| panic!("reload error message: {error}"));
    assert_ne!(
        message, NOT_ENABLED,
        "unwired stdio reload context is not a signing restart refusal"
    );
    assert!(
        message.to_ascii_lowercase().contains("restart"),
        "safe restart refusal, got {message}"
    );
    for secret in leaked {
        assert!(
            !message.contains(secret),
            "field-only diagnostics leaked {secret}: {message}"
        );
    }
}

fn assert_replay_refused(response: &Value) {
    assert!(
        response.get("error").is_some() || response["result"]["isError"] == true,
        "original nonce must stay reserved: {response}"
    );
}

fn verifier_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/common/signing_verifier.mjs")
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_secs()
}

async fn verify_wire(wire: &str, key: &str, request_id: &str, nonce: &str) {
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
                    "key": key,
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

async fn backends() -> (BackendFixture, BackendFixture) {
    (
        BackendFixture::start(backend_result(A_SENTINEL)).await,
        BackendFixture::start(backend_result(B_SENTINEL)).await,
    )
}

async fn prime_a(gateway: &mut StdioGateway, a: &BackendFixture, id: &str, nonce: &str) -> String {
    let (response, wire) = gateway
        .call_raw(invoke(json!(id), json!(nonce), json!({})))
        .await;
    assert_invoke_sentinel(&response, A_SENTINEL);
    assert_eq!(a.calls().len(), 1, "prime must dispatch once: {response}");
    verify_wire(&wire, KEY, id, nonce).await;
    wire
}

#[tokio::test]
async fn stdio_reload_backend_url_applies_and_preserves_nonce_state() {
    let (a, b) = backends().await;
    let mut gateway = StdioGateway::start(fixture_config(&a.url)).await;
    let nonce = "stdio-reload-ordinary-nonce";
    let _prime = prime_a(&mut gateway, &a, "ordinary-prime", nonce).await;

    let unchanged = assert_reload_applied(&gateway.call(reload_request("reload-unchanged")).await);
    assert_eq!(
        unchanged["restart_required"], false,
        "byte-identical reload stays live: {unchanged}"
    );

    gateway.write_config(&fixture_config(&b.url));
    let reloaded = assert_reload_applied(&gateway.call(reload_request("reload-backend")).await);
    assert_backend_modified(&reloaded);

    let fresh = "stdio-reload-ordinary-fresh";
    let (live, wire) = gateway
        .call_raw(invoke(json!("ordinary-fresh"), json!(fresh), json!({})))
        .await;
    assert_invoke_sentinel(&live, B_SENTINEL);
    assert_eq!(a.calls().len(), 1);
    assert_eq!(b.calls().len(), 1);
    verify_wire(&wire, KEY, "ordinary-fresh", fresh).await;

    let replay = gateway
        .call(invoke(json!("ordinary-replay"), json!(nonce), json!({})))
        .await;
    assert_replay_refused(&replay);
    assert_eq!(a.calls().len(), 1, "replay must not dispatch A: {replay}");
    assert_eq!(b.calls().len(), 1, "replay must not dispatch B: {replay}");
}

async fn refuse_signing_edit(edit: impl FnOnce(&mut Value), leaked: &[&str]) {
    let (a, b) = backends().await;
    let mut gateway = StdioGateway::start(with_previous(fixture_config(&a.url))).await;
    let nonce = "stdio-reload-reserved-nonce";
    let _prime = prime_a(&mut gateway, &a, "signing-prime", nonce).await;

    let mut next = with_previous(fixture_config(&b.url));
    edit(&mut next);
    gateway.write_config(&next);

    let reload = gateway.call(reload_request("reload-signing")).await;
    assert_restart_refusal(&reload, leaked);
    assert_eq!(b.calls().len(), 0, "refused reload must not publish B");

    let fresh = "stdio-reload-signing-fresh";
    let (live, wire) = gateway
        .call_raw(invoke(json!("signing-fresh"), json!(fresh), json!({})))
        .await;
    assert_invoke_sentinel(&live, A_SENTINEL);
    assert_eq!(a.calls().len(), 2);
    assert_eq!(b.calls().len(), 0);
    verify_wire(&wire, KEY, "signing-fresh", fresh).await;

    let replay = gateway
        .call(invoke(json!("signing-replay"), json!(nonce), json!({})))
        .await;
    assert_replay_refused(&replay);
    assert_eq!(a.calls().len(), 2, "replay must not dispatch: {replay}");
    assert_eq!(b.calls().len(), 0);
}

#[tokio::test]
async fn stdio_reload_refuses_enabled_false_keeping_backend_and_key() {
    refuse_signing_edit(
        |config| config["security"]["message_signing"]["enabled"] = json!(false),
        &[KEY, PREVIOUS, ROTATED],
    )
    .await;
}

#[tokio::test]
async fn stdio_reload_refuses_shared_secret_edit_keeping_backend_and_key() {
    refuse_signing_edit(
        |config| config["security"]["message_signing"]["shared_secret"] = json!(ROTATED),
        &[KEY, PREVIOUS, ROTATED],
    )
    .await;
}

#[tokio::test]
async fn stdio_reload_refuses_previous_secret_edit_keeping_backend_and_key() {
    refuse_signing_edit(
        |config| config["security"]["message_signing"]["previous_secret"] = json!(ROTATED),
        &[KEY, PREVIOUS, ROTATED],
    )
    .await;
}

#[tokio::test]
async fn stdio_reload_refuses_require_nonce_false_keeping_backend_and_key() {
    refuse_signing_edit(
        |config| config["security"]["message_signing"]["require_nonce"] = json!(false),
        &[KEY, PREVIOUS, ROTATED],
    )
    .await;
}

#[tokio::test]
async fn stdio_reload_refuses_replay_window_edit_keeping_backend_and_key() {
    refuse_signing_edit(
        |config| config["security"]["message_signing"]["replay_window"] = json!(301),
        &[KEY, PREVIOUS, ROTATED],
    )
    .await;
}

#[tokio::test]
async fn stdio_reload_refuses_key_id_edit_keeping_backend_and_key() {
    refuse_signing_edit(
        |config| {
            config["security"]["message_signing"]["key_id"] = json!("stdio-reload-rotated-key-id")
        },
        &[KEY, PREVIOUS, ROTATED],
    )
    .await;
}

fn unique_suffix(path: &Path) -> String {
    let suffix: String = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if suffix.is_empty() {
        "X".into()
    } else {
        suffix
    }
}

fn write_env(path: &Path, current_name: &str, previous_name: &str, current: &str, previous: &str) {
    std::fs::write(
        path,
        format!("{current_name}='{current}'\n{previous_name}='{previous}'\n"),
    )
    .expect("write env file");
}

#[tokio::test]
async fn stdio_reload_refuses_env_file_key_rotation_then_recovers() {
    let (a, b) = backends().await;
    let env_dir = tempfile::tempdir().expect("env directory");
    let suffix = unique_suffix(env_dir.path());
    let current_name = format!("SIGNING_STDIO_CURRENT_{suffix}");
    let previous_name = format!("SIGNING_STDIO_PREVIOUS_{suffix}");
    for name in [&current_name, &previous_name] {
        assert!(
            std::env::var_os(name).is_none(),
            "fixture names are isolated"
        );
    }
    let env_path = env_dir.path().join("signing.env");
    write_env(&env_path, &current_name, &previous_name, KEY, PREVIOUS);

    let mut config = fixture_config(&a.url);
    config["env_files"] = json!([env_path.display().to_string()]);
    config["security"]["message_signing"]["shared_secret"] = json!(format!("env:{current_name}"));
    config["security"]["message_signing"]["previous_secret"] =
        json!(format!("${{{previous_name}}}"));

    let mut gateway = StdioGateway::start(config.clone()).await;
    let nonce = "stdio-reload-env-nonce";
    let _prime = prime_a(&mut gateway, &a, "env-prime", nonce).await;

    write_env(
        &env_path,
        &current_name,
        &previous_name,
        ROTATED,
        ROTATED_PREV,
    );
    let reload = gateway.call(reload_request("reload-env")).await;
    assert_restart_refusal(&reload, &[KEY, PREVIOUS, ROTATED, ROTATED_PREV]);
    assert_eq!(b.calls().len(), 0);

    let fresh = "stdio-reload-env-fresh";
    let (live, wire) = gateway
        .call_raw(invoke(json!("env-fresh"), json!(fresh), json!({})))
        .await;
    assert_invoke_sentinel(&live, A_SENTINEL);
    assert_eq!(a.calls().len(), 2);
    assert_eq!(b.calls().len(), 0);
    verify_wire(&wire, KEY, "env-fresh", fresh).await;

    let replay = gateway
        .call(invoke(json!("env-replay"), json!(nonce), json!({})))
        .await;
    assert_replay_refused(&replay);
    assert_eq!(a.calls().len(), 2);
    assert_eq!(b.calls().len(), 0);

    write_env(&env_path, &current_name, &previous_name, KEY, PREVIOUS);
    let restored =
        assert_reload_applied(&gateway.call(reload_request("reload-env-restored")).await);
    assert_eq!(restored["restart_required"], false, "{restored}");

    config["backends"][BACKEND]["http_url"] = json!(b.url);
    gateway.write_config(&config);
    let swapped = assert_reload_applied(&gateway.call(reload_request("reload-env-backend")).await);
    assert_backend_modified(&swapped);

    let after = "stdio-reload-env-after";
    let (live, wire) = gateway
        .call_raw(invoke(json!("env-after"), json!(after), json!({})))
        .await;
    assert_invoke_sentinel(&live, B_SENTINEL);
    assert_eq!(b.calls().len(), 1);
    verify_wire(&wire, KEY, "env-after", after).await;
}
