// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7377.SIGNING.5 nonce discovery schema via real `tools/list`.
//!
//! Wire-level schema only. Admission, signing, metrics, and quota errors are
//! out of this slice. A missing nonce property is the intended red; a fixture
//! that cannot start or list tools is a broken harness, not behavioral evidence.

#[path = "common/signing_gateway.rs"]
pub mod signing_gateway;

use std::collections::BTreeSet;
use std::process::Stdio;
use std::time::Duration;

use serde_json::{Value, json};
use signing_gateway::{BackendFixture, HttpGateway, child_command, fixture_config};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::process::{Child, ChildStdin, ChildStdout};

const IO_TIMEOUT: Duration = Duration::from_secs(30);
const UTF8_BYTE_LIMIT: &str = "at most 256 UTF-8 bytes";

#[derive(Clone, Copy, Debug)]
enum Mode {
    /// `signing.enabled && require_nonce` — nonce must be required.
    Required,
    /// Signing on, nonce optional — property present, not required.
    Optional,
    /// Signing off with dormant `require_nonce: true` — must not require nonce.
    Disabled,
    /// Signing off and `require_nonce: false` — property present, not required.
    DisabledDefault,
}

impl Mode {
    fn label(self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::Optional => "optional",
            Self::Disabled => "disabled",
            Self::DisabledDefault => "disabled-default",
        }
    }

    fn expect_required(self) -> bool {
        matches!(self, Self::Required)
    }

    fn apply(self, config: &mut Value) {
        match self {
            Self::Required => {}
            Self::Optional => {
                config["security"]["message_signing"]["require_nonce"] = json!(false);
            }
            Self::Disabled => {
                config["security"]["message_signing"]["enabled"] = json!(false);
            }
            Self::DisabledDefault => {
                config["security"]["message_signing"]["enabled"] = json!(false);
                config["security"]["message_signing"]["require_nonce"] = json!(false);
            }
        }
    }
}

fn tools_list_request(id: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/list", "params": {}})
}

fn listed_tools(response: &Value) -> &[Value] {
    assert!(
        response.get("error").is_none(),
        "tools/list fixture refused: {response}"
    );
    response["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("tools/list result.tools must be an array: {response}"))
}

fn tool_named<'a>(tools: &'a [Value], name: &str) -> &'a Value {
    tools
        .iter()
        .find(|tool| tool["name"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("{name} missing from tools/list: {tools:?}"))
}

fn required_names(schema: &Value) -> BTreeSet<&str> {
    schema["required"]
        .as_array()
        .unwrap_or_else(|| panic!("inputSchema.required must be an array: {schema}"))
        .iter()
        .map(|name| {
            name.as_str()
                .unwrap_or_else(|| panic!("required entry must be a string: {schema}"))
        })
        .collect()
}

fn assert_nonce_property(schema: &Value, mode: Mode) {
    let properties = schema["properties"]
        .as_object()
        .unwrap_or_else(|| panic!("gateway_invoke properties must be an object: {schema}"));
    for key in ["server", "tool", "arguments"] {
        assert!(
            properties.contains_key(key),
            "SIGNING.5 {mode} must keep {key} on gateway_invoke: {schema}",
            mode = mode.label()
        );
    }
    let nonce = properties.get("nonce").unwrap_or_else(|| {
        panic!(
            "SIGNING.5 {mode} tools/list must advertise gateway_invoke.nonce: {schema}",
            mode = mode.label()
        )
    });
    assert_eq!(
        nonce["type"], "string",
        "SIGNING.5 nonce type must be string: {nonce}"
    );
    assert_eq!(
        nonce["minLength"], 1,
        "SIGNING.5 nonce minLength must be 1: {nonce}"
    );
    assert_eq!(
        nonce["maxLength"], 256,
        "SIGNING.5 nonce maxLength is the 256-character coarse ceiling: {nonce}"
    );
    let description = nonce["description"]
        .as_str()
        .unwrap_or_else(|| panic!("SIGNING.5 nonce description must be a string: {nonce}"));
    assert!(
        description.contains(UTF8_BYTE_LIMIT),
        "SIGNING.5 nonce description must say {UTF8_BYTE_LIMIT} (JSON Schema maxLength counts characters): {nonce}"
    );
}

fn assert_invoke_schema(tools: &[Value], mode: Mode) {
    let schema = &tool_named(tools, "gateway_invoke")["inputSchema"];
    assert_nonce_property(schema, mode);
    let required = required_names(schema);
    assert!(
        required.contains("server") && required.contains("tool"),
        "SIGNING.5 gateway_invoke required must keep server and tool: {schema}"
    );
    if mode.expect_required() {
        assert_eq!(
            required,
            BTreeSet::from(["server", "tool", "nonce"]),
            "SIGNING.5 required mode must list nonce in required: {schema}"
        );
    } else {
        assert_eq!(
            required,
            BTreeSet::from(["server", "tool"]),
            "SIGNING.5 {} mode must not require nonce: {schema}",
            mode.label()
        );
    }
}

fn assert_foreign_tools_lack_nonce(tools: &[Value]) {
    for tool in tools {
        let name = tool["name"].as_str().unwrap_or("");
        if name == "gateway_invoke" {
            continue;
        }
        let schema = &tool["inputSchema"];
        assert!(
            schema.pointer("/properties/nonce").is_none(),
            "SIGNING.5 other tool schemas must not acquire nonce ({name}): {schema}"
        );
        if schema.get("required").is_some() {
            assert!(
                !required_names(schema).contains("nonce"),
                "SIGNING.5 other tool required must not list nonce ({name}): {schema}"
            );
        }
    }
}

fn assert_code_mode_surface(tools: &[Value]) {
    let names: BTreeSet<&str> = tools
        .iter()
        .map(|tool| {
            tool["name"]
                .as_str()
                .unwrap_or_else(|| panic!("code-mode tool name: {tool}"))
        })
        .collect();
    assert_eq!(
        tools.len(),
        2,
        "SIGNING.5 code-mode tools/list must list exactly two tools: {tools:?}"
    );
    assert_eq!(
        names,
        BTreeSet::from(["gateway_search", "gateway_execute"]),
        "SIGNING.5 code-mode tools/list must stay search+execute, no new meta-tool: {tools:?}"
    );
    assert!(
        !names.contains("gateway_invoke"),
        "SIGNING.5 code-mode must not surface gateway_invoke: {tools:?}"
    );
    assert_foreign_tools_lack_nonce(tools);
}

async fn http_tools_list_at(gateway: &HttpGateway, session: &str, path: &str, id: &str) -> Value {
    let response = gateway
        .client
        .post(format!("{}{path}", gateway.url))
        .header("mcp-session-id", session)
        .json(&tools_list_request(json!(id)))
        .send()
        .await
        .expect("gateway HTTP response");
    let status = response.status();
    let body = response.text().await.expect("gateway response body");
    serde_json::from_str(&body)
        .unwrap_or_else(|error| panic!("gateway JSON response ({status}): {error}; body={body}"))
}

struct StdioGateway {
    _child: Child,
    _directory: TempDir,
    input: ChildStdin,
    output: Lines<BufReader<ChildStdout>>,
}

impl StdioGateway {
    async fn start(config: Value) -> Self {
        let directory = tempfile::tempdir().expect("stdio gateway directory");
        let config_path = directory.path().join("gateway.yaml");
        std::fs::write(
            &config_path,
            serde_yaml::to_string(&config).expect("config YAML"),
        )
        .expect("write gateway config");
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
            input,
            output,
        };
        let initialized = gateway
            .call(json!({
                "jsonrpc": "2.0", "id": "stdio-initialize", "method": "initialize", "params": {
                    "protocolVersion": "2025-06-18", "capabilities": {},
                    "clientInfo": {"name": "nonce-schema-stdio", "version": "test"}
                }
            }))
            .await;
        assert!(
            initialized.get("result").is_some(),
            "real stdio initialize succeeds: {initialized}"
        );
        gateway
    }

    async fn call(&mut self, request: Value) -> Value {
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
                    return frame;
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

async fn traditional_http_tools_list(mode: Mode) {
    let backend = BackendFixture::start(json!({"content": []})).await;
    let mut config = fixture_config(&backend.url);
    mode.apply(&mut config);
    let gateway = HttpGateway::start(config).await;
    let session = gateway.initialize().await;
    let response = gateway
        .call(&session, &tools_list_request(json!(mode.label())))
        .await;
    let tools = listed_tools(&response);
    assert_invoke_schema(tools, mode);
    assert_foreign_tools_lack_nonce(tools);
}

async fn traditional_stdio_tools_list(mode: Mode) {
    let backend = BackendFixture::start(json!({"content": []})).await;
    let mut config = fixture_config(&backend.url);
    mode.apply(&mut config);
    let mut gateway = StdioGateway::start(config).await;
    let response = gateway.call(tools_list_request(json!(mode.label()))).await;
    let tools = listed_tools(&response);
    assert_invoke_schema(tools, mode);
    assert_foreign_tools_lack_nonce(tools);
}

#[tokio::test]
async fn http_traditional_nonce_schema_required() {
    traditional_http_tools_list(Mode::Required).await;
}

#[tokio::test]
async fn http_traditional_nonce_schema_optional() {
    traditional_http_tools_list(Mode::Optional).await;
}

#[tokio::test]
async fn http_traditional_nonce_schema_disabled() {
    traditional_http_tools_list(Mode::Disabled).await;
}

#[tokio::test]
async fn http_traditional_nonce_schema_disabled_default() {
    traditional_http_tools_list(Mode::DisabledDefault).await;
}

#[tokio::test]
async fn stdio_traditional_nonce_schema_required() {
    traditional_stdio_tools_list(Mode::Required).await;
}

#[tokio::test]
async fn stdio_traditional_nonce_schema_optional() {
    traditional_stdio_tools_list(Mode::Optional).await;
}

#[tokio::test]
async fn stdio_traditional_nonce_schema_disabled() {
    traditional_stdio_tools_list(Mode::Disabled).await;
}

#[tokio::test]
async fn stdio_traditional_nonce_schema_disabled_default() {
    traditional_stdio_tools_list(Mode::DisabledDefault).await;
}

#[tokio::test]
async fn http_code_mode_schemas_never_gain_nonce() {
    let backend = BackendFixture::start(json!({"content": []})).await;
    let mut config = fixture_config(&backend.url);
    config["code_mode"] = json!({"enabled": true});
    let gateway = HttpGateway::start(config).await;
    let session = gateway.initialize().await;
    let static_list = gateway
        .call(&session, &tools_list_request(json!("code-mode-static")))
        .await;
    assert_code_mode_surface(listed_tools(&static_list));
}

#[tokio::test]
async fn stdio_code_mode_schemas_never_gain_nonce() {
    let backend = BackendFixture::start(json!({"content": []})).await;
    let mut config = fixture_config(&backend.url);
    config["code_mode"] = json!({"enabled": true});
    let mut gateway = StdioGateway::start(config).await;
    let response = gateway
        .call(tools_list_request(json!("stdio-code-mode")))
        .await;
    assert_code_mode_surface(listed_tools(&response));
}

#[tokio::test]
async fn http_url_override_code_mode_does_not_borrow_invoke_nonce() {
    let backend = BackendFixture::start(json!({"content": []})).await;
    let gateway = HttpGateway::start(fixture_config(&backend.url)).await;
    let session = gateway.initialize().await;
    let override_list = http_tools_list_at(
        &gateway,
        &session,
        "/mcp?codemode=search_and_execute",
        "url-override",
    )
    .await;
    assert_code_mode_surface(listed_tools(&override_list));

    let traditional = gateway
        .call(&session, &tools_list_request(json!("traditional-control")))
        .await;
    assert_invoke_schema(listed_tools(&traditional), Mode::Required);
}

#[tokio::test]
async fn http_exposure_filter_does_not_readd_suppressed_tools() {
    let backend = BackendFixture::start(json!({"content": []})).await;
    let mut hide_invoke = fixture_config(&backend.url);
    hide_invoke["meta_mcp"] = json!({
        "exposed_meta_tools": ["gateway_list_servers"]
    });
    let hidden_gateway = HttpGateway::start(hide_invoke).await;
    let hidden_session = hidden_gateway.initialize().await;
    let hidden_response = hidden_gateway
        .call(&hidden_session, &tools_list_request(json!("hide-invoke")))
        .await;
    let hidden = listed_tools(&hidden_response);
    let hidden_names: BTreeSet<&str> = hidden
        .iter()
        .map(|tool| tool["name"].as_str().unwrap_or(""))
        .collect();
    assert_eq!(
        hidden.len(),
        1,
        "SIGNING.5 hiding gateway_invoke must list exactly one tool: {hidden:?}"
    );
    assert_eq!(
        hidden_names,
        BTreeSet::from(["gateway_list_servers"]),
        "SIGNING.5 hiding gateway_invoke must leave it absent: {hidden:?}"
    );
    assert_foreign_tools_lack_nonce(hidden);

    let mut keep_invoke = fixture_config(&backend.url);
    keep_invoke["meta_mcp"] = json!({
        "exposed_meta_tools": ["gateway_invoke", "gateway_list_tools"]
    });
    let gateway = HttpGateway::start(keep_invoke).await;
    let session = gateway.initialize().await;
    let kept_response = gateway
        .call(&session, &tools_list_request(json!("expose-invoke")))
        .await;
    let kept = listed_tools(&kept_response);
    let kept_names: BTreeSet<&str> = kept
        .iter()
        .map(|tool| tool["name"].as_str().unwrap_or(""))
        .collect();
    assert_eq!(
        kept.len(),
        2,
        "SIGNING.5 exposure allow-list must list exactly the named tools: {kept:?}"
    );
    assert_eq!(
        kept_names,
        BTreeSet::from(["gateway_invoke", "gateway_list_tools"]),
        "SIGNING.5 exposure allow-list must not re-add suppressed meta-tools: {kept:?}"
    );
    assert_invoke_schema(kept, Mode::Required);
    assert_foreign_tools_lack_nonce(kept);
}
