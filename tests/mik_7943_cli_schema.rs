// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7943: the CLI entry points check arguments against the tool's input
//! schema as a gateway call does. `cap test` refuses a call that breaks the
//! schema before sending it, and `tool invoke` types `key=value` text by the
//! schema, so `zip=12` for a string property is sent as the string `"12"`.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::process::{Command, Output, Stdio};

fn run(dir: &std::path::Path, args: &[&str]) -> (Output, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_mcp-gateway"))
        .env("HOME", dir)
        .env("USERPROFILE", dir)
        .env("MCP_GATEWAY_TEST_HOME_DIR", dir)
        .env_remove("MCP_GATEWAY_CAPABILITIES")
        .stdin(Stdio::null())
        .args(args)
        .output()
        .expect("run mcp-gateway");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out, text)
}

#[test]
fn cap_test_refuses_a_call_that_breaks_the_schema_before_it_is_sent() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file = dir.path().join("schema_probe.yaml");
    std::fs::write(
        &file,
        "name: schema_probe
description: probe
schema:
  input:
    type: object
    properties:
      id:
        type: string
    required: [id]
providers:
  primary:
    service: rest
    config:
      base_url: https://schema-probe.invalid
      path: /items/{id}
      method: GET
",
    )
    .expect("write capability");
    let path = file.to_string_lossy().into_owned();
    let (out, text) = run(dir.path(), &["cap", "test", &path, "--args", "{}"]);
    assert!(!out.status.success(), "{text}");
    assert!(text.contains("required parameter is missing"), "{text}");
}

#[test]
fn tool_invoke_types_key_value_text_by_the_tool_schema() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        let mut reader = BufReader::new(stream);
        let mut request_line = String::new();
        reader.read_line(&mut request_line).expect("read request");
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).expect("read header") == 0 || line == "\r\n" {
                break;
            }
        }
        let body = r#"{"ok":true}"#;
        write!(
            reader.get_mut(),
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        )
        .expect("respond");
        request_line
    });

    let dir = tempfile::tempdir().expect("tempdir");
    let caps = dir.path().join("caps");
    std::fs::create_dir(&caps).expect("caps dir");
    std::fs::write(
        caps.join("zip_probe.yaml"),
        format!(
            "name: zip_probe
description: probe
schema:
  input:
    type: object
    properties:
      zip:
        type: string
    required: [zip]
providers:
  primary:
    service: rest
    config:
      base_url: http://127.0.0.1:{port}
      path: /zip/{{zip}}
      method: GET
"
        ),
    )
    .expect("write capability");
    let caps = caps.to_string_lossy().into_owned();
    let (out, text) = run(
        dir.path(),
        &["tool", "invoke", "zip_probe", "-C", &caps, "zip=12"],
    );
    assert!(out.status.success(), "a string zip is accepted: {text}");
    let request_line = server.join().expect("server thread");
    assert!(request_line.starts_with("GET /zip/12 "), "{request_line}");
}
