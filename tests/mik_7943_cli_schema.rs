// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7943: the CLI entry points check arguments against the tool's input
//! schema as a gateway call does. `cap test` refuses a call that breaks the
//! schema before sending it, and `tool invoke` types `key=value` text by the
//! schema, so `kind=12` for a string property is sent as the string `"12"`.

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::process::{Output, Stdio};

fn run(dir: &std::path::Path, args: &[&str]) -> (Output, String) {
    let out = gateway_bin::command(dir, gateway_bin::Inherit::Environment)
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
      base_url: https://127.0.0.1
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

/// The selector must be a string; without the schema, `kind=12` is guessed as
/// the number 12 and `build_url` refuses it. Typed by the schema, it is `"12"`
/// and the call gets past the selector to the egress check, which refuses
/// loopback by default: no request is made and nothing waits on DNS.
#[test]
fn tool_invoke_types_key_value_text_by_the_tool_schema() {
    let dir = tempfile::tempdir().expect("tempdir");
    let caps = dir.path().join("caps");
    std::fs::create_dir(&caps).expect("caps dir");
    std::fs::write(
        caps.join("selector_probe.yaml"),
        "name: selector_probe
description: probe
schema:
  input:
    type: object
    properties:
      kind:
        type: string
        enum: [\"12\"]
        default: \"12\"
providers:
  primary:
    service: rest
    config:
      base_url: https://127.0.0.1
      path_selector:
        parameter: kind
        default: \"12\"
        paths:
          \"12\": /twelve
      method: GET
",
    )
    .expect("write capability");
    let caps = caps.to_string_lossy().into_owned();
    let (out, text) = run(
        dir.path(),
        &["tool", "invoke", "selector_probe", "-C", &caps, "kind=12"],
    );
    assert!(!out.status.success(), "{text}");
    assert!(
        text.contains("SSRF blocked"),
        "the URL was built and reached the egress check: {text}"
    );
}
