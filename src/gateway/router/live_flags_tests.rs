// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `security.sanitize_input` applies on reload (ADR-023), over HTTP.
//!
//! The flag was copied into the router state at startup, so a reload that
//! changed it had no effect until a restart. Each row here changes it by
//! reload and observes the next call, on the direct route and on `/mcp`
//! `gateway_invoke`. Red until the flag is read from the published config.

use std::sync::atomic::Ordering;

use serde_json::{Value, json};

use super::direct_guards_fixture::{
    Answer, Fx, fixture_built, post_direct, post_meta_invoke, replace_backend_configured,
    sanitizing,
};
use crate::config::{BackendConfig, TransportConfig};

const NUL: &str = "a\u{0}b";
const NUL_REFUSED: &str = "Protocol error: Input contains null bytes which are not allowed";

fn message(body: &Value) -> &str {
    body.pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or_default()
}

fn calls(fx: &Fx) -> usize {
    fx.calls.load(Ordering::SeqCst)
}

/// Apply `edit` to the published config, as a reload would.
fn reload(fx: &Fx, edit: impl FnOnce(&mut crate::config::Config)) {
    let mut config = (*fx.state.live_config.get()).clone();
    edit(&mut config);
    fx.state.live_config.set(config);
}

/// F1 (direct route): started with sanitizing off, a NUL passes; a reload
/// turns it on and the next call is refused with the sanitizer's refusal and
/// nothing runs; a reload turns it off again and the NUL passes again.
#[tokio::test]
async fn f1_direct_sanitize_input_follows_a_reload() {
    let fx = Box::pin(sanitizing(false, fixture_built(Answer::Ok, |meta| meta))).await;

    let (_, body) = post_direct(
        &fx,
        "alpha",
        "k-std",
        "read",
        json!({"cmd": NUL}),
        None,
        None,
    )
    .await;
    assert!(body.get("error").is_none(), "off at start: {body}");
    let ran = calls(&fx);

    reload(&fx, |c| c.security.sanitize_input = true);
    let (_, body) = post_direct(
        &fx,
        "alpha",
        "k-std",
        "read",
        json!({"cmd": NUL}),
        None,
        None,
    )
    .await;
    assert_eq!(message(&body), NUL_REFUSED, "on after reload: {body}");
    assert_eq!(calls(&fx), ran, "on after reload: dispatched");

    reload(&fx, |c| c.security.sanitize_input = false);
    let (_, body) = post_direct(
        &fx,
        "alpha",
        "k-std",
        "read",
        json!({"cmd": NUL}),
        None,
        None,
    )
    .await;
    assert!(body.get("error").is_none(), "off after reload: {body}");
    assert!(
        calls(&fx) > ran,
        "off after reload: nothing reached the backend"
    );
}

/// F1 (`/mcp` `gateway_invoke`): the same through the meta route.
#[tokio::test]
async fn f1_mcp_sanitize_input_follows_a_reload() {
    let fx = Box::pin(sanitizing(false, fixture_built(Answer::Ok, |meta| meta))).await;

    let (_, body) = post_meta_invoke(
        &fx,
        "k-std",
        "alpha",
        "read",
        json!({"cmd": NUL}),
        None,
        None,
    )
    .await;
    assert!(body.get("error").is_none(), "off at start: {body}");
    let ran = calls(&fx);

    reload(&fx, |c| c.security.sanitize_input = true);
    let (_, body) = post_meta_invoke(
        &fx,
        "k-std",
        "alpha",
        "read",
        json!({"cmd": NUL}),
        None,
        None,
    )
    .await;
    assert_eq!(message(&body), NUL_REFUSED, "on after reload: {body}");
    assert_eq!(calls(&fx), ran, "on after reload: dispatched");

    reload(&fx, |c| c.security.sanitize_input = false);
    let (_, body) = post_meta_invoke(
        &fx,
        "k-std",
        "alpha",
        "read",
        json!({"cmd": NUL}),
        None,
        None,
    )
    .await;
    assert!(body.get("error").is_none(), "off after reload: {body}");
    assert!(
        calls(&fx) > ran,
        "off after reload: nothing reached the backend"
    );
}

/// F4: with `trust_configured_backends` off (the fixture's state), a reload
/// that turns `ssrf_protection` on refuses the next call to a backend
/// declared on a loopback address, and nothing runs; turned off again, the
/// call runs.
#[tokio::test]
async fn f4_ssrf_protection_follows_a_reload() {
    let fx = Box::pin(fixture_built(Answer::Ok, |meta| meta)).await;
    let calls = replace_backend_configured(
        &fx,
        "alpha",
        BackendConfig {
            transport: TransportConfig::Http {
                http_url: "http://127.0.0.1:9/mcp".to_string(),
                streamable_http: Some(false),
                protocol_version: None,
            },
            ..BackendConfig::default()
        },
    );
    let call = || post_direct(&fx, "alpha", "k-std", "read", json!({}), None, None);
    reload(&fx, |c| c.security.ssrf_protection = false);
    let (_, body) = call().await;
    assert!(body.get("error").is_none(), "off: {body}");
    let ran = calls.load(Ordering::SeqCst);
    assert!(ran > 0, "off: the call reached the backend");

    reload(&fx, |c| c.security.ssrf_protection = true);
    let (_, body) = call().await;
    // The direct route answers a refused target as absent (it never says
    // why), so the reason is read from the same judgement, on the generation
    // the reload published.
    assert!(
        body.pointer("/result/isError") == Some(&json!(true))
            && body
                .to_string()
                .contains("does not list a tool named `read`"),
        "on after reload: not withheld: {body}"
    );
    let refusal = super::authorization::authorize_tool_target(
        &fx.state,
        &fx.state.live_config.generation(),
        None,
        None,
        None,
        crate::gateway::authz::ToolTarget {
            server: "alpha",
            tool: "read",
            arguments: &json!({}),
        },
    )
    .expect_err("on after reload: the target is admitted");
    assert!(
        refusal
            .message
            .contains(crate::security::ssrf::SSRF_BLOCKED),
        "on after reload: refused, but not by SSRF: {}",
        refusal.message
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        ran,
        "on after reload: dispatched"
    );

    reload(&fx, |c| c.security.ssrf_protection = false);
    let refused_at = calls.load(Ordering::SeqCst);
    let (_, body) = call().await;
    assert!(body.get("error").is_none(), "off after reload: {body}");
    assert_ne!(
        body.pointer("/result/isError"),
        Some(&json!(true)),
        "off after reload: {body}"
    );
    assert!(
        calls.load(Ordering::SeqCst) > refused_at,
        "off after reload: nothing reached the backend"
    );
}

/// F3 (HTTP resume): a task stored while `sanitize_input` was off, resumed
/// after a reload turned it on, is judged by the flag current at resume. Its
/// dirty key is refused by key validation and nothing is sent. Only a live
/// resume can pass: admission, with the flag off, never validated the key.
#[tokio::test]
async fn f3_a_resume_takes_the_flag_current_at_resume() {
    let fx = Box::pin(sanitizing(false, fixture_built(Answer::Ok, |meta| meta))).await;
    reload(&fx, |c| c.security.sanitize_input = true);
    let host = crate::gateway::task_service::host::LiveHost::Http(std::sync::Arc::clone(&fx.state));
    let call = crate::gateway::task_service::TaskCall {
        tool: "gateway_invoke".to_owned(),
        arguments: json!({"ser\u{7}ver": "alpha", "tool": "read", "arguments": {}}),
        surfaced_server: None,
    };
    let caller = crate::gateway::meta_mcp::anonymous_caller();
    let refused = match host
        .readmit(&call, &caller, (None, &host.generation()))
        .await
    {
        Ok((arguments, _)) => panic!("f3: re-admitted as {arguments}"),
        Err(refused) => serde_json::to_value(&*refused).expect("a response serializes"),
    };
    assert!(
        refused.to_string().contains("control characters"),
        "f3: not the key validation's refusal: {refused}"
    );
    assert_eq!(calls(&fx), 0, "f3: dispatched");
}

/// Submit `gateway_invoke alpha read {cmd: NUL}` as a task on `/mcp` and
/// return the last `tasks/get` body once it leaves `working`.
async fn task_with_nul(fx: &Fx, key: &str) -> Value {
    use super::direct_guards_fixture::send_with_headers;
    let modern = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {
            "extensions": {"io.modelcontextprotocol/tasks": {}}
        },
    });
    let mut submit_meta = modern.clone();
    submit_meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!(key);
    let submit = json!({
        "name": "gateway_invoke",
        "arguments": {"server": "alpha", "tool": "read", "arguments": {"cmd": NUL}},
        "task": {},
        "_meta": submit_meta,
    });
    let headers = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "tools/call"),
        ("mcp-name", "gateway_invoke"),
    ];
    let (_, created) =
        send_with_headers(fx, "/mcp", "k-std", "tools/call", submit, None, &headers).await;
    let id = created
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("the submit was refused: {created}"))
        .to_owned();
    let get_headers = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "tasks/get"),
        ("mcp-name", id.as_str()),
    ];
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            let get = json!({"taskId": id, "_meta": modern});
            let (_, body) =
                send_with_headers(fx, "/mcp", "k-std", "tasks/get", get, None, &get_headers).await;
            if body.pointer("/result/status").and_then(Value::as_str) != Some("working") {
                return body;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the task never settled")
}

/// F3 (first dispatch): a task admitted while sanitizing is off, with a
/// reload turning it on before the worker dispatches, is judged by the
/// generation current at dispatch: the NUL is refused and nothing is sent.
/// Admission could not have refused it, so only a live first dispatch passes.
#[tokio::test]
async fn f3_a_first_dispatch_takes_the_flag_current_at_dispatch() {
    let fx = Box::pin(sanitizing(false, fixture_built(Answer::Ok, |meta| meta))).await;
    let live = std::sync::Arc::clone(&fx.state.live_config);
    crate::gateway::meta_mcp::visible::seams::before_task_dispatch(move || {
        live.edit(|c| c.security.sanitize_input = true);
    });
    let got = task_with_nul(&fx, "f3-first").await;
    assert!(
        fx.state.live_config.get().security.sanitize_input,
        "the seam never ran, so this row tested nothing"
    );
    assert!(got.to_string().contains("null bytes"), "{got}");
    assert_eq!(calls(&fx), 0, "dispatched");
}

/// A readmission refused at first dispatch is the gateway's refusal
/// and is tied to its task: the settlement writes the task's record, traced
/// by the task id (the refusal carries no invocation trace of its own).
#[tokio::test]
async fn a_refused_readmission_is_tied_to_its_task() {
    use crate::gateway::router::route_matrix_driver_tests::response::{delivery_rows, temp_log};
    let (_dir, log) = temp_log(None);
    let logged = std::sync::Arc::clone(&log);
    let fx = Box::pin(sanitizing(
        false,
        fixture_built(Answer::Ok, move |mut meta| {
            meta.enable_transparency_log(logged);
            meta
        }),
    ))
    .await;
    let live = std::sync::Arc::clone(&fx.state.live_config);
    crate::gateway::meta_mcp::visible::seams::before_task_dispatch(move || {
        live.edit(|c| c.security.sanitize_input = true);
    });
    let got = task_with_nul(&fx, "taskjoin-readmit").await;
    assert!(got.to_string().contains("null bytes"), "premise: {got}");
    assert_eq!(calls(&fx), 0, "premise: dispatched");
    let task = got
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("no task id: {got}"));
    let _ = delivery_rows(&log).await;
    let entries: Vec<Value> = std::fs::read_to_string(log.path())
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();
    let records: Vec<&Value> = entries
        .iter()
        .filter(|entry| entry["route"] == "task_settlement" && entry["task_id"] == task)
        .collect();
    let [record] = records.as_slice() else {
        panic!("task {task}: one task_settlement record: {entries:#?}");
    };
    assert_eq!(record["response_effect"], "refused", "{record}");
    assert_eq!(record["outcome"], "denied", "{record}");
    // The readmission's protocol refusal, the code the task settles with.
    assert_eq!(record["error_code"], -32600, "{record}");
    assert_eq!(record["server"], "alpha", "{record}");
    assert_eq!(record["tool"], "read", "{record}");
    assert_eq!(record["trace_id"], task, "{record}");
}
