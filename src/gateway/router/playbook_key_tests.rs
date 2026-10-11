// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8341: a playbook run under a client's idempotency key runs every step.
//! The key identifies the RUN (its admission replays a retry); each step keeps
//! the key scoped to its own label, so steps never collide on the client's
//! entry, and a step retried inside the run is still served its stored failure
//! (ADR-012). A run carries no continuation, so retry fields on it are refused.
//! Design: handoff/secC-design-8341.md r4.

use std::sync::atomic::Ordering;

use serde_json::{Value, json};

use super::direct_guards_fixture::{Answer, Fx, fixture_hardened_signed_built};
use crate::protocol::mrtr::IDEMPOTENCY_KEY_META;

/// A playbook named `name` whose steps are `alpha/read` with each `cmd`.
fn reads(name: &str, cmds: &[&str], extra: Value) -> crate::playbook::PlaybookDefinition {
    let steps: Vec<Value> = cmds
        .iter()
        .enumerate()
        .map(|(n, cmd)| {
            json!({ "name": format!("s{n}"), "tool": "read", "server": "alpha",
                    "arguments": { "cmd": cmd } })
        })
        .collect();
    let mut definition = json!({ "playbook": "1.0", "name": name,
        "description": "plain steps", "steps": steps });
    if let Value::Object(more) = extra {
        definition.as_object_mut().expect("object").extend(more);
    }
    serde_json::from_value(definition).expect("the playbook deserialises")
}

/// A signed fixture answering `answer`, serving `definitions`.
async fn served(answer: Answer, definitions: Vec<crate::playbook::PlaybookDefinition>) -> Fx {
    fixture_hardened_signed_built(answer, true, move |meta| {
        let mut engine = crate::playbook::PlaybookEngine::new();
        for definition in definitions {
            engine.register(definition);
        }
        meta.set_playbook_engine(engine);
        meta
    })
    .await
}

/// A signed modern `tools/call` of `name` on `path`, keyed when `key` is given,
/// with `extra` merged into its params (retry fields). The whole body.
async fn call(
    fx: &Fx,
    (path, name): (&str, &str),
    mut params: Value,
    (key, nonce): (Option<&str>, &str),
    extra: Value,
) -> Value {
    use crate::gateway::meta_mcp::signing::NONCE_META;
    let mut meta = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {},
        NONCE_META: nonce,
    });
    if let Some(key) = key {
        meta[IDEMPOTENCY_KEY_META] = json!(key);
    }
    params["_meta"] = meta;
    if let Value::Object(more) = extra {
        params.as_object_mut().expect("object").extend(more);
    }
    let headers = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "tools/call"),
        ("mcp-name", name),
    ];
    super::direct_guards_fixture::send_with_headers(
        fx,
        path,
        "k-std",
        "tools/call",
        params,
        None,
        &headers,
    )
    .await
    .1
}

/// Run playbook `name` with `arguments`; the whole body.
async fn run_body(
    fx: &Fx,
    name: &str,
    arguments: Value,
    key: (Option<&str>, &str),
    extra: Value,
) -> Value {
    call(
        fx,
        ("/mcp", "gateway_run_playbook"),
        json!({"name": "gateway_run_playbook",
               "arguments": {"name": name, "arguments": arguments}}),
        key,
        extra,
    )
    .await
}

/// The playbook's report (the JSON text in `content`); a refusal panics with
/// the body, so a 409 names itself.
fn report(body: &Value) -> Value {
    let text = body["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("the run was refused: {body}"));
    serde_json::from_str(text).unwrap_or_else(|_| panic!("no playbook report: {body}"))
}

/// Run `name` and return its report.
async fn run(fx: &Fx, name: &str, key: Option<&str>, nonce: &str) -> Value {
    report(&run_body(fx, name, json!({}), (key, nonce), json!({})).await)
}

/// A direct keyed `alpha/read` with `cmd`; the whole body.
async fn direct(fx: &Fx, cmd: &str, key: &str, nonce: &str) -> Value {
    call(
        fx,
        ("/mcp/alpha", "read"),
        json!({"name": "read", "arguments": {"cmd": cmd}}),
        (Some(key), nonce),
        json!({}),
    )
    .await
}

fn calls(fx: &Fx) -> usize {
    fx.calls.load(Ordering::SeqCst)
}

/// PRK.3a: unkeyed, both steps run (control); keyed, both steps run too. Red
/// on base: the second step reuses the client's entry and is refused 409.
#[tokio::test]
async fn a_keyed_playbook_runs_every_step() {
    let fx = served(Answer::Ok, vec![reads("two", &["one", "two"], json!({}))]).await;
    let unkeyed = run(&fx, "two", None, "pk-n1").await;
    assert_eq!(
        unkeyed["steps_completed"],
        json!(["s0", "s1"]),
        "setup: {unkeyed}"
    );
    let keyed = run(&fx, "two", Some("pk-key"), "pk-n2").await;
    assert_eq!(keyed["steps_completed"], json!(["s0", "s1"]), "{keyed}");
}

/// PRK.3b: a second identical keyed call is the client retrying the run: it
/// gets the run's complete report back and no step is dispatched again.
#[tokio::test]
async fn a_keyed_retry_replays_the_run_without_running_a_step() {
    let fx = served(Answer::Ok, vec![reads("two", &["one", "two"], json!({}))]).await;
    let first = run(&fx, "two", Some("pk-retry"), "pk-r1").await;
    assert_eq!(
        calls(&fx),
        2,
        "setup: the run made one call per step: {first}"
    );
    let again = run(&fx, "two", Some("pk-retry"), "pk-r2").await;
    assert_eq!(again, first, "the retry is not the run's result");
    assert_eq!(calls(&fx), 2, "the retry dispatched a step again");
}

/// PRK.3c (green pin): the same key on a run with different arguments is a
/// reused key, refused like any other, and runs nothing.
#[tokio::test]
async fn a_key_reused_for_another_run_is_refused() {
    let fx = served(Answer::Ok, vec![reads("one", &["one"], json!({}))]).await;
    run(&fx, "one", Some("pk-reuse"), "pk-u1").await;
    let before = calls(&fx);
    let other = run_body(
        &fx,
        "one",
        json!({"x": 1}),
        (Some("pk-reuse"), "pk-u2"),
        json!({}),
    )
    .await;
    // The run admission's own reuse refusal (the run, not a step, owns K).
    assert_eq!(other["error"]["code"], 409, "{other}");
    assert!(
        other["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("belongs to another execution")),
        "a reused key was not refused as a reuse: {other}"
    );
    assert_eq!(calls(&fx), before, "a refused run dispatched a step");
}

/// ID: two steps with IDENTICAL arguments are two calls, both run. Red on
/// base: the second step meets the first step's entry under the client's key.
#[tokio::test]
async fn two_identical_steps_both_run() {
    let fx = served(Answer::Ok, vec![reads("same", &["one", "one"], json!({}))]).await;
    let ran = run(&fx, "same", Some("pk-same"), "pk-i1").await;
    assert_eq!(ran["steps_completed"], json!(["s0", "s1"]), "{ran}");
    assert_eq!(calls(&fx), 2, "the second step was not dispatched");
}

/// PRK.2: no step settles the client's OWN entry: after a keyed run, a direct
/// call under the same key with step 0's exact tool and arguments is not
/// served step 0's answer; it reaches the backend. Red on base: step 0
/// settled the client's entry, so the direct call is served it without a call.
#[tokio::test]
async fn a_step_never_settles_the_clients_own_key() {
    let fx = served(Answer::Ok, vec![reads("one", &["one"], json!({}))]).await;
    run(&fx, "one", Some("pk-own"), "pk-o1").await;
    let before = calls(&fx);
    direct(&fx, "one", "pk-own", "pk-o2").await;
    assert_eq!(
        calls(&fx),
        before + 1,
        "the direct call was served a step's entry"
    );
}

/// ADV (green pin): a client key that spells a step's scope (`K|step:0`) is
/// its own key, never a step's, in both population orders: each call reaches
/// the backend.
#[tokio::test]
async fn a_client_key_spelling_a_step_scope_shares_no_entry() {
    for run_first in [true, false] {
        let fx = served(Answer::Ok, vec![reads("one", &["one"], json!({}))]).await;
        let order = if run_first {
            "run first"
        } else {
            "direct first"
        };
        if run_first {
            run(&fx, "one", Some("pk-adv"), "pk-a1").await;
        }
        let before = calls(&fx);
        direct(&fx, "one", "pk-adv|step:0", "pk-a2").await;
        assert_eq!(
            calls(&fx),
            before + 1,
            "{order}: the direct call was served"
        );
        if !run_first {
            let before = calls(&fx);
            run(&fx, "one", Some("pk-adv"), "pk-a3").await;
            assert_eq!(calls(&fx), before + 1, "{order}: the step was served");
        }
    }
}

/// A transport that answers every `tools/call` Ok WITHOUT a chain receipt and
/// counts the sends: under `signature_chain: Require` each answer is refused
/// after the backend ran (a post-dispatch failure).
struct Unsigned(std::sync::Arc<std::sync::atomic::AtomicUsize>);

#[async_trait::async_trait]
impl crate::transport::Transport for Unsigned {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        let body = if method == "tools/list" {
            json!({"tools": [{"name": "read", "inputSchema": {"type": "object"}}]})
        } else {
            self.0.fetch_add(1, Ordering::SeqCst);
            json!({"content": [{"type": "text", "text": "done"}], "isError": false})
        };
        let id = crate::protocol::RequestId::Number(1);
        Ok(crate::protocol::JsonRpcResponse::success(id, body))
    }
    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        Ok(())
    }
    fn is_connected(&self) -> bool {
        true
    }
    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// ADR12: a keyed run whose one step's backend ran and then failed (a required
/// chain receipt is missing) is retried by the engine (`on_error: retry`), and
/// the retry is served the stored failure instead of running the side effect
/// again: one backend call. Unkeyed control: two. Green at base (the step is
/// keyed on the client's key); red when steps carry no key (mutant m3).
#[tokio::test]
async fn a_retried_step_in_a_keyed_run_is_served_its_stored_failure() {
    use crate::config::{BackendConfig, ChainEmit, ChainMode, FailsafeConfig};
    for (key, want) in [(Some("pk-adr12"), 1), (None, 2)] {
        let definition = serde_json::from_value(json!({
            "playbook": "1.0", "name": "chained", "description": "a refused answer",
            "on_error": "retry", "max_retries": 2,
            "steps": [{"name": "s0", "tool": "read", "server": "alpha-chain",
                       "arguments": {"cmd": "go"}}]
        }))
        .expect("the playbook deserialises");
        let fx = fixture_hardened_signed_built(Answer::Ok, true, move |mut meta| {
            meta.set_chain_signer(
                crate::gateway::chain_test_support::signer(),
                ChainEmit::OnRequest,
            );
            let mut engine = crate::playbook::PlaybookEngine::new();
            engine.register(definition);
            meta.set_playbook_engine(engine);
            meta
        })
        .await;
        let reached = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let backend = std::sync::Arc::new(crate::backend::Backend::new(
            "alpha-chain",
            BackendConfig {
                signature_chain: ChainMode::Require,
                ..BackendConfig::default()
            },
            &FailsafeConfig::default(),
            std::time::Duration::from_secs(60),
        ));
        backend.set_transport_for_test(std::sync::Arc::new(Unsigned(reached.clone())));
        assert!(fx.state.backends.register(backend), "fixture registration");
        let body = run_body(&fx, "chained", json!({}), (key, "pk-c1"), json!({})).await;
        // The step failed for the missing receipt, on every attempt: a
        // different second-attempt refusal would not be a stored replay.
        let failed = report(&body)["step_errors"]["s0"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        assert!(
            failed.contains("signature chain did not verify"),
            "key {key:?}: s0 did not fail for the missing receipt: {body}"
        );
        assert_eq!(
            reached.load(Ordering::SeqCst),
            want,
            "key {key:?}: backend sends for a twice-attempted step: {body}"
        );
    }
}

/// D3a: a run carrying `inputResponses: {}` (no continuation to resume) is
/// refused -32602 with the playbook's own reason and dispatches nothing; the
/// refused request's nonce is refunded (a corrected request reuses it and is
/// served the earlier run's result; mutant m8). Whether a round was reserved
/// is pinned at `admit_meta_sync` itself (m9), not here: the corrected request
/// addresses a different round.
/// Red on base: the retry fields open a new round and re-run the steps.
#[tokio::test]
async fn a_run_carrying_input_responses_is_refused_and_reserves_nothing() {
    let fx = served(Answer::Ok, vec![reads("one", &["one"], json!({}))]).await;
    let first = run(&fx, "one", Some("pk-d3"), "pk-d1").await;
    let before = calls(&fx);
    let refused = run_body(
        &fx,
        "one",
        json!({}),
        (Some("pk-d3"), "pk-d2"),
        json!({"inputResponses": {}}),
    )
    .await;
    assert_eq!(refused["error"]["code"], -32602, "{refused}");
    assert!(
        refused["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("no continuation to resume")),
        "not the playbook's refusal: {refused}"
    );
    assert_eq!(calls(&fx), before, "the refused run dispatched a step");
    let corrected = run_body(&fx, "one", json!({}), (Some("pk-d3"), "pk-d2"), json!({})).await;
    assert_eq!(
        report(&corrected),
        first,
        "the corrected request (same nonce) was not served the run's result"
    );
    assert_eq!(calls(&fx), before, "the honest retry re-ran a step");
}

/// D3b: the same with `requestState: ""` on a sync call. The base control is
/// the generic -32602 continuation routing gives; the row pins the playbook's
/// own reason. Red on base: the generic message.
#[tokio::test]
async fn a_run_carrying_request_state_is_refused_for_the_playbook_reason() {
    let fx = served(Answer::Ok, vec![reads("one", &["one"], json!({}))]).await;
    let refused = run_body(
        &fx,
        "one",
        json!({}),
        (Some("pk-d3b"), "pk-e1"),
        json!({"requestState": ""}),
    )
    .await;
    assert_eq!(refused["error"]["code"], -32602, "{refused}");
    assert!(
        refused["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("no continuation to resume")),
        "not the playbook's refusal: {refused}"
    );
    assert_eq!(calls(&fx), 0, "the refused run dispatched a step");
}
