// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8176 cache guards: the idempotency cache owns no holds (H3 dropped),
//! and what that rests on. Split from `direct_continuation_tests.rs` to keep
//! both under the 800-line ceiling.

use serde_json::{Value, json};

use super::direct_guards_fixture::{Answer, Fx};
use crate::protocol::mrtr::IDEMPOTENCY_KEY_META;

/// Whether any string in `value` (or in a JSON document a string carries) is
/// an envelope that opens under `fx`'s continuation keyring.
fn carries_envelope(fx: &Fx, value: &Value) -> bool {
    super::direct_guards_fixture::envelope_in(fx, value).is_some()
}

/// A signed, keyed modern `tools/call` of `name` on `path`, as `k-std`.
async fn signed_keyed(
    fx: &Fx,
    (path, name): (&str, &str),
    mut params: Value,
    (key, nonce): (&str, &str),
) -> Value {
    use crate::gateway::meta_mcp::signing::NONCE_META;
    params["_meta"] = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {"elicitation": {"form": {}}},
        NONCE_META: nonce,
        IDEMPOTENCY_KEY_META: key,
    });
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

/// MIK-8176 guard: the idempotency cache keeps no question it is handed
/// directly, so it owns no holds (H3 dropped). Signed and keyed, on every
/// route that reaches the cache:
/// - a delivered top-level question is not final, so `mark_completed_read`
///   refuses it (direct, `gateway_invoke`); the completed answer that follows
///   IS cached (positive control) and carries no envelope;
/// - a completed answer that NESTS a question (a playbook's output) is final,
///   so only routing keeps it out: it is stored by execution admission, never
///   by this cache.
///
/// The other way an envelope could reach a cached answer, playbook
/// interpolation handing it to a step backend, is closed at the interpolation
/// (MIK-8323; see `a_playbook_handing_a_request_state_to_a_step_is_refused`). Mutants: the cache
/// stores non-final answers; a playbook's output is stored in it.
#[tokio::test]
async fn the_idempotency_cache_keeps_no_question_it_was_handed_directly() {
    use super::direct_guards_fixture::{fixture_hardened_signed_built, send_with_headers};
    use crate::gateway::meta_mcp::signing::NONCE_META;
    let mut failures = Vec::new();
    for route in ["direct", "meta", "playbook"] {
        let fx = fixture_hardened_signed_built(Answer::AskOnce, true, |meta| {
            meta.set_playbook_engine(asking_playbook());
            meta
        })
        .await;
        for (n, label) in [(1, "asks"), (2, "completes")] {
            let key = format!("h3-probe-{route}-{n}");
            let nonce = format!("h3-{route}-n{n}");
            let meta = json!({
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {"elicitation": {"form": {}}},
                NONCE_META: nonce,
                IDEMPOTENCY_KEY_META: key,
            });
            let (path, name, params) = match route {
                "direct" => (
                    "/mcp/alpha",
                    "read",
                    json!({"name": "read", "arguments": {}, "_meta": meta}),
                ),
                "meta" => (
                    "/mcp",
                    "gateway_invoke",
                    json!({"name": "gateway_invoke", "_meta": meta,
                           "arguments": {"server": "alpha", "tool": "read", "arguments": {}}}),
                ),
                _ => (
                    "/mcp",
                    "gateway_run_playbook",
                    json!({"name": "gateway_run_playbook", "_meta": meta,
                           "arguments": {"name": "ask-once"}}),
                ),
            };
            let headers = [
                ("mcp-protocol-version", "2026-07-28"),
                ("mcp-method", "tools/call"),
                ("mcp-name", name),
            ];
            let (_, body) =
                send_with_headers(&fx, path, "k-std", "tools/call", params, None, &headers).await;
            let sealed = carries_envelope(&fx, &body);
            if (n == 1) != sealed {
                failures.push(format!(
                    "{route} {label}: want a sealed question only on the first call: {body}"
                ));
            }
        }
        let cached = fx.state.meta_mcp.idempotency_completed_for_test();
        if route != "playbook" && cached.is_empty() {
            failures.push(format!(
                "{route}: the completed answer was not cached (no positive control)"
            ));
        }
        if let Some(value) = cached.iter().find(|value| carries_envelope(&fx, value)) {
            failures.push(format!(
                "{route}: the idempotency cache retains a sealed envelope: {value}"
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// A keyed playbook `ask` -> `echo(cmd)` on `alpha/read`, answering
/// `AskThenEcho`, whose output omits every envelope.
async fn echo_fixture(cmd: &str) -> Fx {
    use super::direct_guards_fixture::fixture_hardened_signed_built;
    let definition: crate::playbook::PlaybookDefinition = serde_json::from_value(json!({
        "playbook": "1.0",
        "name": "ask-echo",
        "description": "the second step echoes its argument",
        "steps": [
            { "name": "ask", "tool": "read", "server": "alpha", "arguments": {} },
            { "name": "echo", "tool": "read", "server": "alpha",
              "arguments": { "cmd": cmd } }
        ],
        "output": { "type": "object",
                    "properties": { "done": { "path": "$echo.isError", "fallback": false } } }
    }))
    .expect("the echo playbook deserialises");
    fixture_hardened_signed_built(Answer::AskThenEcho, true, move |meta| {
        let mut engine = crate::playbook::PlaybookEngine::new();
        engine.register(definition);
        meta.set_playbook_engine(engine);
        meta
    })
    .await
}

/// MIK-8323 D3 (formerly the MIK-8176 leak pin, which asserted the echo step's
/// cached answer carried the envelope E): a playbook whose step argument names
/// `$ask.requestState` is refused before any step runs, naming the step and
/// the reference, so no backend is handed E and nothing caches it.
#[tokio::test]
async fn a_playbook_handing_a_request_state_to_a_step_is_refused() {
    let fx = echo_fixture("$ask.requestState").await;
    let ran = signed_keyed(
        &fx,
        ("/mcp", "gateway_run_playbook"),
        json!({"name": "gateway_run_playbook", "arguments": {"name": "ask-echo"}}),
        ("h3-echo", "h3-echo-n1"),
    )
    .await;
    let text = ran.to_string();
    assert!(
        ran.get("error").is_some() && text.contains("echo") && text.contains("$ask.requestState"),
        "the playbook is refused naming its step and reference: {ran}"
    );
    assert_eq!(
        fx.calls.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "a refused playbook ran a step"
    );
    let cached = fx.state.meta_mcp.idempotency_completed_for_test();
    assert!(
        !cached.iter().any(|value| carries_envelope(&fx, value)),
        "the cache holds an envelope: {cached:?}"
    );
}

/// MIK-8176 guard, moved here from the D3 row with no envelope in it: a keyed
/// playbook whose asking step's envelope is never delivered (its output omits
/// it) completes, and that envelope's slot is released.
#[tokio::test]
async fn a_playbook_ask_steps_undelivered_envelope_releases_its_slot() {
    let fx = echo_fixture("marker-8323").await;
    let minted = || {
        fx.state
            .meta_mcp
            .continuation()
            .keyring()
            .mint_budget_remaining()
    };
    let budget_before = minted();
    let ran = signed_keyed(
        &fx,
        ("/mcp", "gateway_run_playbook"),
        json!({"name": "gateway_run_playbook", "arguments": {"name": "ask-echo"}}),
        ("h3-echo", "h3-echo-n1"),
    )
    .await;
    assert!(
        ran.get("error").is_none() && !carries_envelope(&fx, &ran),
        "the playbook completes and its output omits the envelope: {ran}"
    );
    // gpt c2: without this the release check passes when nothing was minted.
    assert!(
        minted() < budget_before,
        "setup: the asking step minted no envelope: {ran}"
    );
    let held = || async {
        fx.state
            .meta_mcp
            .continuation()
            .in_flight()
            .len(crate::protocol::continuation::now_unix_secs())
            .await
    };
    let bound = tokio::time::Instant::now() + crate::test_wait::HANG_BOUND;
    while held().await != 0 && tokio::time::Instant::now() < bound {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(
        held().await,
        0,
        "the undelivered envelope's slot is released"
    );
}

/// The fingerprint half of the old D3 row, on a keyed DIRECT call so it does
/// not depend on how a playbook's steps use the client's key (MIK-8341): a
/// cached answer replays only for the same arguments. Mutant: the fingerprint
/// ignores the arguments.
#[tokio::test]
async fn a_cached_answer_needs_its_own_arguments_to_replay() {
    use super::direct_guards_fixture::fixture_hardened_signed_built;
    const MARKER: &str = "marker-8323";
    let fx = fixture_hardened_signed_built(Answer::AskThenEcho, true, |meta| meta).await;
    let read = |arguments: Value, nonce: &'static str| {
        let fx = &fx;
        async move {
            signed_keyed(
                fx,
                ("/mcp/alpha", "read"),
                json!({"name": "read", "arguments": arguments}),
                ("fp-key", nonce),
            )
            .await
        }
    };
    // `AskThenEcho` asks on its first call; spend it under another key.
    let asked = signed_keyed(
        &fx,
        ("/mcp/alpha", "read"),
        json!({"name": "read", "arguments": {}}),
        ("fp-ask", "fp-ask-n1"),
    )
    .await;
    assert!(
        carries_envelope(&fx, &asked),
        "setup: the first call asks: {asked}"
    );
    let first = read(json!({"cmd": MARKER}), "fp-n1").await;
    assert!(
        first.to_string().contains(MARKER),
        "setup: the keyed call is answered: {first}"
    );
    for (arguments, nonce) in [(json!({}), "fp-n2"), (json!({"cmd": "other"}), "fp-n3")] {
        let replay = read(arguments, nonce).await;
        assert!(
            !replay.to_string().contains(MARKER),
            "a reuse with other arguments is served the cached answer: {replay}"
        );
    }
    // The control that keeps the misses honest: the same arguments hit. The
    // backend echoes, so the marker alone cannot tell a hit from a fresh call;
    // a hit is the answer with no new backend call.
    let before = fx.calls.load(std::sync::atomic::Ordering::SeqCst);
    let hit = read(json!({"cmd": MARKER}), "fp-n4").await;
    assert!(
        hit.to_string().contains(MARKER)
            && fx.calls.load(std::sync::atomic::Ordering::SeqCst) == before,
        "the same arguments are not served from the cache: {hit}"
    );
}

/// A one-step playbook, `ask-once`, whose step (`alpha/read`) asks once.
fn asking_playbook() -> crate::playbook::PlaybookEngine {
    let definition: crate::playbook::PlaybookDefinition = serde_json::from_value(json!({
        "playbook": "1.0",
        "name": "ask-once",
        "description": "one step whose backend stops to ask",
        "steps": [ { "name": "step", "tool": "read", "server": "alpha", "arguments": {} } ]
    }))
    .expect("the probe playbook deserialises");
    let mut engine = crate::playbook::PlaybookEngine::new();
    engine.register(definition);
    engine
}
