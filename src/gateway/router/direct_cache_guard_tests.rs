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
/// An envelope can still reach a cached answer when playbook interpolation
/// hands it to a step backend (see
/// `an_echoed_envelope_in_the_cache_needs_its_own_arguments_to_replay`); that
/// backend could also return it uncached, so the fix belongs at the
/// interpolation, not in cache ownership (MIK-8323). Mutants: the cache
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

/// MIK-8176 guard (gpt counter-path, lead ruling): a keyed playbook whose
/// second step echoes the first step's envelope E caches that completed
/// answer WITH E, while its declared output omits E, so E's slot is
/// released. The entry replays only for a call presenting the same arguments
/// (the fingerprint covers them): a replay without E misses and serves no
/// envelope. This does NOT make the path safe: a backend handed E by
/// interpolation can return E from its own state, cached or not. That is
/// MIK-8323 (the gateway must not hand a sealed envelope to a backend).
/// Mutant: the fingerprint ignores the arguments.
#[tokio::test]
async fn an_echoed_envelope_in_the_cache_needs_its_own_arguments_to_replay() {
    use super::direct_guards_fixture::fixture_hardened_signed_built;
    let definition: crate::playbook::PlaybookDefinition = serde_json::from_value(json!({
        "playbook": "1.0",
        "name": "ask-echo",
        "description": "the second step echoes the first step's envelope",
        "steps": [
            { "name": "ask", "tool": "read", "server": "alpha", "arguments": {} },
            { "name": "echo", "tool": "read", "server": "alpha",
              "arguments": { "cmd": "$ask.requestState" } }
        ],
        "output": { "type": "object",
                    "properties": { "done": { "path": "$echo.isError", "fallback": false } } }
    }))
    .expect("the echo playbook deserialises");
    let fx = fixture_hardened_signed_built(Answer::AskThenEcho, true, move |meta| {
        let mut engine = crate::playbook::PlaybookEngine::new();
        engine.register(definition);
        meta.set_playbook_engine(engine);
        meta
    })
    .await;
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
    let cached = fx.state.meta_mcp.idempotency_completed_for_test();
    assert!(
        cached.iter().any(|value| carries_envelope(&fx, value)),
        "the echo step's completed answer is cached WITH the envelope: {cached:?} \
         (backend calls {}, params seen {:?}, playbook answer {ran})",
        fx.calls.load(std::sync::atomic::Ordering::SeqCst),
        fx.seen.lock().unwrap()
    );
    let now = crate::protocol::continuation::now_unix_secs();
    let mut held = fx.state.meta_mcp.continuation().in_flight().len(now).await;
    let bound = tokio::time::Instant::now() + crate::test_wait::HANG_BOUND;
    while held != 0 && tokio::time::Instant::now() < bound {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        held = fx
            .state
            .meta_mcp
            .continuation()
            .in_flight()
            .len(crate::protocol::continuation::now_unix_secs())
            .await;
    }
    assert_eq!(held, 0, "the undelivered envelope's slot is released");
    for (n, arguments) in [(2, json!({})), (3, json!({"cmd": "not-the-envelope"}))] {
        let replay = signed_keyed(
            &fx,
            ("/mcp/alpha", "read"),
            json!({"name": "read", "arguments": arguments}),
            ("h3-echo", &format!("h3-echo-n{n}")),
        )
        .await;
        assert!(
            !carries_envelope(&fx, &replay),
            "a replay without the envelope is served none: {replay}"
        );
    }
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
