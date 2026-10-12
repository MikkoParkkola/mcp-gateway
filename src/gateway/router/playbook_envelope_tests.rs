// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8323: a playbook never hands the gateway's continuation envelope to a
//! backend. The envelope E is a secret between the gateway and the client it
//! was minted for; a later step's arguments must not carry it, in any
//! spelling, to another backend that could keep it and return it later.
//!
//! The oracle never trusts the code under test: each row's playbook hands E
//! to its own client through its declared output (the legitimate hand-off),
//! the row authenticates that E with the keyring, and then asserts no
//! argument any backend received contains E as a substring.

use serde_json::{Value, json};

use super::direct_guards_fixture::{Answer, Fx, envelope_in, fixture_hardened_signed_built};
use crate::protocol::mrtr::IDEMPOTENCY_KEY_META;

/// A playbook `ask` -> `stage(cmd)`, whose `ask` step asks (its result
/// carries E) and whose declared output hands E to its own client.
/// `on_error: continue`, so a refused step still lets the playbook finish and
/// hand E over. The fixture's `read` takes a string `cmd`.
fn definition(stage_cmd: &str) -> crate::playbook::PlaybookDefinition {
    serde_json::from_value(json!({
        "playbook": "1.0",
        "name": "carry",
        "description": "a later step references the asking step's result",
        "on_error": "continue",
        "steps": [
            { "name": "ask", "tool": "read", "server": "alpha", "arguments": {} },
            { "name": "stage", "tool": "read", "server": "alpha",
              "arguments": { "cmd": stage_cmd } }
        ],
        "output": { "type": "object",
                    "properties": { "e": { "path": "$ask.requestState" } } }
    }))
    .expect("the playbook deserialises")
}

/// A fixture serving `definition(stage_cmd)` with `answer`.
async fn fixture(answer: Answer, stage_cmd: &str) -> Fx {
    fixture_with(answer, definition(stage_cmd)).await
}

/// A one-step playbook `stage(cmd)` that only forwards its inputs: its step
/// is the first call to complete under the run's key, so it is dispatched.
fn input_definition(stage_cmd: &str) -> crate::playbook::PlaybookDefinition {
    serde_json::from_value(json!({
        "playbook": "1.0",
        "name": "carry",
        "description": "a step forwards a caller input",
        "steps": [ { "name": "stage", "tool": "read", "server": "alpha",
                     "arguments": { "cmd": stage_cmd } } ]
    }))
    .expect("the playbook deserialises")
}

/// The caller's own envelope: a direct-route call the backend asks on (its
/// first call), authenticated with the keyring.
async fn direct_envelope(fx: &Fx) -> String {
    let asked = signed(
        fx,
        ("/mcp/alpha", "read"),
        json!({"name": "read", "arguments": {}}),
        ("own", "own-n1"),
    )
    .await;
    envelope_in(fx, &asked)
        .unwrap_or_else(|| panic!("setup: the direct call was handed no envelope: {asked}"))
}

/// A fixture serving `definition` with `answer`.
async fn fixture_with(answer: Answer, definition: crate::playbook::PlaybookDefinition) -> Fx {
    fixture_hardened_signed_built(answer, true, move |meta| {
        let mut engine = crate::playbook::PlaybookEngine::new();
        engine.register(definition);
        meta.set_playbook_engine(engine);
        meta
    })
    .await
}

/// Run the playbook on `fx` with `inputs`, returning E authenticated from its
/// own output (the legitimate hand-off).
async fn run_on(fx: &Fx, inputs: Value, key: &str) -> String {
    let ran = signed(
        fx,
        ("/mcp", "gateway_run_playbook"),
        json!({"name": "gateway_run_playbook",
               "arguments": {"name": "carry", "arguments": inputs}}),
        (key, &format!("{key}-n1")),
    )
    .await;
    envelope_in(fx, &ran)
        .unwrap_or_else(|| panic!("setup: the playbook hands its own client no envelope: {ran}"))
}

/// Run the playbook on `fx` with `inputs`, for a run whose own output need
/// carry nothing (the backend asks only on its first call).
async fn run_plain(fx: &Fx, inputs: Value, key: &str) -> Value {
    signed(
        fx,
        ("/mcp", "gateway_run_playbook"),
        json!({"name": "gateway_run_playbook",
               "arguments": {"name": "carry", "arguments": inputs}}),
        (key, &format!("{key}-n1")),
    )
    .await
}

/// A signed, keyed modern `tools/call` of `name` on `path`, as `k-std`.
async fn signed(
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

/// The recorded backend calls whose arguments contain `envelope`.
fn calls_carrying(fx: &Fx, envelope: &str) -> Vec<String> {
    fx.seen
        .lock()
        .unwrap()
        .iter()
        .map(Value::to_string)
        .filter(|params| params.contains(envelope))
        .collect()
}

/// Assert no backend call carried `envelope`, after checking the stage step
/// really was dispatched or refused (the fixture saw the asking call).
fn assert_no_backend_got(fx: &Fx, envelope: &str, case: &str) {
    assert!(
        fx.calls.load(std::sync::atomic::Ordering::SeqCst) >= 1,
        "setup: {case}: the asking step never reached the backend"
    );
    let leaked = calls_carrying(fx, envelope);
    assert!(
        leaked.is_empty(),
        "{case}: a backend received the envelope: {leaked:?}"
    );
}

/// R1 (whole-step form, gpt's sequence): `stage(cmd = "note: $ask")` renders
/// the whole asking step's result, E inside, into another backend call.
/// Red on base: the stage call's arguments contain E.
#[tokio::test]
async fn r1_a_whole_step_reference_hands_no_envelope_to_a_backend() {
    let fx = fixture(Answer::AskThenEcho, "note: $ask").await;
    let envelope = run_on(&fx, json!({}), "r1").await;
    assert_no_backend_got(&fx, &envelope, "r1");
}

/// R2 (gpt's fresh-call variant): a backend that kept what it was handed
/// returns it to a later, fresh call. After the playbook, a fresh direct
/// `get` must be served no envelope. Red on base: stage stored E and the
/// fresh get returns it.
#[tokio::test]
async fn r2_no_later_fresh_call_is_served_an_envelope() {
    let fx = fixture(Answer::AskThenStore, "store note: $ask").await;
    let envelope = run_on(&fx, json!({}), "r2").await;
    let fresh = signed(
        &fx,
        ("/mcp/alpha", "read"),
        json!({"name": "read", "arguments": {"cmd": "get"}}),
        ("r2-fresh", "r2-fresh-n1"),
    )
    .await;
    assert!(
        !fresh.to_string().contains(&envelope),
        "a fresh call was served the envelope a backend kept: {fresh}"
    );
}

/// R3 (glued): `"x$inputs.x"` with `$inputs.x` a raw envelope makes the
/// substituted text glue `x` to E, so only a check made BEFORE substitution
/// sees E whole. Red on base: the stage call carries E.
#[tokio::test]
async fn r3_a_glued_reference_hands_no_envelope_to_a_backend() {
    assert_inputs_forward_none("r3", "x$inputs.x", false).await;
}

/// R9 (the caller's own envelope through `$inputs`, whole): forwarded to no
/// backend. Red on base: the stage call carries E.
#[tokio::test]
async fn r9_an_envelope_in_the_inputs_reaches_no_backend() {
    assert_inputs_forward_none("r9", "$inputs.x", false).await;
}

/// R13 (the caller's own envelope wrapped in input text, `"see " + E`):
/// forwarded to no backend. Red on base: the stage call carries E.
#[tokio::test]
async fn r13_a_wrapped_envelope_in_the_inputs_reaches_no_backend() {
    assert_inputs_forward_none("r13", "note: $inputs.x", true).await;
}

/// Run `input_definition(cmd)` with `$inputs.x` carrying the caller's own E
/// (wrapped in text when `wrap`), and assert no backend call carried E.
async fn assert_inputs_forward_none(case: &str, cmd: &str, wrap: bool) {
    let fx = fixture_with(Answer::AskThenEcho, input_definition(cmd)).await;
    let envelope = direct_envelope(&fx).await;
    let x = if wrap {
        format!("see {envelope}")
    } else {
        envelope.clone()
    };
    let before = fx.seen.lock().unwrap().len();
    let ran = run_plain(&fx, json!({"x": x}), case).await;
    assert!(
        fx.seen.lock().unwrap().len() > before || ran.to_string().contains("refused"),
        "setup: {case}: the stage step was neither dispatched nor refused: {ran}"
    );
    let after: Vec<String> = fx.seen.lock().unwrap()[before..]
        .iter()
        .map(Value::to_string)
        .filter(|params| params.contains(&envelope))
        .collect();
    assert!(
        after.is_empty(),
        "{case}: an input envelope reached a backend: {after:?}"
    );
}

/// R6 (green pin): a playbook's declared OUTPUT may hand E to its own client,
/// and E's slot stays held for that client to redeem (MIK-8176). The load
/// check covers step arguments only; applied to outputs it would refuse this.
#[tokio::test]
async fn r6_the_output_hands_the_envelope_to_its_own_client() {
    let definition = serde_json::from_value(json!({
        "playbook": "1.0",
        "name": "carry",
        "description": "the output hands the envelope to the playbook's client",
        "steps": [ { "name": "ask", "tool": "read", "server": "alpha", "arguments": {} } ],
        "output": { "type": "object",
                    "properties": { "e": { "path": "$ask.requestState" } } }
    }))
    .expect("the playbook deserialises");
    let fx = fixture_with(Answer::AskThenEcho, definition).await;
    let envelope = run_on(&fx, json!({}), "r6").await;
    let now = crate::protocol::continuation::now_unix_secs();
    assert!(
        fx.state
            .meta_mcp
            .continuation()
            .keyring()
            .open_now(&envelope)
            .is_ok(),
        "the delivered envelope does not open"
    );
    assert!(
        fx.state.meta_mcp.continuation().in_flight().len(now).await >= 1,
        "the delivered envelope's slot was released"
    );
}
