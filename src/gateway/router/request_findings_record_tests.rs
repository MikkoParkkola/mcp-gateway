// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What the request scans raised lands in each call's own record: scan type,
//! severity and where, never the text that matched. Rows drive the meta and
//! direct HTTP routes with a planted shell injection and read the record the
//! transparency log holds for the call.

use serde_json::{Value, json};

use super::{Answer, Logged, Route, call_as, fixture, injected, injected_answer, invocations};
use crate::gateway::router::direct_guards_fixture::send;
use crate::security::firewall::FirewallAction;

/// The triple the planted shell injection raises in a call's arguments.
fn shell_hit() -> Value {
    json!({"scan_type": "shell_injection", "severity": "high", "location": "request_args"})
}

/// The live config as the fixture built it, for `call_as` to pin.
fn as_built(fx: &Logged) -> crate::config::Config {
    (*fx.state.live_config.get()).clone()
}

/// `alpha:read` with `args` through `route` under the fixture's own config,
/// boxed as the sibling rows box it (the call's future is large).
async fn sent(fx: &Logged, route: Route, args: Value) -> super::Outcome {
    Box::pin(call_as(fx, (route, args), &as_built(fx), None)).await
}

/// The newest invocation record's decision object.
async fn newest_decision(fx: &Logged) -> Value {
    let rows = invocations(fx).await;
    rows.last().expect("one record at least")["decision"].clone()
}

/// The findings list a decision object carries, panicking when it has none.
fn findings_of(decision: &Value) -> Vec<Value> {
    decision["request_findings"]
        .as_array()
        .unwrap_or_else(|| panic!("a findings list: {decision}"))
        .clone()
}

/// One code-mode step calling the fixture's read tool with `args`.
fn read_step(args: Value) -> Value {
    let mut step = json!({"tool": "alpha:read"});
    step["arguments"] = args;
    step
}

/// An allowed meta call records its planted finding, and the record holds
/// none of the payload's text anywhere.
#[tokio::test(flavor = "current_thread")]
async fn an_allowed_meta_call_records_its_finding_and_no_payload_text() {
    let fx = fixture(Answer::Ok, Some(FirewallAction::Warn)).await;
    let got = sent(&fx, Route::MetaInvoke, injected()).await;
    assert!(
        !got.refused && got.calls == 1,
        "premise, delivered: {got:?}"
    );
    let rows = invocations(&fx).await;
    let record = rows.last().expect("the call's record");
    assert!(
        findings_of(&record["decision"]).contains(&shell_hit()),
        "{record}"
    );
    let text = record.to_string();
    for fragment in ["rm -", "evil.example", "| sh"] {
        assert!(!text.contains(fragment), "{fragment:?} leaked: {text}");
    }
}

/// A call the request scan refuses before the backend keeps the finding that
/// refused it.
#[tokio::test(flavor = "current_thread")]
async fn a_refused_meta_call_records_the_finding_that_refused_it() {
    let fx = fixture(Answer::Ok, Some(FirewallAction::Block)).await;
    let got = sent(&fx, Route::MetaInvoke, injected()).await;
    assert!(got.refused && got.calls == 0, "premise, refused: {got:?}");
    assert_eq!(got.kind, "firewall", "{got:?}");
    assert!(findings_of(&newest_decision(&fx).await).contains(&shell_hit()));
}

/// The direct route's own scan records its planted finding.
#[tokio::test(flavor = "current_thread")]
async fn a_direct_call_records_its_finding() {
    let fx = fixture(Answer::Ok, Some(FirewallAction::Warn)).await;
    let got = sent(&fx, Route::Direct, injected()).await;
    assert!(
        !got.refused && got.calls == 1,
        "premise, delivered: {got:?}"
    );
    assert!(findings_of(&newest_decision(&fx).await).contains(&shell_hit()));
}

/// A retry whose answers alone carry the injection: its own arguments are
/// clean, so its record lists a clean scan, and nothing from the answers.
#[tokio::test(flavor = "current_thread")]
async fn findings_in_answers_stay_out_of_the_record() {
    let fx = fixture(Answer::AskAlways, Some(FirewallAction::Warn)).await;
    let got = sent(&fx, Route::MetaRetry, injected_answer()).await;
    assert!(
        !got.refused && got.calls == 2,
        "premise, delivered: {got:?}"
    );
    assert_eq!(newest_decision(&fx).await["request_findings"], json!([]));
}

/// The same tool twice in one code-mode chain, clean then planted: each
/// step's record lists what its own arguments raised, so the clean step does
/// not take the planted step's finding.
#[tokio::test(flavor = "current_thread")]
async fn each_chain_step_records_only_its_own_findings() {
    let fx = fixture(Answer::Ok, Some(FirewallAction::Warn)).await;
    let before = invocations(&fx).await.len();
    let chain = vec![read_step(json!({"cmd": "x"})), read_step(injected())];
    let call = json!({"name": "gateway_execute", "arguments": {"chain": chain}});
    let reply = send(&fx, "/mcp", "k-std", "tools/call", call, None).await.1;
    let rows = invocations(&fx).await;
    let steps: Vec<&Value> = rows[before..].iter().map(|r| &r["decision"]).collect();
    assert_eq!(steps.len(), 2, "one record per step: {reply}");
    assert_eq!(
        steps[0]["request_findings"],
        json!([]),
        "clean step: {reply}"
    );
    assert!(findings_of(steps[1]).contains(&shell_hit()), "{reply}");
}

/// A queued task carrying the injection: the worker's dispatch scans the
/// arguments it sends, and its one record lists that finding.
#[tokio::test(flavor = "current_thread")]
async fn a_task_run_records_what_its_send_scan_raised() {
    let fx = fixture(Answer::Ok, Some(FirewallAction::Warn)).await;
    let settled = Box::pin(super::task_with(&fx, "findings-task", injected())).await;
    assert!(settled.get("error").is_none(), "premise, ran: {settled}");
    let records = invocations(&fx).await;
    let [worker] = records.as_slice() else {
        panic!("the worker's one record: {records:?}");
    };
    assert!(
        findings_of(&worker["decision"]).contains(&shell_hit()),
        "{worker}"
    );
}

/// Serve one playbook `name` whose single step calls `read` with
/// `step_arguments` as written in the definition.
fn serve_one_step(fx: &Logged, name: &str, step_arguments: Value) {
    let only =
        json!({"name": "only", "server": "alpha", "tool": "read", "arguments": step_arguments});
    let definition =
        json!({"playbook": "1.0", "name": name, "description": "one step", "steps": [only]});
    let mut engine = crate::playbook::PlaybookEngine::new();
    engine.register(serde_json::from_value(definition).expect("a playbook definition"));
    fx.state.meta_mcp.set_playbook_engine(engine);
}

/// Run playbook `name` with `inputs` on `/mcp`; the whole answer.
async fn run_playbook(fx: &Logged, name: &str, inputs: Value) -> Value {
    let run =
        json!({"name": "gateway_run_playbook", "arguments": {"name": name, "arguments": inputs}});
    send(fx, "/mcp", "k-std", "tools/call", run, None).await.1
}

/// A playbook step whose definition takes the injection from the run's
/// inputs: the route stage scans the template, the step's own dispatch
/// scans the filled-in arguments, and the step's record lists that finding.
#[tokio::test(flavor = "current_thread")]
async fn a_playbook_step_records_what_its_filled_in_arguments_raised() {
    let fx = fixture(Answer::Ok, Some(FirewallAction::Warn)).await;
    serve_one_step(&fx, "fill-in", json!({"cmd": "$inputs.cmd"}));
    let before = invocations(&fx).await.len();
    let reply = run_playbook(&fx, "fill-in", injected()).await;
    let rows = invocations(&fx).await;
    let step = rows[before..]
        .iter()
        .find(|r| r["tool"] == "read")
        .unwrap_or_else(|| panic!("the step's record: {reply}"));
    assert!(
        findings_of(&step["decision"]).contains(&shell_hit()),
        "{step}"
    );
}

/// A playbook step whose definition itself carries the injection is
/// refused at the route stage, before any step runs: the refusal's record
/// keeps the finding that refused it.
#[tokio::test(flavor = "current_thread")]
async fn a_playbook_step_refused_at_the_route_stage_records_its_finding() {
    let fx = fixture(Answer::Ok, Some(FirewallAction::Block)).await;
    serve_one_step(&fx, "written-in", injected());
    let before = invocations(&fx).await.len();
    let reply = run_playbook(&fx, "written-in", json!({})).await;
    let rows = invocations(&fx).await;
    let refusal = rows[before..]
        .iter()
        .find(|r| r["decision"]["kind"] == "firewall")
        .unwrap_or_else(|| panic!("a firewall refusal record: {reply}"));
    assert!(
        findings_of(&refusal["decision"]).contains(&shell_hit()),
        "{refusal}"
    );
}
