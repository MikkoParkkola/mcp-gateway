// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The egress firewall must not serve a seal over pre-redaction
//! bytes. A child of the delivery suite to reuse its backend, both signers,
//! trust set and real finalization path. No configured-value scrub is armed.

use super::*;
use serde_json::Value;

use crate::security::firewall::{Firewall, FirewallAction, FirewallConfig, FirewallRule, ScanType};

fn canary() -> String {
    crate::gateway::egress_fixture::secret()
}

/// The credentials-only warning rule permits delivery after the credential
/// redactor rewrites the answer. Redaction is a policy switch, not an action.
fn install_firewall(meta: &mut MetaMcp, redacts: bool) {
    let firewall = Firewall::from_config(
        FirewallConfig {
            enabled: true,
            scan_requests: false,
            scan_responses: true,
            credential_redaction: redacts,
            prompt_injection_detection: false,
            rules: vec![FirewallRule {
                tool_match: if redacts { "*" } else { "unrelated_tool" }.into(),
                action: FirewallAction::Warn,
                scan: vec![ScanType::Credentials],
                reason: None,
                servers: None,
                keys: None,
                except: None,
                allowed_roots: None,
                path_args: None,
            }],
            ..FirewallConfig::default()
        },
        None,
    )
    .with_continuations(meta.continuation());
    meta.set_firewall(Some(Arc::new(firewall)));
}

fn sealing_meta() -> MetaMcp {
    let mut meta = MetaMcp::new(answering_backend(json!({
        "content": [{"type": "text", "text": canary()}],
        "isError": false,
    })))
    .with_code_mode(true);
    dual_signed_meta(&mut meta);
    meta
}

fn parsed_answer(result: &Value) -> Value {
    serde_json::from_str(
        result
            .pointer("/content/0/text")
            .and_then(Value::as_str)
            .expect("the sealed composite answer carries JSON text"),
    )
    .expect("the sealed composite answer's text parses")
}

fn chain_steps(answer: &Value) -> Vec<&Value> {
    let results = answer["results"]
        .as_array()
        .expect("the sealed chain carries results");
    assert_eq!(
        results.len(),
        2,
        "the chain seal claim needs two executed steps: {answer}"
    );
    results
        .iter()
        .map(|step| step.get("result").expect("a sealed step result"))
        .collect()
}

fn assert_sealed_bound(result: &Value, claim: &str) {
    let prov = result
        .pointer("/_meta/provenance")
        .unwrap_or_else(|| panic!("{claim}: the sealed result has no receipt: {result}"));
    assert!(
        prov.get("public_signature").is_some(),
        "{claim}: the seal is absent: {result}"
    );
    assert!(
        verify_public(prov, &trust_set(), Some(result))
            .is_ok_and(|verified| verified.status == VerifyStatus::Bound),
        "{claim}: the seal does not verify Bound against the delivered bytes: {result}"
    );
}

/// Every seal with the object it covers, including seals carried as JSON text
/// (the same walk as the stored-answer suite's `seals_in`).
fn seals_in(served: &Value) -> Vec<(Value, Value)> {
    let mut found = Vec::new();
    let mut pending = vec![served];
    while let Some(next) = pending.pop() {
        match next {
            Value::Object(object) => {
                if let Some(prov) = next.pointer("/_meta/provenance")
                    && prov.get("public_signature").is_some()
                {
                    found.push((prov.clone(), next.clone()));
                }
                pending.extend(object.values());
            }
            Value::Array(items) => pending.extend(items),
            Value::String(text) if text.contains("public_signature") => {
                let inner = serde_json::from_str(text).expect("seal-bearing JSON text parses");
                found.extend(seals_in(&inner));
            }
            _ => {}
        }
    }
    found
}

fn assert_redacted(result: &Value, claim: &str) {
    let text = result.to_string();
    assert!(
        !text.contains(&canary()),
        "{claim}: the firewall served the unredacted value: {result}"
    );
    assert!(
        text.contains("[REDACTED:credential]"),
        "{claim}: the firewall did not redact the value: {result}"
    );
}

fn assert_no_stale_seal(result: &Value, claim: &str) {
    let trust = trust_set();
    for (prov, sealed) in seals_in(result) {
        assert!(
            verify_public(&prov, &trust, Some(&sealed))
                .is_ok_and(|verified| verified.status == VerifyStatus::Bound),
            "{claim}: {result}"
        );
    }
}

/// Mint the steps before installing the delivery firewall, so a per-invoke
/// scan cannot erase the canary before the step seal is made. This models a
/// stricter policy at delivery; finalize_routed runs the real egress scan.
async fn delivered_chain(redacts: bool) -> Value {
    with_minted_receipts(Box::pin(async {
        let mut meta = sealing_meta();
        let response = meta
            .handle_tools_call(
                RequestId::Number(9428),
                "gateway_execute",
                json!({"chain": [
                    {"tool": "remote_docs:search", "arguments": {}},
                    {"tool": "remote_docs:search", "arguments": {}},
                ]}),
                Some("session-9428"),
                allow_all_ctx_named(Some("alice"), None),
            )
            .await;
        let plain = parsed_answer(response.result.as_ref().expect("a chain answer"));
        for step in chain_steps(&plain) {
            assert!(
                step.to_string().contains(&canary()),
                "premise: the step seal covers the plain canary"
            );
            assert_sealed_bound(step, "premise: the chain step seal before the firewall");
        }
        install_firewall(&mut meta, redacts);
        let targets = Vec::new();
        meta.finalize_routed(
            response,
            &delivery_ctx(&targets, "tools/call", "gateway_execute"),
            None,
        )
        .result
        .expect("the firewall delivers the sealed chain answer")
    }))
    .await
}

/// A chain's step seals were made before the final firewall rewrote its JSON text.
#[tokio::test]
async fn a_chain_step_the_firewall_redacts_keeps_no_seal() {
    let served = delivered_chain(true).await;
    for step in chain_steps(&parsed_answer(&served)) {
        assert_redacted(step, "the chain step seal claim");
        assert_no_stale_seal(
            step,
            "a step the firewall redacted kept the seal made over its unredacted bytes",
        );
    }
}

/// With no output mapping, each playbook output is the sealed step result itself.
#[tokio::test]
async fn a_playbook_step_the_firewall_redacts_keeps_no_seal() {
    with_minted_receipts(Box::pin(async {
        let mut meta = sealing_meta();
        let definition: crate::playbook::PlaybookDefinition = crate::yaml::from_str(
            r"
name: two_search
description: two searches with no output mapping
on_error: abort
steps:
  - name: first
    server: remote_docs
    tool: search
  - name: second
    server: remote_docs
    tool: search
",
        ).expect("the signed playbook fixture parses");
        let mut engine = crate::playbook::PlaybookEngine::new();
        engine.register(definition);
        meta.set_playbook_engine(engine);
        let response = meta.handle_tools_call(
            RequestId::Number(9429), "gateway_run_playbook",
            json!({"name": "two_search", "arguments": {}}),
            Some("session-9428"), allow_all_ctx_named(Some("alice"), None),
        ).await;
        let plain = parsed_answer(response.result.as_ref().expect("a playbook answer"));
        for name in ["first", "second"] {
            let step = &plain["output"][name];
            assert!(step.to_string().contains(&canary()), "premise: the playbook seal covers the plain canary");
            assert_sealed_bound(step, "premise: the playbook step seal before the firewall");
        }
        install_firewall(&mut meta, true);
        let targets = Vec::new();
        let delivered = meta.finalize_routed(response,
            &delivery_ctx(&targets, "tools/call", "gateway_run_playbook"), None)
            .result.expect("the firewall delivers the playbook answer");
        let parsed = parsed_answer(&delivered);
        for name in ["first", "second"] {
            let step = &parsed["output"][name];
            assert_redacted(step, "the playbook step seal claim");
            assert_no_stale_seal(step, "a playbook step the firewall redacted kept the seal made over its unredacted bytes");
        }
    })).await;
}

/// A task sealed at creation meets a newly redacting firewall at tasks/get.
/// Use the production stored-read scan, then finalize the marked frame just
/// as the route does; no receipt from creation is minted in the read scope.
#[tokio::test]
async fn a_stored_task_the_firewall_redacts_at_read_keeps_no_seal() {
    let mut meta = sealing_meta();
    let stored_result = with_minted_receipts(Box::pin(async {
        meta.recover_task_result(
            "remote_docs",
            "search",
            None,
            "trace-9428",
            json!({"content": [{"type": "text", "text": canary()}]}),
        )
    }))
    .await
    .expect("the plain task result settles");
    assert_sealed_bound(
        &stored_result,
        "premise: the stored task seal before the firewall",
    );
    assert!(
        stored_result.to_string().contains(&canary()),
        "premise: the stored seal covers the plain canary"
    );
    let mut task = crate::protocol::tasks::Task::create("gateway_invoke").expect("a task");
    task.complete(&stored_result)
        .expect("the sealed task completes");
    let stored = crate::gateway::task_service::CommittedTask {
        task,
        revision: 1,
        targets: vec![crate::gateway::task_service::Target {
            server: "remote_docs".into(),
            tool: "search".into(),
        }],
        targets_recorded: true,
        output_free: false,
        error_author: None,
        owner_digest: String::new(),
        gateway_writes: crate::gateway::gateway_writes::WriteRecord::default(),
        bindings: Vec::new(),
        bindings_recorded: true,
    };
    let mut envelope = serde_json::to_value(stored.task.wire()).expect("the stored task wire");
    envelope["resultType"] = json!("complete");
    let mut frame = JsonRpcResponse::success(RequestId::Number(9430), envelope);
    install_firewall(&mut meta, true);
    let served = with_minted_receipts(Box::pin(async {
        meta.scan_task_read(&stored, None, &mut frame);
        let targets = Vec::new();
        meta.finalize_routed(
            frame,
            &delivery_ctx(&targets, "tasks/get", "gateway_invoke"),
            None,
        )
    }))
    .await;
    let envelope = served.result.expect("the stored task is delivered");
    let result = envelope
        .get("result")
        .expect("tasks/get carries the stored result");
    assert_redacted(result, "the stored task seal claim");
    assert_no_stale_seal(
        result,
        "a stored task the firewall redacted at read kept the seal made over its unredacted bytes",
    );
    assert_sealed_bound(
        &stored_result,
        "the original stored seal still covers its original bytes",
    );
}

/// Control: the firewall is on, its rule misses, and no redacting policy
/// applies. A redacting policy would strip seals even when no value matches.
#[tokio::test]
async fn chain_step_seals_stay_bound_with_a_nonmatching_firewall() {
    let served = delivered_chain(false).await;
    for step in chain_steps(&parsed_answer(&served)) {
        assert!(
            step.to_string().contains(&canary()),
            "the unchanged chain step seal covers the original canary"
        );
        assert_sealed_bound(step, "the nonmatching firewall keeps the chain step seal");
    }
}

/// Control: the fresh outer seal is applied after the firewall has rewritten
/// the result, so it authenticates the bytes actually delivered.
#[tokio::test]
async fn the_top_level_seal_is_bound_after_firewall_redaction() {
    with_minted_receipts(Box::pin(async {
        let mut meta = sealing_meta();
        let response = meta
            .handle_tools_call(
                RequestId::Number(9431),
                "gateway_invoke",
                invoke_args(),
                Some("session-9428"),
                allow_all_ctx_named(Some("alice"), None),
            )
            .await;
        let plain = response.result.as_ref().expect("the invoke answer");
        assert!(
            plain.to_string().contains(&canary()),
            "premise: the top-level seal will cover a redacted canary"
        );
        assert!(
            plain.pointer("/_meta/provenance").is_some(),
            "premise: the top-level receipt was minted before delivery"
        );
        assert!(
            plain
                .pointer("/_meta/provenance/public_signature")
                .is_none(),
            "premise: the top-level seal is left for delivery"
        );
        install_firewall(&mut meta, true);
        let targets = Vec::new();
        let served = meta
            .finalize_routed(
                response,
                &delivery_ctx(&targets, "tools/call", "gateway_invoke"),
                None,
            )
            .result
            .expect("the firewall delivers the invoke answer");
        assert_redacted(&served, "the fresh top-level seal covers redacted bytes");
        assert_sealed_bound(&served, "the top-level seal made after firewall redaction");
    }))
    .await;
}
