// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The egress firewall must not serve a seal over pre-redaction
//! bytes. A child of the delivery suite to reuse its backend, both signers,
//! trust set and real finalization path. No configured-value scrub is armed.

use super::*;
use serde_json::Value;

use crate::gateway::gateway_writes::WriteRecord;
use crate::security::firewall::{Firewall, FirewallAction, FirewallConfig, FirewallRule, ScanType};

fn canary() -> String {
    crate::gateway::egress_fixture::secret()
}

/// The credentials-only warning rule permits delivery after the credential
/// redactor rewrites the answer. Redaction is a policy switch, not an action.
fn install_firewall(meta: &mut MetaMcp, redacts: bool) {
    install_firewall_with_scan(meta, redacts, true);
}

fn install_firewall_with_scan(meta: &mut MetaMcp, redacts: bool, scan_responses: bool) {
    let firewall = Firewall::from_config(
        FirewallConfig {
            enabled: true,
            scan_requests: false,
            scan_responses,
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
    delivered_chain_with_scan(redacts, true, &canary()).await
}

async fn delivered_chain_with_scan(redacts: bool, scan_responses: bool, text: &str) -> Value {
    with_minted_receipts(Box::pin(async {
        let mut meta = MetaMcp::new(answering_backend(json!({
            "content": [{"type": "text", "text": text}],
            "isError": false,
        })))
        .with_code_mode(true);
        dual_signed_meta(&mut meta);
        let mut response = meta
            .handle_tools_call(
                RequestId::Number(61),
                "gateway_execute",
                json!({"chain": [
                    {"tool": "remote_docs:search", "arguments": {}},
                    {"tool": "remote_docs:search", "arguments": {}},
                ]}),
                Some("seal-firewall-session"),
                allow_all_ctx_named(Some("alice"), None),
            )
            .await;
        let plain = parsed_answer(response.result.as_ref().expect("a chain answer"));
        for step in chain_steps(&plain) {
            assert!(
                step.to_string().contains(text),
                "premise: the step seal covers the original text"
            );
            assert_sealed_bound(step, "premise: the chain step seal before the firewall");
        }
        // Chain dispatch mints only step receipts. Give this fixture a fresh
        // outer receipt too, so delivery can prove it seals the final bytes.
        let result = response.result.take().expect("the chain result to stamp");
        response.result =
            Some(meta.stamp_direct_result(result, "remote_docs", "search", Some("alice")));
        install_firewall_with_scan(&mut meta, redacts, scan_responses);
        // Finalization consumes the route's policy targets; it does not infer
        // them from the composite answer. Both steps use this same target.
        let targets = [ResponsePolicyTarget::routed("remote_docs", "search")];
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
        assert_no_public_signature(
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
            RequestId::Number(62), "gateway_run_playbook",
            json!({"name": "two_search", "arguments": {}}),
            Some("seal-firewall-session"), allow_all_ctx_named(Some("alice"), None),
        ).await;
        let plain = parsed_answer(response.result.as_ref().expect("a playbook answer"));
        for name in ["first", "second"] {
            let step = &plain["output"][name];
            assert!(step.to_string().contains(&canary()), "premise: the playbook seal covers the plain canary");
            assert_sealed_bound(step, "premise: the playbook step seal before the firewall");
        }
        install_firewall(&mut meta, true);
        let targets = [ResponsePolicyTarget::routed("remote_docs", "search")];
        let delivered = meta.finalize_routed(response,
            &delivery_ctx(&targets, "tools/call", "gateway_run_playbook"), None)
            .result.expect("the firewall delivers the playbook answer");
        let parsed = parsed_answer(&delivered);
        for name in ["first", "second"] {
            let step = &parsed["output"][name];
            assert_redacted(step, "the playbook step seal claim");
            assert_no_public_signature(step, "a playbook step the firewall redacted kept the seal made over its unredacted bytes");
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
            "seal-firewall-trace",
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
    let mut frame = JsonRpcResponse::success(RequestId::Number(63), envelope);
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
                RequestId::Number(64),
                "gateway_invoke",
                invoke_args(),
                Some("seal-firewall-session"),
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
        let targets = [ResponsePolicyTarget::routed("remote_docs", "search")];
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

/// Walk every key, including objects encoded in JSON text, not just receipts
/// in their conventional position.
fn assert_no_public_signature(value: &Value, claim: &str) {
    match value {
        Value::Object(object) => {
            assert!(
                !object.contains_key("public_signature"),
                "{claim}: a public_signature remains: {value}"
            );
            for child in object.values() {
                assert_no_public_signature(child, claim);
            }
        }
        Value::Array(items) => {
            for child in items {
                assert_no_public_signature(child, claim);
            }
        }
        Value::String(text) => {
            if let Ok(inner) = serde_json::from_str::<Value>(text) {
                assert_no_public_signature(&inner, claim);
            } else {
                assert!(
                    !text.contains("public_signature"),
                    "{claim}: unparseable text may retain a seal: {text}"
                );
            }
        }
        _ => {}
    }
}

async fn sealed_result(meta: &MetaMcp) -> (Value, WriteRecord) {
    // A real task stores the creation write record beside its result. Without
    // that record, delivered_wire removes provenance before the firewall sees it.
    let (result, writes) = with_minted_receipts(Box::pin(async {
        crate::gateway::meta_mcp::invoke::relay::collecting(async {
            let result = meta
                .recover_task_result(
                    "remote_docs",
                    "search",
                    None,
                    "seal-firewall",
                    json!({"content": [{"type": "text", "text": canary()}]}),
                )
                .expect("the result settles before the redacting policy is installed");
            (result, crate::gateway::gateway_writes::recorded())
        })
        .await
    }))
    .await;
    assert_sealed_bound(&result, "premise: a real seal covers the original bytes");
    (result, writes)
}

fn completed_task(
    result: &Value,
    writes: WriteRecord,
) -> crate::gateway::task_service::CommittedTask {
    let mut task = crate::protocol::tasks::Task::create("gateway_invoke").expect("a task");
    task.complete(result).expect("the sealed task completes");
    crate::gateway::task_service::CommittedTask {
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
        gateway_writes: writes,
        bindings: Vec::new(),
        bindings_recorded: true,
    }
}

/// A notification's stored-task scan has no request and removes a creation
/// seal before rewriting the stored result for its subscriber.
#[tokio::test]
async fn a_task_notification_the_firewall_redacts_keeps_no_seal() {
    let mut meta = sealing_meta();
    let (original, writes) = sealed_result(&meta).await;
    let stored = completed_task(&original, writes);
    let mut delivered = stored.delivered_wire();
    assert_eq!(
        delivered["result"], original,
        "premise: notification shaping preserves the sealed stored result"
    );
    assert_sealed_bound(
        &delivered["result"],
        "premise: the notification carries its creation seal into the firewall",
    );
    install_firewall(&mut meta, true);
    assert_eq!(
        meta.scan_stored_task(&stored, None, &mut delivered),
        crate::gateway::meta_mcp::invoke::egress::EgressOutcome::Rewritten,
        "the notification scan with no request redacts the stored result"
    );
    assert_redacted(
        &delivered,
        "the task notification redacts its stored result",
    );
    assert_no_public_signature(&delivered, "the task notification keeps no creation seal");
    assert_sealed_bound(
        &original,
        "notification delivery leaves the stored original bound",
    );
}

/// The existing-task branch used by keyed repeats returns the stored answer
/// through delivery egress, which removes its seal before firewall redaction.
#[tokio::test]
async fn a_repeated_keyed_task_the_firewall_redacts_keeps_no_seal() {
    let mut meta = sealing_meta();
    let (original, writes) = sealed_result(&meta).await;
    let stored = completed_task(&original, writes);
    let targets = stored.targets.clone();
    let policy_targets = [ResponsePolicyTarget::routed("remote_docs", "search")];
    install_firewall(&mut meta, true);
    let served = with_minted_receipts(Box::pin(async {
        let caller = allow_all_ctx_named(Some("alice"), None);
        let response = meta
            .defer_or_serve_existing(
                RequestId::Number(71),
                "gateway_invoke",
                &targets,
                crate::gateway::meta_mcp::sealed_hold::Held::new(
                    stored,
                    crate::gateway::meta_mcp::sealed_hold::CarriedHolds::none(),
                ),
                &caller,
            )
            .await;
        let before = response
            .result
            .as_ref()
            .expect("the keyed repeat serves the task");
        assert_eq!(
            before["resultType"],
            json!("task"),
            "the keyed repeat takes the existing-task branch"
        );
        assert_sealed_bound(
            &before["result"],
            "premise: the repeat still carries the creation seal before egress",
        );
        assert_eq!(
            before["result"], original,
            "premise: keyed repeat shaping preserves the sealed stored result"
        );
        meta.finalize_routed(
            response,
            &delivery_ctx(&policy_targets, "tools/call", "gateway_invoke"),
            None,
        )
    }))
    .await;
    let delivered = served.result.expect("the repeated task is delivered");
    assert_redacted(
        &delivered["result"],
        "the keyed repeat redacts its stored result at delivery",
    );
    assert_no_public_signature(&delivered, "the keyed repeat keeps no creation seal");
}

/// Even without a matching credential, a redacting policy pays the documented
/// cost of stripping step seals; the newly minted outer seal stays bound.
#[tokio::test]
async fn a_redacting_policy_that_matches_nothing_still_strips_step_seals() {
    let served = delivered_chain_with_scan(true, true, "ordinary search result").await;
    for step in chain_steps(&parsed_answer(&served)) {
        assert_eq!(
            step["content"][0]["text"],
            json!("ordinary search result"),
            "the nonmatching redactor preserves step text"
        );
        assert_no_public_signature(
            step,
            "a redacting policy strips step seals even without a match",
        );
    }
    assert_sealed_bound(
        &served,
        "the nonmatching redacting policy leaves the fresh outer seal Bound",
    );
}

/// Disabling response scanning also disables the redaction-time strip, even
/// with credential redaction configured and a matching value in each step.
#[tokio::test]
async fn seals_stay_when_response_scanning_is_off() {
    let served = delivered_chain_with_scan(true, false, &canary()).await;
    for step in chain_steps(&parsed_answer(&served)) {
        assert_eq!(
            step["content"][0]["text"],
            json!(canary()),
            "response scanning off leaves the credential untouched"
        );
        assert_sealed_bound(step, "response scanning off keeps each step seal Bound");
    }
}

const UNPARSEABLE_SEAL_TEXT: &str = "{\"public_signature\":";

fn firewall_at<'a>(
    meta: &'a MetaMcp,
    delivery: &'a ResponseDeliveryContext<'a>,
) -> crate::gateway::meta_mcp::invoke::egress::Egress<'a> {
    crate::gateway::meta_mcp::invoke::egress::Egress {
        content: crate::gateway::meta_mcp::invoke::egress::ContentChecks::Dispatched,
        targets: delivery.targets,
        correlation: &delivery.correlation,
        api_key_name: None,
        firewall: meta.firewall.as_deref(),
        generation: None,
    }
}

fn scan_seal_text(
    redact: bool,
) -> (
    crate::gateway::meta_mcp::invoke::egress::EgressOutcome,
    JsonRpcResponse,
) {
    let mut meta = sealing_meta();
    install_firewall(&mut meta, true);
    let value = json!({"content": [
        {"type": "text", "text": UNPARSEABLE_SEAL_TEXT},
        {"type": "text", "text": if redact { canary() } else { "ordinary text".into() }},
    ]});
    let mut frame = JsonRpcResponse::success(RequestId::Number(72), value);
    let targets = [ResponsePolicyTarget::routed("remote_docs", "search")];
    let delivery = delivery_ctx(&targets, "tools/call", "gateway_invoke");
    let outcome = meta.scan_egress(&mut frame, &firewall_at(&meta, &delivery));
    (outcome, frame)
}

/// An incomplete strip alone does not refuse an answer the firewall leaves
/// unchanged: refusal requires an actual rewrite after the strip.
#[tokio::test]
async fn an_unchanged_answer_with_unparseable_seal_text_is_delivered() {
    let (outcome, frame) = scan_seal_text(false);
    assert_eq!(
        outcome,
        crate::gateway::meta_mcp::invoke::egress::EgressOutcome::Delivered,
        "unparseable seal text without a rewrite is delivered"
    );
    let result = frame
        .result
        .expect("the unchanged answer is delivered, not refused");
    assert_eq!(
        result["content"][0]["text"],
        json!(UNPARSEABLE_SEAL_TEXT),
        "the unchanged answer preserves its unparseable seal text"
    );
    assert!(
        frame.error.is_none(),
        "the unchanged answer has no delivery refusal"
    );
}

/// Rewriting any value while seal-naming text remains unparseable replaces
/// the whole answer with the standard delivery refusal.
#[tokio::test]
async fn a_rewritten_answer_with_unparseable_seal_text_is_refused() {
    let (outcome, frame) = scan_seal_text(true);
    assert_eq!(
        outcome,
        crate::gateway::meta_mcp::invoke::egress::EgressOutcome::Refused,
        "a rewrite over unparseable seal text is refused"
    );
    assert!(
        frame.result.is_none(),
        "the refused answer serves no result bytes"
    );
    assert_eq!(
        frame
            .error
            .expect("the rewritten answer is a delivery refusal")
            .message,
        crate::gateway::meta_mcp::invoke::egress::REFUSAL,
        "the rewritten answer uses the standard delivery refusal"
    );
}

#[derive(Clone, Copy, Debug)]
enum RedactionPoint {
    StoredScrub,
    EgressFirewall,
}

#[derive(Clone, Copy, Debug)]
enum SealSite {
    TopLevel,
    StoredTask,
    ChainStep,
    PlaybookStep,
}

impl SealSite {
    fn wrap(self, sealed: Value, writes: &WriteRecord) -> Value {
        match self {
            Self::TopLevel => sealed,
            Self::StoredTask => completed_task(&sealed, writes.clone()).delivered_wire(),
            Self::ChainStep => json!({"content": [{"type": "text", "text":
                json!({"results": [{"result": sealed}]}).to_string()}]}),
            Self::PlaybookStep => json!({"content": [{"type": "text", "text":
                json!({"output": {"first": sealed}}).to_string()}]}),
        }
    }
}

/// Every redaction point strips every seal site, including composite results
/// encoded as JSON text. Exhaustive matches require handling new variants.
#[tokio::test]
async fn every_redaction_point_strips_every_seal_site() {
    use crate::gateway::meta_mcp::invoke::egress::EgressOutcome;
    use crate::security::needles::{NeedleSet, Scrubbed, scrub_stored};

    let mut meta = sealing_meta();
    let (sealed, writes) = sealed_result(&meta).await;
    install_firewall(&mut meta, true);
    for point in [RedactionPoint::StoredScrub, RedactionPoint::EgressFirewall] {
        for site in [
            SealSite::TopLevel,
            SealSite::StoredTask,
            SealSite::ChainStep,
            SealSite::PlaybookStep,
        ] {
            let claim = format!("{point:?} at {site:?} strips every seal before redaction");
            let mut value = site.wrap(sealed.clone(), &writes);
            assert_eq!(
                seals_in(&value).len(),
                1,
                "{claim}: premise: the cell carries one real seal"
            );
            assert_no_stale_seal(
                &value,
                &format!("{claim}: premise: the original seal is Bound"),
            );
            match point {
                RedactionPoint::StoredScrub => {
                    let held = Arc::new(NeedleSet::default());
                    held.insert("remote_docs", &canary());
                    let mut frame = JsonRpcResponse::success(RequestId::Number(73), value);
                    assert_eq!(
                        scrub_stored(&[held], &mut frame),
                        Scrubbed::Redacted,
                        "{claim}: the stored scrub rewrites the held value"
                    );
                    value = frame.result.expect("the scrub delivers the redacted cell");
                    assert!(
                        value.to_string().contains("[redacted]"),
                        "{claim}: the held value is redacted"
                    );
                }
                RedactionPoint::EgressFirewall => {
                    let targets = [ResponsePolicyTarget::routed("remote_docs", "search")];
                    let delivery = delivery_ctx(&targets, "tools/call", "gateway_invoke");
                    assert_eq!(
                        meta.firewall_result(&mut value, &firewall_at(&meta, &delivery)),
                        EgressOutcome::Rewritten,
                        "{claim}: the firewall rewrites the matching value"
                    );
                    assert_redacted(&value, &claim);
                }
            }
            assert!(
                !value.to_string().contains(&canary()),
                "{claim}: no original credential remains"
            );
            assert_no_public_signature(&value, &claim);
        }
    }
}
