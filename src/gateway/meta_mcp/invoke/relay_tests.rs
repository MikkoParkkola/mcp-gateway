// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! COLLUDE.1 §13.3 M12, and the shared outbound builder.

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::{Value, json};

use super::*;
use crate::gateway::authz::AllowAll;
use crate::gateway::meta_mcp::authz_tests::ctx;
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::security::firewall::{
    CollusionAction, CollusionConfig, Firewall, FirewallConfig, RelayCaller,
};

/// Ordinary prose, long enough for several fingerprints.
const PROSE: &str = "The orchard ledger for the north slope records seven rows of late pears, \
    the grafting dates for each rootstock, the hours the drip lines ran during the dry weeks of \
    August, and which crew pruned the older trees after the second frost. It closes with the \
    count of crates sent to the cooperative press and a note about the broken ladder by the barn.";

/// A backend keeping every `tools/call` params it received.
struct Seen(Arc<parking_lot::Mutex<Vec<Value>>>);

#[async_trait::async_trait]
impl crate::transport::Transport for Seen {
    async fn request(&self, method: &str, params: Option<Value>) -> crate::Result<JsonRpcResponse> {
        let id = RequestId::Number(1);
        if method == "tools/list" {
            let tool = json!({"name": "send", "description": "A tool.", "inputSchema": {"type": "object"}});
            return Ok(JsonRpcResponse::success(id, json!({"tools": [tool]})));
        }
        self.0.lock().push(params.unwrap_or(Value::Null));
        let sent = json!({"content": [{"type": "text", "text": "sent"}], "isError": false});
        Ok(JsonRpcResponse::success(id, sent))
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

/// M12: an injected secret is never part of what the relay check reads.
/// The secret here is text another caller was delivered: a check on the
/// post-injection params would refuse the call; the backend still gets it.
#[tokio::test]
async fn relay_audit_has_no_injected_secret() {
    let registry = Arc::new(crate::backend::BackendRegistry::new());
    let backend = Arc::new(crate::backend::Backend::new(
        "alpha",
        crate::config::BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    ));
    let seen = Arc::new(parking_lot::Mutex::new(Vec::new()));
    backend.set_transport_for_test(Arc::new(Seen(Arc::clone(&seen))));
    assert!(registry.register(backend));
    let rule: crate::secret_injection::CredentialRule =
        serde_json::from_value(json!({"name": "token", "value": PROSE, "inject_key": "token"}))
            .expect("rule parses");
    let injector = crate::secret_injection::SecretInjector::new(HashMap::from([(
        "alpha".to_string(),
        vec![rule],
    )]));
    let firewall = Arc::new(Firewall::from_config(
        FirewallConfig {
            rules: serde_yaml::from_str("[{match: \"*\", action: allow}]").unwrap(),
            collusion: CollusionConfig {
                action: CollusionAction::Block,
                sources: vec!["alpha:*".to_string()],
                ..CollusionConfig::default()
            },
            ..FirewallConfig::default()
        },
        None,
    ));
    let mut meta = MetaMcp::new(registry).with_secret_injector(injector);
    meta.set_firewall(Some(Arc::clone(&firewall)));
    let delivered = json!({"content": [{"type": "text", "text": PROSE}]});
    firewall.record_delivery(RelayCaller::Keyed("alice"), "alpha", "send", &delivered);

    let bob = MetaMcpCallerContext {
        caller_key: Some("bob"),
        ..ctx(&AllowAll)
    };
    let call = json!({"server": "alpha", "tool": "send", "arguments": {"text": "hello"}});
    let result = meta.invoke_tool(&call, None, &bob).await;
    assert!(
        result.is_ok(),
        "the injected secret was checked: {result:?}"
    );
    let seen = seen.lock().clone();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(seen[0]["arguments"]["token"], PROSE, "base: injected");
}

/// A value the caller put under a key secret injection overwrites never
/// leaves the gateway, so the relay check does not read it either.
#[tokio::test]
async fn relay_check_skips_a_caller_value_the_injector_overwrites() {
    let registry = Arc::new(crate::backend::BackendRegistry::new());
    let backend = Arc::new(crate::backend::Backend::new(
        "alpha",
        crate::config::BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    ));
    let seen = Arc::new(parking_lot::Mutex::new(Vec::new()));
    backend.set_transport_for_test(Arc::new(Seen(Arc::clone(&seen))));
    assert!(registry.register(backend));
    let rule: crate::secret_injection::CredentialRule = serde_json::from_value(
        json!({"name": "token", "value": "vault-secret", "inject_key": "token"}),
    )
    .expect("rule parses");
    let injector = crate::secret_injection::SecretInjector::new(HashMap::from([(
        "alpha".to_string(),
        vec![rule],
    )]));
    let firewall = Arc::new(Firewall::from_config(
        FirewallConfig {
            rules: serde_yaml::from_str("[{match: \"*\", action: allow}]").unwrap(),
            collusion: CollusionConfig {
                action: CollusionAction::Block,
                sources: vec!["alpha:*".to_string()],
                ..CollusionConfig::default()
            },
            ..FirewallConfig::default()
        },
        None,
    ));
    let mut meta = MetaMcp::new(registry).with_secret_injector(injector);
    meta.set_firewall(Some(Arc::clone(&firewall)));
    let delivered = json!({"content": [{"type": "text", "text": PROSE}]});
    firewall.record_delivery(RelayCaller::Keyed("alice"), "alpha", "send", &delivered);

    let bob = MetaMcpCallerContext {
        caller_key: Some("bob"),
        ..ctx(&AllowAll)
    };
    let call = json!({"server": "alpha", "tool": "send", "arguments": {"token": PROSE}});
    let result = meta.invoke_tool(&call, None, &bob).await;
    assert!(
        result.is_ok(),
        "an overwritten caller value was checked: {result:?}"
    );
    let seen = seen.lock().clone();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(
        seen[0]["arguments"]["token"], "vault-secret",
        "base: overwritten"
    );
}

/// Under `observe` a relay on the meta route is let through and reported: the
/// backend is called, and the audit log holds one digest-only relay finding.
#[tokio::test]
async fn meta_observe_reports_a_relay_and_sends_it() {
    let registry = Arc::new(crate::backend::BackendRegistry::new());
    let backend = Arc::new(crate::backend::Backend::new(
        "alpha",
        crate::config::BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    ));
    let seen = Arc::new(parking_lot::Mutex::new(Vec::new()));
    backend.set_transport_for_test(Arc::new(Seen(Arc::clone(&seen))));
    assert!(registry.register(backend));
    let dir = tempfile::tempdir().expect("tempdir");
    let firewall = Arc::new(Firewall::from_config(
        FirewallConfig {
            rules: serde_yaml::from_str("[{match: \"*\", action: allow}]").unwrap(),
            audit_log: Some(dir.path().join("audit.ndjson")),
            collusion: CollusionConfig {
                action: CollusionAction::Observe,
                sources: vec!["alpha:*".to_string()],
                ..CollusionConfig::default()
            },
            ..FirewallConfig::default()
        },
        None,
    ));
    let mut meta = MetaMcp::new(registry);
    meta.set_firewall(Some(Arc::clone(&firewall)));
    let delivered = json!({"content": [{"type": "text", "text": PROSE}]});
    firewall.record_delivery(RelayCaller::Keyed("alice"), "alpha", "send", &delivered);

    let bob = MetaMcpCallerContext {
        caller_key: Some("bob"),
        ..ctx(&AllowAll)
    };
    let call = json!({"server": "alpha", "tool": "send", "arguments": {"text": PROSE}});
    let result = meta.invoke_tool(&call, None, &bob).await;
    assert!(result.is_ok(), "observe must not refuse: {result:?}");
    assert_eq!(seen.lock().len(), 1, "base: the relay was sent");
    let audit = std::fs::read_to_string(dir.path().join("audit.ndjson")).expect("audited");
    assert_eq!(audit.matches("collusion_relay").count(), 1, "{audit}");
    assert!(!audit.contains("orchard"), "content leaked into the audit");
}

/// MIK-7800: HTTP receipts ride on the response and record only when
/// `emit_http`, the last step, lets it out. A response a later step replaces
/// (the grant slot) is dropped, and its receipts with it.
#[tokio::test]
async fn http_receipts_record_only_when_emit_http_lets_the_answer_out() {
    let firewall = Arc::new(Firewall::from_config(
        FirewallConfig {
            collusion: CollusionConfig {
                action: CollusionAction::Block,
                sources: vec!["alpha:*".to_string()],
                ..CollusionConfig::default()
            },
            ..FirewallConfig::default()
        },
        None,
    ));
    let mut meta = MetaMcp::new(Arc::new(crate::backend::BackendRegistry::new()));
    meta.set_firewall(Some(Arc::clone(&firewall)));
    let meta = Arc::new(meta);
    let deliver = |delivers: bool| {
        let meta = Arc::clone(&meta);
        async move {
            let value = json!({"content": [{"type": "text", "text": PROSE}]});
            meta.stage_relay_receipt(RelayKey::new("alice", true), ("alpha", "send"), &value);
            let answer = if delivers {
                JsonRpcResponse::success(RequestId::Number(1), value)
            } else {
                JsonRpcResponse::error(Some(RequestId::Number(1)), -32000, "refused")
            };
            meta.settle_relay_receipts(&answer);
            axum::Json(json!({"ok": true}))
        }
    };
    let relayed = || {
        let params = json!({"name": "send", "arguments": {"text": PROSE}});
        let verdict = firewall.check_relay(
            RelayCaller::Keyed("bob"),
            "alpha",
            "send",
            &params,
            ("s", "bob"),
        );
        !verdict.allowed
    };

    // Replaced after the dispatch: dropped before `emit_http`.
    drop(
        crate::gateway::meta_mcp::invoke::relay::collecting_http(Arc::clone(&meta), deliver(true))
            .await,
    );
    assert!(!relayed(), "a replaced answer must record no receipt");
    // An answer that is not a delivered result records nothing either.
    let refused =
        crate::gateway::meta_mcp::invoke::relay::collecting_http(Arc::clone(&meta), deliver(false))
            .await;
    crate::gateway::outbound::emit_http(refused, None).await;
    assert!(!relayed(), "an error answer must record no receipt");
    // Out as built: recorded.
    let out =
        crate::gateway::meta_mcp::invoke::relay::collecting_http(Arc::clone(&meta), deliver(true))
            .await;
    crate::gateway::outbound::emit_http(out, None).await;
    assert!(relayed(), "control: a delivered answer records its receipt");
}

/// A second ordinary paragraph, unrelated to [`PROSE`].
const OTHER_PROSE: &str = "Minutes of the harbour committee: the dredging contract moves to the \
    spring tender, the ferry timetable keeps its Sunday gap, and the pilot boat needs a new \
    engine mount before the first autumn gale. Two residents asked about the lighting on the \
    east pier and were told the quote arrives after the council recess.";

/// A meta with a Block-mode relay detector over `alpha:*`.
fn relay_meta() -> (Arc<MetaMcp>, Arc<Firewall>) {
    let firewall = Arc::new(Firewall::from_config(
        FirewallConfig {
            collusion: CollusionConfig {
                action: CollusionAction::Block,
                sources: vec!["alpha:*".to_string()],
                ..CollusionConfig::default()
            },
            ..FirewallConfig::default()
        },
        None,
    ));
    let mut meta = MetaMcp::new(Arc::new(crate::backend::BackendRegistry::new()));
    meta.set_firewall(Some(Arc::clone(&firewall)));
    (Arc::new(meta), firewall)
}

/// Whether `bob` sending `text` through `alpha:send` is refused as a relay.
fn relayed_by_bob(firewall: &Firewall, text: &str) -> bool {
    let params = json!({"name": "send", "arguments": {"text": text}});
    !firewall
        .check_relay(
            RelayCaller::Keyed("bob"),
            "alpha",
            "send",
            &params,
            ("s", "bob"),
        )
        .allowed
}

fn text_result(text: &str) -> Value {
    json!({"content": [{"type": "text", "text": text}]})
}

/// MIK-7887 AC2: a redaction that changes part of a delivered result drops
/// only the text that was removed. The text the caller still got keeps its
/// receipt, so relaying it is still caught.
#[tokio::test]
async fn a_redaction_keeps_the_receipt_for_the_text_still_delivered() {
    let (meta, firewall) = relay_meta();
    let both = text_result(&format!("{PROSE} {OTHER_PROSE}"));
    let delivered = text_result(PROSE);
    let ((), staged) = meta
        .collecting_staged(async {
            meta.stage_relay_receipt(RelayKey::new("alice", true), ("alpha", "send"), &both);
            let snapshot = meta.relay_snapshot(&both);
            meta.restage_if_changed(snapshot, Some(&delivered));
        })
        .await;
    staged.commit(true);
    assert!(
        relayed_by_bob(&firewall, PROSE),
        "delivered text lost its receipt"
    );
    assert!(
        !relayed_by_bob(&firewall, OTHER_PROSE),
        "redacted text kept a receipt"
    );
}

/// MIK-7887: a `gateway_invoke` answer carries the backend value as one
/// pretty-printed text block. Rebuilt from that block as written, multi-line
/// text would be fingerprinted with its newlines escaped, and relaying the
/// lines the caller read would go unmatched.
#[tokio::test]
async fn a_redacted_wrapped_answer_keeps_the_receipt_for_its_lines() {
    let (meta, firewall) = relay_meta();
    // Lines shorter than a fingerprint: every window crosses a newline.
    let lines = PROSE
        .split(' ')
        .collect::<Vec<_>>()
        .chunks(4)
        .map(|words| words.join(" "))
        .collect::<Vec<_>>()
        .join("\n");
    let both = text_result(&format!("{lines}\n{OTHER_PROSE}"));
    let delivered = crate::gateway::meta_mcp_helpers::wrap_tool_success(
        RequestId::Number(1),
        &text_result(&lines),
        false,
    )
    .result
    .expect("a success carries a result");
    let ((), staged) = meta
        .collecting_staged(async {
            meta.stage_relay_receipt(RelayKey::new("alice", true), ("alpha", "send"), &both);
            let snapshot = meta.relay_snapshot(&both);
            meta.restage_if_changed(snapshot, Some(&delivered));
        })
        .await;
    staged.commit(true);
    assert!(
        relayed_by_bob(&firewall, &lines),
        "wrapped lines lost their receipt"
    );
    assert!(
        !relayed_by_bob(&firewall, OTHER_PROSE),
        "redacted text kept a receipt"
    );
}

/// MIK-7887: a native result whose text happens to be JSON keeps its text as
/// delivered in the rebuilt receipt; decoding alone would drop a number in it.
#[tokio::test]
async fn a_native_json_text_keeps_its_numbers_in_the_receipt() {
    let (meta, firewall) = relay_meta();
    // Long enough for several winnowed fingerprints.
    let digits: String = (1000..1050).map(|n: u32| n.to_string()).collect();
    let both = text_result(&format!(r#"{{"n": {digits}, "s": "{OTHER_PROSE}"}}"#));
    let delivered = text_result(&format!(r#"{{"n": {digits}}}"#));
    let ((), staged) = meta
        .collecting_staged(async {
            meta.stage_relay_receipt(RelayKey::new("alice", true), ("alpha", "send"), &both);
            let snapshot = meta.relay_snapshot(&both);
            meta.restage_if_changed(snapshot, Some(&delivered));
        })
        .await;
    staged.commit(true);
    assert!(
        relayed_by_bob(&firewall, &digits),
        "the number lost its receipt"
    );
}

/// MIK-7887: with several staged receipts (a plan) a change cannot be
/// attributed to one of them, so they are dropped, as before.
#[tokio::test]
async fn a_redaction_over_several_receipts_drops_them() {
    let (meta, firewall) = relay_meta();
    let both = text_result(PROSE);
    let ((), staged) = meta
        .collecting_staged(async {
            let alice = RelayKey::new("alice", true);
            meta.stage_relay_receipt(alice, ("alpha", "send"), &both);
            meta.stage_relay_receipt(alice, ("alpha", "other"), &text_result(OTHER_PROSE));
            let snapshot = meta.relay_snapshot(&both);
            meta.restage_if_changed(snapshot, Some(&text_result("changed")));
        })
        .await;
    staged.commit(true);
    assert!(!relayed_by_bob(&firewall, PROSE));
    assert!(!relayed_by_bob(&firewall, OTHER_PROSE));
}

/// MIK-7887: an unchanged result keeps every staged receipt.
#[tokio::test]
async fn an_unchanged_result_keeps_its_receipts() {
    let (meta, firewall) = relay_meta();
    let value = text_result(PROSE);
    let ((), staged) = meta
        .collecting_staged(async {
            meta.stage_relay_receipt(RelayKey::new("alice", true), ("alpha", "send"), &value);
            let snapshot = meta.relay_snapshot(&value);
            meta.restage_if_changed(snapshot, Some(&value.clone()));
        })
        .await;
    staged.commit(true);
    assert!(relayed_by_bob(&firewall, PROSE));
}

/// A stored task, one recorded call, ended as `end` says.
fn stored_task(
    end: impl FnOnce(&mut crate::gateway::task_service::Task),
) -> crate::gateway::task_service::CommittedTask {
    let mut task = crate::gateway::task_service::Task::create("gateway_invoke");
    end(&mut task);
    crate::gateway::task_service::CommittedTask {
        task,
        revision: 1,
        targets: vec![crate::gateway::task_service::Target {
            server: "alpha".to_owned(),
            tool: "send".to_owned(),
        }],
        targets_recorded: true,
        output_free: false,
        owner_digest: String::new(),
    }
}

/// MIK-7887 AC1 (seat review): the error is classified like a pending
/// prompt, so a sensitive one needs no `sources` rule.
#[tokio::test]
async fn a_failed_task_error_is_receipted_by_its_classification() {
    // No `sources` rule: the error is receipted, and it is sensitive only if
    // the classification of its text says so; PROSE is ordinary text, so the
    // control is a non-relay.
    let (meta, firewall) = classified_only_meta();
    let stored = stored_task(|task| {
        task.fail(crate::protocol::JsonRpcError {
            code: -32042,
            message: PROSE.to_owned(),
            data: None,
        });
    });
    let ((), staged) = meta
        .collecting_staged(async {
            meta.stage_stored_receipt(RelayKey::new("alice", true), None, &stored);
        })
        .await;
    staged.commit(true);
    assert!(
        !relayed_by_bob(&firewall, PROSE),
        "ordinary error text is not sensitive without a rule"
    );
}

/// MIK-7887: a task with several recorded targets stages nothing on a read
/// (a plan's result cannot be attributed to one target); the limit is stated
/// in the design doc. A single-target completed read is the control.
#[tokio::test]
async fn reading_a_multi_target_task_stages_no_receipt() {
    for targets in [1usize, 2] {
        let (meta, firewall) = relay_meta();
        let mut stored = stored_task(|task| task.complete(text_result(PROSE)));
        if targets == 2 {
            stored.targets.push(crate::gateway::task_service::Target {
                server: "alpha".to_owned(),
                tool: "other".to_owned(),
            });
        }
        let ((), staged) = meta
            .collecting_staged(async {
                meta.stage_stored_receipt(RelayKey::new("alice", true), None, &stored);
            })
            .await;
        staged.commit(true);
        assert_eq!(relayed_by_bob(&firewall, PROSE), targets == 1, "{targets}");
    }
}

/// MIK-7887 AC1: reading a failed task hands the reader the backend's own
/// error, so the read renews a receipt for it, as a completed task's does. A
/// failure only the gateway wrote (`output_free`) delivers nothing to receipt.
#[tokio::test]
async fn reading_a_failed_task_receipts_the_backend_error() {
    use crate::protocol::JsonRpcError;
    for (output_free, expect_receipt) in [(false, true), (true, false)] {
        let (meta, firewall) = relay_meta();
        let mut stored = stored_task(|task| {
            task.fail(JsonRpcError {
                code: -32042,
                message: PROSE.to_owned(),
                data: None,
            });
        });
        stored.output_free = output_free;
        let ((), staged) = meta
            .collecting_staged(async {
                meta.stage_stored_receipt(RelayKey::new("alice", true), None, &stored);
            })
            .await;
        staged.commit(true);
        assert_eq!(
            relayed_by_bob(&firewall, PROSE),
            expect_receipt,
            "output_free: {output_free}"
        );
    }
}

/// A Block-mode detector with NO `sources` rule: only the classification
/// verdict carried by a result makes it sensitive.
fn classified_only_meta() -> (Arc<MetaMcp>, Arc<Firewall>) {
    let firewall = Arc::new(Firewall::from_config(
        FirewallConfig {
            collusion: CollusionConfig {
                action: CollusionAction::Block,
                ..CollusionConfig::default()
            },
            ..FirewallConfig::default()
        },
        None,
    ));
    let mut meta = MetaMcp::new(Arc::new(crate::backend::BackendRegistry::new()));
    meta.set_firewall(Some(Arc::clone(&firewall)));
    (Arc::new(meta), firewall)
}

/// MIK-7887 (seat review): a rebuild from the redacted copy keeps the
/// sensitivity the original delivery was judged to have, even when the
/// redaction removed the classification marker.
#[tokio::test]
async fn a_redaction_keeps_the_sensitivity_verdict_of_the_delivery() {
    let (meta, firewall) = classified_only_meta();
    let marker = json!({"classification": {"data_classes": ["personal_data"]}});
    let mut classified = text_result(&format!("{PROSE} {OTHER_PROSE}"));
    classified["_context_integrity"] = marker;
    let delivered = text_result(PROSE);
    let ((), staged) = meta
        .collecting_staged(async {
            meta.stage_relay_receipt(RelayKey::new("alice", true), ("alpha", "send"), &classified);
            let snapshot = meta.relay_snapshot(&classified);
            meta.restage_if_changed(snapshot, Some(&delivered));
        })
        .await;
    staged.commit(true);
    assert!(relayed_by_bob(&firewall, PROSE), "the verdict was lost");
}

/// A client channel whose send ends as scripted; `Hang` never answers.
enum Scripted {
    Reply(Result<Value, crate::gateway::input_bridge::DeliveryError>),
    Hang,
}

#[async_trait::async_trait]
impl crate::gateway::input_bridge::ClientChannel for Scripted {
    async fn send_request(
        &self,
        _session_id: &str,
        _id: &str,
        _method: &str,
        _params: Option<Value>,
    ) -> Result<Value, crate::gateway::input_bridge::DeliveryError> {
        match self {
            Self::Reply(reply) => reply.clone(),
            Self::Hang => std::future::pending().await,
        }
    }
}

/// MIK-7887 AC3 (withdrawn as a code change, pinned as behaviour): a bridged
/// prompt is receipted when it is handed to the client channel, before the
/// reply, so a second caller cannot relay it during the wait and a client that
/// never answers (the bridge drops the send at its timeout) was still shown
/// it. The cost, stated in the design doc: a send that finds no session leaves
/// a receipt for a prompt nobody saw.
#[tokio::test]
async fn a_bridged_prompt_is_receipted_at_hand_off() {
    use crate::gateway::input_bridge::{ClientChannel as _, DeliveryError};
    let cases = [
        Scripted::Reply(Ok(json!({"action": "accept"}))),
        Scripted::Reply(Err(DeliveryError::Declined {
            action: "decline".into(),
        })),
        Scripted::Hang,
    ];
    for inner in cases {
        let (meta, firewall) = relay_meta();
        let channel = RecordingChannel {
            inner: &inner,
            meta: &meta,
            who: RelayKey::new("alice", true),
            target: ("alpha", "send"),
            api_key_name: None,
            trace_id: "t",
        };
        let send = channel.send_request(
            "s",
            "1",
            "elicitation/create",
            Some(json!({"message": PROSE})),
        );
        // Dropped at the bridge's timeout, or answered: recorded either way,
        // and already recorded while the reply was pending.
        let _ = tokio::time::timeout(std::time::Duration::from_millis(50), send).await;
        assert!(relayed_by_bob(&firewall, PROSE));
    }
}

/// The relay check and the dispatch read one builder: every field a
/// backend receives beside `arguments` is in it.
#[test]
fn outbound_params_carry_meta_and_retry_fields() {
    let retry = OutboundRetry {
        request_state: Some("state".to_string()),
        input_responses: Some(json!({"k1": {"roots": []}})),
    };
    let inbound = json!({"progressToken": "p-1", "baggage": "k=v", "other": "dropped"});
    let params = outbound_params("send", json!({"a": 1}), Some(&inbound), Some("ck"), &retry);
    assert_eq!(params["name"], "send");
    assert_eq!(params["arguments"]["a"], 1);
    assert_eq!(params["_meta"]["progressToken"], "p-1");
    assert_eq!(params["_meta"]["baggage"], "k=v");
    assert_eq!(params["_meta"]["prompt_cache_key"], "ck");
    assert!(params["_meta"].get("other").is_none(), "{params}");
    assert_eq!(params["requestState"], "state");
    assert_eq!(params["inputResponses"]["k1"]["roots"], json!([]));
}
