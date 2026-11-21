// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Signing refusals on stdio leave exactly one invocation record, as on
//! `/mcp`: a replayed nonce names `replay_guard`; a nonce of the wrong shape,
//! two nonces on one call, or none where one is required name `syntax`. The
//! JSON-RPC answer is the one stdio gave before.

use super::*;

/// Where the transparency log of one row lives.
struct Logged {
    meta: Arc<MetaMcp>,
    /// Fails closed; a row may make its appends fail.
    log: Arc<crate::security::TransparencyLogger>,
    path: std::path::PathBuf,
    _dir: Arc<tempfile::TempDir>,
}

/// A stdio Meta-MCP serving `alpha` with signing on: `scope` from the
/// posture, `required` deciding whether a call with no nonce is refused,
/// and a transparency log.
async fn signing_stdio(posture: crate::security::SecurityPosture, required: bool) -> Logged {
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = dir.path().join("audit.jsonl");
    let log_path = path.to_string_lossy().into_owned();
    let counting = Arc::new(Counting {
        calls: Arc::new(AtomicUsize::new(0)),
        answer: json!({"content": [{"type": "text", "text": "ok"}], "isError": false}),
    });
    let log = Arc::new(
        crate::security::TransparencyLogger::open(Arc::new(
            crate::security::transparency_log::TransparencyLogConfig {
                enabled: true,
                path: log_path,
                key_id: "stdio-signing".to_owned(),
                ..Default::default()
            },
        ))
        .expect("the log opens")
        .with_failure_policy(crate::security::audit::AuditFailurePolicy::FailClosed),
    );
    let kept = Arc::clone(&log);
    let meta = stdio_meta(
        move |meta| {
            meta.enable_transparency_log(kept);
            meta.enable_message_signing(
                crate::security::message_signing::MessageSigner::new(
                    b"stdio-signing-records-key-32byte".to_vec(),
                    None,
                    "stdio".to_owned(),
                ),
                Duration::from_secs(300),
                required,
            );
            meta.set_signing_scope(crate::gateway::meta_mcp::signing::SigningScope::of(posture));
        },
        counting,
    )
    .await;
    Logged {
        meta,
        log,
        path,
        _dir: dir,
    }
}

/// The invocation records in the row's log, oldest first.
fn invocation_records(logged: &Logged) -> Vec<Value> {
    std::fs::read_to_string(&logged.path)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|entry| entry.get("request_hash").is_some())
        .collect()
}

/// `gateway_invoke alpha read` whose `_meta` is `meta`, and whose own
/// arguments carry `argument_nonce` when given.
fn invoke_params(meta: Value, argument_nonce: Option<&str>) -> Value {
    let mut params = invoke_read(&json!({}));
    if let Some(nonce) = argument_nonce {
        params["arguments"]["nonce"] = json!(nonce);
    }
    params["_meta"] = meta;
    params
}

/// The `_meta` member carrying `nonce` as the signing nonce.
fn with_nonce(nonce: &str) -> Value {
    json!({ (crate::gateway::meta_mcp::signing::NONCE_META): nonce })
}

/// The fields every recorded stdio signing refusal shares.
fn assert_refusal_record(record: &Value, outcome: &str, code: i64, kind: &str) {
    assert_eq!(record["route"], "meta", "{record}");
    assert_eq!(record["server"], "alpha", "{record}");
    assert_eq!(record["tool"], "read", "{record}");
    assert_eq!(record["outcome"], outcome, "{record}");
    assert_eq!(record["error_code"], code, "{record}");
    assert_eq!(record["decision"]["kind"], kind, "{record}");
    assert_eq!(record["decision"]["decided"], "fresh", "{record}");
}

/// The single record of a call refused before anything was delivered.
fn sole_record(logged: &Logged, answer: &Value) -> Value {
    let all = invocation_records(logged);
    let [record] = all.as_slice() else {
        panic!("exactly one invocation record: {all:?}; answer {answer}");
    };
    record.clone()
}

/// T2: the same nonce twice on stdio; the replay's record names
/// `replay_guard`, beside the first call's own record.
#[tokio::test]
async fn t2_stdio_a_replayed_nonce_records_replay_guard() {
    let logged = signing_stdio(crate::security::SecurityPosture::Hardened, false).await;
    let first = stdio_send(&logged.meta, invoke_params(with_nonce("t2-nonce"), None)).await;
    assert!(first.get("result").is_some(), "premise: delivered: {first}");
    let second = stdio_send(&logged.meta, invoke_params(with_nonce("t2-nonce"), None)).await;
    assert_eq!(second["error"]["code"], -32001, "{second}");
    assert_eq!(
        second["error"]["message"], "Nonce replay detected",
        "{second}"
    );
    let all = invocation_records(&logged);
    assert_eq!(all.len(), 2, "one record for each call: {all:?}");
    assert_refusal_record(&all[1], "denied", -32001, "replay_guard");
}

/// S2: a nonce longer than the store accepts, on stdio.
#[tokio::test]
async fn s2_stdio_an_over_long_nonce_records_syntax() {
    let logged = signing_stdio(crate::security::SecurityPosture::Hardened, false).await;
    let long = "n".repeat(257);
    let answer = stdio_send(&logged.meta, invoke_params(with_nonce(&long), None)).await;
    assert_eq!(answer["error"]["code"], -32602, "{answer}");
    assert_eq!(
        answer["error"]["message"], "Invalid signing nonce",
        "{answer}"
    );
    let record = sole_record(&logged, &answer);
    assert_refusal_record(&record, "invalid", -32602, "syntax");
}

/// S4: signing required and no nonce sent, on a meta tool called by name:
/// refused before the store, noted `syntax`, with the missing nonce's own
/// code. The record spells the target as that request does: no server, the
/// called name.
#[tokio::test]
async fn s4_stdio_a_missing_required_nonce_records_syntax() {
    let logged = signing_stdio(crate::security::SecurityPosture::Hardened, true).await;
    let params = json!({"name": "gateway_list_servers", "arguments": {}});
    let answer = stdio_send(&logged.meta, params).await;
    assert_eq!(answer["error"]["code"], -32001, "{answer}");
    assert_eq!(
        answer["error"]["message"], "Nonce required when message signing is enforced",
        "{answer}"
    );
    let record = sole_record(&logged, &answer);
    assert_eq!(record["route"], "meta", "{record}");
    assert_eq!(record["tool"], "gateway_list_servers", "{record}");
    assert_eq!(
        record["server"].as_str().unwrap_or_default(),
        "",
        "{record}"
    );
    assert_eq!(record["outcome"], "denied", "{record}");
    assert_eq!(record["error_code"], -32001, "{record}");
    assert_eq!(record["decision"]["kind"], "syntax", "{record}");
}

/// S6: under the invoke-only scope, a `gateway_invoke` carrying both an
/// argument nonce and a `_meta` nonce has two replay identities: refused as
/// the request's shape, after the invocation policy.
#[tokio::test]
async fn s6_stdio_two_nonces_record_syntax() {
    let logged = signing_stdio(crate::security::SecurityPosture::Standard, false).await;
    let params = invoke_params(with_nonce("s6-meta"), Some("s6-argument"));
    let answer = stdio_send(&logged.meta, params).await;
    assert_eq!(answer["error"]["code"], -32602, "{answer}");
    assert_eq!(answer["error"]["message"], "two signing nonces", "{answer}");
    let record = sole_record(&logged, &answer);
    assert_refusal_record(&record, "invalid", -32602, "syntax");
}

/// F2: the log fails closed and its append now fails. A replayed nonce is
/// not answered as an unrecorded refusal: stdio answers that the audit log
/// is unavailable (-32005), as `/mcp` answers 503.
#[tokio::test]
async fn f2_stdio_a_failed_refusal_write_answers_unavailable() {
    let logged = signing_stdio(crate::security::SecurityPosture::Hardened, false).await;
    let first = stdio_send(&logged.meta, invoke_params(with_nonce("f2-nonce"), None)).await;
    assert!(first.get("result").is_some(), "premise: delivered: {first}");
    logged.log.set_append_failure_for_test(true);
    let second = stdio_send(&logged.meta, invoke_params(with_nonce("f2-nonce"), None)).await;
    assert_eq!(second["error"]["code"], -32005, "{second}");
}

/// P2: P1 on stdio. Under the invoke-only scope the operator killed alpha;
/// the signing check's invocation policy refuses it, answered as before, and
/// recorded with the policy's own kind and no rule id (the kill switch names
/// none).
#[tokio::test]
async fn p2_stdio_a_signing_time_policy_refusal_records_its_own_kind() {
    let logged = signing_stdio(crate::security::SecurityPosture::Standard, false).await;
    logged.meta.kill_switch().kill("alpha");
    let answer = stdio_send(&logged.meta, invoke_params(with_nonce("p2-nonce"), None)).await;
    assert_eq!(answer["error"]["code"], -32000, "{answer}");
    assert_eq!(
        answer["error"]["message"], "Server 'alpha' is currently disabled by operator kill switch",
        "{answer}"
    );
    let record = sole_record(&logged, &answer);
    assert_refusal_record(&record, "error", -32000, "kill_switch");
    assert!(record["decision"].get("rule_id").is_none(), "{record}");
}
