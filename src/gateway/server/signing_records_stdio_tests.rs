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

/// The transparency log a stdio row's gateway runs with.
#[derive(Clone, Copy, PartialEq, Eq)]
enum StdioLog {
    FailClosed,
    BestEffort,
    /// None configured; the row's log file is never written.
    Off,
}

/// [`signing_stdio_with`] with a log that fails closed.
async fn signing_stdio(posture: crate::security::SecurityPosture, required: bool) -> Logged {
    signing_stdio_with(posture, required, StdioLog::FailClosed).await
}

/// A stdio Meta-MCP serving `alpha` with signing on: `scope` from the
/// posture, `required` deciding whether a call with no nonce is refused,
/// and the transparency log `mode` names.
async fn signing_stdio_with(
    posture: crate::security::SecurityPosture,
    required: bool,
    mode: StdioLog,
) -> Logged {
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
        .with_failure_policy(if mode == StdioLog::BestEffort {
            crate::security::audit::AuditFailurePolicy::BestEffort
        } else {
            crate::security::audit::AuditFailurePolicy::FailClosed
        }),
    );
    let kept = Arc::clone(&log);
    let meta = stdio_meta(
        move |meta| {
            if mode != StdioLog::Off {
                meta.enable_transparency_log(kept);
            }
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
/// `replay_guard`, beside the first call's own record, and is counted once
/// on the counters and in D4.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t2_stdio_a_replayed_nonce_records_replay_guard() {
    let logged = signing_stdio(crate::security::SecurityPosture::Hardened, false).await;
    let (second, counted, d4) = replay_counted(&logged, "t2-nonce", false).await;
    assert_eq!(second["error"]["code"], -32001, "{second}");
    assert_eq!(
        second["error"]["message"], "Nonce replay detected",
        "{second}"
    );
    let all = invocation_records(&logged);
    // One assert, so a red run shows every count at once.
    assert_eq!(
        (all.len(), counted, d4),
        (
            2,
            ONE_SERVED_ONE_REFUSED,
            crate::security::metrics_scrape::ONE_DENIAL
        ),
        "one record for each call: {all:?}"
    );
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

/// S6: under the every-call scope (hardened), the only scope that reads a
/// `_meta` nonce on `gateway_invoke` (signing.rs `capture_scoped`), a call carrying
/// both an argument nonce and a `_meta` nonce has two replay identities:
/// refused as the request's shape, after the invocation policy.
#[tokio::test]
async fn s6_stdio_two_nonces_record_syntax() {
    let logged = signing_stdio(crate::security::SecurityPosture::Hardened, false).await;
    let params = invoke_params(with_nonce("s6-meta"), Some("s6-argument"));
    let answer = stdio_send(&logged.meta, params).await;
    assert_eq!(answer["error"]["code"], -32602, "{answer}");
    assert_eq!(answer["error"]["message"], "two signing nonces", "{answer}");
    let record = sole_record(&logged, &answer);
    assert_refusal_record(&record, "invalid", -32602, "syntax");
}

/// F2: the log fails closed and its append now fails. A replayed nonce is
/// not answered as an unrecorded refusal: stdio answers that the audit log
/// is unavailable (-32005), as `/mcp` answers 503. A guard: the late site
/// already failed closed before this change; F2e pins the early one.
#[tokio::test]
async fn f2_stdio_a_failed_refusal_write_answers_unavailable() {
    let logged = signing_stdio(crate::security::SecurityPosture::Hardened, false).await;
    let first = stdio_send(&logged.meta, invoke_params(with_nonce("f2-nonce"), None)).await;
    assert!(first.get("result").is_some(), "premise: delivered: {first}");
    logged.log.set_append_failure_for_test(true);
    let second = stdio_send(&logged.meta, invoke_params(with_nonce("f2-nonce"), None)).await;
    assert_eq!(second["error"]["code"], -32005, "{second}");
}

/// F2e: F2 at the early site, which refuses an over-long nonce under the
/// every-call scope before any gate. Its record cannot be written, so it
/// is answered as the log being unavailable.
#[tokio::test]
async fn f2e_stdio_an_unrecordable_early_refusal_answers_unavailable() {
    let row = signing_stdio(crate::security::SecurityPosture::Hardened, false).await;
    row.log.set_append_failure_for_test(true);
    let too_long = with_nonce(&"e".repeat(300));
    let refused = stdio_send(&row.meta, invoke_params(too_long, None)).await;
    assert_eq!(refused["error"]["code"], -32005, "{refused}");
}

/// P2: P1 on stdio. Under the invoke-only scope the operator killed alpha;
/// the signing check's invocation policy refuses it, answered as before, and
/// recorded `denied` with its own code and the policy's own kind, with no
/// rule id (the kill switch names none).
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
    assert_refusal_record(&record, "denied", -32000, "kill_switch");
    assert!(record["decision"].get("rule_id").is_none(), "{record}");
}

/// The stdio replay rows' counters: `[calls, blocks, errors, firewall
/// refusals, cache hits]` after one delivered call and one refused replay.
const ONE_SERVED_ONE_REFUSED: [u64; 5] = [2, 1, 0, 0, 0];

/// One delivered call, then its nonce replayed under a counter store and a
/// recorder local to the row: the replay's answer, the counters and D4's
/// meta-route refusals.
async fn replay_counted(
    logged: &Logged,
    nonce: &str,
    fail_appends: bool,
) -> (Value, [u64; 5], Option<u64>) {
    let store = Arc::new(crate::counters::CounterStore::new(
        crate::clock::unix_secs().expect("a readable clock"),
    ));
    logged.meta.set_counters(Arc::clone(&store));
    let first = stdio_send(&logged.meta, invoke_params(with_nonce(nonce), None)).await;
    assert!(first.get("result").is_some(), "premise: delivered: {first}");
    logged.log.set_append_failure_for_test(fail_appends);
    let (second, text) = crate::security::metrics_scrape::scrape_if_enabled(stdio_send(
        &logged.meta,
        invoke_params(with_nonce(nonce), None),
    ));
    let d4 = crate::security::metrics_scrape::meta_denials(text.as_deref(), "gateway_refusal");
    (second, crate::counters::test_totals::totals(&store), d4)
}

/// The replay's answer as stdio always gave it.
fn assert_stdio_replay_answer(answer: &Value) {
    assert_eq!(answer["error"]["code"], -32001, "{answer}");
    assert_eq!(
        answer["error"]["message"], "Nonce replay detected",
        "{answer}"
    );
}

/// B2: the log is best-effort and its append fails: the replay is answered as
/// before, leaves no record, and is counted once on the counters and in D4.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b2_stdio_a_failed_refusal_write_keeps_the_answer_when_best_effort() {
    let logged = signing_stdio_with(
        crate::security::SecurityPosture::Hardened,
        false,
        StdioLog::BestEffort,
    )
    .await;
    let (answer, counted, d4) = replay_counted(&logged, "b2-nonce", true).await;
    assert_stdio_replay_answer(&answer);
    let all = invocation_records(&logged);
    assert_eq!(all.len(), 1, "only the delivered call's record: {all:?}");
    assert_eq!(
        (counted, d4),
        (
            ONE_SERVED_ONE_REFUSED,
            crate::security::metrics_scrape::ONE_DENIAL
        )
    );
}

/// L2: no transparency log at all: the replay is answered as before and
/// counted once on the counters and in D4.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn l2_stdio_with_no_log_a_refused_replay_is_answered_and_counted() {
    let logged = signing_stdio_with(
        crate::security::SecurityPosture::Hardened,
        false,
        StdioLog::Off,
    )
    .await;
    let (answer, counted, d4) = replay_counted(&logged, "l2-nonce", false).await;
    assert_stdio_replay_answer(&answer);
    assert!(
        invocation_records(&logged).is_empty(),
        "no log was configured"
    );
    assert_eq!(
        (counted, d4),
        (
            ONE_SERVED_ONE_REFUSED,
            crate::security::metrics_scrape::ONE_DENIAL
        )
    );
}

/// W5: an early refusal (a nonce too long, refused at intake under the
/// every-call scope) and a late one (a replay, refused at the signing check)
/// name the same caller: their records' `who` is one value, so the two ways
/// the stdio writer is handed its caller cannot drift apart.
#[tokio::test]
async fn w5_stdio_early_and_late_refusals_name_one_caller() {
    let logged = signing_stdio(crate::security::SecurityPosture::Hardened, false).await;
    let long = "n".repeat(257);
    let early = stdio_send(&logged.meta, invoke_params(with_nonce(&long), None)).await;
    assert_eq!(
        early["error"]["code"], -32602,
        "premise: refused early: {early}"
    );
    let first = stdio_send(&logged.meta, invoke_params(with_nonce("w5-nonce"), None)).await;
    assert!(first.get("result").is_some(), "premise: delivered: {first}");
    let late = stdio_send(&logged.meta, invoke_params(with_nonce("w5-nonce"), None)).await;
    assert_eq!(
        late["error"]["code"], -32001,
        "premise: refused late: {late}"
    );
    let all = invocation_records(&logged);
    assert_eq!(all.len(), 3, "early, delivered, late: {all:?}");
    assert!(
        all[0]["who"].is_object(),
        "the early record names a caller: {}",
        all[0]
    );
    assert_eq!(
        all[0]["who"], all[2]["who"],
        "early {} / late {}",
        all[0], all[2]
    );
}

/// P3: a call with a malformed nonce AND a malformed retry field gets the
/// nonce's refusal, as before: the early refusal keeps its place ahead of the
/// retry-field check (gpt r3c IMP 2, precedence), and is recorded once.
#[tokio::test]
async fn p3_stdio_an_early_nonce_refusal_keeps_its_precedence() {
    let logged = signing_stdio(crate::security::SecurityPosture::Hardened, false).await;
    let mut meta = with_nonce(&"n".repeat(257));
    meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!(7);
    let answer = stdio_send(&logged.meta, invoke_params(meta, None)).await;
    assert_eq!(answer["error"]["code"], -32602, "{answer}");
    assert_eq!(
        answer["error"]["message"], "Invalid signing nonce",
        "{answer}"
    );
    let record = sole_record(&logged, &answer);
    assert_refusal_record(&record, "invalid", -32602, "syntax");
}

/// N2c: N2a on stdio. A message with no id and a malformed nonce is refused
/// early, before the message is parsed; it is answered with no id and the
/// nonce's own words, and recorded once.
#[tokio::test]
async fn n2c_stdio_an_id_less_early_refusal_is_recorded() {
    let logged = signing_stdio(crate::security::SecurityPosture::Hardened, false).await;
    let params = invoke_params(with_nonce(&"n".repeat(257)), None);
    let request = json!({ "jsonrpc": "2.0", "method": "tools/call", "params": params });
    let policy = crate::security::ToolPolicyConfig::default();
    let answer = super::stdio_send_raw(&logged.meta, &request, &policy)
        .await
        .expect("the early refusal is answered");
    assert_eq!(answer["error"]["code"], -32602, "{answer}");
    assert_eq!(
        answer["error"]["message"], "Invalid signing nonce",
        "{answer}"
    );
    assert!(answer["id"].is_null(), "no id: {answer}");
    let record = sole_record(&logged, &answer);
    assert_refusal_record(&record, "invalid", -32602, "syntax");
}
