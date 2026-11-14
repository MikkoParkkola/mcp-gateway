// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Independent byte fixtures; no fixture calls a behavior stub.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::{
    Action, Fact, FileRevision, FrozenRecord, IntentId, JournalDecision, JournalSession, JournalV2,
    Locked, LogId, OpenJournal, ParkReason, Phase, Reason, ResultClass, Role, TerminalRole,
    TokenState, open,
};
use crate::config_persistence::journal;
use crate::config_persistence::lock;
use crate::config_persistence::{FileMode, Symlink, sync_dir_of, write_atomic};
use crate::security::transparency_log::settle::IntentKind;

pub(super) const OLD: &[u8] = b"server:\n  port: 1\n";
pub(super) const NEW: &[u8] = b"server:\n  port: 2\n";
pub(super) const INTENT: Role = Role::Intent(IntentKind::Save);

// New cases return diagnostics instead of asserting; even a production panic
// must leave the remaining cases runnable. Existing row assertions stay intact.
pub(super) fn collect_case(
    failures: &mut Vec<String>,
    row: &str,
    case: &str,
    expected: &str,
    run: impl FnOnce() -> Result<(), String>,
) {
    let got = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(run)) {
        Ok(Ok(())) => {
            println!("{row} {case}: passed");
            return;
        }
        Ok(Err(detail)) => detail,
        Err(panic) => {
            let detail = panic
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| panic.downcast_ref::<&str>().copied())
                .unwrap_or("non-string panic payload");
            format!("panic: {detail}")
        }
    };
    failures.push(format!("{row} {case}: expected {expected}, got {got}"));
}

pub(super) fn config() -> (tempfile::TempDir, PathBuf, Locked) {
    let dir = tempfile::tempdir().expect("fixture directory");
    let path = dir.path().join("gateway.yaml");
    write_atomic(&path, OLD, FileMode::Private, Symlink::Replace).expect("fixture config");
    let held =
        lock::lock_config_blocking_deferred(&path, Instant::now() + Duration::from_secs(2), |_| {})
            .expect("fixture lock");
    let path = held.target.clone();
    (dir, path, held)
}

pub(super) fn intended(_dir: &Path) -> JournalV2 {
    // A fixed binding: the rows need an id, not a live log (an opened log in a temp dir would
    // have to be kept alive for the whole test).
    let binding = LogId::from_journal("opaque-log:fixture".to_owned()).expect("fixture log id");
    JournalV2 {
        version: 2,
        binding: Some(binding),
        phase: Phase::Intended,
        original_revision: Some(FileRevision::of(OLD)),
        new_revision: None,
        pending: None,
        fact: Some(Fact::Untouched),
        writer: Some(writer()),
        attempts: Vec::new(),
    }
}

pub(super) fn frozen(token: &str, role: Role, payload: &Value) -> FrozenRecord {
    let mut caller = payload.as_object().expect("fixture payload object").clone();
    caller.insert("event".into(), role.event().into());
    caller.insert("token".into(), token.into());
    FrozenRecord {
        role,
        payload_json: serde_json::to_vec(payload).expect("fixture payload"),
        attribution: None,
        caller_digest: crate::hashing::sha256_hex(
            &serde_json::to_vec(&caller).expect("fixture caller view"),
        ),
        delivered: false,
        parked: None,
    }
}

fn writer() -> TokenState {
    let token = IntentId(uuid::Uuid::new_v4().simple().to_string());
    TokenState {
        intent: frozen(&token.0, INTENT, &json!({"kind": "settle.save"})),
        intent_id: token,
        intent_counter: None,
        decision: None,
        records: Vec::new(),
        handed_over: false,
    }
}

pub(super) fn decision(result: ResultClass, reason: Reason) -> JournalDecision {
    JournalDecision {
        result,
        reason,
        settled_by: None,
        terminal: TerminalRole::Outcome,
        delivery_stopped: false,
    }
}

fn decision_wire(decision: &JournalDecision) -> Value {
    json!({
        "result": match decision.result {
            ResultClass::Written => "written",
            ResultClass::NotWritten => "not_written",
            ResultClass::Unproven => "unproven",
        },
        "reason": decision.reason,
        "settled_by": decision.settled_by.as_ref().map(|t| &t.0),
        "terminal": match decision.terminal {
            TerminalRole::Outcome => "outcome",
            TerminalRole::Abandoned => "abandoned",
        },
        "delivery_stopped": decision.delivery_stopped,
    })
}

fn record_wire(record: &FrozenRecord) -> Value {
    json!({
        "role": record.role.event(),
        "payload_json": record.payload_json,
        "attribution": record.attribution,
        "caller_digest": record.caller_digest,
        "delivered": record.delivered,
        "parked": record.parked.map(|p| match p {
            ParkReason::InvalidPayload => "invalid_payload",
            ParkReason::ContentConflict => "content_conflict",
            ParkReason::ArtifactCorrupt => "artifact_corrupt",
        }),
    })
}

fn token_wire(token: &TokenState) -> Value {
    json!({
        "token": token.intent_id.0,
        "intent": record_wire(&token.intent),
        "intent_counter": token.intent_counter,
        "decision": token.decision.as_ref().map(decision_wire),
        "records": token.records.iter().map(record_wire).collect::<Vec<_>>(),
        "handed_over": token.handed_over,
    })
}

pub(super) fn wire(state: &JournalV2) -> Value {
    json!({
        "version": state.version,
        "binding": state.binding.as_ref().map(LogId::as_str),
        "phase": match state.phase {
            Phase::Intended => "intended",
            Phase::Staged => "staged",
            Phase::Accepted => "accepted",
        },
        "original_revision": state.original_revision.as_ref().map(FileRevision::as_str),
        "new_revision": state.new_revision.as_ref().map(FileRevision::as_str),
        "pending": state.pending.as_ref().map(|p| json!({
            "action": match p.action { Action::Forward => "forward", Action::Restore => "restore" },
            "expected": p.expected.as_str(),
            // pre_action is derived on load, never a separate wire field.
            "tried": p.tried,
        })),
        "fact": state.fact.as_ref().map(|f| match f {
            Fact::Untouched => json!("untouched"),
            Fact::Committed(r) => json!({"committed": r.as_str()}),
            Fact::RolledBack(r) => json!({"rolled_back": r.as_str()}),
        }),
        "writer": state.writer.as_ref().map(token_wire),
        "attempts": state.attempts.iter().map(token_wire).collect::<Vec<_>>(),
    })
}

pub(super) fn seed(target: &Path, state: &JournalV2) {
    let path = journal::journal_path(target);
    write_atomic(
        &path,
        &serde_json::to_vec(&wire(state)).expect("fixture journal"),
        FileMode::Private,
        Symlink::Replace,
    )
    .expect("seed journal");
    sync_dir_of(&path).expect("sync fixture journal");
}

pub(super) fn session(locked: &Locked, state: JournalV2) -> JournalSession {
    seed(&locked.target, &state);
    JournalSession {
        target: locked.target.clone(),
        state,
        backing: super::Backing::Journal,
    }
}

pub(super) fn bytes(target: &Path) -> Vec<u8> {
    std::fs::read(journal::journal_path(target)).expect("fixture journal bytes")
}

pub(super) fn checked<T: std::fmt::Debug, E: std::fmt::Debug>(
    result: Result<T, E>,
    row: &str,
) -> T {
    assert!(result.is_ok(), "{row}: operation must succeed: {result:?}");
    result.expect(row)
}

pub(super) fn reopened(locked: &Locked, row: &str) -> JournalV2 {
    let opened = open(locked);
    assert!(
        matches!(&opened, Ok(Some(OpenJournal::Current(_)))),
        "{row}: reopen must retain v2: {opened:?}"
    );
    let state = match opened.expect(row).expect(row) {
        OpenJournal::Current(state) => Some(*state),
        OpenJournal::Legacy(_) => None,
    };
    state.expect(row)
}

pub(super) const JOURNAL_V2_ATTRIBUTION: &[u8] = concat!(
    r#"{"attempts":[],"binding":"opaque-log:fixture","fact":"untouched","new_revision":null,"or"#,
    r#"iginal_revision":null,"pending":null,"phase":"intended","version":2,"writer":{"decision""#,
    r#":null,"handed_over":false,"intent":{"attribution":{"actor":{"account":"key-admin","autho"#,
    r#"rity":"https://issuer.example","credential_kind":"oidc_bearer","principal":"0123ab45cd67"#,
    r#"","subject":"operator-7"}},"caller_digest":"485a9281eea8d059ea8528045e677d06ae19ea25cea9"#,
    r#"3d706395419c28878653","delivered":false,"parked":null,"payload_json":[123,34,107,105,110"#,
    r#",100,34,58,34,115,101,116,116,108,101,46,107,101,121,95,99,114,101,97,116,101,34,44,34,1"#,
    r#"15,117,98,106,101,99,116,34,58,34,100,101,112,108,111,121,45,98,111,116,34,125],"role":""#,
    r#"config_key_create_intent"},"intent_counter":null,"records":[],"token":"writer-1"}}"#,
)
.as_bytes();

pub(super) const JOURNAL_V2_NONE: &[u8] = concat!(
    r#"{"attempts":[],"binding":"opaque-log:fixture","fact":"untouched","new_revision":null,"or"#,
    r#"iginal_revision":null,"pending":null,"phase":"intended","version":2,"writer":{"decision""#,
    r#":null,"handed_over":false,"intent":{"attribution":{"actor":{"account":"gateway","princip"#,
    r#"al":""}},"caller_digest":"485a9281eea8d059ea8528045e677d06ae19ea25cea93d706395419c288786"#,
    r#"53","delivered":false,"parked":null,"payload_json":[123,34,107,105,110,100,34,58,34,115,"#,
    r#"101,116,116,108,101,46,107,101,121,95,99,114,101,97,116,101,34,44,34,115,117,98,106,101,"#,
    r#"99,116,34,58,34,100,101,112,108,111,121,45,98,111,116,34,125],"role":"config_key_create_"#,
    r#"intent"},"intent_counter":null,"records":[],"token":"writer-1"}}"#,
)
.as_bytes();

pub(super) const JOURNAL_V2_ROOT: &[u8] = concat!(
    r#"{"attempts":[{"decision":null,"handed_over":false,"intent":{"attribution":null,"caller_d"#,
    r#"igest":"ff808f85a5675af934e1b28062a14b401766191c37dc3c9cdab3439790873a48","delivered":fa"#,
    r#"lse,"parked":null,"payload_json":[123,34,107,105,110,100,34,58,34,115,101,116,116,108,10"#,
    r#"1,46,114,101,99,111,118,101,114,121,34,44,34,114,111,111,116,34,58,116,114,117,101,125],"#,
    r#""role":"config_recovery_intent"},"intent_counter":null,"records":[],"token":"writer-1"}]"#,
    r#","binding":"opaque-log:fixture","fact":"untouched","new_revision":null,"original_revisio"#,
    r#"n":null,"pending":null,"phase":"intended","version":2,"writer":null}"#,
)
.as_bytes();

pub(super) const JOURNAL_V2_PARKED: &[u8] = concat!(
    r#"{"attempts":[],"binding":"opaque-log:fixture","fact":"untouched","new_revision":null,"or"#,
    r#"iginal_revision":null,"pending":null,"phase":"intended","version":2,"writer":{"decision""#,
    r#":null,"handed_over":false,"intent":{"attribution":null,"caller_digest":"40b5cafe045b9c9e"#,
    r#"31a1c3fdcfbc89f934906ff06a6276b55c2a0e517be21655","delivered":false,"parked":"invalid_pa"#,
    r#"yload","payload_json":[123,105,110,118,97,108,105,100],"role":"config_save_intent"},"int"#,
    r#"ent_counter":null,"records":[],"token":"writer-1"}}"#,
)
.as_bytes();

pub(super) const JOURNAL_V2_HANDED_OVER: &[u8] = concat!(
    r#"{"attempts":[],"binding":"opaque-log:fixture","fact":"untouched","new_revision":null,"or"#,
    r#"iginal_revision":null,"pending":null,"phase":"intended","version":2,"writer":{"decision""#,
    r#":null,"handed_over":true,"intent":{"attribution":null,"caller_digest":"8db52a270d606fc20"#,
    r#"78954f3a4f4766037fdf26b170d107b2131f00250db7f35","delivered":false,"parked":null,"payloa"#,
    r#"d_json":[123,34,107,105,110,100,34,58,34,115,101,116,116,108,101,46,115,97,118,101,34,12"#,
    r#"5],"role":"config_save_intent"},"intent_counter":null,"records":[],"token":"writer-1"}}"#,
)
.as_bytes();

pub(super) const AUDIT_WHO_PRINCIPAL: &[u8] = concat!(
    r#"{"credential_kind":"oidc_bearer","principal":"0123ab45cd67","account":"key-admin","autho"#,
    r#"rity":"https://issuer.example","subject":"operator-7"}"#,
)
.as_bytes();

pub(super) const AUDIT_WHO_NONE: &[u8] = r#"{"principal":"","account":"gateway"}"#.as_bytes();

// Literal wire-contract goldens: specified independently of JournalV2 and its codec.
pub(super) const JOURNAL_V2_ADOPT: &[u8] = concat!(
    r#"{"attempts":[],"binding":"opaque-log:fixture","fact":"untouched","new_revision":null,"original_r"#,
    r#"evision":null,"pending":null,"phase":"intended","version":2,"writer":{"decision":null,"handed_ov"#,
    r#"er":false,"intent":{"attribution":null,"caller_digest":"70280cce11f4896609969a29c87756ad85da1422"#,
    r#"ce8a09b600bad622a1cdb3e8","delivered":false,"parked":null,"payload_json":[123,34,107,105,110,100"#,
    r#",34,58,34,115,101,116,116,108,101,46,97,100,111,112,116,34,125],"role":"config_adopt_intent"},"i"#,
    r#"ntent_counter":null,"records":[],"token":"writer-1"}}"#,
)
.as_bytes();

pub(super) const JOURNAL_V2_RESTORE: &[u8] = concat!(
    r#"{"attempts":[],"binding":"opaque-log:fixture","fact":"untouched","new_revision":null,"original_r"#,
    r#"evision":null,"pending":null,"phase":"intended","version":2,"writer":{"decision":null,"handed_ov"#,
    r#"er":false,"intent":{"attribution":null,"caller_digest":"f67222649618324eb141dfc50fd6521492096e17"#,
    r#"74967acef8ff8759a8d0b821","delivered":false,"parked":null,"payload_json":[123,34,107,105,110,100"#,
    r#",34,58,34,115,101,116,116,108,101,46,114,101,115,116,111,114,101,34,125],"role":"config_restore_"#,
    r#"intent"},"intent_counter":null,"records":[],"token":"writer-1"}}"#,
)
.as_bytes();

pub(super) const JOURNAL_V2_BACKEND: &[u8] = concat!(
    r#"{"attempts":[],"binding":"opaque-log:fixture","fact":"untouched","new_revision":null,"original_r"#,
    r#"evision":null,"pending":null,"phase":"intended","version":2,"writer":{"decision":null,"handed_ov"#,
    r#"er":false,"intent":{"attribution":null,"caller_digest":"543a6cc28babf8984a86d2f5af1bc52d4cf93491"#,
    r#"dd07eb22cdbcb803ca70bf27","delivered":false,"parked":null,"payload_json":[123,34,107,105,110,100"#,
    r#",34,58,34,115,101,116,116,108,101,46,98,97,99,107,101,110,100,34,125],"role":"config_backend_int"#,
    r#"ent"},"intent_counter":null,"records":[],"token":"writer-1"}}"#,
)
.as_bytes();

pub(super) const JOURNAL_V2_DECISION_WRITTEN: &[u8] = concat!(
    r#"{"attempts":[],"binding":"opaque-log:fixture","fact":{"committed":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbb"#,
    r#"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"new_revision":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"#,
    r#"bbbbbbbbbbbbbbbbbbbbbb","original_revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"#,
    r#"aaaaaaaaaaaaa","pending":null,"phase":"accepted","version":2,"writer":{"decision":{"delivery_sto"#,
    r#"pped":false,"reason":"committed","result":"written","settled_by":null,"terminal":"outcome"},"han"#,
    r#"ded_over":false,"intent":{"attribution":null,"caller_digest":"8db52a270d606fc2078954f3a4f4766037"#,
    r#"fdf26b170d107b2131f00250db7f35","delivered":true,"parked":null,"payload_json":[123,34,107,105,11"#,
    r#"0,100,34,58,34,115,101,116,116,108,101,46,115,97,118,101,34,125],"role":"config_save_intent"},"i"#,
    r#"ntent_counter":7,"records":[],"token":"writer-1"}}"#,
)
.as_bytes();

pub(super) const JOURNAL_V2_DECISION_NOT_WRITTEN: &[u8] = concat!(
    r#"{"attempts":[],"binding":"opaque-log:fixture","fact":"untouched","new_revision":"bbbbbbbbbbbbbbb"#,
    r#"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","original_revision":"aaaaaaaaaaaaaaaaaaaaaaaa"#,
    r#"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","pending":null,"phase":"staged","version":2,"writer":{"#,
    r#""decision":{"delivery_stopped":false,"reason":"refused","result":"not_written","settled_by":null"#,
    r#","terminal":"outcome"},"handed_over":false,"intent":{"attribution":null,"caller_digest":"8db52a2"#,
    r#"70d606fc2078954f3a4f4766037fdf26b170d107b2131f00250db7f35","delivered":true,"parked":null,"paylo"#,
    r#"ad_json":[123,34,107,105,110,100,34,58,34,115,101,116,116,108,101,46,115,97,118,101,34,125],"rol"#,
    r#"e":"config_save_intent"},"intent_counter":7,"records":[],"token":"writer-1"}}"#,
)
.as_bytes();

pub(super) const JOURNAL_V2_DECISION_UNPROVEN: &[u8] = concat!(
    r#"{"attempts":[],"binding":"opaque-log:fixture","fact":null,"new_revision":"bbbbbbbbbbbbbbbbbbbbbb"#,
    r#"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","original_revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"#,
    r#"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","pending":null,"phase":"staged","version":2,"writer":{"decisi"#,
    r#"on":{"delivery_stopped":false,"reason":"abandoned","result":"unproven","settled_by":null"#,
    r#","terminal":"abandoned"},"handed_over":false,"intent":{"attribution":null,"caller_digest":"8db52"#,
    r#"a270d606fc2078954f3a4f4766037fdf26b170d107b2131f00250db7f35","delivered":true,"parked":null,"pay"#,
    r#"load_json":[123,34,107,105,110,100,34,58,34,115,101,116,116,108,101,46,115,97,118,101,34,125],"r"#,
    r#"ole":"config_save_intent"},"intent_counter":7,"records":[],"token":"writer-1"}}"#,
)
.as_bytes();

pub(super) const JOURNAL_V2_DECISION_ABANDONED_NOT_WRITTEN: &[u8] = concat!(
    r#"{"attempts":[],"binding":"opaque-log:fixture","fact":"untouched","new_revision":"bbbbbbbbbbbbbbb"#,
    r#"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","original_revision":"aaaaaaaaaaaaaaaaaaaaaaaa"#,
    r#"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","pending":null,"phase":"staged","version":2,"writer":{"#,
    r#""decision":{"delivery_stopped":true,"reason":"abandoned","result":"not_written","settled_by":nul"#,
    r#"l,"terminal":"abandoned"},"handed_over":false,"intent":{"attribution":null,"caller_digest":"8db5"#,
    r#"2a270d606fc2078954f3a4f4766037fdf26b170d107b2131f00250db7f35","delivered":true,"parked":null,"pa"#,
    r#"yload_json":[123,34,107,105,110,100,34,58,34,115,101,116,116,108,101,46,115,97,118,101,34,125],""#,
    r#"role":"config_save_intent"},"intent_counter":7,"records":[],"token":"writer-1"}}"#,
)
.as_bytes();

pub(super) const JOURNAL_V2_INVALID_OUTCOME_UNPROVEN: &[u8] = concat!(
    r#"{"attempts":[],"binding":"opaque-log:fixture","fact":"untouched","new_revision":"bbbbbbbbbbbbbbb"#,
    r#"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","original_revision":"aaaaaaaaaaaaaaaaaaaaaaaa"#,
    r#"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","pending":null,"phase":"staged","version":2,"writer":{"#,
    r#""decision":{"delivery_stopped":false,"reason":"refused","result":"unproven","settled_by":null,"t"#,
    r#"erminal":"outcome"},"handed_over":false,"intent":{"attribution":null,"caller_digest":"8db52a270d"#,
    r#"606fc2078954f3a4f4766037fdf26b170d107b2131f00250db7f35","delivered":true,"parked":null,"payload_"#,
    r#"json":[123,34,107,105,110,100,34,58,34,115,101,116,116,108,101,46,115,97,118,101,34,125],"role":"#,
    r#""config_save_intent"},"intent_counter":7,"records":[],"token":"writer-1"}}"#,
)
.as_bytes();

pub(super) const JOURNAL_V2_INVALID_OUTCOME_ABANDONED: &[u8] = concat!(
    r#"{"attempts":[],"binding":"opaque-log:fixture","fact":"untouched","new_revision":"bbbbbbbbbbbbbbb"#,
    r#"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","original_revision":"aaaaaaaaaaaaaaaaaaaaaaaa"#,
    r#"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","pending":null,"phase":"staged","version":2,"writer":{"#,
    r#""decision":{"delivery_stopped":false,"reason":"abandoned","result":"not_written","settled_by":nu"#,
    r#"ll,"terminal":"outcome"},"handed_over":false,"intent":{"attribution":null,"caller_digest":"8db52"#,
    r#"a270d606fc2078954f3a4f4766037fdf26b170d107b2131f00250db7f35","delivered":true,"parked":null,"pay"#,
    r#"load_json":[123,34,107,105,110,100,34,58,34,115,101,116,116,108,101,46,115,97,118,101,34,125],"r"#,
    r#"ole":"config_save_intent"},"intent_counter":7,"records":[],"token":"writer-1"}}"#,
)
.as_bytes();

pub(super) const JOURNAL_V2_INVALID_OUTCOME_RENAMED: &[u8] = concat!(
    r#"{"attempts":[],"binding":"opaque-log:fixture","fact":"untouched","new_revision":"bbbbbbbbbbbbbbb"#,
    r#"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","original_revision":"aaaaaaaaaaaaaaaaaaaaaaaa"#,
    r#"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","pending":null,"phase":"staged","version":2,"writer":{"#,
    r#""decision":{"delivery_stopped":false,"reason":"renamed_not_durable","result":"not_written","sett"#,
    r#"led_by":null,"terminal":"outcome"},"handed_over":false,"intent":{"attribution":null,"caller_dige"#,
    r#"st":"8db52a270d606fc2078954f3a4f4766037fdf26b170d107b2131f00250db7f35","delivered":true,"parked""#,
    r#":null,"payload_json":[123,34,107,105,110,100,34,58,34,115,101,116,116,108,101,46,115,97,118,101,"#,
    r#"34,125],"role":"config_save_intent"},"intent_counter":7,"records":[],"token":"writer-1"}}"#,
)
.as_bytes();

pub(super) const JOURNAL_V2_INVALID_OUTCOME_DEFERRED: &[u8] = concat!(
    r#"{"attempts":[],"binding":"opaque-log:fixture","fact":"untouched","new_revision":"bbbbbbbbbbbbbbb"#,
    r#"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","original_revision":"aaaaaaaaaaaaaaaaaaaaaaaa"#,
    r#"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","pending":null,"phase":"staged","version":2,"writer":{"#,
    r#""decision":{"delivery_stopped":false,"reason":"left_to_recovery","result":"not_written","settled"#,
    r#"_by":null,"terminal":"outcome"},"handed_over":false,"intent":{"attribution":null,"caller_digest""#,
    r#":"8db52a270d606fc2078954f3a4f4766037fdf26b170d107b2131f00250db7f35","delivered":true,"parked":nu"#,
    r#"ll,"payload_json":[123,34,107,105,110,100,34,58,34,115,101,116,116,108,101,46,115,97,118,101,34,"#,
    r#"125],"role":"config_save_intent"},"intent_counter":7,"records":[],"token":"writer-1"}}"#,
)
.as_bytes();

pub(super) const JOURNAL_V2_INVALID_ABANDONED_WRITTEN: &[u8] = concat!(
    r#"{"attempts":[],"binding":"opaque-log:fixture","fact":"untouched","new_revision":"bbbbbbbbbbbbbbb"#,
    r#"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","original_revision":"aaaaaaaaaaaaaaaaaaaaaaaa"#,
    r#"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","pending":null,"phase":"staged","version":2,"writer":{"#,
    r#""decision":{"delivery_stopped":false,"reason":"abandoned","result":"written","settled_by":null,""#,
    r#"terminal":"abandoned"},"handed_over":false,"intent":{"attribution":null,"caller_digest":"8db52a2"#,
    r#"70d606fc2078954f3a4f4766037fdf26b170d107b2131f00250db7f35","delivered":true,"parked":null,"paylo"#,
    r#"ad_json":[123,34,107,105,110,100,34,58,34,115,101,116,116,108,101,46,115,97,118,101,34,125],"rol"#,
    r#"e":"config_save_intent"},"intent_counter":7,"records":[],"token":"writer-1"}}"#,
)
.as_bytes();

pub(super) const JOURNAL_V2_INVALID_ABANDONED_REFUSED: &[u8] = concat!(
    r#"{"attempts":[],"binding":"opaque-log:fixture","fact":"untouched","new_revision":"bbbbbbbbbbbbbbb"#,
    r#"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","original_revision":"aaaaaaaaaaaaaaaaaaaaaaaa"#,
    r#"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","pending":null,"phase":"staged","version":2,"writer":{"#,
    r#""decision":{"delivery_stopped":false,"reason":"refused","result":"not_written","settled_by":null"#,
    r#","terminal":"abandoned"},"handed_over":false,"intent":{"attribution":null,"caller_digest":"8db52"#,
    r#"a270d606fc2078954f3a4f4766037fdf26b170d107b2131f00250db7f35","delivered":true,"parked":null,"pay"#,
    r#"load_json":[123,34,107,105,110,100,34,58,34,115,101,116,116,108,101,46,115,97,118,101,34,125],"r"#,
    r#"ole":"config_save_intent"},"intent_counter":7,"records":[],"token":"writer-1"}}"#,
)
.as_bytes();

pub(super) const JOURNAL_V2_INVALID_ABANDONED_UNPROVEN_REFUSED: &[u8] = concat!(
    r#"{"attempts":[],"binding":"opaque-log:fixture","fact":"untouched","new_revision":"bbbbbbbbbbbbbbb"#,
    r#"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","original_revision":"aaaaaaaaaaaaaaaaaaaaaaaa"#,
    r#"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","pending":null,"phase":"staged","version":2,"writer":{"#,
    r#""decision":{"delivery_stopped":false,"reason":"refused","result":"unproven","settled_by":null,"t"#,
    r#"erminal":"abandoned"},"handed_over":false,"intent":{"attribution":null,"caller_digest":"8db52a27"#,
    r#"0d606fc2078954f3a4f4766037fdf26b170d107b2131f00250db7f35","delivered":true,"parked":null,"payloa"#,
    r#"d_json":[123,34,107,105,110,100,34,58,34,115,101,116,116,108,101,46,115,97,118,101,34,125],"role"#,
    r#"":"config_save_intent"},"intent_counter":7,"records":[],"token":"writer-1"}}"#,
)
.as_bytes();

pub(super) const JOURNAL_V2_ACCEPTED: &[u8] = concat!(
    r#"{"attempts":[],"binding":null,"fact":{"committed":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"#,
    r#"bbbbbbbbbbbbbbbbbbb"},"new_revision":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"#,
    r#"bbbbbb","original_revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",""#,
    r#"pending":null,"phase":"accepted","version":2,"writer":null}"#,
)
.as_bytes();

pub(super) const JOURNAL_V2_INVALID_ACCEPTED_NO_REVISION: &[u8] = concat!(
    r#"{"attempts":[],"binding":null,"fact":{"committed":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"#,
    r#"bbbbbbbbbbbbbbbbbbb"},"new_revision":null,"original_revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"#,
    r#"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","pending":null,"phase":"accepted","version":2,"writer":null}"#,
)
.as_bytes();

pub(super) const JOURNAL_V2_INVALID_ACCEPTED_NO_FACT: &[u8] = concat!(
    r#"{"attempts":[],"binding":null,"fact":null,"new_revision":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"#,
    r#"bbbbbbbbbbbbbbbbbbbbbbbbbb","original_revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"#,
    r#"aaaaaaaaaaaaaaaaa","pending":null,"phase":"accepted","version":2,"writer":null}"#,
)
.as_bytes();

pub(super) const JOURNAL_V2_INVALID_ACCEPTED_UNTOUCHED: &[u8] = concat!(
    r#"{"attempts":[],"binding":null,"fact":"untouched","new_revision":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"#,
    r#"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","original_revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"#,
    r#"aaaaaaaaaaaaaaaaaaaaaaaa","pending":null,"phase":"accepted","version":2,"writer":null}"#,
)
.as_bytes();

pub(super) const JOURNAL_V2_INVALID_ACCEPTED_WRONG_REVISION: &[u8] = concat!(
    r#"{"attempts":[],"binding":null,"fact":{"committed":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"#,
    r#"aaaaaaaaaaaaaaaaaaa"},"new_revision":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"#,
    r#"bbbbbb","original_revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",""#,
    r#"pending":null,"phase":"accepted","version":2,"writer":null}"#,
)
.as_bytes();

pub(super) const JOURNAL_V2_PENDING: &[u8] = concat!(
    r#"{"attempts":[],"binding":null,"fact":null,"new_revision":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"#,
    r#"bbbbbbbbbbbbbbbbbbbbbbbbbb","original_revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"#,
    r#"aaaaaaaaaaaaaaaaa","pending":{"action":"forward","expected":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"#,
    r#"bbbbbbbbbbbbbbbbbbbbbbbbbbbbb","tried":false},"phase":"staged","version":2,"writer":null}"#,
)
.as_bytes();

pub(super) const JOURNAL_V2_INVALID_PENDING_FACT: &[u8] = concat!(
    r#"{"attempts":[],"binding":null,"fact":"untouched","new_revision":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"#,
    r#"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","original_revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"#,
    r#"aaaaaaaaaaaaaaaaaaaaaaaa","pending":{"action":"forward","expected":"bbbbbbbbbbbbbbbbbbbbbbbbbbbb"#,
    r#"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","tried":false},"phase":"staged","version":2,"writer":null}"#,
)
.as_bytes();

// Duplicate owners have individually valid but different decisions for the same id.
pub(super) const JOURNAL_V2_DUPLICATE_WRITER_ATTEMPT: &[u8] = br#"{
    "version":2,"binding":"opaque-log:fixture","phase":"intended",
    "original_revision":null,"new_revision":null,"pending":null,"fact":"untouched",
    "writer":{
        "token":"writer-1","handed_over":false,"intent_counter":7,
        "decision":{"result":"not_written","reason":"refused","settled_by":null,
                    "terminal":"outcome","delivery_stopped":false},
        "intent":{"role":"config_save_intent","attribution":null,
                  "payload_json":[123,34,107,105,110,100,34,58,34,115,101,116,116,
                                  108,101,46,115,97,118,101,34,125],
                  "caller_digest":"8db52a270d606fc2078954f3a4f4766037fdf26b170d107b2131f00250db7f35",
                  "delivered":true,"parked":null},"records":[]
    },
    "attempts":[{
        "token":"writer-1","handed_over":false,"intent_counter":8,
        "decision":{"result":"unproven","reason":"abandoned","settled_by":null,
                    "terminal":"abandoned","delivery_stopped":false},
        "intent":{"role":"config_recovery_intent","attribution":null,
                  "payload_json":[123,34,107,105,110,100,34,58,34,115,101,116,116,
                                  108,101,46,114,101,99,111,118,101,114,121,34,
                                  44,34,114,111,111,116,34,58,116,114,117,101,125],
                  "caller_digest":"ff808f85a5675af934e1b28062a14b401766191c37dc3c9cdab3439790873a48",
                  "delivered":true,"parked":null},"records":[]
    }]
}"#;

pub(super) const JOURNAL_V2_DUPLICATE_ATTEMPTS: &[u8] = br#"{
    "version":2,"binding":"opaque-log:fixture","phase":"intended",
    "original_revision":null,"new_revision":null,"pending":null,"fact":"untouched",
    "writer":null,"attempts":[{
        "token":"writer-1","handed_over":false,"intent_counter":7,
        "decision":{"result":"not_written","reason":"refused","settled_by":null,
                    "terminal":"outcome","delivery_stopped":false},
        "intent":{"role":"config_recovery_intent","attribution":null,
                  "payload_json":[123,34,107,105,110,100,34,58,34,115,101,116,116,
                                  108,101,46,114,101,99,111,118,101,114,121,34,
                                  44,34,114,111,111,116,34,58,116,114,117,101,125],
                  "caller_digest":"ff808f85a5675af934e1b28062a14b401766191c37dc3c9cdab3439790873a48",
                  "delivered":true,"parked":null},"records":[]
    },{
        "token":"writer-1","handed_over":false,"intent_counter":8,
        "decision":{"result":"unproven","reason":"abandoned","settled_by":null,
                    "terminal":"abandoned","delivery_stopped":false},
        "intent":{"role":"config_recovery_intent","attribution":null,
                  "payload_json":[123,34,107,105,110,100,34,58,34,115,101,116,116,
                                  108,101,46,114,101,99,111,118,101,114,121,34,
                                  44,34,114,111,111,116,34,58,116,114,117,101,125],
                  "caller_digest":"ff808f85a5675af934e1b28062a14b401766191c37dc3c9cdab3439790873a48",
                  "delivered":true,"parked":null},"records":[]
    }]
}"#;

#[path = "config_persistence_journal_v2_r2_cases_tests.rs"]
pub(super) mod r2_cases;
#[path = "config_persistence_journal_v2_r2_fixtures_tests.rs"]
pub(super) mod r2_fixtures;
