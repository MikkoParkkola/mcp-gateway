// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Independent drain fixtures and live-log ownership for the S6a2 rows.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{Map, Value};

use super::super::fixtures::{AUDIT_WHO_PRINCIPAL, NEW, OLD, decision, intended, seed, session};
use super::super::{
    Fact, FrozenRecord, IntentId, JournalSession, JournalV2, OpenJournal, Phase, ResultClass,
    TokenState, open,
};
use super::{DrainSession, JournalDrain};
use crate::config_persistence::commit::FileRevision;
use crate::config_persistence::journal;
use crate::config_persistence::lock::{self, Locked};
use crate::config_persistence::{FileMode, Symlink, sync_dir_of, write_atomic};
use crate::security::audit::AuditWho;
use crate::security::audit_rotation_config::RotationConfig;
use crate::security::transparency_log::settle::{Attribution, IntentKind, Reason, Role};
use crate::security::transparency_log::{
    TransparencyLogConfig, TransparencyLogger, VerifyMode, verify_audit_log,
};
use crate::test_dir_keep::kept_tempdir;

pub(super) const WRITER: &str = "writer-1";
pub(super) const ATTEMPT: &str = "attempt-1";
pub(super) const SAVE: &[u8] = br#"{"kind":"settle.save"}"#;
pub(super) const OUTCOME: &[u8] =
    br#"{"intent_counter":3,"kind":"settle.save","reason":"refused","result":"not_written"}"#;
pub(super) const RECOVERY: &[u8] =
    br#"{"at_start":false,"kind":"settle.recovery","settles":"writer-1"}"#;
pub(super) const ROOT: &[u8] = br#"{"at_start":true,"kind":"settle.recovery","root":true}"#;
pub(super) const FOREIGN: &[u8] = b"server:\n  port: 9\n";

pub(super) fn runtime<T>(future: impl Future<Output = T>) -> T {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("fixture runtime")
        .block_on(future)
}

pub(super) fn payload(bytes: &[u8]) -> Map<String, Value> {
    serde_json::from_slice(bytes).expect("literal object fixture")
}

pub(super) fn actor() -> AuditWho {
    AuditWho::from_persisted(AUDIT_WHO_PRINCIPAL).expect("literal actor fixture")
}

pub(super) fn record(role: Role, bytes: &[u8], digest: &str) -> FrozenRecord {
    FrozenRecord {
        role,
        payload_json: bytes.to_vec(),
        attribution: None,
        caller_digest: digest.to_owned(),
        delivered: false,
        parked: None,
    }
}

pub(super) fn state(dir: &Path) -> JournalV2 {
    let mut state = intended(dir);
    let writer = state.writer.as_mut().expect("fixture writer");
    writer.intent_id = IntentId(WRITER.to_owned());
    writer.intent = record(
        Role::Intent(IntentKind::Save),
        SAVE,
        "8db52a270d606fc2078954f3a4f4766037fdf26b170d107b2131f00250db7f35",
    );
    state
}

pub(super) fn decided(state: &mut JournalV2) {
    let writer = state.writer.as_mut().expect("fixture writer");
    writer.intent_counter = Some(3);
    writer.decision = Some(decision(ResultClass::NotWritten, Reason::Refused));
    writer.records = vec![record(Role::Outcome, OUTCOME, OUTCOME_DIGEST)];
}

pub(super) fn attempt() -> TokenState {
    TokenState {
        intent_id: IntentId(ATTEMPT.to_owned()),
        intent: record(Role::RecoveryIntent, RECOVERY, RECOVERY_DIGEST),
        intent_counter: None,
        decision: None,
        records: Vec::new(),
        handed_over: false,
    }
}

pub(super) fn staged(state: &mut JournalV2) {
    state.phase = Phase::Staged;
    state.original_revision = Some(FileRevision::of(OLD));
    state.new_revision = Some(FileRevision::of(NEW));
    state.fact = Some(Fact::Committed(FileRevision::of(NEW)));
}

pub(super) fn acquire(path: &Path) -> Locked {
    lock::lock_config_blocking_deferred(path, Instant::now() + Duration::from_secs(2), |_| {})
        .expect("fixture raw lock")
}

pub(super) fn reopen(locked: Locked) -> DrainSession {
    let state = match open(&locked).expect("fixture reopen") {
        Some(OpenJournal::Current(state)) => Some(JournalSession {
            target: locked.target.clone(),
            state: *state,
        }),
        _ => None,
    };
    DrainSession {
        configured: locked.target.clone(),
        locked,
        journal: state,
    }
}

pub(super) fn reread(owner: &mut DrainSession) {
    if let Some(OpenJournal::Current(state)) = open(&owner.locked).expect("fixture reread") {
        owner.journal = Some(JournalSession {
            target: owner.locked.target.clone(),
            state: *state,
        });
    }
}

pub(super) fn state_of(owner: &DrainSession) -> &JournalV2 {
    &owner.journal.as_ref().expect("fixture owner").state
}

pub(super) fn replace_bytes(path: &Path, bytes: &[u8]) {
    write_atomic(path, bytes, FileMode::Private, Symlink::Replace).expect("fixture bytes");
    sync_dir_of(path).expect("fixture directory sync");
}

pub(super) struct Live {
    pub(super) dir: Arc<tempfile::TempDir>,
    pub(super) resolved: PathBuf,
    pub(super) path: PathBuf,
    pub(super) log_path: PathBuf,
    pub(super) log: Arc<TransparencyLogger>,
    pub(super) config: Arc<TransparencyLogConfig>,
}

impl Live {
    pub(super) fn new() -> Self {
        Self::with_rotation(RotationConfig::default())
    }

    pub(super) fn with_rotation(rotation: RotationConfig) -> Self {
        let dir = kept_tempdir();
        let root = std::fs::canonicalize(dir.path()).expect("resolved fixture directory");
        // The overlay projects only config files; the logger owns its audit durability.
        let resolved = root.join("config");
        let audit = root.join("audit");
        std::fs::create_dir(&resolved).expect("fixture config directory");
        std::fs::create_dir(&audit).expect("fixture audit directory");
        let path = resolved.join("gateway.yaml");
        replace_bytes(&path, OLD);
        let log_path = audit.join("audit.jsonl");
        let config = audit_config(&log_path, rotation);
        let log = Arc::new(TransparencyLogger::open(Arc::clone(&config)).expect("fixture log"));
        log.keep_test_dir(Arc::clone(&dir));
        Self {
            dir,
            resolved,
            path,
            log_path,
            log,
            config,
        }
    }

    pub(super) fn reopen_log(self) -> Self {
        let Self {
            dir,
            resolved,
            path,
            log_path,
            log,
            config,
        } = self;
        drop(log);
        let log = Arc::new(TransparencyLogger::open(Arc::clone(&config)).expect("reopen log"));
        log.keep_test_dir(Arc::clone(&dir));
        Self {
            dir,
            resolved,
            path,
            log_path,
            log,
            config,
        }
    }

    pub(super) fn seed(&self, mut state: JournalV2, row: &str) -> DrainSession {
        state.binding = Some(self.log.log_id());
        if let Some(writer) = &state.writer
            && writer.intent_counter.is_some()
        {
            let appended = runtime(self.log.settle(
                &self.log.log_id(),
                &writer.intent_id.0,
                writer.intent.role,
                payload(&writer.intent.payload_json),
            ))
            .expect("seed surviving intent");
            assert_eq!(
                Some(appended.counter),
                writer.intent_counter,
                "{row}: fixture intent counter"
            );
        }
        for attempt in &state.attempts {
            if attempt.intent_counter.is_some() {
                let appended = runtime(self.log.settle(
                    &self.log.log_id(),
                    &attempt.intent_id.0,
                    attempt.intent.role,
                    payload(&attempt.intent.payload_json),
                ))
                .expect("seed surviving attempt");
                assert_eq!(
                    Some(appended.counter),
                    attempt.intent_counter,
                    "{row}: fixture attempt counter"
                );
            }
        }
        let locked = acquire(&self.path);
        if state.phase != Phase::Intended {
            replace_bytes(&journal::original_path(&self.path), OLD);
        }
        let journal = Some(session(&locked, state));
        DrainSession {
            locked,
            configured: self.path.clone(),
            journal,
        }
    }

    pub(super) fn records(&self) -> Vec<Value> {
        records_at(&self.log_path)
    }

    pub(super) fn verify(&self, row: &str) {
        let verdict = verify_audit_log(&self.log_path, &self.config, VerifyMode::Live, None);
        assert!(verdict.is_ok(), "{row}: reader must return a verdict");
        assert!(verdict.expect(row).ok, "{row}: verified chain and pairing");
    }
}

/// The one audit-log configuration every fixture and child process uses.
fn audit_config(log_path: &Path, rotation: RotationConfig) -> Arc<TransparencyLogConfig> {
    Arc::new(TransparencyLogConfig {
        enabled: true,
        path: log_path.to_string_lossy().into_owned(),
        key_id: "s6a2-fixture".into(),
        rotation,
        ..Default::default()
    })
}

#[cfg(unix)]
/// A child process's audit log, in the `audit` directory beside its config
/// directory. The parent test keeps that directory alive for the child's life.
pub(super) fn open_child_log(config_dir: &Path, row: &str) -> Arc<TransparencyLogger> {
    let log_path = config_dir
        .parent()
        .expect("fixture root")
        .join("audit/audit.jsonl");
    let config = audit_config(&log_path, RotationConfig::default());
    Arc::new(TransparencyLogger::open(config).expect(row))
}

pub(super) fn records_at(path: &Path) -> Vec<Value> {
    match std::fs::read_to_string(path) {
        Ok(text) => text
            .lines()
            .map(|line| serde_json::from_str(line).expect("log JSON"))
            .collect(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => panic!("fixture log read: {error}"),
    }
}

pub(super) fn terminal_count(records: &[Value], token: &str) -> usize {
    records
        .iter()
        .filter(|r| r["token"] == token && r["event"] == "config_write_outcome")
        .map(|r| {
            (
                r["result"].to_string(),
                r["reason"].to_string(),
                r["settled_by"].to_string(),
            )
        })
        .collect::<std::collections::BTreeSet<_>>()
        .len()
}

pub(super) fn retry(owner: &mut DrainSession, live: &Live, row: &str) {
    let result = runtime(JournalDrain::deliver(owner, &live.log));
    assert_eq!(result, Ok(()), "{row}: frozen delivery succeeds");
    reread(owner);
}

pub(super) fn reseed(owner: &DrainSession) {
    seed(&owner.locked.target, state_of(owner));
}

pub(super) fn attributed(state: &mut JournalV2) {
    state
        .writer
        .as_mut()
        .expect("fixture writer")
        .intent
        .attribution = Some(Attribution { actor: actor() });
}

pub(super) const OUTCOME_DIGEST: &str =
    "e5c5ab1d661170afae06f338c06ef26786f3315ef0fa760590bf6b3a1fa0d6fe";

pub(super) const RECOVERY_DIGEST: &str =
    "a8f80ead33544ad92cbde4781fdf3d71a62507c11c994eb65391a638d5071dee";

pub(super) const COMMITTED_OUTCOME: &[u8] =
    br#"{"intent_counter":3,"kind":"settle.save","reason":"committed","result":"written"}"#;

pub(super) fn accepted(state: &mut JournalV2) {
    staged(state);
    state.phase = Phase::Accepted;
    let writer = state.writer.as_mut().expect("fixture writer");
    writer.intent_counter = Some(3);
    writer.decision = Some(decision(ResultClass::Written, Reason::Committed));
    writer.records = vec![record(Role::Outcome, COMMITTED_OUTCOME, COMMITTED_DIGEST)];
}

const COMMITTED_DIGEST: &str = "37cc11330088e8903bfdf4d2d3f0b9a5eb025aa2a2516d457083ba40199cf074";
