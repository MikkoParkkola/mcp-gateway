// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The first API key on a single-user gateway: the one question
//! (`waiting_first_key`), the writer's hold for a restart, and the waiting
//! fact the reload keeps. A gateway never changes status while running; a held
//! file is applied by the next start.

use std::sync::Arc;

use super::first_key::{
    Decision, FaultCause, KeyListRefusal, Waiting, restart_pending_decision, restart_pending_guard,
    waiting_first_key,
};
use super::refusals::RefusalCode;
use super::reload_context::replace::{
    Expected, RefusalClass, Replace, ReplaceError, ReplaceReload, Replaced, StatusChange,
    replace_detached,
};
use crate::config::Config;
use crate::config_persistence::keyedit::Template;
use crate::config_reload::{LiveConfig, ReloadContext};
use crate::gateway::auth::ResolvedAuthConfig;
use crate::gateway::test_helpers::write_owner_only;

const WAIT: std::time::Duration = std::time::Duration::from_secs(5);
/// The starter's admin credential.
const BEARER: &str = "first-key-tests-bearer-0123456789abcdef";
/// The first key's secret.
const FIRST: &str = "first-key-tests-secret-first";

/// One key entry, named as its secret's prefix says.
fn key(name: &str, secret: &str) -> String {
    format!(
        "    - name: {name}\n      key_sha256: \"{}\"\n      backends: [\"*\"]\n      admin: false\n",
        crate::config::api_key_digest_spec(secret.as_bytes())
    )
}

/// The starter shape: auth on, single-user, the bearer, and `keys`.
fn starter(keys: &[(&str, &str)]) -> String {
    let mut text =
        format!("auth:\n  enabled: true\n  bearer_token: \"{BEARER}\"\n  single_user: true\n");
    if !keys.is_empty() {
        text.push_str("  api_keys:\n");
        for (name, secret) in keys {
            text.push_str(&key(name, secret));
        }
    }
    text
}

/// A gateway running a file, with a reload context over it.
struct Gw {
    dir: tempfile::TempDir,
    path: std::path::PathBuf,
    live: Arc<LiveConfig>,
    ctx: Arc<ReloadContext>,
}

/// A replacement whose new bytes are `text`, whatever the file holds.
fn replace(text: &str, status_change: StatusChange) -> Replace {
    let bytes = text.as_bytes().to_vec();
    Replace {
        expected: Expected::Any,
        compute: Box::new(move |_| Ok(Template::plain(bytes))),
        replaced: Replaced::Discard,
        secrets: None,
        status_change,
    }
}

impl Gw {
    fn start(text: &str) -> Self {
        Self::start_with(text, None)
    }

    /// [`Self::start`] on `gateway.yaml`, a link to `real.yaml`, with
    /// `other.yaml` beside it holding the same text to re-point the link at.
    #[cfg(unix)]
    fn start_linked(text: &str) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        write_owner_only(dir.path().join("real.yaml"), text).expect("write");
        write_owner_only(dir.path().join("other.yaml"), text).expect("write");
        let path = dir.path().join("gateway.yaml");
        std::os::unix::fs::symlink(dir.path().join("real.yaml"), &path).expect("symlink");
        Self::on(dir, path, None)
    }

    /// The same file under a new process: the journal recovery the first
    /// holder of the config lock runs, then a start from what it left.
    fn restart(self) -> (Self, crate::config_persistence::journal::Recovered) {
        let Self { dir, path, .. } = self;
        let recovered = crate::config_persistence::journal::recover(&path).expect("recovery runs");
        (Self::on(dir, path, None), recovered)
    }

    /// [`Self::start`] whose reloads after a write refuse with a text that is
    /// no status change (kind `Other`); the writer's own checks before the
    /// write still run on the real loader.
    fn start_refusing_reloads(text: &str) -> Self {
        fn refused(
            _: &std::path::Path,
            _: &Arc<LiveConfig>,
            _: &crate::config::LiveEnv,
        ) -> Result<super::reload_context::EvaluatedReload, String> {
            Err("the reload refused the new bytes (test)".to_owned())
        }
        Self::start_with(text, Some(refused))
    }

    fn start_with(text: &str, load: Option<super::reload_context::LoadPatch>) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("gateway.yaml");
        write_owner_only(&path, text).expect("write");
        Self::on(dir, path, load)
    }

    fn on(
        dir: tempfile::TempDir,
        path: std::path::PathBuf,
        load: Option<super::reload_context::LoadPatch>,
    ) -> Self {
        let config = Config::load(Some(&path)).expect("the running config loads");
        let auth = ResolvedAuthConfig::from_config(
            &config.auth,
            crate::gateway::record_principal::TEST_RECORD_KEY,
        );
        let live = Arc::new(LiveConfig::with_auth(config, Arc::new(auth)));
        let ctx = ReloadContext::new(
            path.clone(),
            Arc::clone(&live),
            Arc::new(crate::backend::BackendRegistry::new()),
            crate::config::FailsafeConfig::default(),
            std::time::Duration::from_secs(60),
        )
        .expect("the registry pairs with the config");
        let ctx = Arc::new(match load {
            Some(load) => ctx.with_load(load),
            None => ctx,
        });
        Self {
            dir,
            path,
            live,
            ctx,
        }
    }

    fn file(&self) -> String {
        std::fs::read_to_string(&self.path).expect("read")
    }

    fn accepts(&self, secret: &str) -> bool {
        self.live
            .generation()
            .auth()
            .validate_token(secret)
            .is_some()
    }

    async fn write(
        &self,
        text: &str,
        status_change: StatusChange,
    ) -> Result<ReplaceReload, ReplaceError> {
        self.run(replace(text, status_change)).await
    }

    async fn run(&self, replace: Replace) -> Result<ReplaceReload, ReplaceError> {
        replace_detached(Arc::clone(&self.ctx), replace, WAIT)
            .await
            .map(|outcome| outcome.reload)
    }

    /// Whether the writer replaced the file since the last look, from its
    /// own trace: a reload that refuses and rolls back leaves the same bytes
    /// and no fact, so only this tells "refused before any write" apart.
    fn wrote(&self) -> bool {
        let target = crate::identity_grants::journal::resolved(&self.path);
        super::reload_context::replace::order::take(&target).contains(&"commit")
    }

    /// The journal's recorded state, `None` when there is no journal.
    fn journal_state(&self) -> Option<String> {
        let path = crate::config_persistence::journal::journal_path(&self.path);
        let text = std::fs::read_to_string(path).ok()?;
        let journal: serde_json::Value = serde_json::from_str(&text).expect("a JSON journal");
        journal["state"].as_str().map(str::to_owned)
    }

    /// Whether the staged original is still beside the file.
    fn original_left(&self) -> bool {
        crate::config_persistence::journal::original_path(&self.path).exists()
    }

    fn multi_user(&self) -> bool {
        self.live.running().auth.implies_multi_user(false)
    }

    async fn hand_edit(&self, text: &str) -> Result<(), String> {
        write_owner_only(&self.path, text).expect("write");
        self.ctx.reload_outcome().await.map(drop)
    }

    fn journal_left(&self) -> bool {
        crate::config_persistence::journal::journal_path(&self.path).exists()
    }

    fn newest_code(&self) -> Option<RefusalCode> {
        self.ctx.refusals().list().first().map(|r| r.code)
    }
}

/// The status rule's own sentence, as the test states it.
fn says_status_change(text: &str) -> bool {
    text.contains("would make the gateway multi-user") && text.contains("restart")
}

/// No admin-visible text of this ticket claims anything about a restart,
/// except the held create's own answer (FIRSTKEY.1).
fn no_restart_claim(text: &str) {
    assert!(!text.to_lowercase().contains("restart"), "{text}");
}

/// The reload's refusal of a clean first key: the keys by name, that the
/// gateway's multi-user status would change, and that nothing was published.
fn says_held_status_change(text: &str, key: &str) {
    assert!(text.contains(key), "{text}");
    assert!(text.contains("multi-user"), "{text}");
    assert!(text.contains("nothing was published"), "{text}");
    no_restart_claim(text);
}

fn parsed(text: &str) -> Config {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(&path, text).expect("write");
    Config::load(Some(&path)).expect("the candidate loads")
}

fn ask(gw: &Gw, candidate: &str) -> Waiting {
    let candidate = parsed(candidate);
    waiting_first_key(
        gw.live.running(),
        &gw.live.generation(),
        &candidate,
        &crate::config::EnvOverlay::none(),
    )
}

// ---- W8: the one question, one condition failing at a time ----

/// All hold: the first key, named exactly. Red today: the question always
/// answers `No`.
#[test]
fn w8_a_clean_first_key_waits_and_names_its_key() {
    let gw = Gw::start(&starter(&[]));
    match ask(&gw, &starter(&[("first", FIRST)])) {
        // The status sentence it carries is W1's to check, on the held refusal.
        Waiting::Yes { keys, .. } => assert_eq!(keys, ["first"]),
        other => panic!("expected Yes, got {other:?}"),
    }
}

/// The status unchanged: `No` (control).
#[test]
fn w8_an_unchanged_status_is_no() {
    let gw = Gw::start(&starter(&[]));
    assert_eq!(ask(&gw, &starter(&[])), Waiting::No);
}

/// (b) fails: removing the key of a two-credential gateway changes its
/// status but adds nothing, so it is faulty as a removal only, with the
/// question's own sentence: the multi-user status would change, and no
/// restart claim (the rule's sentence would say it applies at a restart).
#[test]
fn w8_a_removal_that_changes_status_is_faulty_as_removal_only() {
    let gw = Gw::start(&starter(&[("first", FIRST)]));
    match ask(&gw, &starter(&[])) {
        Waiting::Faulty { reason, cause } => {
            assert_eq!(cause, FaultCause::RemovalOnly);
            assert!(reason.contains("multi-user"), "{reason}");
            no_restart_claim(&reason);
        }
        other => panic!("expected Faulty, got {other:?}"),
    }
}

/// (c) fails: a new key whose digest is the running bearer's is faulty with
/// the collision's text, never the restart sentence.
#[test]
fn w8_a_colliding_key_is_faulty_with_the_collision() {
    let gw = Gw::start(&starter(&[]));
    // The file's own bearer differs, so the loader accepts it; only the key
    // table built on the RUNNING bearer sees the collision.
    let candidate = starter(&[("clash", BEARER)]).replacen(
        &format!("bearer_token: \"{BEARER}\""),
        "bearer_token: \"first-key-tests-another-bearer-0123456789\"",
        1,
    );
    match ask(&gw, &candidate) {
        Waiting::Faulty { reason, cause } => {
            assert_eq!(cause, FaultCause::KeyTable);
            assert!(reason.contains("auth.api_keys"), "{reason}");
            assert!(!says_status_change(&reason), "{reason}");
        }
        other => panic!("expected Faulty, got {other:?}"),
    }
}

/// (d) fails: a first key in a file whose next start is refused (two replicas
/// with the task store on) is faulty with the start check's sentence.
#[test]
fn w8_a_first_key_that_would_not_start_is_faulty_with_the_start_check() {
    let gw = Gw::start(&starter(&[]));
    let candidate = format!(
        "server:\n  replicas: 2\n  modern_protocol: true\n{}",
        starter(&[("first", FIRST)])
    );
    match ask(&gw, &candidate) {
        Waiting::Faulty { reason, cause } => {
            assert_eq!(cause, FaultCause::Start);
            assert!(reason.contains("replicas"), "{reason}");
            assert!(!says_status_change(&reason), "{reason}");
        }
        other => panic!("expected Faulty, got {other:?}"),
    }
}

// ---- W1, W2, W3, W9: the writer ----

/// W1 (and W9: the candidate changes keys only): a held write keeps its
/// bytes, removes its journal, names the key, and sets the waiting fact; the
/// key does not authenticate before a restart. Red today: the pre-check
/// refuses the status change.
#[tokio::test]
async fn w1_a_held_first_key_keeps_its_bytes_until_a_restart() {
    let gw = Gw::start(&starter(&[]));
    let candidate = starter(&[("first", FIRST)]);
    let reload = gw
        .write(&candidate, StatusChange::HoldForRestart)
        .await
        .expect("a held first key answers");
    match reload {
        ReplaceReload::HeldForRestart { refusal, keys } => {
            assert_eq!(keys, ["first"]);
            says_held_status_change(&refusal, "first");
        }
        ReplaceReload::Applied(_) => panic!("the status changed while running"),
    }
    assert_eq!(gw.file(), candidate);
    assert!(!gw.journal_left(), "a held write finishes its journal");
    assert_eq!(gw.live.waiting_keys(), Some(vec!["first".to_owned()]));
    assert!(!gw.accepts(FIRST), "the key works before the restart");
    assert!(gw.accepts(BEARER), "the bearer stopped working");
}

/// The shared decision's sentence for a key list that only creating the key
/// may bring in: an API key, the multi-user status, nothing written, and no
/// restart claim (the bytes were never written, so no restart applies them).
fn says_only_create_adds(text: &str) {
    assert!(text.contains("API key"), "{text}");
    assert!(text.contains("multi-user"), "{text}");
    assert!(text.contains("nothing was written"), "{text}");
    no_restart_claim(text);
}

/// W2 (and W9): the same candidate under `Refuse`, on the starter, whose
/// file holds no waiting key: refused before any write as invalid, with the
/// decision's own sentence; no restart-pending answer.
#[tokio::test]
async fn w2_the_same_first_key_under_refuse_is_invalid_with_its_own_sentence() {
    let gw = Gw::start(&starter(&[]));
    let before = gw.file();
    let error = gw
        .write(&starter(&[("first", FIRST)]), StatusChange::Refuse)
        .await
        .expect_err("refused");
    match error {
        ReplaceError::ReloadRefused { class, reason } => {
            // Typed, so the routes show this sentence without reading text.
            assert_eq!(class, RefusalClass::KeyList(KeyListRefusal::OnlyCreateAdds));
            says_only_create_adds(&reason);
        }
        other => panic!("expected ReloadRefused, got {other:?}"),
    }
    assert!(!gw.wrote(), "the file was written before the refusal");
    assert_eq!(gw.file(), before);
    assert_eq!(gw.live.waiting_keys(), None);
}

/// W2b: a `Refuse` write on a file that already holds a waiting key, and
/// keeps it: restart pending naming the file's waiting key, no restart
/// claim, nothing written.
#[tokio::test]
async fn w2b_a_refuse_write_keeping_a_waiting_key_is_restart_pending() {
    let gw = Gw::start(&starter(&[]));
    let held = starter(&[("first", FIRST)]);
    gw.write(&held, StatusChange::HoldForRestart)
        .await
        .expect("held");
    // The held write's own trace, so the check below sees only what follows.
    assert!(gw.wrote(), "premise: the held write wrote");
    let error = gw
        .write(
            &format!("environment: \"edited\"\n{held}"),
            StatusChange::Refuse,
        )
        .await
        .expect_err("refused");
    match error {
        ReplaceError::ReloadRefused {
            class: RefusalClass::RestartPending { waiting },
            reason,
        } => {
            assert_eq!(waiting.names(), ["first"]);
            no_restart_claim(&reason);
        }
        other => panic!("expected RestartPending, got {other:?}"),
    }
    assert!(!gw.wrote(), "the file was written before the refusal");
    assert_eq!(gw.file(), held);
}

/// R10: a `Refuse` write that only removes keys and so changes the status
/// (the multi-user gateway's one key taken out) is refused before any write
/// as invalid, with the question's removal sentence: no restart claim.
#[tokio::test]
async fn r10_a_removal_only_write_is_refused_without_a_restart_claim() {
    let gw = Gw::start(&starter(&[("first", FIRST)]));
    let before = gw.file();
    let error = gw
        .write(&starter(&[]), StatusChange::Refuse)
        .await
        .expect_err("refused");
    match error {
        ReplaceError::ReloadRefused { class, reason } => {
            assert_eq!(class, RefusalClass::KeyList(KeyListRefusal::RemovalOnly));
            assert!(reason.contains("multi-user"), "{reason}");
            no_restart_claim(&reason);
        }
        other => panic!("expected ReloadRefused, got {other:?}"),
    }
    assert!(!gw.wrote(), "the file was written before the refusal");
    assert_eq!(gw.file(), before);
}

/// R3: a `Refuse` write that would repair a start fault in a file whose key
/// waits still keeps that key: restart pending naming it, nothing written.
#[tokio::test]
async fn r3_a_write_repairing_a_start_fault_beside_a_waiting_key_is_restart_pending() {
    let gw = Gw::start(&starter(&[]));
    let held = starter(&[("first", FIRST)]);
    gw.write(&held, StatusChange::HoldForRestart)
        .await
        .expect("held");
    // The held write's own trace, so the check below sees only what follows.
    assert!(gw.wrote(), "premise: the held write wrote");
    let broken = first_key_with("server:\n  replicas: 2\n  modern_protocol: true\n");
    gw.hand_edit(&broken)
        .await
        .expect_err("a start fault is refused");
    let error = gw
        .write(&held, StatusChange::Refuse)
        .await
        .expect_err("refused");
    match error {
        ReplaceError::ReloadRefused {
            class: RefusalClass::RestartPending { waiting },
            ..
        } => assert_eq!(waiting.names(), ["first"]),
        other => panic!("expected RestartPending, got {other:?}"),
    }
    assert!(!gw.wrote(), "the file was written before the refusal");
    assert_eq!(gw.file(), broken);
}

// ---- R6: the shared decision, one row per cell ----

fn yes(keys: &[&str]) -> Waiting {
    Waiting::Yes {
        keys: keys.iter().map(|k| (*k).to_owned()).collect(),
        status: String::new(),
    }
}

fn faulty() -> Waiting {
    Waiting::Faulty {
        reason: "a start from it would be refused".to_owned(),
        cause: FaultCause::Start,
    }
}

fn names(keys: &[&str]) -> Vec<String> {
    keys.iter().map(|k| (*k).to_owned()).collect()
}

/// A candidate `Yes` on a file whose keys wait: pending, naming the FILE's
/// keys, not the candidate's.
#[test]
fn r6_yes_with_waiting_file_keys_is_pending_naming_the_file_keys() {
    match restart_pending_decision(&yes(&["first", "second"]), names(&["first"])) {
        Decision::Pending(waiting) => assert_eq!(waiting.names(), ["first"]),
        other => panic!("expected Pending, got {other:?}"),
    }
}

/// A candidate `Yes` on a file with no waiting key: invalid, with the
/// decision's own sentence.
#[test]
fn r6_yes_with_no_waiting_file_keys_is_invalid() {
    match restart_pending_decision(&yes(&["first"]), Vec::new()) {
        Decision::Invalid(refusal) => {
            assert_eq!(refusal, KeyListRefusal::OnlyCreateAdds);
            says_only_create_adds(refusal.sentence());
        }
        other => panic!("expected Invalid, got {other:?}"),
    }
}

/// `No` and `Faulty` candidates are not the decision's: the caller goes on.
#[test]
fn r6_no_and_faulty_candidates_continue() {
    assert_eq!(
        restart_pending_decision(&Waiting::No, names(&["late"])),
        Decision::Continue
    );
    assert_eq!(
        restart_pending_decision(&faulty(), names(&["first"])),
        Decision::Continue
    );
}

/// The create's guard: a file that is `Yes`, or `Faulty` while keys wait in
/// it, is pending naming them; `Faulty` with none, or `No` even with names
/// (a key added by hand to a multi-user gateway), is no answer.
#[test]
fn r6_the_create_guard_answers_by_the_file() {
    let named = |file: &Waiting, keys: &[&str]| {
        restart_pending_guard(file, names(keys)).map(|w| w.names().to_vec())
    };
    assert_eq!(named(&yes(&["first"]), &["first"]), Some(names(&["first"])));
    assert_eq!(named(&faulty(), &["first"]), Some(names(&["first"])));
    assert_eq!(named(&faulty(), &[]), None);
    assert_eq!(named(&Waiting::No, &["late"]), None);
}

/// W3: a first key that also collides with the bearer is refused before any
/// write with the collision's text, not the restart sentence, even under
/// `HoldForRestart`. A control: the loader refuses a key that collides with
/// the file's own bearer before this ticket's checks, held or not; the order
/// inside the question (collision before restart) is W8's to prove.
#[tokio::test]
async fn w3_a_colliding_first_key_is_refused_with_the_collision() {
    let gw = Gw::start(&starter(&[]));
    let before = gw.file();
    let error = gw
        .write(&starter(&[("clash", BEARER)]), StatusChange::HoldForRestart)
        .await
        .expect_err("refused");
    match error {
        ReplaceError::ReloadRefused { class, reason } => {
            assert_eq!(class, RefusalClass::Invalid);
            assert!(!says_status_change(&reason), "{reason}");
        }
        other => panic!("expected ReloadRefused, got {other:?}"),
    }
    assert_eq!(gw.file(), before);
    assert_eq!(gw.live.waiting_keys(), None);
}

/// A record key reference of the shape the loader takes.
const RECORD_KEY: &str = "first-key-tests-record-key-5a5a5a5a5a5a5a5a";

/// `extra` lines in front of the starter with a first key.
fn first_key_with(extra: &str) -> String {
    format!("{extra}{}", starter(&[("first", FIRST)]))
}

/// A held candidate that the question calls a clean first key, written by
/// the writer: it must be refused before anything is written, kept or
/// waiting, with a text that is no restart sentence. Returns the refusal.
async fn held_but_refused_first(candidate: &str) -> (RefusalClass, String) {
    let gw = Gw::start(&starter(&[]));
    assert!(
        matches!(ask(&gw, candidate), Waiting::Yes { .. }),
        "premise: the question calls it a clean first key: {:?}",
        ask(&gw, candidate)
    );
    let before = gw.file();
    let error = gw
        .write(candidate, StatusChange::HoldForRestart)
        .await
        .expect_err("refused");
    assert!(!gw.wrote(), "the file was written before the refusal");
    assert_eq!(gw.file(), before);
    assert!(!gw.journal_left());
    assert_eq!(gw.live.waiting_keys(), None);
    match error {
        ReplaceError::ReloadRefused { class, reason } => {
            assert!(!says_status_change(&reason), "{reason}");
            (class, reason)
        }
        other => panic!("expected ReloadRefused, got {other:?}"),
    }
}

/// W3, the posture class: a held first key that also changes a posture
/// setting is refused by the posture check, as any candidate is.
#[tokio::test]
async fn w3_a_held_first_key_changing_the_posture_is_refused_by_it() {
    let candidate =
        first_key_with("security:\n  hardened:\n    private_backends: [\"elsewhere\"]\n");
    let (class, reason) = held_but_refused_first(&candidate).await;
    assert_eq!(class, RefusalClass::Invalid);
    assert!(
        reason.contains("security.hardened requires restart"),
        "{reason}"
    );
}

/// W3, the restart-only class: a held first key that also changes the
/// record key is refused for that field.
#[tokio::test]
async fn w3_a_held_first_key_changing_a_restart_only_field_is_refused_by_it() {
    let candidate = first_key_with(&format!(
        "security:\n  record_principal_key: \"{RECORD_KEY}\"\n"
    ));
    let (class, reason) = held_but_refused_first(&candidate).await;
    assert_eq!(class, RefusalClass::Invalid);
    assert!(
        reason.contains("security.record_principal_key requires restart"),
        "{reason}"
    );
}

/// W3, the before-apply class: a held first key that also declares a public
/// URL the running listener would serve in cleartext is refused by the
/// network check. The file names who terminates TLS, so its own start is not
/// refused and the question still calls it a clean first key.
#[tokio::test]
async fn w3_a_held_first_key_opening_the_listener_is_refused_before_apply() {
    let candidate = first_key_with(
        "server:\n  public_url: \"https://first-key.example.test\"\n  cleartext_http: tls_terminated_upstream\n",
    );
    let (class, reason) = held_but_refused_first(&candidate).await;
    assert_eq!(class, RefusalClass::Posture);
    assert!(reason.contains("refusing to serve HTTP"), "{reason}");
}

/// W4: a held first key whose only other fault is that its own start is
/// refused (the running config's start is not) is refused before any write
/// with the start check's sentence. Kills the start check dropped, and the
/// start check asked about the running config instead of the candidate.
#[tokio::test]
async fn w4_a_held_first_key_whose_start_is_refused_is_refused_with_it() {
    let gw = Gw::start(&starter(&[]));
    let before = gw.file();
    let candidate = first_key_with("server:\n  replicas: 2\n  modern_protocol: true\n");
    let error = gw
        .write(&candidate, StatusChange::HoldForRestart)
        .await
        .expect_err("refused");
    match error {
        ReplaceError::ReloadRefused { class, reason } => {
            assert_eq!(class, RefusalClass::Invalid);
            assert!(reason.contains("replicas"), "{reason}");
            assert!(!says_status_change(&reason), "{reason}");
        }
        other => panic!("expected ReloadRefused, got {other:?}"),
    }
    assert!(!gw.wrote(), "the file was written before the refusal");
    assert_eq!(gw.file(), before);
    assert_eq!(gw.live.waiting_keys(), None);
}

/// W5: a held write whose reload refuses for any reason but the status
/// change is rolled back as any write is: the old bytes, no journal, today's
/// class, no fact. Red today: the pre-check refuses before the write.
#[tokio::test]
async fn w5_a_held_write_refused_for_another_reason_rolls_back() {
    let gw = Gw::start_refusing_reloads(&starter(&[]));
    let before = gw.file();
    let error = gw
        .write(&starter(&[("first", FIRST)]), StatusChange::HoldForRestart)
        .await
        .expect_err("rolled back");
    match error {
        ReplaceError::ReloadRefused { class, reason } => {
            assert_eq!(class, RefusalClass::Internal);
            assert!(reason.contains("(test)"), "{reason}");
        }
        other => panic!("expected ReloadRefused, got {other:?}"),
    }
    assert_eq!(gw.file(), before);
    assert!(!gw.journal_left());
    assert_eq!(gw.live.waiting_keys(), None);
}

// ---- L1-L4: the waiting fact and the ledger ----

/// L1: after a held write the ledger's newest row is `first_key_waiting` and
/// a restart is pending for the key list; a second refused reload of the same
/// file keeps the fact; a reload that applies (the key removed) clears it.
/// Red today: the write is refused.
#[tokio::test]
async fn l1_the_waiting_fact_follows_each_reload() {
    let gw = Gw::start(&starter(&[]));
    let candidate = starter(&[("first", FIRST)]);
    gw.write(&candidate, StatusChange::HoldForRestart)
        .await
        .expect("held");
    assert_eq!(gw.newest_code(), Some(RefusalCode::FirstKeyWaiting));
    let row = gw.ctx.refusals().list().first().cloned().expect("a row");
    no_restart_claim(&row.cause);
    no_restart_claim(row.fix);
    assert!(
        gw.live.pending_restart().contains(&"auth.api_keys"),
        "{:?}",
        gw.live.pending_restart()
    );
    let refusal = gw.hand_edit(&candidate).await.expect_err("still refused");
    says_held_status_change(&refusal, "first");
    assert_eq!(gw.live.waiting_keys(), Some(vec!["first".to_owned()]));
    gw.hand_edit(&starter(&[]))
        .await
        .expect("the removal applies");
    assert_eq!(gw.live.waiting_keys(), None);
    assert!(!gw.live.pending_restart().contains(&"auth.api_keys"));
}

/// L2: a hand edit after a clean hold that makes the file faulty (the key
/// now collides with the bearer) clears the fact, and the ledger shows the
/// invalid-config code. Red today: the hold fails first.
#[tokio::test]
async fn l2_a_faulty_edit_after_a_hold_clears_the_fact() {
    let gw = Gw::start(&starter(&[]));
    gw.write(&starter(&[("first", FIRST)]), StatusChange::HoldForRestart)
        .await
        .expect("held");
    gw.hand_edit(&starter(&[("first", BEARER)]))
        .await
        .expect_err("a colliding key is refused");
    assert_eq!(gw.live.waiting_keys(), None);
    assert_eq!(gw.newest_code(), Some(RefusalCode::InvalidConfig));
}

/// L3 (control): a hand edit that was never a clean first key is never told
/// to restart: today's refusal, the invalid-config code, no fact.
#[tokio::test]
async fn l3_a_faulty_first_key_by_hand_is_not_told_to_restart() {
    let gw = Gw::start(&starter(&[]));
    let error = gw
        .hand_edit(&starter(&[("clash", BEARER)]))
        .await
        .expect_err("refused");
    assert!(!says_status_change(&error), "{error}");
    assert_eq!(gw.newest_code(), Some(RefusalCode::InvalidConfig));
    assert_eq!(gw.live.waiting_keys(), None);
}

/// L4 (control): a `Refuse` write stopped by the pre-check records no fact.
#[tokio::test]
async fn l4_a_refused_status_change_records_no_fact() {
    let gw = Gw::start(&starter(&[]));
    gw.write(&starter(&[("first", FIRST)]), StatusChange::Refuse)
        .await
        .expect_err("refused");
    assert_eq!(gw.live.waiting_keys(), None);
}

#[path = "first_key_fact_tests.rs"]
mod fact;
#[path = "first_key_hold_tests.rs"]
mod hold;
