// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The first API key on a single-user gateway: the one question
//! (`waiting_first_key`), the writer's hold for a restart, and the waiting
//! fact the reload keeps. A gateway never changes status while running; a held
//! file is applied by the next start.

use std::sync::Arc;

use super::first_key::{Waiting, waiting_first_key};
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
    _dir: tempfile::TempDir,
    path: std::path::PathBuf,
    live: Arc<LiveConfig>,
    ctx: Arc<ReloadContext>,
}

impl Gw {
    fn start(text: &str) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("gateway.yaml");
        write_owner_only(&path, text).expect("write");
        let config = Config::load(Some(&path)).expect("the running config loads");
        let auth = ResolvedAuthConfig::from_config(
            &config.auth,
            crate::gateway::record_principal::TEST_RECORD_KEY,
        );
        let live = Arc::new(LiveConfig::with_auth(config, Arc::new(auth)));
        let ctx = Arc::new(
            ReloadContext::new(
                path.clone(),
                Arc::clone(&live),
                Arc::new(crate::backend::BackendRegistry::new()),
                crate::config::FailsafeConfig::default(),
                std::time::Duration::from_secs(60),
            )
            .expect("the registry pairs with the config"),
        );
        Self {
            _dir: dir,
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
        let bytes = text.as_bytes().to_vec();
        let replace = Replace {
            expected: Expected::Any,
            compute: Box::new(move |_| Ok(Template::plain(bytes))),
            replaced: Replaced::Discard,
            secrets: None,
            status_change,
        };
        replace_detached(Arc::clone(&self.ctx), replace, WAIT)
            .await
            .map(|outcome| outcome.reload)
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
    assert_eq!(
        ask(&gw, &starter(&[("first", FIRST)])),
        Waiting::Yes {
            keys: vec!["first".to_owned()]
        }
    );
}

/// The status unchanged: `No` (control).
#[test]
fn w8_an_unchanged_status_is_no() {
    let gw = Gw::start(&starter(&[]));
    assert_eq!(ask(&gw, &starter(&[])), Waiting::No);
}

/// (b) fails: removing the key of a two-credential gateway changes its
/// status but adds nothing, so it is faulty with the rule's own sentence.
#[test]
fn w8_a_removal_that_changes_status_is_faulty_with_the_rule() {
    let gw = Gw::start(&starter(&[("first", FIRST)]));
    match ask(&gw, &starter(&[])) {
        Waiting::Faulty { reason } => {
            assert!(
                reason.contains("single-user") && reason.contains("restart"),
                "{reason}"
            );
        }
        other => panic!("expected Faulty, got {other:?}"),
    }
}

/// (c) fails: a new key whose digest is the running bearer's is faulty with
/// the collision's text, never the restart sentence.
#[test]
fn w8_a_colliding_key_is_faulty_with_the_collision() {
    let gw = Gw::start(&starter(&[]));
    match ask(&gw, &starter(&[("clash", BEARER)])) {
        Waiting::Faulty { reason } => {
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
        Waiting::Faulty { reason } => {
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
            assert!(says_status_change(&refusal), "{refusal}");
        }
        ReplaceReload::Applied(_) => panic!("the status changed while running"),
    }
    assert_eq!(gw.file(), candidate);
    assert!(!gw.journal_left(), "a held write finishes its journal");
    assert_eq!(gw.live.waiting_keys(), Some(vec!["first".to_owned()]));
    assert!(!gw.accepts(FIRST), "the key works before the restart");
    assert!(gw.accepts(BEARER), "the bearer stopped working");
}

/// W2 (and W9): the same candidate under `Refuse` is refused before any
/// write as `RestartPending`. Red today: it is refused as `Invalid`.
#[tokio::test]
async fn w2_the_same_first_key_under_refuse_is_restart_pending() {
    let gw = Gw::start(&starter(&[]));
    let before = gw.file();
    let error = gw
        .write(&starter(&[("first", FIRST)]), StatusChange::Refuse)
        .await
        .expect_err("refused");
    match error {
        ReplaceError::ReloadRefused { class, .. } => {
            assert_eq!(class, RefusalClass::RestartPending)
        }
        other => panic!("expected ReloadRefused, got {other:?}"),
    }
    assert_eq!(gw.file(), before);
    assert_eq!(gw.live.waiting_keys(), None);
}

/// W3: a first key that also collides with the bearer is refused before any
/// write with the collision's text, not the restart sentence, even under
/// `HoldForRestart`. Red today: the status sentence wins.
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
    assert!(
        gw.live.pending_restart().contains(&"auth.api_keys"),
        "{:?}",
        gw.live.pending_restart()
    );
    gw.hand_edit(&candidate).await.expect_err("still refused");
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
