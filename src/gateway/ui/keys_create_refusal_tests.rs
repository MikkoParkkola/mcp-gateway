// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `POST /ui/api/keys`, the rows that refuse: the strict body, the
//! preconditions in their order, the validation that names a field, the
//! expiry, the audit posture, the multi-user flip and the keyedit refusals.
//! Every refusal leaves the file byte-identical and the answer free of the
//! secret and its digest.

use axum::http::StatusCode;
use serde_json::{Value, json};

use std::sync::Arc;

use super::keys_create::BeforeLock;
use super::keys_create_fixture_tests::{
    Call, Fixture, KNOWN, ROOT, Setup, item, root_item, spec, yaml_of,
};

/// Posts `body`, then checks the status, the error code and that nothing was
/// written and nothing leaked.
fn refused(fx: &Fixture, body: &Value, status: StatusCode, code: &str) -> Value {
    let before = fx.bytes();
    let sent = fx.post(Call::new(body));
    assert_eq!(sent.status, status, "{}", sent.body);
    assert_eq!(sent.json()["error"], code, "{}", sent.body);
    assert_eq!(fx.bytes(), before, "the file changed");
    fx.assert_leak_free(&sent, KNOWN);
    sent.json()
}

const CANARY: &str = "zq-create-canary";

/// P2: an unlisted key, a missing name or revision and a wrong type each get
/// one fixed 422 that never quotes the body.
#[test]
fn p2_a_malformed_body_gets_fixed_text_that_does_not_echo() {
    let fx = Fixture::new(Setup::default());
    let rev = fx.revision();
    let bodies = [
        json!({"name": CANARY, "backends": ["*"], "revision": rev, CANARY: 1}),
        json!({"backends": ["*"], "revision": rev, "x": CANARY}),
        json!({"name": CANARY, "backends": ["*"]}),
        json!({"name": CANARY, "backends": CANARY, "revision": rev}),
        json!({"name": CANARY, "backends": ["*"], "revision": rev, "rate_limit": CANARY}),
    ];
    let mut texts = Vec::new();
    for body in bodies {
        let sent = fx.post(Call::new(&body));
        assert_eq!(
            sent.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{}",
            sent.body
        );
        assert!(!sent.body.contains(CANARY), "{}", sent.body);
        fx.assert_leak_free(&sent, KNOWN);
        texts.push(sent.body);
    }
    assert!(texts.windows(2).all(|w| w[0] == w[1]), "not one fixed text");
}

/// P4: a name already in the file is 409 `name_taken`.
#[test]
fn p4_a_taken_name_is_refused() {
    let fx = Fixture::new(Setup::default());
    refused(&fx, &fx.body("root"), StatusCode::CONFLICT, "name_taken");
    assert!(fx.records("config_key_create_intent").is_empty());
}

/// P3: each precondition alone.
#[test]
fn p3_each_precondition_refuses_alone() {
    let absent = Fixture::new(Setup {
        file: false,
        ..Setup::default()
    });
    refused(
        &absent,
        &json!({"name":"a","backends":["*"],"revision":"x"}),
        StatusCode::CONFLICT,
        "no_config_file",
    );
    let off = Fixture::new(Setup {
        reload: false,
        ..Setup::default()
    });
    let sent = off.post(Call::new(&off.body("a")));
    assert_eq!(
        sent.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        sent.body
    );
    let broken = Fixture::new(Setup::default());
    let body = broken.body("a");
    std::fs::write(broken.path(), "backends: [\n").expect("break");
    let sent = broken.post(Call::new(&body));
    assert_eq!(
        sent.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        sent.body
    );
    let stale = Fixture::new(Setup::default());
    let mut body = stale.body("a");
    body["revision"] = json!("0000");
    let answer = refused(&stale, &body, StatusCode::CONFLICT, "stale");
    assert_eq!(answer["current"], stale.revision());
}

/// P3 combined: the earlier refusal wins.
#[test]
fn p3_combined_faults_answer_the_earlier_refusal() {
    let stale = |fx: &Fixture, name: &str| {
        let mut b = fx.body(name);
        b["revision"] = json!("0000");
        b
    };
    let absent = Fixture::new(Setup {
        file: false,
        ..Setup::default()
    });
    refused(
        &absent,
        &stale(&absent, "a"),
        StatusCode::CONFLICT,
        "no_config_file",
    );
    let off = Fixture::new(Setup {
        reload: false,
        ..Setup::default()
    });
    let sent = off.post(Call::new(&stale(&off, "a")));
    assert_eq!(
        sent.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        sent.body
    );
    let sent = off.post(Call::new(&off.body("root")));
    assert_eq!(
        sent.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        sent.body
    );
    let taken = Fixture::new(Setup::default());
    refused(
        &taken,
        &stale(&taken, "root"),
        StatusCode::CONFLICT,
        "name_taken",
    );
    let gone = Fixture::new(Setup {
        file: false,
        ..Setup::default()
    });
    refused(
        &gone,
        &gone.body("root"),
        StatusCode::CONFLICT,
        "no_config_file",
    );
    let broken = Fixture::new(Setup::default());
    let body = stale(&broken, "a");
    std::fs::write(broken.path(), "backends: [\n").expect("break");
    let sent = broken.post(Call::new(&body));
    assert_eq!(
        sent.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        sent.body
    );
}

/// A3: no audit log (auth on, and auth off) is 503 `audit_unavailable`.
#[test]
fn a3_no_audit_log_refuses_the_write() {
    let on = Fixture::new(Setup {
        audit_log: false,
        ..Setup::default()
    });
    refused(
        &on,
        &on.body("a"),
        StatusCode::SERVICE_UNAVAILABLE,
        "audit_unavailable",
    );
    let mut running = Setup::default().running;
    running.enabled = false;
    let off = Fixture::new(Setup {
        audit_log: false,
        running,
        ..Setup::default()
    });
    refused(
        &off,
        &off.body("a"),
        StatusCode::SERVICE_UNAVAILABLE,
        "audit_unavailable",
    );
}

/// F2: the first key beside a lone bearer flips the gateway to multi-user:
/// 409 `restart_required`, nothing written, no intent.
#[test]
fn f2_a_key_that_flips_the_mode_is_refused_before_the_write() {
    let mut running = Setup::default().running;
    running.api_keys.clear();
    running.single_user = true;
    running.bearer_token = Some("a-bearer".into());
    let text =
        "secrets:\n  store: files\nbackends: {}\nauth:\n  enabled: true\n  single_user: true\n"
            .to_owned();
    let fx = Fixture::new(Setup {
        text,
        running,
        ..Setup::default()
    });
    refused(
        &fx,
        &fx.body("first"),
        StatusCode::CONFLICT,
        "restart_required",
    );
    assert!(fx.records("config_key_create_intent").is_empty());
}

/// P5: a pattern the loader refuses, and a bad name, are 422 naming the
/// field and never the value.
#[test]
fn p5_validation_refusals_name_the_field_not_the_value() {
    let fx = Fixture::new(Setup::default());
    let cases = [
        ("backends", json!({"backends": ["a*b-zq"]})),
        ("allowed_tools", json!({"allowed_tools": ["a*b-zq"]})),
        ("denied_tools", json!({"denied_tools": ["a*b-zq"]})),
        ("name", json!({"name": " zq-padded "})),
    ];
    for (field, patch) in cases {
        let mut body = fx.body("fine");
        body.as_object_mut()
            .expect("object")
            .extend(patch.as_object().expect("object").clone());
        let answer = refused(
            &fx,
            &body,
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_field",
        );
        assert_eq!(answer["field"], field);
        assert!(!answer.to_string().contains("zq"), "{answer}");
    }
}

/// P5 duplicate principal: an existing key whose explicit principal equals
/// the one the new digest derives is refused by the writer's candidate check.
#[test]
fn p5_a_duplicate_principal_is_a_reload_refusal_with_fixed_text() {
    let derived = crate::gateway::auth::configured_key_principal(
        None,
        &crate::config::parse_api_key_digest(&spec(KNOWN)).expect("digest"),
    );
    let extra = format!("      principal: \"{}\"\n", derived.storage_form());
    let text = yaml_of(&[root_item(), item("twin", "twin-secret", &extra)]);
    let fx = Fixture::new(Setup {
        text,
        ..Setup::default()
    });
    refused(&fx, &fx.body("new"), StatusCode::CONFLICT, "reload_refused");
    assert_eq!(fx.records("config_key_create_intent").len(), 1);
}

const NOW: u64 = 1_793_880_000;

fn at(secs: u64) -> String {
    chrono::DateTime::from_timestamp(i64::try_from(secs).expect("secs"), 0)
        .expect("time")
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// P6: an expiry at or before now is 422 naming `expires_at`; one second
/// after is accepted.
#[test]
fn p6_an_expiry_not_after_now_is_refused() {
    let _clock = crate::clock::test_clock::at_secs(NOW);
    let fx = Fixture::new(Setup::default());
    for when in [NOW, NOW - 3600] {
        let mut body = fx.body("short");
        body["expires_at"] = json!(at(when));
        let answer = refused(
            &fx,
            &body,
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_field",
        );
        assert_eq!(answer["field"], "expires_at");
    }
    let mut body = fx.body("short");
    body["expires_at"] = json!(at(NOW + 1));
    assert_eq!(fx.post(Call::new(&body)).status, StatusCode::CREATED);
}

/// P6 under the lock: an expiry still ahead when the route checks, but past
/// when the writer holds the lock, is refused. The test holds the config lock
/// until the route says it is about to ask for it, then moves the clock and
/// lets go, so only a clock read made under the lock sees the later time.
#[test]
fn p6_the_clock_is_read_again_under_the_lock() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let _clock = crate::clock::test_clock::at_secs(NOW);
    let fx = Fixture::new(Setup::default());
    let mut body = fx.body("late");
    body["expires_at"] = json!(at(NOW + 60));
    let reached = Arc::new(tokio::sync::Notify::new());
    let fired = Arc::new(AtomicBool::new(false));
    let (ping, flag) = (Arc::clone(&reached), Arc::clone(&fired));
    let mut call = Call::new(&body);
    call.before_lock = Some(BeforeLock(Arc::new(move || {
        flag.store(true, Ordering::SeqCst);
        ping.notify_one();
    })));
    let before = fx.bytes();
    let later = std::cell::RefCell::new(None);
    let sent = fx.rt.block_on(async {
        let held = crate::config_persistence::lock::lock_config(
            &fx.path(),
            std::time::Instant::now() + std::time::Duration::from_secs(30),
        )
        .await
        .expect("the test holds the lock");
        let advance = async {
            // A hang guard only: it never decides pass or fail in a normal run.
            tokio::time::timeout(std::time::Duration::from_secs(60), reached.notified())
                .await
                .expect("the route never reached the lock; a hung row is not a red");
            *later.borrow_mut() = Some(crate::clock::test_clock::at_secs(NOW + 120));
            drop(held);
        };
        tokio::join!(fx.send(call), advance).0
    });
    assert!(fired.load(Ordering::SeqCst), "the route never signalled");
    assert_eq!(
        sent.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{}",
        sent.body
    );
    assert_eq!(sent.json()["field"], "expires_at");
    assert_eq!(fx.bytes(), before);
}

/// P7: a list or `auth` keyedit cannot edit in place is 409 `not_written`
/// with the file path and the hash-key steps.
#[test]
fn p7_keyedit_refusals_are_not_written_with_hand_steps() {
    let anchored = format!(
        "secrets:\n  store: files\nbackends: {{}}\nauth:\n  enabled: true\n  api_keys: &keys\n{}",
        root_item()
    );
    let flow =
        "secrets:\n  store: files\nbackends: {}\nauth: {enabled: true, api_keys: []}\n".to_owned();
    let anchored_auth = format!(
        "secrets:\n  store: files\nbackends: {{}}\nauth: &a\n  enabled: true\n  api_keys:\n{}",
        root_item()
    );
    for text in [anchored, flow, anchored_auth] {
        let fx = Fixture::new(Setup {
            text,
            ..Setup::default()
        });
        let answer = refused(&fx, &fx.body("hand"), StatusCode::CONFLICT, "not_written");
        let text = answer.to_string();
        assert!(text.contains("mcp-gateway hash-key"), "{text}");
        assert!(text.contains(&fx.path().display().to_string()), "{text}");
    }
    let _ = ROOT;
}

/// A4: an audit append that fails, and separately one whose fsync fails, each
/// refuse the write: 503 `audit_unavailable`, the file byte-identical, no
/// secret.
#[test]
fn a4_a_failed_intent_append_or_fsync_refuses_the_write() {
    use crate::security::transparency_log::rotation_fault::WriteFault;
    for fault in [WriteFault::WriteError, WriteFault::SyncError] {
        let fx = Fixture::new(Setup::default());
        let log = fx.state.transparency_log.clone().expect("an audit log");
        log.arm_write_fault(Some(fault));
        refused(
            &fx,
            &fx.body("a"),
            StatusCode::SERVICE_UNAVAILABLE,
            "audit_unavailable",
        );
        assert_eq!(
            log.write_faults_fired(),
            1,
            "{fault:?} never reached the intent"
        );
    }
}

/// A4 success: the intent's base revision is the original file's.
#[test]
fn a4_the_intent_base_is_the_original_revision() {
    let fx = Fixture::new(Setup::default());
    let original = fx.revision();
    assert_eq!(
        fx.post(Call::new(&fx.body("a"))).status,
        StatusCode::CREATED
    );
    let intents = fx.records("config_key_create_intent");
    assert_eq!(intents.len(), 1, "{}", fx.audit_text());
    assert_eq!(intents[0]["base_revision"], original);
    assert_ne!(fx.revision(), original);
}
