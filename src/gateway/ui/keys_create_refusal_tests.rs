// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `POST /ui/api/keys`, the rows that refuse: the strict body, the
//! preconditions in their order, the validation that names a field, the
//! expiry, the audit posture, the multi-user flip and the keyedit refusals.
//! Every refusal leaves the file byte-identical and the answer free of the
//! secret and its digest.

use axum::http::StatusCode;
use serde_json::{Value, json};

use super::keys_create_fixture_tests::{
    Call, Fixture, KNOWN, ROOT, Sent, Setup, item, root_item, spec, yaml_of,
};

/// How far a refused request got. Only an audit append that itself failed may
/// have left its intent line; every other refusal came before the writer
/// recorded one.
#[derive(Clone, Copy)]
enum Reached {
    BeforeWriter,
    AuditAppend,
}

/// The fixed answer of `{"error": code}`.
fn code(code: &str) -> Value {
    json!({ "error": code })
}

/// The fixed answer naming a field the loader or the clock refused.
fn invalid_field(field: &str) -> Value {
    json!({"error": "invalid_field", "field": field, "message": "the value is not accepted"})
}

/// The fixed answer of a missing reload or an unloadable gateway.yaml.
fn reload_off() -> Value {
    code("reload is off or gateway.yaml could not be loaded")
}

/// The one assertion every refusal row ends in: the status, the whole fixed
/// body byte for byte, gateway.yaml byte-identical, and no intent unless the
/// refusal is the intent append's own. L1 (no secret or digest anywhere) ran
/// inside `post`.
fn assert_refusal(
    fx: &Fixture,
    before: &[u8],
    sent: &Sent,
    (status, expected): (StatusCode, &Value),
    reached: Reached,
) {
    assert_eq!(sent.status, status, "{}", sent.body);
    assert_eq!(sent.body, expected.to_string(), "not the fixed body");
    assert_eq!(fx.bytes(), before, "the file changed");
    if matches!(reached, Reached::BeforeWriter) {
        let intents = fx.records("config_key_create_intent");
        assert!(intents.is_empty(), "an intent was recorded: {intents:?}");
    }
}

/// Posts `body`, then runs [`assert_refusal`] for a refusal before the writer.
fn refused(fx: &Fixture, body: &Value, status: StatusCode, expected: &Value) -> Value {
    refused_at(fx, body, (status, expected), Reached::BeforeWriter)
}

fn refused_at(
    fx: &Fixture,
    body: &Value,
    (status, expected): (StatusCode, &Value),
    reached: Reached,
) -> Value {
    let before = fx.bytes();
    let sent = fx.post(Call::new(body));
    assert_refusal(fx, &before, &sent, (status, expected), reached);
    sent.json()
}

const CANARY: &str = "zq-create-canary";

/// The one answer every unreadable body gets.
fn invalid_body() -> Value {
    json!({
        "error": "invalid_body",
        "message": "the body must be {\"name\", \"backends\", \"revision\"} and the optional \
                    allowed_tools, denied_tools, admin, rate_limit and expires_at, and nothing else",
    })
}

/// P2: a key outside the list, a missing name or revision and a wrong type
/// each get one fixed 422 that never quotes the body.
#[test]
fn p2_a_malformed_body_gets_fixed_text_that_does_not_echo() {
    let fx = Fixture::new(Setup::default());
    let rev = fx.revision();
    let bodies = [
        json!({"name": CANARY, "backends": ["*"], "revision": rev, CANARY: 1}),
        // Only the name is missing: no other fault to refuse first.
        json!({"backends": [CANARY], "revision": rev}),
        json!({"name": CANARY, "backends": ["*"]}),
        json!({"name": CANARY, "backends": CANARY, "revision": rev}),
        json!({"name": CANARY, "backends": ["*"], "revision": rev, "rate_limit": CANARY}),
    ];
    let expected = invalid_body();
    for body in bodies {
        let before = fx.bytes();
        let sent = fx.post(Call::new(&body));
        let status = StatusCode::UNPROCESSABLE_ENTITY;
        assert_refusal(
            &fx,
            &before,
            &sent,
            (status, &expected),
            Reached::BeforeWriter,
        );
        assert!(!sent.body.contains(CANARY), "{}", sent.body);
    }
}

/// P4: a name already in the file is 409 `name_taken`.
#[test]
fn p4_a_taken_name_is_refused() {
    let fx = Fixture::new(Setup::default());
    refused(
        &fx,
        &fx.body("root"),
        StatusCode::CONFLICT,
        &code("name_taken"),
    );
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
        &code("no_config_file"),
    );
    let off = Fixture::new(Setup {
        reload: false,
        ..Setup::default()
    });
    let unavailable = StatusCode::SERVICE_UNAVAILABLE;
    refused(&off, &off.body("a"), unavailable, &reload_off());
    let broken = Fixture::new(Setup::default());
    let body = broken.body("a");
    std::fs::write(broken.path(), "backends: [\n").expect("break");
    refused(&broken, &body, unavailable, &reload_off());
    let stale = Fixture::new(Setup::default());
    let mut body = stale.body("a");
    body["revision"] = json!("0000");
    let current = json!({"error": "stale", "current": stale.revision()});
    refused(&stale, &body, StatusCode::CONFLICT, &current);
}

/// P3 combined: the earlier refusal wins.
#[test]
fn p3_combined_faults_answer_the_earlier_refusal() {
    let stale = |fx: &Fixture, name: &str| {
        let mut b = fx.body(name);
        b["revision"] = json!("0000");
        b
    };
    let (conflict, unavailable) = (StatusCode::CONFLICT, StatusCode::SERVICE_UNAVAILABLE);
    let absent = Fixture::new(Setup {
        file: false,
        ..Setup::default()
    });
    let none = code("no_config_file");
    refused(&absent, &stale(&absent, "a"), conflict, &none);
    let off = Fixture::new(Setup {
        reload: false,
        ..Setup::default()
    });
    refused(&off, &stale(&off, "a"), unavailable, &reload_off());
    refused(&off, &off.body("root"), unavailable, &reload_off());
    let taken = Fixture::new(Setup::default());
    refused(
        &taken,
        &stale(&taken, "root"),
        conflict,
        &code("name_taken"),
    );
    let gone = Fixture::new(Setup {
        file: false,
        ..Setup::default()
    });
    refused(&gone, &gone.body("root"), conflict, &none);
    let broken = Fixture::new(Setup::default());
    let body = stale(&broken, "a");
    std::fs::write(broken.path(), "backends: [\n").expect("break");
    refused(&broken, &body, unavailable, &reload_off());
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
        &code("audit_unavailable"),
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
        &code("audit_unavailable"),
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
        &code("restart_required"),
    );
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
        let status = StatusCode::UNPROCESSABLE_ENTITY;
        let answer = refused(&fx, &body, status, &invalid_field(field));
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
    // The candidate check runs before the intent is appended.
    refused(
        &fx,
        &fx.body("new"),
        StatusCode::CONFLICT,
        &code("reload_refused"),
    );
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
        let status = StatusCode::UNPROCESSABLE_ENTITY;
        refused(&fx, &body, status, &invalid_field("expires_at"));
    }
    let mut body = fx.body("short");
    body["expires_at"] = json!(at(NOW + 1));
    assert_eq!(fx.post(Call::new(&body)).status, StatusCode::CREATED);
}

/// P6b: the expiry checked is the expiry written. gateway.yaml holds whole
/// seconds, so half a second after now is refused rather than stored
/// truncated to now (a key that would never authenticate), and a fractional
/// expiry further ahead is stored as the whole second it was checked at.
#[test]
fn p6b_the_expiry_checked_is_the_expiry_written() {
    let _clock = crate::clock::test_clock::at_secs(NOW);
    let fx = Fixture::new(Setup::default());
    let half_past = |secs: u64| at(secs).replace('Z', ".500Z");
    let mut body = fx.body("half");
    body["expires_at"] = json!(half_past(NOW));
    let status = StatusCode::UNPROCESSABLE_ENTITY;
    refused(&fx, &body, status, &invalid_field("expires_at"));
    let mut body = fx.body("later");
    body["expires_at"] = json!(half_past(NOW + 1));
    assert_eq!(fx.post(Call::new(&body)).status, StatusCode::CREATED);
    let file = String::from_utf8(fx.bytes()).expect("gateway.yaml is UTF-8");
    assert!(file.contains(&at(NOW + 1)), "{file}");
}

/// P6 under the lock: an expiry still ahead when the route checks, but past
/// when the writer holds the lock, is refused. The test holds the config lock
/// until the writer itself is waiting on it (the lock's own waiter count, a
/// signal only the writer's wait raises), then moves the clock and lets go, so
/// only a clock read made under the lock sees the later time.
#[test]
fn p6_the_clock_is_read_again_under_the_lock() {
    use crate::config_persistence::lock::{lock_config, lock_path, waiters_for_test};
    use std::time::{Duration, Instant};
    let _clock = crate::clock::test_clock::at_secs(NOW);
    let fx = Fixture::new(Setup::default());
    let mut body = fx.body("late");
    body["expires_at"] = json!(at(NOW + 60));
    let lock = lock_path(&crate::identity_grants::journal::resolved(&fx.path()));
    let before = fx.bytes();
    let (later, waited) = (std::cell::RefCell::new(None), std::cell::Cell::new(false));
    let sent = fx.post_driven(Call::new(&body), |send| async {
        let held = lock_config(&fx.path(), Instant::now() + Duration::from_secs(30))
            .await
            .expect("the test holds the lock");
        let advance = async {
            // A hang guard only: it never decides pass or fail in a normal run.
            let wait = async {
                while waiters_for_test(&lock) == 0 {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            };
            tokio::time::timeout(Duration::from_secs(60), wait)
                .await
                .expect("the writer never waited on the lock; a hung row is not a red");
            waited.set(true);
            *later.borrow_mut() = Some(crate::clock::test_clock::at_secs(NOW + 120));
            drop(held);
        };
        tokio::join!(send, advance).0
    });
    assert!(waited.get(), "premise: the writer's lock wait never began");
    let status = StatusCode::UNPROCESSABLE_ENTITY;
    let expected = invalid_field("expires_at");
    assert_refusal(
        &fx,
        &before,
        &sent,
        (status, &expected),
        Reached::BeforeWriter,
    );
}

/// The 409 of a file keyedit cannot edit in place: its path and the hand steps.
fn not_written(fx: &Fixture) -> Value {
    let path = fx.path().display().to_string();
    json!({"error": "not_written", "message": format!(
        "{path} cannot be edited in place; nothing was written. Run \
         `mcp-gateway hash-key` on the new key, add an entry to auth.api_keys \
         with the key_sha256 it prints, then reload."
    )})
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
        refused(
            &fx,
            &fx.body("hand"),
            StatusCode::CONFLICT,
            &not_written(&fx),
        );
    }
}

/// P7b: a block-style `auth` whose only flaw is a flow-style `api_keys` list
/// is refused for that list alone.
#[test]
fn p7b_a_flow_style_key_list_under_a_block_auth_is_not_written() {
    let listed = format!(
        "[{{name: root, key_sha256: \"{}\", backends: [\"*\"], admin: true}}]",
        spec(ROOT)
    );
    let text = format!(
        "secrets:\n  store: files\nbackends: {{}}\nauth:\n  enabled: true\n  api_keys: {listed}\n"
    );
    let fx = Fixture::new(Setup {
        text,
        ..Setup::default()
    });
    refused(
        &fx,
        &fx.body("hand"),
        StatusCode::CONFLICT,
        &not_written(&fx),
    );
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
        let target = crate::identity_grants::journal::resolved(&fx.path());
        crate::config_reload::write_order::take(&target);
        log.arm_write_fault(Some(fault));
        // The append itself failed: its line may or may not be on disk.
        let status = StatusCode::SERVICE_UNAVAILABLE;
        let expected = code("audit_unavailable");
        refused_at(
            &fx,
            &fx.body("a"),
            (status, &expected),
            Reached::AuditAppend,
        );
        assert_eq!(
            log.write_faults_fired(),
            1,
            "{fault:?} never reached the intent"
        );
        // The writer records "intent" only after the append returned: a
        // failed append or fsync leaves no such step, and no commit follows.
        let steps = crate::config_reload::write_order::take(&target);
        assert!(steps.is_empty(), "{fault:?}: the writer went on: {steps:?}");
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
