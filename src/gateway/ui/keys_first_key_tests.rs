// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Creating a key on a gateway with one credential: the route keeps the new
//! entry on disk for the next start, refuses another create meanwhile, and
//! the list and gateway reads report what is pending. Every `post` also runs
//! the shared leak check.

use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;

use super::keys_create_fixture_tests::{Call, Fixture, KNOWN, Sent, Setup, admin_client};
use crate::config::{AuthConfig, Config};

/// The single operator's token in these rows.
const BEARER: &str = "first-key-route-bearer-0123456789abcdef";
/// What a refused second create would have handed out.
const OTHER: &str = "mcpgw_first-key-route-second-0123456789abcd";

/// gateway.yaml as `init` leaves it for one operator, after `extra`.
fn starter_text(extra: &str) -> String {
    format!(
        "{extra}secrets:\n  store: files\nbackends: {{}}\nauth:\n  enabled: true\n  single_user: true\n  bearer_token: \"{BEARER}\"\n"
    )
}

fn starter(extra: &str) -> Setup {
    Setup {
        text: starter_text(extra),
        running: AuthConfig {
            enabled: true,
            single_user: true,
            bearer_token: Some(BEARER.into()),
            ..AuthConfig::default()
        },
        ..Setup::default()
    }
}

/// `secret`'s digest spec, worked out here rather than by the route.
fn digest_of(secret: &str) -> String {
    format!("sha256:{}", crate::hashing::sha256_hex(secret.as_bytes()))
}

/// How this test binary would be started again on the fixture's file; a
/// Windows gateway has no such command, so the answer carries none there.
fn start_command(fx: &Fixture) -> Value {
    if cfg!(windows) {
        return Value::Null;
    }
    // The running test binary's path, named the way the crate's spawn guard
    // requires (this builds a command and never runs it).
    let binary = crate::test_home::test_binary();
    let exe = std::path::Path::new(binary.get_program());
    let config = std::path::absolute(fx.path()).expect("an absolute config path");
    json!(format!(
        "'{}' serve --config '{}'",
        exe.display(),
        config.display()
    ))
}

/// Asserts `value` is an object with exactly the members `names`, less
/// `start_command` on a platform that has none.
fn members(value: &Value, names: &[&str]) {
    let object = value.as_object().expect("an object");
    let names: Vec<&str> = (names.iter().copied())
        .filter(|name| !(cfg!(windows) && *name == "start_command"))
        .collect();
    assert_eq!(object.len(), names.len(), "{value}");
    for name in names {
        assert!(object.contains_key(name), "no {name}: {value}");
    }
}

/// The shared 409: exactly its three members, the code, the waiting keys
/// by name, and a message that names each of them and claims nothing about a
/// restart.
fn restart_pending(answer: &Value, waiting: &[&str]) {
    members(answer, &["waiting_keys", "message", "error"]);
    assert_eq!(answer["error"], "restart_pending", "{answer}");
    assert_eq!(answer["waiting_keys"], json!(waiting), "{answer}");
    let message = answer["message"].as_str().unwrap_or_default();
    for name in waiting {
        assert!(message.contains(name), "{message}");
    }
    assert!(!message.to_lowercase().contains("restart"), "{message}");
}

fn create_first(fx: &Fixture) -> Sent {
    let sent = fx.post(Call::new(&fx.body("first")));
    assert_eq!(sent.status, StatusCode::CREATED, "{}", sent.body);
    sent
}

/// The admin's read of the gateway page.
fn gateway_read(fx: &Fixture) -> Value {
    let request = Request::builder()
        .uri(super::routes::UI_GATEWAY)
        .extension(fx.live.generation())
        .extension(admin_client())
        .body(Body::empty())
        .expect("request");
    fx.rt.block_on(async {
        let response = super::admin_audit::audited_api_router(&fx.state)
            .with_state(Arc::clone(&fx.state))
            .oneshot(request)
            .await
            .expect("infallible");
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), 1 << 20).await.expect("body");
        serde_json::from_slice(&bytes).expect("json")
    })
}

fn reload_context(fx: &Fixture) -> Arc<crate::config_reload::ReloadContext> {
    fx.state.meta_mcp.reload_context().expect("reload is on")
}

/// One admin call through the UI router: its status and JSON answer.
fn call(fx: &Fixture, method: &str, uri: &str, body: &Value) -> (StatusCode, Value) {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .extension(fx.live.generation())
        .extension(admin_client())
        .body(Body::from(body.to_string()))
        .expect("request");
    fx.rt.block_on(async {
        let response = super::admin_audit::audited_api_router(&fx.state)
            .with_state(Arc::clone(&fx.state))
            .oneshot(request)
            .await
            .expect("infallible");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1 << 20).await.expect("body");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    })
}

fn revoke(fx: &Fixture, name: &str) -> (StatusCode, Value) {
    let body = json!({"revision": fx.revision()});
    call(fx, "DELETE", &format!("/ui/api/keys/{name}"), &body)
}

/// A settings save of one plain field.
fn save_environment(fx: &Fixture, value: &str) -> (StatusCode, Value) {
    let field = json!({"field": "environment", "value": {"set": value}});
    let body = json!({"base_revision": fx.revision(), "fields": [field]});
    call(fx, "POST", super::routes::UI_SETTINGS, &body)
}

/// Hand-writes `text` and reloads it, as an operator editing the file does.
fn by_hand(fx: &Fixture, text: &str) {
    crate::gateway::test_helpers::write_owner_only(fx.path(), text).expect("hand edit");
    drop(fx.rt.block_on(reload_context(fx).reload_outcome()));
}

/// One `auth.api_keys` item for `name` under `secret`'s digest.
fn key_item(name: &str, secret: &str) -> String {
    format!(
        "    - name: {name}\n      key_sha256: \"{}\"\n      backends: [\"*\"]\n",
        digest_of(secret)
    )
}

/// F9 and L6 (undo): revoking the pending key through the route succeeds,
/// takes its entry out, ends the wait, and the next save goes through.
#[test]
fn f9_revoking_the_waiting_key_ends_the_wait() {
    let fx = Fixture::new(starter(""));
    create_first(&fx);
    let (status, answer) = revoke(&fx, "first");
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert!(fx.file_keys().is_empty(), "{}", fx.text());
    assert_eq!(fx.live.waiting_keys(), None);
    let (status, answer) = save_environment(&fx, "after-undo");
    assert_eq!(status, StatusCode::OK, "{answer}");
}

/// L7 and R7 (two keys pending after a hand edit, unsupported to revoke
/// one): revoking one answers the shared 409 naming both, since nothing was
/// written; with several waiting the message points at a change that takes
/// out all of them (a hand edit), and the file stays as it is.
#[test]
fn l7_revoking_one_of_two_waiting_keys_is_restart_pending() {
    let fx = Fixture::new(starter(""));
    let both = format!(
        "{}  api_keys:\n{}{}",
        fx.text(),
        key_item("first", KNOWN),
        key_item("second", OTHER)
    );
    by_hand(&fx, &both);
    assert_eq!(
        fx.live.waiting_keys(),
        Some(vec!["first".to_owned(), "second".to_owned()]),
        "premise: both keys pending"
    );
    let before = fx.bytes();
    let (status, answer) = revoke(&fx, "first");
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    restart_pending(&answer, &["first", "second"]);
    let message = answer["message"].as_str().unwrap_or_default();
    assert!(message.contains("hand"), "{message}");
    assert_eq!(fx.bytes(), before, "the file changed");
}

/// L8: with the token and one key running (two credentials), revoking the
/// key would leave one credential: refused with `restart_required` as before.
#[test]
fn l8_a_status_changing_revoke_keeps_restart_required() {
    let mut setup = starter("");
    setup.text = format!("{}  api_keys:\n{}", setup.text, key_item("first", KNOWN));
    setup.running.api_keys = vec![crate::config::ApiKeyConfig {
        name: "first".into(),
        key_sha256: Some(digest_of(KNOWN)),
        backends: vec!["*".into()],
        ..Default::default()
    }];
    let fx = Fixture::new(setup);
    let before = fx.bytes();
    let (status, answer) = revoke(&fx, "first");
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    assert_eq!(
        answer,
        json!({"error": "restart_required", "revoked": false})
    );
    assert_eq!(fx.bytes(), before, "the file changed");
}

/// L5 (the settings half): a save that keeps the pending key is refused with
/// the shared 409 naming it, and nothing is written.
#[test]
fn l5_a_settings_save_while_a_key_waits_is_restart_pending() {
    let fx = Fixture::new(starter(""));
    create_first(&fx);
    let before = fx.bytes();
    let (status, answer) = save_environment(&fx, "while-pending");
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    restart_pending(&answer, &["first"]);
    assert_eq!(fx.bytes(), before, "the file changed");
}

/// The window before a reload: a key added to gateway.yaml by hand that no
/// reload has read yet. A settings save then is refused for that key, and the
/// answer names it although the gateway's own record of the last reload names
/// nothing yet: the names come from the file, never from that record.
#[test]
fn l5_a_save_before_the_reload_names_the_hand_added_key() {
    let fx = Fixture::new(starter(""));
    let edited = format!("{}  api_keys:\n{}", fx.text(), key_item("late", OTHER));
    crate::gateway::test_helpers::write_owner_only(fx.path(), &edited).expect("hand edit");
    assert_eq!(
        fx.live.waiting_keys(),
        None,
        "premise: nothing reloaded yet"
    );
    let before = fx.bytes();
    let (status, answer) = save_environment(&fx, "before-reload");
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    restart_pending(&answer, &["late"]);
    assert_eq!(fx.bytes(), before, "the file changed");
}

/// L5 (the backend half): editing a backend while the key is pending keeps
/// the key, so it gets the same 409 and the file stays as it is. The
/// backend is written as a block, which the in-place editor can change.
#[test]
fn l5_a_backend_edit_while_a_key_waits_is_restart_pending() {
    let mut setup = starter("");
    setup.text = setup.text.replace(
        "backends: {}\n",
        "backends:\n  a:\n    http_url: \"http://127.0.0.1:9/mcp\"\n",
    );
    let fx = Fixture::new(setup);
    create_first(&fx);
    let before = fx.bytes();
    let body = json!({"description": "edited while pending"});
    let (status, answer) = call(&fx, "PATCH", "/ui/api/backends/a", &body);
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    restart_pending(&answer, &["first"]);
    assert_eq!(fx.bytes(), before, "the file changed");
}

/// F1: a 201 that is never cached, with exactly the members a kept key
/// answers (no restart advice, no start command); the entry on disk carries
/// the digest of the secret handed out; the admin record says which key,
/// what was done, and that it is pending.
#[test]
fn f1_the_first_key_is_created_and_held_for_a_restart() {
    let fx = Fixture::new(starter(""));
    let sent = create_first(&fx);
    assert_eq!(sent.cache_control.as_deref(), Some("no-store"));
    let answer = sent.json();
    members(
        &answer,
        &["message", "secret", "revision", "pending_restart", "name"],
    );
    assert_eq!(answer["name"], "first");
    assert_eq!(answer["secret"], KNOWN);
    assert_eq!(answer["revision"], fx.revision());
    assert_eq!(answer["pending_restart"], true);
    // The one route answer that may speak of a restart (FIRSTKEY.1).
    let message = answer["message"].as_str().unwrap_or_default();
    assert!(message.contains("restart"), "{answer}");
    let keys = fx.file_keys();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].name, "first");
    assert_eq!(
        keys[0].key_sha256.as_deref(),
        Some(digest_of(KNOWN).as_str())
    );
    let actions = fx.records("admin_action");
    let ours: Vec<_> = actions.iter().filter(|r| r["method"] == "POST").collect();
    assert_eq!(ours.len(), 1, "{}", fx.audit_text());
    assert_eq!(ours[0]["key"], "first");
    assert_eq!(ours[0]["action"], "create");
    assert_eq!(ours[0]["pending_restart"], true);
    let intents = fx.records("config_key_create_intent");
    assert_eq!(intents.len(), 1, "{}", fx.audit_text());
    assert_eq!(intents[0]["who"], fx.who(&admin_client()));
}

/// The secret still fails, the token still administers, and the running
/// table is still empty, as it was before the create.
fn unchanged_until_restart(fx: &Fixture, when: &str) {
    let generation = fx.live.generation();
    let auth = generation.auth();
    assert!(auth.validate_token(KNOWN).is_none(), "{when}: key accepted");
    assert_eq!(
        auth.validate_token(BEARER).map(|c| c.admin),
        Some(true),
        "{when}: token lost admin"
    );
    assert!(auth.api_keys().is_empty(), "{when}: table changed");
}

/// F2: the kept key stays unusable whichever way the file is read again: a
/// plain reload, an unrelated edit made by hand, and the UI's reload button.
#[test]
fn f2_the_held_key_does_not_authenticate_on_any_reload_path() {
    let fx = Fixture::new(starter(""));
    create_first(&fx);
    unchanged_until_restart(&fx, "create");
    let context = reload_context(&fx);
    fx.rt
        .block_on(context.reload_outcome())
        .expect_err("refused again");
    unchanged_until_restart(&fx, "reload");
    let edited = format!("environment: \"edited\"\n{}", fx.text());
    crate::gateway::test_helpers::write_owner_only(fx.path(), &edited).expect("hand edit");
    fx.rt
        .block_on(context.reload_outcome())
        .expect_err("refused again");
    unchanged_until_restart(&fx, "edit");
    let ui = crate::config_reload::history::Source::Ui { who: String::new() };
    fx.rt
        .block_on(context.manual_reload_outcome(ui))
        .expect_err("refused again");
    unchanged_until_restart(&fx, "button");
}

/// F3: booting from what was written takes that very secret, serves more
/// than one principal, and keeps the token as admin.
#[test]
fn f3_a_start_from_the_written_file_accepts_the_same_secret() {
    let fx = Fixture::new(starter(""));
    create_first(&fx);
    let config = Config::load(Some(&fx.path())).expect("the written file starts");
    assert!(config.auth.implies_multi_user(false));
    let auth = crate::gateway::auth::ResolvedAuthConfig::from_config(
        &config.auth,
        crate::gateway::record_principal::TEST_RECORD_KEY,
    );
    assert_eq!(
        auth.validate_token(KNOWN).map(|c| c.name),
        Some("first".to_owned())
    );
    assert_eq!(auth.validate_token(BEARER).map(|c| c.admin), Some(true));
}

/// F4 and R7: creating another key before the restart is the shared 409
/// naming the pending key, whose message offers its revoke; nothing on disk
/// or in the audit log moves.
#[test]
fn f4_a_second_create_while_a_key_waits_is_restart_pending() {
    let fx = Fixture::new(starter(""));
    create_first(&fx);
    let before = fx.bytes();
    let mut call = Call::new(&fx.body("second"));
    call.known = Some(OTHER.to_owned());
    let sent = fx.post(call);
    assert_eq!(sent.status, StatusCode::CONFLICT, "{}", sent.body);
    let answer = sent.json();
    restart_pending(&answer, &["first"]);
    // One waiting key: the message names its revoke as the way back.
    let message = answer["message"].as_str().unwrap_or_default();
    assert!(message.to_lowercase().contains("revoke"), "{message}");
    assert_eq!(fx.bytes(), before, "the file changed");
    assert_eq!(fx.records("config_key_create_intent").len(), 1);
    assert_eq!(fx.file_keys().len(), 1);
}

/// F5: with several credentials already, a create answers its three members
/// and nothing about a restart.
#[test]
fn f5_an_ordinary_create_has_no_restart_keys() {
    let fx = Fixture::new(Setup::default());
    let sent = fx.post(Call::new(&fx.body("plain")));
    assert_eq!(sent.status, StatusCode::CREATED, "{}", sent.body);
    members(&sent.json(), &["revision", "secret", "name"]);
}

/// F6: when the file already carries something a fresh start would reject,
/// adding the first key is the route's ordinary reload refusal: no write, no
/// intent, nothing pending.
#[test]
fn f6_a_first_key_whose_start_is_refused_is_a_reload_refusal() {
    let fx = Fixture::new(starter("server:\n  replicas: 2\n  modern_protocol: true\n"));
    let before = fx.bytes();
    let sent = fx.post(Call::new(&fx.body("first")));
    assert_eq!(sent.status, StatusCode::CONFLICT, "{}", sent.body);
    assert_eq!(sent.json(), json!({"error": "reload_refused"}));
    assert_eq!(fx.bytes(), before, "the file changed");
    assert!(fx.records("config_key_create_intent").is_empty());
    assert_eq!(fx.live.waiting_keys(), None);
}

/// F8: the kept key's answer holds its secret exactly once; the leak check
/// inside `post` covers every other place.
#[test]
fn f8_the_held_answer_carries_the_secret_once() {
    let fx = Fixture::new(starter(""));
    let sent = create_first(&fx);
    assert_eq!(sent.json()["secret"], KNOWN);
    assert_eq!(sent.body.matches(KNOWN).count(), 1, "{}", sent.body);
}

/// K1: one operator whose only credential is a key adds a second one. The
/// list reports the new one as not in use yet and never used, the old one as
/// in use and never used; the gateway read names only the new one.
#[test]
fn k1_the_keys_list_shows_the_waiting_key_not_live() {
    let solo = "solo-key-route-secret";
    let text = format!(
        "secrets:\n  store: files\nbackends: {{}}\nauth:\n  enabled: true\n  single_user: true\n  api_keys:\n    - name: solo\n      key_sha256: \"{}\"\n      backends: [\"*\"]\n",
        digest_of(solo)
    );
    let running = AuthConfig {
        enabled: true,
        single_user: true,
        api_keys: vec![crate::config::ApiKeyConfig {
            name: "solo".into(),
            key_sha256: Some(digest_of(solo)),
            backends: vec!["*".into()],
            ..Default::default()
        }],
        ..AuthConfig::default()
    };
    let fx = Fixture::new(Setup {
        text,
        running,
        ..Setup::default()
    });
    let sent = fx.post(Call::new(&fx.body("second")));
    assert_eq!(sent.status, StatusCode::CREATED, "{}", sent.body);
    let listed = fx.get();
    let entry = |name: &str| {
        listed["keys"]
            .as_array()
            .and_then(|k| k.iter().find(|e| e["name"] == name))
            .cloned()
            .unwrap_or(Value::Null)
    };
    let (waiting, live) = (entry("second"), entry("solo"));
    assert_eq!(waiting["live"], false, "{listed}");
    assert_eq!(waiting["last_used"], Value::Null, "{listed}");
    assert_eq!(live["live"], true, "{listed}");
    assert_eq!(live["last_used"], Value::Null, "{listed}");
    let block = &gateway_read(&fx)["pending_restart"];
    assert_eq!(block["waiting_keys"], json!(["second"]), "{block}");
}

/// L1 (what is served): while the key is pending, the gateway read's restart
/// block carries the frozen flag, the pending key, the guidance line and the
/// command besides its field list, and nothing else.
#[test]
fn l1_the_gateway_read_serves_the_wait() {
    let fx = Fixture::new(starter(""));
    create_first(&fx);
    let block = gateway_read(&fx)["pending_restart"].clone();
    members(
        &block,
        &[
            "fields",
            "frozen",
            "restart_advice",
            "start_command",
            "waiting_keys",
        ],
    );
    assert_eq!(block["frozen"], true);
    assert_eq!(block["waiting_keys"], json!(["first"]));
    let fields = block["fields"].as_array().cloned().unwrap_or_default();
    assert!(fields.contains(&json!("auth.api_keys")), "{block}");
    assert_eq!(block["start_command"], start_command(&fx));
}

/// R10 on the settings route: the gateway runs the token and "first" (two
/// credentials); "first" was then taken out of gateway.yaml by hand. A save
/// on top of that file only removes a key yet changes the multi-user status,
/// so it is a 422 `invalid` whose message is the question's own sentence for
/// that case, never the loader's generic one, and claims nothing about a
/// restart. Nothing is written.
#[test]
fn r10_a_settings_save_that_only_removes_a_key_shows_its_own_sentence() {
    let running_key = crate::config::ApiKeyConfig {
        backends: vec!["*".into()],
        key_sha256: Some(digest_of(KNOWN)),
        name: "first".into(),
        ..Default::default()
    };
    let mut two_credentials = starter("");
    two_credentials.running.api_keys.push(running_key);
    two_credentials.text.push_str("  api_keys:\n");
    two_credentials.text.push_str(&key_item("first", KNOWN));
    let fx = Fixture::new(two_credentials);
    by_hand(&fx, &starter_text(""));
    let untouched = fx.bytes();
    let (code, body) = save_environment(&fx, "after-removal");
    assert_eq!(code, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["error"], "invalid", "{body}");
    let said = body["message"].as_str().unwrap_or_default();
    assert!(said.contains("multi-user"), "{said}");
    assert!(!said.contains("config loader"), "{said}");
    assert!(!said.to_lowercase().contains("restart"), "{said}");
    assert_eq!(fx.bytes(), untouched, "the save wrote gateway.yaml");
}

/// Two replicas with the task store on: a start the starter never refuses.
const START_FAULT: &str = "server:\n  replicas: 2\n  modern_protocol: true\n";

/// F4b: the waiting file was since broken by hand (a start fault beside the
/// key). A second create still gets the shared 409 for "first"; no bytes
/// move and no second intent is logged.
#[test]
fn f4b_a_second_create_on_a_broken_waiting_file_is_restart_pending() {
    let fx = Fixture::new(starter(""));
    create_first(&fx);
    by_hand(&fx, &format!("{START_FAULT}{}", fx.text()));
    let before = fx.bytes();
    let mut call = Call::new(&fx.body("second"));
    call.known = Some(OTHER.to_owned());
    let sent = fx.post(call);
    assert_eq!(sent.status, StatusCode::CONFLICT, "{}", sent.body);
    restart_pending(&sent.json(), &["first"]);
    assert_eq!(fx.bytes(), before, "the file changed");
    assert_eq!(fx.records("config_key_create_intent").len(), 1);
}

/// F11: several credentials already, and an unreloaded extra key ("late")
/// sits in the file. Names the running table lacks are not enough to call
/// it a pending first key: the next create is an ordinary 201.
#[test]
fn f11_a_hand_added_key_on_a_multi_user_gateway_is_no_pending_first_key() {
    let fx = Fixture::new(Setup::default());
    let edited = format!("{}{}", fx.text(), key_item("late", OTHER));
    crate::gateway::test_helpers::write_owner_only(fx.path(), &edited).expect("hand edit");
    let sent = fx.post(Call::new(&fx.body("plain")));
    assert_eq!(sent.status, StatusCode::CREATED, "{}", sent.body);
    members(&sent.json(), &["revision", "secret", "name"]);
}

/// F-U: the held create's journal mark fails. 500 `state_uncertain`, no
/// secret anywhere in the body, and a recovery text that does not say which
/// file survives but tells the admin what to do (including the hand-edit
/// way out). Once the next save puts the old file back, revoking "first"
/// answers exactly as revoking a name that never existed.
#[test]
fn fu_a_held_create_whose_journal_mark_fails_is_uncertain_without_a_secret() {
    use crate::config_persistence::journal::fault::{self, Fault};
    let fx = Fixture::new(starter(""));
    // The file the next writer puts back, and so the base its save names.
    let original = fx.revision();
    let armed = fault::set(&fx.path(), Fault::FailJournalMark);
    let sent = fx.post(Call::new(&fx.body("first")));
    assert_eq!(
        fault::fired(&fx.path()),
        1,
        "premise: the fault was reached"
    );
    drop(armed);
    assert_eq!(
        sent.status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "{}",
        sent.body
    );
    let answer = sent.json();
    members(&answer, &["error", "recovery"]);
    assert_eq!(answer["error"], "state_uncertain");
    assert!(!sent.body.contains(KNOWN), "{}", sent.body);
    let recovery = answer["recovery"].as_str().unwrap_or_default();
    assert!(recovery.contains("revoke"), "{recovery}");
    assert!(recovery.contains("by hand"), "{recovery}");
    assert!(recovery.contains("gateway.yaml"), "{recovery}");
    // A save made against the file before the create: the writer restores
    // that file first, then applies the save to it.
    let field = json!({"field": "environment", "value": {"set": "settles-it"}});
    let body = json!({"base_revision": original, "fields": [field]});
    let (status, answer) = call(&fx, "POST", super::routes::UI_SETTINGS, &body);
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert!(fx.file_keys().is_empty(), "{}", fx.text());
    assert_eq!(revoke(&fx, "first"), revoke(&fx, "never-there"));
}

/// R8: "first" and "second" both wait, and the file without "first" would
/// not start. The revoke answers 422 `invalid` carrying the start check's
/// reason: not `restart_required`, no restart wording, file untouched.
#[test]
fn r8_revoking_into_a_faulty_file_with_waiting_keys_is_invalid() {
    let fx = Fixture::new(starter(""));
    let both = format!(
        "{START_FAULT}{}  api_keys:\n{}{}",
        fx.text(),
        key_item("first", KNOWN),
        key_item("second", OTHER)
    );
    by_hand(&fx, &both);
    let before = fx.bytes();
    let (status, answer) = revoke(&fx, "first");
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{answer}");
    assert_eq!(answer["error"], "invalid", "{answer}");
    assert_eq!(answer["revoked"], false, "{answer}");
    let message = answer["message"].as_str().unwrap_or_default();
    assert!(message.contains("replicas"), "{message}");
    assert!(!message.to_lowercase().contains("restart"), "{message}");
    assert_eq!(fx.bytes(), before, "the file changed");
}
