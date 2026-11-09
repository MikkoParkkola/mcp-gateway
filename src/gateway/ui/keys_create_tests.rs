// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `POST /ui/api/keys`, the rows that create a key: the entry written, the
//! secret handed out once, the intent and admin records, and the source
//! pins that keep the secret out of the writer.

use std::sync::Arc;

use axum::http::StatusCode;
use serde_json::{Value, json};

use super::keys_create::BeforeLock;
use super::keys_create_fixture_tests::{
    Call, Fixture, KNOWN, Setup, admin_client, item, root_item, spec, yaml_of,
};

fn created(fx: &Fixture, body: &Value) -> super::keys_create_fixture_tests::Sent {
    let sent = fx.post(Call::new(body));
    assert_eq!(sent.status, StatusCode::CREATED, "{}", sent.body);
    sent
}

/// P1: every field non-default; the file gains one element holding them and
/// the secret's digest, the answer carries the secret once with no-store,
/// the secret authenticates, and GET lists the key live under the revision.
#[test]
fn p1_a_full_body_writes_the_entry_and_answers_the_secret_once() {
    let fx = Fixture::new(Setup::default());
    let mut body = fx.body("alpha");
    body["backends"] = json!(["one", "two"]);
    body["allowed_tools"] = json!(["read_*"]);
    body["denied_tools"] = json!(["write_file"]);
    body["admin"] = json!(true);
    body["rate_limit"] = json!(7);
    body["expires_at"] = json!("2999-01-01T00:00:00Z");
    let sent = created(&fx, &body);
    let answer = sent.json();
    assert_eq!(answer["name"], "alpha");
    assert_eq!(answer["secret"], KNOWN);
    assert_eq!(answer["revision"], fx.revision());
    assert_eq!(sent.cache_control.as_deref(), Some("no-store"));
    let keys = fx.file_keys();
    assert_eq!(keys.len(), 2);
    let key = &keys[1];
    assert_eq!(key.name, "alpha");
    assert_eq!(key.key_sha256.as_deref(), Some(spec(KNOWN).as_str()));
    assert_eq!(key.backends, ["one", "two"]);
    assert_eq!(
        key.allowed_tools.as_deref(),
        Some(&["read_*".to_owned()][..])
    );
    assert_eq!(
        key.denied_tools.as_deref(),
        Some(&["write_file".to_owned()][..])
    );
    assert!(key.admin);
    assert_eq!(key.rate_limit, 7);
    let expiry: chrono::DateTime<chrono::Utc> = "2999-01-01T00:00:00Z".parse().expect("instant");
    assert_eq!(key.expires_at, Some(expiry), "the stored expiry");
    let client = fx.live.generation().auth().validate_token(KNOWN);
    assert_eq!(client.map(|c| c.name), Some("alpha".to_owned()));
    let listed = fx.get();
    assert_eq!(listed["revision"], answer["revision"]);
    // Every supplied field comes back as given. The call above used the key,
    // so `last_used` is set; its instant is the one thing not pinned.
    let expected = json!({
        "name": "alpha",
        "backends": ["one", "two"],
        "allowed_tools": ["read_*"],
        "denied_tools": ["write_file"],
        "admin": true,
        "expires_at": "2999-01-01T00:00:00Z",
        "previous_expires_at": null,
        "rate_limit": 7,
        "live": true,
    });
    let mut entry = listed["keys"][1].clone();
    let last_used = entry.as_object_mut().and_then(|e| e.remove("last_used"));
    assert!(last_used.is_some_and(|at| at.is_string()), "{entry}");
    assert_eq!(entry, expected);
}

/// P0: the real generator, no seam: two creates, two distinct 49-character
/// `mcpgw_` secrets, each the digest in its entry and each authenticating.
#[test]
fn p0_the_real_generator_hands_out_distinct_working_secrets() {
    let fx = Fixture::new(Setup::default());
    let mut secrets = Vec::new();
    for name in ["one", "two"] {
        let mut call = Call::new(&fx.body(name));
        call.known = None;
        let sent = fx.post(call);
        assert_eq!(sent.status, StatusCode::CREATED, "{}", sent.body);
        let secret = sent.json()["secret"].as_str().expect("secret").to_owned();
        assert!(
            secret.starts_with("mcpgw_") && secret.len() == 49,
            "{secret}"
        );
        assert!(fx.text().contains(&spec(&secret)));
        assert!(
            fx.live
                .generation()
                .auth()
                .validate_token(&secret)
                .is_some()
        );
        secrets.push(secret);
    }
    assert_ne!(secrets[0], secrets[1]);
}

/// P8b: a minimal body writes no tool lists, admin false, the default rate
/// limit and no expiry.
#[test]
fn p8b_a_minimal_body_writes_the_defaults() {
    let fx = Fixture::new(Setup::default());
    created(&fx, &fx.body("plain"));
    let key = fx.file_keys().remove(1);
    assert_eq!(key.allowed_tools, None);
    assert_eq!(key.denied_tools, None);
    assert!(!key.admin && key.rate_limit == 0 && key.expires_at.is_none());
}

/// P8: a file with no `auth.api_keys` takes a key with two backends and both
/// tool lists; keyedit creates the list.
#[test]
fn p8_a_file_with_no_key_list_gets_one() {
    let text = "secrets:\n  store: files\nbackends: {}\nauth:\n  enabled: true\n".to_owned();
    let fx = Fixture::new(Setup {
        text,
        ..Setup::default()
    });
    let mut body = fx.body("first");
    body["backends"] = json!(["a", "b"]);
    body["allowed_tools"] = json!(["x*"]);
    body["denied_tools"] = json!(["y"]);
    created(&fx, &body);
    let keys = fx.file_keys();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].backends, ["a", "b"]);
    assert_eq!(
        keys[0].allowed_tools.as_deref(),
        Some(&["x*".to_owned()][..])
    );
    assert_eq!(keys[0].denied_tools.as_deref(), Some(&["y".to_owned()][..]));
}

/// P11: the key is live on the next call, and the reload does not report
/// `auth` as awaiting a restart (the restart-only comparison leaves the key
/// list out, `config_reload/diff.rs`; #4558 fixed the old misreport).
#[test]
fn p11_a_new_key_is_live_and_not_reported_as_awaiting_restart() {
    let fx = Fixture::new(Setup::default());
    created(&fx, &fx.body("late"));
    assert!(!fx.live.pending_restart_fields().contains(&"auth"));
    assert!(fx.live.generation().auth().validate_token(KNOWN).is_some());
}

/// A5: the intent is a `KeyCreate` one naming the caller and the key, for an
/// admin key and for a dashboard session.
#[test]
fn a5_the_intent_names_the_caller_and_the_key() {
    use crate::gateway::record_principal::InternalPrincipal;
    // The fields `auth_clients::dashboard_client` gives a valid session.
    let session = crate::gateway::auth::AuthenticatedClient {
        quota_principal: Some(crate::gateway::auth::QuotaPrincipal::dashboard_session()),
        name: "dashboard".into(),
        principal: InternalPrincipal::new("dashboard-session".into()),
        rate_limit: 0,
        backends: vec!["*".into()],
        allowed_tools: None,
        denied_tools: None,
        admin: true,
        authenticated: true,
        credential_kind: crate::security::audit::CredentialKind::DashboardSession,
    };
    for client in [admin_client(), session] {
        let fx = Fixture::new(Setup::default());
        let mut call = Call::new(&fx.body("watched"));
        call.client = client.clone();
        assert_eq!(fx.post(call).status, StatusCode::CREATED);
        let intents = fx.records("config_key_create_intent");
        assert_eq!(intents.len(), 1, "{}", fx.audit_text());
        assert_eq!(intents[0]["subject"], "watched");
        assert_eq!(intents[0]["who"], fx.who(&client));
        if client.credential_kind == crate::security::audit::CredentialKind::DashboardSession {
            let generation = fx.live.generation();
            let real = crate::gateway::auth::dashboard_session_who(generation.auth().record_key());
            assert_eq!(intents[0]["who"], serde_json::to_value(real).expect("who"));
        }
    }
}

/// P12: the `admin_action` record carries the key name and `create`, never the
/// secret or its digest.
#[test]
fn p12_the_admin_action_record_names_the_key_and_the_action() {
    let fx = Fixture::new(Setup::default());
    created(&fx, &fx.body("noted"));
    let actions = fx.records("admin_action");
    let ours: Vec<_> = actions.iter().filter(|r| r["method"] == "POST").collect();
    assert_eq!(ours.len(), 1, "{}", fx.audit_text());
    assert_eq!(
        (&ours[0]["key"], &ours[0]["action"]),
        (&json!("noted"), &json!("create"))
    );
}

/// Two keys already: the new one lands after both and the others stay.
#[test]
fn the_new_key_is_appended_after_the_existing_ones() {
    let text = yaml_of(&[root_item(), item("beta", "beta-secret", "")]);
    let fx = Fixture::new(Setup {
        text,
        ..Setup::default()
    });
    created(&fx, &fx.body("gamma"));
    let names: Vec<_> = fx.file_keys().into_iter().map(|k| k.name).collect();
    assert_eq!(names, ["root", "beta", "gamma"]);
}

fn production(file: &str) -> String {
    let text = std::fs::read_to_string(format!(
        "{}/src/gateway/ui/{file}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("source");
    crate::test_source_text::production_text(&text)
}

/// W1: the writer's input type has no secret, the `Replace` carries no secret
/// step, and the generator's result touches only the digest and the answer.
#[test]
fn w1_the_secret_never_enters_the_writers_input() {
    let code = production("keys_create.rs");
    let entry = code
        .split("struct NewKeyEntry {")
        .nth(1)
        .expect("NewKeyEntry");
    assert!(!entry.split('}').next().unwrap_or("").contains("secret"));
    let compute = code.split("fn compute(").nth(1).expect("compute builder");
    let header = compute.split('{').next().unwrap_or("");
    assert!(
        header.contains("NewKeyEntry") && !header.contains("secret"),
        "{header}"
    );
    assert!(code.contains("secrets: None"));
    assert_eq!(uses_of(&code, "secret"), SECRET_USES);
    assert_eq!(uses_of(&code, "once"), ONCE_USES);
}

/// The code lines (comments left out) holding `name` as a whole word.
fn uses_of<'a>(code: &'a str, name: &str) -> Vec<&'a str> {
    code.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with("//"))
        .filter(|l| {
            l.split(|c: char| !(c.is_alphanumeric() || c == '_'))
                .any(|w| w == name)
        })
        .collect()
}

/// Every use of the generator's binding: the binding, the digest call and the
/// 201 body (`created` takes it as `once`). An alias, a clone or a log line
/// adds a line here and fails the pin.
const SECRET_USES: [&str; 4] = [
    "Json(json!({\"name\": name, \"secret\": once, \"revision\": revision.as_str()})),",
    "let secret = crate::random_secret::random_secret(\"mcpgw_\");",
    "let digest = crate::config::api_key_digest_spec(secret.as_bytes());",
    "}) if landed(&state, &name, &digest) => created(&name, &secret, &revision),",
];

/// `created` holds the secret as `once`: its signature and the body only.
const ONCE_USES: [&str; 2] = [
    "fn created(name: &str, once: &str, revision: &FileRevision) -> Response {",
    "Json(json!({\"name\": name, \"secret\": once, \"revision\": revision.as_str()})),",
];

/// The generator seam and the pre-write hook exist only under cfg(test).
#[test]
fn the_test_seams_are_compiled_out_of_production() {
    let raw = std::fs::read_to_string(format!(
        "{}/src/gateway/ui/keys_create.rs",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("source");
    let code = production("keys_create.rs");
    for seam in ["KnownSecret", "BeforeLock"] {
        assert!(raw.contains(seam) && !code.contains(seam), "{seam}");
    }
}

/// L1: a log line written inside `spawn_blocking` during a POST is captured,
/// so a secret logged by the blocking loader cannot escape the leak check.
#[test]
fn l1_the_capture_sees_a_blocking_thread() {
    let fx = Fixture::new(Setup::default());
    let mut call = Call::new(&fx.body("watched"));
    call.before_lock = Some(BeforeLock(Arc::new(|| {
        let (done, waited) = std::sync::mpsc::channel();
        tokio::task::spawn_blocking(move || {
            tracing::warn!("zq-blocking-marker");
            done.send(()).expect("the waiter lives");
        });
        waited.recv().expect("the blocking task ran");
    })));
    let sent = fx.post(call);
    assert_eq!(sent.status, StatusCode::CREATED, "{}", sent.body);
    assert!(sent.logs.contains("zq-blocking-marker"), "{}", sent.logs);
}

fn raw_source(file: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/src/gateway/ui/{file}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("source")
}

/// L1: the leak check runs inside `post`, and no row reaches the route by
/// another door (`send` skips the capture and the check).
#[test]
fn l1_every_post_row_runs_the_leak_check() {
    let fixture = raw_source("keys_create_fixture_tests.rs");
    let post = fixture
        .split("fn post_driven<")
        .nth(1)
        .expect("post_driven");
    let post = post.split("\n    }\n").next().unwrap_or("");
    assert!(post.contains("self.assert_leak_free("), "{post}");
    let door = ["fx.se", "nd("].concat();
    for file in [
        "keys_create_tests.rs",
        "keys_create_refusal_tests.rs",
        "keys_create_writer_tests.rs",
        "keys_file_tests.rs",
    ] {
        assert!(!raw_source(file).contains(&door), "{file} bypasses post");
    }
}
