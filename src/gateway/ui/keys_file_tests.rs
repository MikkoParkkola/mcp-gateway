// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `GET /ui/api/keys` answering `{revision, keys}`: the keys come from
//! gateway.yaml, under the revision of the bytes read, with `live` and
//! `last_used` joined by name from the request's pinned key table.

use std::path::Path;
use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;

use super::keys::AfterRead;
use crate::config::{ApiKeyConfig, AuthConfig, Config};
use crate::config_reload::FileRevision;
use crate::gateway::auth::ResolvedAuthConfig;
use crate::gateway::auth::runtime::AuthRuntime;
use crate::gateway::test_helpers::write_owner_only;

const URI: &str = "/ui/api/keys";
const ALPHA: &str = "keys-file-secret-alpha";
const BETA: &str = "keys-file-secret-beta";
const BETA_OLD: &str = "keys-file-secret-beta-old";
const GAMMA: &str = "keys-file-secret-gamma";
const FUTURE: &str = "2999-01-01T00:00:00Z";
const PAST: &str = "2000-01-01T00:00:00Z";

fn spec(secret: &str) -> String {
    crate::config::api_key_digest_spec(secret.as_bytes())
}

/// One `auth.api_keys` list item of gateway.yaml.
fn item(name: &str, secret: &str, extra: &str) -> String {
    format!(
        "    - name: {name}\n      key_sha256: \"{}\"\n      backends: [\"*\"]\n{extra}",
        spec(secret)
    )
}

/// gateway.yaml text over the given list items.
fn yaml_of(items: &[String]) -> String {
    format!(
        "secrets:\n  store: files\nbackends: {{}}\nauth:\n  enabled: true\n  api_keys:\n{}",
        items.concat()
    )
}

/// `alpha`, then a rotated `beta`, in that file order.
fn items() -> Vec<String> {
    let beta = format!(
        "      admin: true\n      rate_limit: 30\n      expires_at: \"{FUTURE}\"\n      \
         previous_key_sha256: \"{}\"\n      previous_expires_at: \"{FUTURE}\"\n",
        spec(BETA_OLD)
    );
    vec![
        item("alpha", ALPHA, "      denied_tools: [write_file]\n"),
        item("beta", BETA, &beta),
    ]
}

fn yaml() -> String {
    yaml_of(&items())
}

fn key(name: &str, secret: &str, expires: Option<&str>) -> ApiKeyConfig {
    ApiKeyConfig {
        key_sha256: Some(spec(secret)),
        name: name.into(),
        backends: vec!["*".into()],
        expires_at: expires.map(|t| t.parse().expect("instant")),
        ..Default::default()
    }
}

/// The key table a reload would have published, over `keys`.
fn table(keys: Vec<ApiKeyConfig>) -> Arc<ResolvedAuthConfig> {
    let config = AuthConfig {
        enabled: true,
        api_keys: keys,
        ..AuthConfig::default()
    };
    let resolved = ResolvedAuthConfig::try_from_config(
        &config,
        &crate::config::EnvOverlay::none(),
        crate::gateway::record_principal::TEST_RECORD_KEY,
    )
    .expect("the key table resolves")
    .with_runtime(Arc::new(AuthRuntime::default()));
    Arc::new(resolved)
}

fn bearer() -> crate::gateway::auth::AuthenticatedClient {
    crate::gateway::auth::AuthenticatedClient {
        name: "bearer".into(),
        admin: true,
        authenticated: true,
        credential_kind: crate::security::audit::CredentialKind::StaticBearer,
        principal: crate::gateway::auth::principal_of("keys-file-bearer"),
        ..crate::gateway::auth::anonymous_client()
    }
}

/// `GET /ui/api/keys` as the admin bearer, on a gateway whose config path is
/// `path`, with `auth` pinned.
async fn get(path: Option<&Path>, auth: Arc<ResolvedAuthConfig>, hook: Option<AfterRead>) -> Value {
    let (mut state, _dir) =
        crate::gateway::router::tests::audience_state(&AuthConfig::default(), (None, None), |m| m)
            .await;
    Arc::get_mut(&mut state).expect("unique").config_path = path.map(Path::to_path_buf);
    let generation = Arc::new(crate::config_reload::Generation::prepare_startup(
        Config::default(),
        auth,
    ));
    let mut request = Request::builder()
        .uri(URI)
        .extension(generation)
        .extension(bearer());
    if let Some(hook) = hook {
        request = request.extension(hook);
    }
    let response = super::admin_audit::audited_api_router(&state)
        .with_state(Arc::clone(&state))
        .oneshot(request.body(Body::empty()).expect("request builds"))
        .await
        .expect("the router is infallible");
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&body).expect("json")
}

/// A gateway.yaml in a fresh directory.
fn write_config(text: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(&path, text).expect("write config");
    (dir, path)
}

fn names(answer: &Value) -> Vec<Value> {
    answer["keys"]
        .as_array()
        .map(|a| a.iter().map(|k| k["name"].clone()).collect())
        .unwrap_or_default()
}

fn entry<'a>(answer: &'a Value, name: &str) -> &'a Value {
    answer["keys"]
        .as_array()
        .and_then(|keys| keys.iter().find(|k| k["name"] == name))
        .unwrap_or_else(|| panic!("no {name} in {answer}"))
}

/// The fields every entry carries, in no order.
const FIELDS: [&str; 10] = [
    "name",
    "backends",
    "allowed_tools",
    "denied_tools",
    "admin",
    "expires_at",
    "previous_expires_at",
    "rate_limit",
    "last_used",
    "live",
];

fn assert_allowlist(answer: &Value) {
    for key in answer["keys"].as_array().expect("keys array") {
        let mut got: Vec<&str> = key
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        got.sort_unstable();
        let mut want = FIELDS.to_vec();
        want.sort_unstable();
        assert_eq!(got, want, "{key}");
    }
}

/// R1: the file's keys in file order, exactly the allowlisted fields, under
/// the revision of the file's bytes, and no credential identifier anywhere.
#[tokio::test]
async fn r1_the_answer_is_the_files_keys_under_its_revision() {
    let (_dir, path) = write_config(&yaml());
    let live = table(vec![key("alpha", ALPHA, None), key("beta", BETA, None)]);
    let answer = get(Some(&path), live, None).await;
    assert_eq!(
        answer["revision"],
        json!(FileRevision::of(yaml().as_bytes()).as_str())
    );
    assert_eq!(
        answer["keys"],
        json!([
            {
                "name": "alpha", "backends": ["*"], "allowed_tools": null,
                "denied_tools": ["write_file"], "admin": false, "expires_at": null,
                "previous_expires_at": null, "rate_limit": 0, "last_used": null,
                "live": true
            },
            {
                "name": "beta", "backends": ["*"], "allowed_tools": null,
                "denied_tools": null, "admin": true, "expires_at": FUTURE,
                "previous_expires_at": FUTURE, "rate_limit": 30, "last_used": null,
                "live": true
            }
        ])
    );
    assert_allowlist(&answer);
    let body = answer.to_string();
    for needle in ["key_sha256", "principal", "\"key\""] {
        assert!(!body.contains(needle), "the body carries {needle}");
    }
    // Every digest the file holds (alpha, beta and beta's previous key), as
    // its spec, its hex in both cases and the secret behind it.
    for secret in [ALPHA, BETA, BETA_OLD] {
        let digest = crate::config::parse_api_key_digest(&spec(secret)).expect("digest");
        for needle in [
            spec(secret),
            hex::encode(digest),
            hex::encode_upper(digest),
            secret.to_owned(),
        ] {
            assert!(!body.contains(&needle), "the body carries {needle}");
        }
    }
}

/// R2: a rewrite between the read and the answer changes neither: two keys,
/// under the revision of the bytes those two keys came from.
#[tokio::test]
async fn r2_a_rewrite_after_the_read_leaves_revision_and_keys_matched() {
    let (_dir, path) = write_config(&yaml());
    let mut three = items();
    three.push(item("gamma", GAMMA, ""));
    let rewrite = {
        let path = path.clone();
        let text = yaml_of(&three);
        Arc::new(move || write_owner_only(&path, &text).expect("rewrite"))
            as Arc<dyn Fn() + Send + Sync>
    };
    let live = table(vec![key("alpha", ALPHA, None)]);
    let answer = get(Some(&path), live, Some(AfterRead(rewrite))).await;
    // The premise: the rewrite really ran between the read and the answer,
    // or this is an ordinary GET proving nothing about one read.
    let after = std::fs::read_to_string(&path).expect("gateway.yaml");
    assert!(after.contains("gamma"), "the after-read rewrite never ran");
    assert_eq!(names(&answer), vec![json!("alpha"), json!("beta")]);
    assert_eq!(
        answer["revision"],
        json!(FileRevision::of(yaml().as_bytes()).as_str())
    );
}

/// R1's boundary, in the source: GET builds each entry field by field from
/// an allowlist and never serialises a key, so a field added to
/// `ApiKeyConfig` (a digest, a principal) cannot reach the answer unseen.
#[test]
fn r1_get_never_serialises_a_key() {
    let text = std::fs::read_to_string(format!(
        "{}/src/gateway/ui/keys.rs",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("keys.rs");
    let code = crate::test_source_text::sanitize(&crate::test_source_text::production_text(&text));
    for serialiser in [
        "to_value(",
        "to_string(",
        "to_vec(",
        "to_writer(",
        "Serialize",
    ] {
        assert!(!code.contains(serialiser), "keys.rs uses {serialiser}");
    }
    // A key passed whole into `json!` serialises it too.
    for whole in ["json!(key)", "json!(config", "json!(live)"] {
        assert!(!code.contains(whole), "keys.rs serialises {whole}");
    }
}

/// R3: no file, and a file that cannot be loaded, each say so, carry no
/// revision and still list the live table with the full allowlist.
#[tokio::test]
async fn r3_an_absent_or_unloadable_file_is_named_and_lists_the_live_table() {
    let live = || {
        table(vec![
            key("alpha", ALPHA, None),
            key("beta", BETA, Some(PAST)),
        ])
    };
    let absent = get(None, live(), None).await;
    assert_eq!(absent["file"], "absent");
    assert_eq!(absent["revision"], Value::Null);
    assert_eq!(names(&absent), vec![json!("alpha"), json!("beta")]);
    assert_allowlist(&absent);

    let (_dir, path) = write_config("backends: [\n");
    let broken = get(Some(&path), live(), None).await;
    assert_eq!(broken["file"], "unloadable");
    assert_eq!(broken["revision"], Value::Null);
    assert_eq!(names(&broken), vec![json!("alpha"), json!("beta")]);
    assert_allowlist(&broken);
    assert_eq!(entry(&broken, "alpha")["live"], true);
    assert_eq!(entry(&broken, "beta")["live"], false);
}

/// R4: `live` is true for an unexpired live key, false for an expired one and
/// for a file entry with no live key; `previous_expires_at` is the file's.
#[tokio::test]
async fn r4_live_follows_the_pinned_table_and_expiry() {
    let mut listed = items();
    listed.push(item("gamma", GAMMA, ""));
    let (_dir, path) = write_config(&yaml_of(&listed));
    let live = table(vec![
        key("alpha", ALPHA, Some(PAST)),
        key("beta", BETA, None),
    ]);
    let answer = get(Some(&path), live, None).await;
    assert_eq!(entry(&answer, "alpha")["live"], false, "expired");
    assert_eq!(entry(&answer, "beta")["live"], true, "present");
    assert_eq!(entry(&answer, "gamma")["live"], false, "absent");
    assert_eq!(entry(&answer, "beta")["previous_expires_at"], FUTURE);
    assert_eq!(entry(&answer, "alpha")["previous_expires_at"], Value::Null);
}

/// R6: the file's order is the answer's order, and `last_used` and `live`
/// land on the key of the same name, not the same position.
#[tokio::test]
async fn r6_the_join_is_by_name_not_by_position() {
    let mut swapped = items();
    swapped.reverse();
    let (_dir, path) = write_config(&yaml_of(&swapped));
    // alpha is expired, so a positional join (file beta with live alpha)
    // would call beta not live and alpha live.
    let live = table(vec![
        key("alpha", ALPHA, Some(PAST)),
        key("beta", BETA, None),
    ]);
    assert!(live.validate_token(BETA).is_some(), "premise");
    let answer = get(Some(&path), live, None).await;
    assert_eq!(names(&answer), vec![json!("beta"), json!("alpha")]);
    assert_ne!(entry(&answer, "beta")["last_used"], Value::Null);
    assert_eq!(entry(&answer, "alpha")["last_used"], Value::Null);
    assert_eq!(entry(&answer, "beta")["live"], true, "beta joins by name");
    assert_eq!(entry(&answer, "alpha")["live"], false, "alpha is expired");
}

/// Every entry's `last_used`, by name.
fn last_useds(answer: &Value) -> Vec<(String, Value)> {
    answer["keys"]
        .as_array()
        .expect("keys")
        .iter()
        .map(|k| {
            (
                k["name"].as_str().expect("name").to_owned(),
                k["last_used"].clone(),
            )
        })
        .collect()
}

/// R5: a last use recorded before a restart is gone after it, and then one
/// matched call sets `keys[i].last_used` of that key only.
#[tokio::test]
async fn r5_last_used_is_null_after_a_restart_until_a_call_matches() {
    let (_dir, path) = write_config(&yaml());
    let both = || vec![key("alpha", ALPHA, None), key("beta", BETA, None)];
    let before = table(both());
    assert!(before.validate_token(ALPHA).is_some(), "premise");
    assert!(before.validate_token(BETA).is_some(), "premise");
    let seeded = last_useds(&get(Some(&path), before, None).await);
    assert!(
        seeded.len() == 2 && seeded.iter().all(|(_, at)| !at.is_null()),
        "premise: both readings are seeded: {seeded:?}"
    );

    let restarted = table(both());
    let answer = get(Some(&path), Arc::clone(&restarted), None).await;
    assert_eq!(last_useds(&answer).len(), 2);
    assert!(
        last_useds(&answer).iter().all(|(_, at)| at.is_null()),
        "{answer}"
    );

    assert!(restarted.validate_token(BETA).is_some(), "one matched call");
    let answer = get(Some(&path), restarted, None).await;
    assert_ne!(entry(&answer, "beta")["last_used"], Value::Null);
    assert_eq!(entry(&answer, "alpha")["last_used"], Value::Null);
}
