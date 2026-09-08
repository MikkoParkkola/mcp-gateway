// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `accounts.descriptors` STATIC configuration contract. Tests only.
//!
//! RED TODAY BY DESIGN: `AccountsConfig` is `deny_unknown_fields` and has no
//! `descriptors` field, so every fixture carrying one is refused right now.
//! That behavioural gap is what these tests pin. The unknown-field rejection
//! itself stays -- nothing here asks for it to be relaxed, and the malformed
//! cases are anchored by a full valid fixture in the SAME test so the current
//! universal-rejection stub cannot satisfy acceptance.
//!
//! STATIC ONLY. Authenticated issuer-metadata retrieval, endpoint equality
//! against that metadata, and SSRF/DNS policy are async bootstrap concerns and
//! are NOT claimed here (NOTES.md). `Config` evaluation performs no network I/O
//! and this module never asks it to: descriptor endpoint strings are carried
//! verbatim until authenticated metadata validates them before serving.

use super::Config;
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};

const KEY_B64: &str = "UVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVE=";
const KEY_VAR: &str = "ACCOUNT_CURRENT_KEY";
const SECRET_VAR: &str = "GOOGLE_OAUTH_CLIENT_SECRET";
/// Synthetic. Never a real credential, never written to the process environment.
const SECRET_VALUE: &str = "synthetic-client-secret-value";

struct Fixture {
    config: PathBuf,
    store_dir: PathBuf,
    authority_dir: PathBuf,
}

/// Descriptors are emitted as a JSON flow mapping inline in the YAML body: a
/// JSON mapping is valid YAML, and keeping the rest of the document in the
/// established `write_yaml` shape keeps the blast radius to one line.
///
/// Each call owns its own directory, so no case can read a previous case's
/// dotenv or config through any caching in the loader.
fn fixture(root: &Path, enabled: bool, descriptors: Option<&Value>) -> Fixture {
    fs::create_dir_all(root).unwrap();
    let env_path = root.join("keys.env");
    fs::write(
        &env_path,
        format!("{KEY_VAR}={KEY_B64}\n{SECRET_VAR}={SECRET_VALUE}\n"),
    )
    .unwrap();
    let store_dir = root.join("store");
    let authority_dir = root.join("authority");
    let descriptors_line = descriptors
        .map(|d| format!("  descriptors: {}\n", serde_json::to_string(d).unwrap()))
        .unwrap_or_default();
    let config = root.join("config.yaml");
    fs::write(
        &config,
        format!(
            "env_files:\n  - {}\nserver:\n  port: 18493\naccounts:\n  schema_version: accounts.v1\n  enabled: {enabled}\n  deployment: single_process\n  instance_id: gateway-a\n  store_dir: {}\n  authority_dir: {}\n  current_key_id: current\n  keys:\n    current: env:{KEY_VAR}\n{descriptors_line}",
            env_path.display(),
            store_dir.display(),
            authority_dir.display(),
        ),
    )
    .unwrap();
    Fixture {
        config,
        store_dir,
        authority_dir,
    }
}

/// Google REST personal account. `send_resource_parameter` is explicitly false:
/// Google's REST APIs take no RFC 8707 resource parameter, and false must
/// survive as a present value, never collapse into "absent".
fn google_descriptor(client_id: &str, scope: &str) -> Value {
    json!({
        "mode": "personal_managed",
        "provider": "google",
        "resource": "https://www.googleapis.com/",
        "issuer": "https://accounts.google.com",
        "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_endpoint": "https://oauth2.googleapis.com/token",
        "revocation_endpoint": "https://oauth2.googleapis.com/revoke",
        "client_id": client_id,
        "client_secret_ref": format!("env:{SECRET_VAR}"),
        "redirect_uri": "https://gateway.example.com/oauth/callback",
        "scopes": [scope],
        "send_resource_parameter": false
    })
}

fn two_google_descriptors() -> Value {
    json!({
        "gmail-personal": google_descriptor(
            "1000.apps.googleusercontent.com",
            "https://www.googleapis.com/auth/gmail.readonly"
        ),
        "calendar-personal": google_descriptor(
            "2000.apps.googleusercontent.com",
            "https://www.googleapis.com/auth/calendar.readonly"
        ),
    })
}

#[test]
fn configured_personal_managed_descriptors_roundtrip_without_custody_or_secret_resolution() {
    let root = tempfile::TempDir::new().unwrap();
    let fx = fixture(root.path(), true, Some(&two_google_descriptors()));

    let evaluated =
        Config::load_evaluated(Some(&fx.config)).expect("valid descriptor config must evaluate");
    let dumped = serde_json::to_value(&evaluated.config).expect("Config must serialize");
    let descriptors = dumped["accounts"]["descriptors"]
        .as_object()
        .expect("configured descriptors must survive Config parse/serialization");

    // Two descriptors, same provider, DISTINCT logical account ids. No join by
    // provider name: `google` alone selects nothing.
    assert_eq!(descriptors.len(), 2);
    let gmail = &descriptors["gmail-personal"];
    let calendar = &descriptors["calendar-personal"];
    assert_ne!(gmail, calendar);
    assert_eq!(gmail["provider"], "google");
    assert_eq!(calendar["provider"], "google");
    assert_eq!(gmail["client_id"], "1000.apps.googleusercontent.com");
    assert_eq!(calendar["client_id"], "2000.apps.googleusercontent.com");

    // Every approved raw field carried verbatim -- no normalization, no
    // rewriting, no metadata substitution at configuration time.
    assert_eq!(gmail["mode"], "personal_managed");
    assert_eq!(gmail["resource"], "https://www.googleapis.com/");
    assert_eq!(gmail["issuer"], "https://accounts.google.com");
    assert_eq!(
        gmail["authorization_endpoint"],
        "https://accounts.google.com/o/oauth2/v2/auth"
    );
    assert_eq!(
        gmail["token_endpoint"],
        "https://oauth2.googleapis.com/token"
    );
    assert_eq!(
        gmail["revocation_endpoint"],
        "https://oauth2.googleapis.com/revoke"
    );
    assert_eq!(
        gmail["redirect_uri"],
        "https://gateway.example.com/oauth/callback"
    );
    assert_eq!(
        gmail["scopes"],
        json!(["https://www.googleapis.com/auth/gmail.readonly"])
    );
    // Present AND false, for both descriptors. `is_boolean` fails on absence.
    assert!(gmail["send_resource_parameter"].is_boolean());
    assert_eq!(gmail["send_resource_parameter"], false);
    assert_eq!(calendar["send_resource_parameter"], false);

    // The reference stays a reference: the secret is not resolved into Config.
    assert_eq!(gmail["client_secret_ref"], format!("env:{SECRET_VAR}"));
    assert!(!dumped.to_string().contains(SECRET_VALUE));
    assert!(!format!("{evaluated:?}").contains(SECRET_VALUE));

    // Evaluation creates no custody state.
    assert!(!fx.store_dir.exists());
    assert!(!fx.authority_dir.exists());
}

#[test]
fn structurally_invalid_managed_descriptors_reject_against_a_valid_anchor() {
    let root = tempfile::TempDir::new().unwrap();
    let valid = google_descriptor(
        "1000.apps.googleusercontent.com",
        "https://www.googleapis.com/auth/gmail.readonly",
    );

    // ANCHOR: the same fixture, unmutated, must be ACCEPTED. Without this the
    // reject table is satisfied by today's reject-everything behaviour.
    let anchor = fixture(
        &root.path().join("anchor"),
        true,
        Some(&json!({ "gmail-personal": valid })),
    );
    Config::load_evaluated(Some(&anchor.config))
        .expect("the unmutated anchor fixture must be accepted");

    // ANCHOR: an absolute non-HTTPS resource URI is a valid RFC 8707 resource.
    // Without this the URI parser is satisfied by requiring https everywhere.
    let mut urn = valid.clone();
    urn["resource"] = json!("urn:example:resource");
    let urn_fixture = fixture(
        &root.path().join("urn"),
        true,
        Some(&json!({ "gmail-personal": urn })),
    );
    Config::load_evaluated(Some(&urn_fixture.config))
        .expect("an absolute URN resource must be accepted");

    let cases: &[(&str, fn(&mut Value))] = &[
        ("unknown mode spelling", |d| {
            d["mode"] = json!("personal-managed")
        }),
        ("missing mode", |d| {
            d.as_object_mut().unwrap().remove("mode");
        }),
        ("non-string mode", |d| d["mode"] = json!(3)),
        ("missing send_resource_parameter", |d| {
            d.as_object_mut().unwrap().remove("send_resource_parameter");
        }),
        ("missing client_id", |d| {
            d.as_object_mut().unwrap().remove("client_id");
        }),
        ("empty client_id", |d| d["client_id"] = json!("")),
        ("missing scopes", |d| {
            d.as_object_mut().unwrap().remove("scopes");
        }),
        ("empty scopes", |d| d["scopes"] = json!([])),
        ("duplicate scopes", |d| {
            d["scopes"] = json!([
                "https://www.googleapis.com/auth/gmail.readonly",
                "https://www.googleapis.com/auth/gmail.readonly"
            ])
        }),
        ("non-HTTPS callback", |d| {
            d["redirect_uri"] = json!("http://gateway.example.com/oauth/callback")
        }),
        ("literal client_secret_ref", |d| {
            d["client_secret_ref"] = json!("inline-literal-not-a-reference")
        }),
        ("unknown descriptor field", |d| {
            d["token_ttl_seconds"] = json!(300)
        }),
        ("relative resource", |d| {
            d["resource"] = json!("/auth/gmail")
        }),
        ("non-HTTPS issuer", |d| {
            d["issuer"] = json!("http://accounts.google.com")
        }),
        ("hostless https token_endpoint", |d| {
            d["token_endpoint"] = json!("https://")
        }),
    ];

    for (index, (label, mutate)) in cases.iter().enumerate() {
        let mut broken = valid.clone();
        mutate(&mut broken);
        let fx = fixture(
            &root.path().join(format!("case-{index}")),
            true,
            Some(&json!({ "gmail-personal": broken })),
        );
        assert!(
            Config::load_evaluated(Some(&fx.config)).is_err(),
            "descriptor case must be rejected: {label}"
        );
    }
    // `shared` and `external` acceptance is NOT asserted here: it cannot be
    // discriminated from a mode-specific rejection without inventing an
    // external_strategy fixture. Deferred, see NOTES.md.
}

#[test]
fn managed_descriptor_requires_accounts_enabled_while_disabled_store_only_stays_accepted() {
    let root = tempfile::TempDir::new().unwrap();

    let with_descriptor = fixture(
        &root.path().join("with-descriptor"),
        false,
        Some(&json!({
            "gmail-personal": google_descriptor(
                "1000.apps.googleusercontent.com",
                "https://www.googleapis.com/auth/gmail.readonly"
            )
        })),
    );
    let err = Config::load_evaluated(Some(&with_descriptor.config))
        .expect_err("personal_managed descriptor under accounts.enabled=false must reject");
    // `AccountsConfigError::NotEnabled` names this field verbatim.
    assert!(
        err.to_string()
            .contains("accounts.enabled must be true for a personal_managed descriptor"),
        "rejection must name the enabled requirement: {err}"
    );

    // CONTROL: the identical block WITHOUT descriptors is an explicitly
    // disabled store-only configuration, and stays accepted and intact.
    let store_only = fixture(&root.path().join("store-only"), false, None);
    let evaluated = Config::load_evaluated(Some(&store_only.config))
        .expect("explicitly disabled store-only accounts block must remain accepted");
    let dumped = serde_json::to_value(&evaluated.config).expect("Config must serialize");
    assert_eq!(dumped["accounts"]["enabled"], false);
    assert_eq!(dumped["accounts"]["instance_id"], "gateway-a");
    assert!(!matches!(
        dumped["accounts"].get("descriptors"),
        Some(value) if !value.is_null()
    ));
}
