// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! L6 (CLI login, successor escape): ordinary `POST /ui/api/keys` cannot make
//! or be used by a CLI key. A body naming `approved_by` or `cli_host` is
//! refused, and a caller authenticated by a CLI key cannot create a key, so
//! no unbound successor outlives the approver's revocation. A named non-CLI
//! admin and the static bearer still create. Every refusal writes nothing.

use std::sync::Arc;

use axum::http::StatusCode;
use serde_json::json;

use super::keys_create_fixture_tests::{
    Call, Fixture, ROOT, Setup, item, root_item, spec, yaml_of,
};
use crate::config::{ApiKeyBinding, ApiKeyConfig, AuthConfig};
use crate::gateway::auth::ResolvedAuthConfig;
use crate::gateway::auth::runtime::AuthRuntime;
use crate::security::audit::CredentialKind;

const CLI_NAME: &str = "cli:laptop:a1";
const CLI_SECRET: &str = "create-cli-child-secret";

fn root_key() -> ApiKeyConfig {
    ApiKeyConfig {
        name: "root".into(),
        key_sha256: Some(spec(ROOT)),
        backends: vec!["*".into()],
        admin: true,
        ..Default::default()
    }
}

fn resolved(keys: Vec<ApiKeyConfig>) -> ResolvedAuthConfig {
    let config = AuthConfig {
        enabled: true,
        api_keys: keys,
        ..AuthConfig::default()
    };
    ResolvedAuthConfig::from_config(&config, crate::gateway::record_principal::TEST_RECORD_KEY)
        .with_runtime(Arc::new(AuthRuntime::default()))
}

fn binding() -> ApiKeyBinding {
    let quota = resolved(vec![root_key()])
        .validate_token(ROOT)
        .expect("premise: the root validates")
        .quota_principal
        .expect("an API key carries a quota principal");
    let digest: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(ROOT.as_bytes()).into();
    ApiKeyBinding {
        quota_principal: quota.limit_store_key().to_owned(),
        digest_tag: crate::gateway::auth::digest_tag_of(&digest),
    }
}

fn cli_key() -> ApiKeyConfig {
    ApiKeyConfig {
        name: CLI_NAME.into(),
        key_sha256: Some(spec(CLI_SECRET)),
        backends: vec!["*".into()],
        admin: true,
        approved_by: Some(binding()),
        cli_host: Some("laptop".into()),
        ..Default::default()
    }
}

/// A gateway whose file and running table hold the root and one CLI key.
fn with_cli_key() -> Fixture {
    let bound = binding();
    let cli_item = item(
        CLI_NAME,
        CLI_SECRET,
        &format!(
            "      admin: true\n      cli_host: laptop\n      approved_by:\n        quota_principal: \"{}\"\n        digest_tag: \"{}\"\n",
            bound.quota_principal, bound.digest_tag
        ),
    );
    Fixture::new(Setup {
        text: yaml_of(&[root_item(), cli_item]),
        running: AuthConfig {
            enabled: true,
            api_keys: vec![root_key(), cli_key()],
            ..AuthConfig::default()
        },
        ..Setup::default()
    })
}

/// A call authenticated as the CLI key, with the provenance the auth layer adds.
fn as_cli_key(body: &serde_json::Value) -> Call {
    let (client, named) = resolved(vec![root_key(), cli_key()])
        .validate_token_with_origin(CLI_SECRET)
        .expect("premise: the CLI key validates");
    let mut call = Call::new(body);
    call.client = client;
    call.named = named;
    call
}

fn refused(fx: &Fixture, call: Call, status: StatusCode) {
    let before = fx.bytes();
    let sent = fx.post(call);
    assert_eq!(sent.status, status, "{}", sent.body);
    assert_eq!(fx.bytes(), before, "a refused create wrote gateway.yaml");
    assert!(
        sent.json().get("secret").is_none(),
        "a refused create answered a secret"
    );
}

#[test]
fn a_body_naming_a_binding_or_a_cli_host_is_refused() {
    let fx = Fixture::new(Setup::default());
    let bound = binding();
    for (field, value) in [
        (
            "approved_by",
            json!({"quota_principal": bound.quota_principal, "digest_tag": bound.digest_tag}),
        ),
        ("cli_host", json!("laptop")),
    ] {
        let mut body = fx.body("successor");
        body[field] = value;
        refused(&fx, Call::new(&body), StatusCode::UNPROCESSABLE_ENTITY);
    }
}

#[test]
fn a_cli_key_caller_cannot_create_a_key() {
    let fx = with_cli_key();
    let body = fx.body("successor");
    refused(&fx, as_cli_key(&body), StatusCode::FORBIDDEN);
}

#[test]
fn a_same_named_ordinary_key_is_not_refused_as_a_cli_key() {
    let ordinary = ApiKeyConfig {
        name: CLI_NAME.into(),
        ..root_key()
    };
    let keys = vec![cli_key(), ordinary];
    let auth = resolved(keys.clone());
    let (client, named) = auth
        .validate_token_with_origin(ROOT)
        .expect("ordinary key validates");
    let cli = auth.validate_token(CLI_SECRET).expect("CLI key validates");
    assert!(client.quota_principal.is_some());
    assert_ne!(client.quota_principal, cli.quota_principal);
    // Only the running table has colliding labels: the loader rejects
    // duplicate names in the backing file before an allowed create can write.
    let fx = Fixture::new(Setup {
        running: AuthConfig {
            enabled: true,
            api_keys: keys,
            ..AuthConfig::default()
        },
        ..Setup::default()
    });
    let mut call = Call::new(&fx.body("successor"));
    call.client = client;
    call.named = named;
    let sent = fx.post(call);
    assert_eq!(sent.status, StatusCode::CREATED, "{}", sent.body);
    assert!(fx.file_keys().iter().any(|key| key.name == "successor"));
}

#[test]
fn a_cli_key_is_refused_even_when_a_same_named_key_is_listed_first() {
    let ordinary = ApiKeyConfig {
        name: CLI_NAME.into(),
        ..root_key()
    };
    // Reverse the collision in the running table; keep the backing file
    // loadable so refusal cannot be credited to duplicate-name validation.
    let fx = Fixture::new(Setup {
        running: AuthConfig {
            enabled: true,
            api_keys: vec![ordinary, cli_key()],
            ..AuthConfig::default()
        },
        ..Setup::default()
    });
    let call = as_cli_key(&fx.body("successor"));
    assert!(call.client.quota_principal.is_some());
    refused(&fx, call, StatusCode::FORBIDDEN);
}

#[test]
fn a_cli_key_renamed_after_it_authenticated_is_still_refused() {
    let renamed = ApiKeyConfig {
        name: "cli:renamed".into(),
        ..cli_key()
    };
    let auth = resolved(vec![root_key(), renamed.clone()]);
    let current = auth
        .validate_token(CLI_SECRET)
        .expect("renamed CLI key validates");
    let fx = Fixture::new(Setup {
        running: AuthConfig {
            enabled: true,
            api_keys: vec![root_key(), renamed],
            ..AuthConfig::default()
        },
        ..Setup::default()
    });
    // The request retains its authenticated name; only the generation's
    // label changed, so the same quota principal must still be refused.
    let call = as_cli_key(&fx.body("successor"));
    assert_eq!(call.named.as_ref().expect("named CLI key").name(), CLI_NAME);
    assert!(call.client.quota_principal.is_some());
    assert_eq!(call.client.quota_principal, current.quota_principal);
    refused(&fx, call, StatusCode::FORBIDDEN);
}

#[test]
fn a_named_admin_and_the_static_bearer_still_create() {
    // One fixture per caller: each create answers the fixture's one known
    // secret, so a second create in the same file would share its digest.
    let fx = with_cli_key();
    let sent = fx.post(Call::new(&fx.body("by-root")));
    assert_eq!(sent.status, StatusCode::CREATED, "{}", sent.body);
    let fx = with_cli_key();
    let mut bearer = Call::new(&fx.body("by-bearer"));
    bearer.client.credential_kind = CredentialKind::StaticBearer;
    bearer.client.name = "bearer".into();
    let sent = fx.post(bearer);
    assert_eq!(sent.status, StatusCode::CREATED, "{}", sent.body);
}
