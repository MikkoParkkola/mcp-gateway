// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The metadata pin and the secret source, without a network or a clock.

use std::sync::Arc;

use super::{AccountDescriptor, EnvSecrets, SecretSource as _, accept_metadata};
use crate::personal_accounts::config::DescriptorMode;

const ISSUER: &str = "https://issuer.fixture.test";
const AUTH: &str = "https://issuer.fixture.test/authorize";
const TOKEN: &str = "https://issuer.fixture.test/token";
const REVOKE: &str = "https://issuer.fixture.test/revoke";

fn descriptor(revocation: Option<&str>) -> AccountDescriptor {
    AccountDescriptor {
        mode: DescriptorMode::PersonalManaged,
        provider: "fixture".to_owned(),
        resource: Some("https://api.fixture.test/".to_owned()),
        issuer: Some(ISSUER.to_owned()),
        authorization_endpoint: Some(AUTH.to_owned()),
        token_endpoint: Some(TOKEN.to_owned()),
        revocation_endpoint: revocation.map(str::to_owned),
        client_id: Some("client".to_owned()),
        client_secret_ref: None,
        redirect_uri: None,
        scopes: None,
        send_resource_parameter: None,
        external_strategy: None,
        authorize_extra: None,
    }
}

fn doc(issuer: &str, auth: &str, token: &str, revoke: Option<&str>) -> String {
    let revoke = revoke.map_or_else(String::new, |r| format!(r#","revocation_endpoint":"{r}""#));
    format!(
        r#"{{"issuer":"{issuer}","authorization_endpoint":"{auth}","token_endpoint":"{token}"{revoke}}}"#
    )
}

/// Mutant: any one of the issuer, authorization, token or revocation bindings
/// is dropped, so a document the configured issuer did not advertise is trusted.
#[test]
fn metadata_is_accepted_only_when_every_configured_endpoint_matches_exactly() {
    let configured = descriptor(Some(REVOKE));
    let good = doc(ISSUER, AUTH, TOKEN, Some(REVOKE));
    assert!(accept_metadata(&configured, &good).is_some(), "control");

    let other = "https://elsewhere.fixture.test/x";
    for (why, body) in [
        ("issuer", doc(other, AUTH, TOKEN, Some(REVOKE))),
        (
            "authorization endpoint",
            doc(ISSUER, other, TOKEN, Some(REVOKE)),
        ),
        ("token endpoint", doc(ISSUER, AUTH, other, Some(REVOKE))),
        ("revocation endpoint", doc(ISSUER, AUTH, TOKEN, Some(other))),
        (
            "missing revocation endpoint",
            doc(ISSUER, AUTH, TOKEN, None),
        ),
        ("not json", "nope".to_owned()),
    ] {
        assert!(accept_metadata(&configured, &body).is_none(), "{why}");
    }
    // An unconfigured revocation endpoint is not required of the document.
    assert!(accept_metadata(&descriptor(None), &doc(ISSUER, AUTH, TOKEN, None)).is_some());
    // A descriptor with no pinned issuer accepts nothing.
    let mut unpinned = descriptor(None);
    unpinned.issuer = None;
    assert!(accept_metadata(&unpinned, &good).is_none());

    // An endpoint the descriptor pins and the document repeats exactly is still
    // refused when it is not https with a host, or carries userinfo: the pin
    // proves it was advertised, not that the client may dial it.
    let refused_endpoint = |why: &str, auth: &str, token: &str, revoke: Option<&str>| {
        let mut pinned = descriptor(revoke);
        pinned.authorization_endpoint = Some(auth.to_owned());
        pinned.token_endpoint = Some(token.to_owned());
        assert!(
            accept_metadata(&pinned, &doc(ISSUER, auth, token, revoke)).is_none(),
            "{why}"
        );
    };
    refused_endpoint(
        "http token endpoint",
        AUTH,
        "http://issuer.fixture.test/token",
        None,
    );
    refused_endpoint(
        "http authorization endpoint",
        "http://issuer.fixture.test/authorize",
        TOKEN,
        None,
    );
    refused_endpoint(
        "http revocation endpoint",
        AUTH,
        TOKEN,
        Some("http://issuer.fixture.test/revoke"),
    );
    for userinfo in ["user@", "user:secret@", ":secret@"] {
        let with_userinfo = format!("https://{userinfo}issuer.fixture.test/token");
        refused_endpoint(userinfo, AUTH, &with_userinfo, None);
        let revoke = format!("https://{userinfo}issuer.fixture.test/revoke");
        refused_endpoint(userinfo, AUTH, TOKEN, Some(&revoke));
    }
}

/// Mutant: a literal is accepted as a secret reference, an unreadable file
/// reference resolves to a value, or an `env:` reference stops reading the
/// gateway's env files.
#[test]
fn a_secret_reference_resolves_from_an_env_file_or_a_file_and_a_literal_does_not() {
    let dir = tempfile::tempdir().unwrap();
    let env_file = dir.path().join(".env");
    crate::gateway::test_helpers::write_owner_only(
        &env_file,
        "MIK7843_ACCOUNT_SECRET=env-fixture-secret\n",
    )
    .unwrap();
    let overlay = Arc::new(crate::config::EnvOverlay::from_paths(&[env_file]));
    let secrets = EnvSecrets::new(Arc::new(crate::config::LiveEnv::new(
        overlay,
        crate::config::ResolvedEnvFiles::default(),
    )));
    assert_eq!(
        secrets.resolve("env:MIK7843_ACCOUNT_SECRET").as_deref(),
        Some("env-fixture-secret"),
        "an env: reference assigned by an env file"
    );
    assert_eq!(secrets.resolve("env:MIK7843_ACCOUNT_SECRET_UNSET"), None);

    let path = dir.path().join("client-secret");
    crate::gateway::test_helpers::write_owner_only(&path, "fixture-secret").unwrap();

    let reference = format!("file:{}", path.display());
    assert_eq!(
        secrets.resolve(&reference).as_deref(),
        Some("fixture-secret")
    );
    let absent = format!("file:{}", dir.path().join("absent").display());
    assert_eq!(secrets.resolve(&absent), None);
    assert_eq!(secrets.resolve("fixture-secret"), None, "a literal");
}
