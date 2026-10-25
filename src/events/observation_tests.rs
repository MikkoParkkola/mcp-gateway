// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8833 §2.1 and B3: a backend's binding from live config, and the key
//! each subscriber is observed under on it.

use super::{ObsRefusal, binding, observe_row, observe_subscriber};
use crate::config::Config;
use crate::identity_propagation::PropagationStrategyKind;
use crate::key_server::oidc::VerifiedIdentity;

fn person(subject: &str) -> VerifiedIdentity {
    VerifiedIdentity {
        subject: subject.into(),
        email: format!("{subject}@example.com"),
        name: None,
        groups: Vec::new(),
        issuer: "https://idp".into(),
    }
}

fn config() -> Config {
    crate::yaml::from_str(
        "backends:\n  \
         shared:\n    http_url: https://h/mcp\n  \
         signed:\n    http_url: https://h/mcp\n    identity_propagation:\n      \
         strategy: signed_assertion\n      audience: https://mail\n      session_mode: per_user\n  \
         managed:\n    http_url: https://backend.fixture.test/mcp\n    account: work\n\
         accounts:\n  schema_version: accounts.v1\n  enabled: true\n  \
         deployment: single_process\n  instance_id: unit\n  store_dir: /unused/store\n  \
         authority_dir: /unused/authority\n  current_key_id: primary\n  keys:\n    \
         primary: env:UNUSED\n  descriptors:\n    \
         work:\n      mode: personal_managed\n      provider: fixture\n      \
         resource: https://api.fixture.test/\n      issuer: https://issuer.fixture.test\n      \
         authorization_endpoint: https://issuer.fixture.test/authorize\n      \
         token_endpoint: https://issuer.fixture.test/token\n      client_id: c\n      \
         redirect_uri: https://gateway.fixture.test/callback\n      scopes: [read]\n      \
         send_resource_parameter: true\n",
    )
    .expect("config parses")
}

#[test]
fn a_shared_backend_has_no_binding() {
    assert!(binding(&config(), "shared").is_none());
    assert!(binding(&config(), "absent").is_none());
}

#[test]
fn a_signed_backend_observes_each_user_apart() {
    let b = binding(&config(), "signed").expect("identity-bound");
    assert_eq!(b.basis.strategy, PropagationStrategyKind::SignedAssertion);
    assert_eq!(b.basis.audience, "https://mail");
    assert_eq!(b.basis.descriptor_id, None);
    let p = b.observe(&person("p")).expect("observes");
    assert_ne!(p, b.observe(&person("q")).expect("observes"));
    assert_eq!(p, b.observe(&person("p")).expect("observes"), "stable");
}

#[test]
fn a_managed_backend_observes_by_account() {
    let b = binding(&config(), "managed").expect("identity-bound");
    assert_eq!(b.basis.strategy, PropagationStrategyKind::Vault);
    assert_eq!(b.basis.descriptor_id.as_deref(), Some("work"));
    let p = b.observe(&person("p")).expect("binds an account");
    assert!(p.starts_with("acct:v1:"), "{p}");
    assert_ne!(p, b.observe(&person("q")).expect("binds an account"));
}

#[test]
fn a_managed_backend_without_its_descriptor_cannot_observe() {
    let mut b = binding(&config(), "managed").expect("identity-bound");
    b.account = None;
    assert_eq!(b.observe(&person("p")), Err(ObsRefusal::NoAccount));
}

#[test]
fn a_subscribe_records_the_basis_only_for_a_per_user_backend() {
    let config = config();
    assert!(
        observe_subscriber(&config, "shared", None)
            .expect("shared needs no identity")
            .is_none()
    );
    let refused = observe_subscriber(&config, "signed", None).expect_err("no identity");
    assert_eq!(refused.code, -32012);
    let observed = observe_subscriber(&config, "signed", Some(&person("p")))
        .expect("observes")
        .expect("per-user");
    assert_eq!(observed.audience, "https://mail");
}

#[test]
fn an_oidc_bearer_row_observes_as_its_own_binding() {
    use crate::events::records::{LiveBinding, Subscription};
    let mut row: Subscription = serde_json::from_value(serde_json::json!({
        "v": 1, "id": "i", "principal": "p", "api_key": null, "url": "https://cb",
        "name": "backend.signed.tools_changed", "arguments": {}, "secret": "s",
        "previous_secret": null, "previous_until": null,
        "granted_at": "2026-10-25T00:00:00Z", "expires_at": null, "active": true,
        "failed_since": null, "last_delivery_at": null, "last_error": null
    }))
    .expect("an old row still loads");
    assert!(row.observed_as().is_none());
    assert!(row.obs_basis.is_none());
    row.observed_identity = Some(person("stored"));
    assert_eq!(row.observed_as().map(|i| i.subject), Some("stored".into()));
    row.binding = Some(LiveBinding::OidcBearer {
        issuer: "https://idp".into(),
        subject: "bearer".into(),
        email: "bearer@example.com".into(),
        groups: vec!["g".into()],
        issued_at: None,
        provider_sha256: None,
    });
    assert_eq!(
        row.observed_as().map(|i| i.subject),
        Some("bearer".into()),
        "the bearer's own fields win"
    );
    if let Some(LiveBinding::OidcBearer { subject, .. }) = &mut row.binding {
        subject.clear();
    }
    assert!(
        row.observed_as().is_none(),
        "a bearer naming nobody observes as no one, never as the stored identity"
    );
}

fn row(name: &str) -> crate::events::records::Subscription {
    serde_json::from_value(serde_json::json!({
        "v": 1, "id": "i", "principal": "p", "api_key": null, "url": "https://cb",
        "name": name, "arguments": {}, "secret": "s",
        "previous_secret": null, "previous_until": null,
        "granted_at": "2026-10-25T00:00:00Z", "expires_at": null, "active": true,
        "failed_since": null, "last_delivery_at": null, "last_error": null
    }))
    .expect("a row")
}

/// The row a subscribe on `backend` commits for `subject`.
fn observed_row(
    config: &Config,
    backend: &str,
    subject: &str,
) -> crate::events::records::Subscription {
    let mut r = row(&format!("backend.{backend}.tools_changed"));
    let observed = observe_subscriber(config, backend, Some(&person(subject)))
        .expect("observes")
        .expect("per-user");
    r.obs_basis = Some(observed);
    r.observed_identity = Some(person(subject));
    r
}

#[test]
fn a_stored_row_keys_as_its_subscribe_did() {
    let config = config();
    assert_eq!(
        observe_row(&config, "shared", &row("backend.shared.tools_changed")),
        Ok(None)
    );
    let p = observed_row(&config, "signed", "p");
    let q = observed_row(&config, "signed", "q");
    let key_p = observe_row(&config, "signed", &p).expect("re-derives");
    assert_eq!(
        key_p,
        binding(&config, "signed").map(|b| b.observe(&person("p")).expect("observes")),
        "replay and subscribe derive the same key"
    );
    assert_ne!(
        key_p,
        observe_row(&config, "signed", &q).expect("re-derives")
    );
}

#[test]
fn a_changed_basis_or_a_lost_identity_holds_no_key() {
    let config = config();
    let mut moved = observed_row(&config, "signed", "p");
    moved.obs_basis.as_mut().expect("basis").audience = "https://calendar".into();
    assert_eq!(
        observe_row(&config, "signed", &moved),
        Err(ObsRefusal::BasisChanged)
    );
    assert_eq!(
        observe_row(&config, "signed", &row("backend.signed.tools_changed")),
        Err(ObsRefusal::BasisChanged),
        "a shared row on a backend that became per-user"
    );
    let shared_now = observed_row(&config, "signed", "p");
    assert_eq!(
        observe_row(&config, "shared", &shared_now),
        Err(ObsRefusal::BasisChanged),
        "a per-user row on a backend that became shared"
    );
    let mut lost = observed_row(&config, "signed", "p");
    lost.observed_identity = None;
    assert_eq!(
        observe_row(&config, "signed", &lost),
        Err(ObsRefusal::NoIdentity)
    );
}
