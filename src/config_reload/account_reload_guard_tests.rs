// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The fail-closed reload guard for changed account bindings — STAGE B.
//!
//! WHY A SEPARATE FILE FROM `account_reload_tests`. That file compiles against
//! the frozen snapshot and produces a behavioural RED. This one names a symbol
//! the snapshot does not have, so registering it turns the build red. Keeping
//! them apart is what lets the supervisor observe an honest behavioural failure
//! first and a compile boundary second, instead of one indistinguishable "it
//! did not build".
//!
//! WHAT IT PINS. A descriptor's authority, resource, issuer, scopes or a
//! backend's account reference cannot change under a running gateway and have
//! the old credentials keep flowing. Eager metadata/authority replacement is NOT
//! implemented in this slice, so the honest answer is a refusal that mutates
//! nothing — the existing restart-required posture, applied before `apply_patch`
//! stops or starts anything.
//!
//! The three positive controls matter as much as the refusal: a reload that
//! refused every account configuration would be indistinguishable from one that
//! works, and would be reverted by the first operator who hit it.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

use crate::config::account_bindings::reload_binding_refusal;
use crate::config::{BackendConfig, Config, TransportConfig};
use crate::personal_accounts::config::{
    AccountDescriptor, AccountsConfig, AccountsLimits, DescriptorMode,
};

const WORK: &str = "work-gmail";
const RESOURCE: &str = "https://www.googleapis.invalid/drive/v3";
const ISSUER: &str = "https://accounts.google.invalid";

fn descriptor(issuer: &str, resource: &str, scopes: &[&str]) -> AccountDescriptor {
    AccountDescriptor {
        mode: DescriptorMode::PersonalManaged,
        provider: "google".to_string(),
        resource: Some(resource.to_string()),
        issuer: Some(issuer.to_string()),
        authorization_endpoint: Some(format!("{issuer}/o/oauth2/v2/auth")),
        token_endpoint: Some(format!("{issuer}/token")),
        revocation_endpoint: None,
        client_id: Some("synthetic-google-client".to_string()),
        client_secret_ref: Some("env:FIXTURE_ACCOUNT_CLIENT_SECRET".to_string()),
        redirect_uri: Some("https://gateway.example.invalid/oauth/callback".to_string()),
        scopes: Some(scopes.iter().map(|s| (*s).to_string()).collect()),
        send_resource_parameter: Some(false),
        external_strategy: None,
    }
}

fn default_descriptor() -> AccountDescriptor {
    descriptor(
        ISSUER,
        RESOURCE,
        &["https://www.googleapis.com/auth/drive.readonly"],
    )
}

fn config(reference: Option<&str>, id: &str, descriptor: AccountDescriptor) -> Config {
    let mut backends = HashMap::new();
    backends.insert(
        "drive".to_string(),
        BackendConfig {
            enabled: true,
            account: reference.map(str::to_string),
            transport: TransportConfig::Http {
                http_url: "https://drive.invalid/mcp".to_string(),
                streamable_http: true,
                protocol_version: None,
            },
            ..BackendConfig::default()
        },
    );
    Config {
        backends,
        accounts: Some(AccountsConfig {
            schema_version: "accounts.v1".to_string(),
            enabled: true,
            deployment: "single_process".to_string(),
            instance_id: "reload-guard-tests".to_string(),
            store_dir: PathBuf::from("/synthetic/fixture/accounts/records"),
            authority_dir: PathBuf::from("/synthetic/fixture/accounts/authority"),
            current_key_id: "current".to_string(),
            keys: BTreeMap::from([(
                "current".to_string(),
                "env:FIXTURE_ACCOUNT_STORE_KEY".to_string(),
            )]),
            descriptors: Some([(id.to_string(), descriptor)].into_iter().collect()),
            limits: AccountsLimits::default(),
        }),
        ..Config::default()
    }
}

fn bound(descriptor: AccountDescriptor) -> Config {
    config(Some(WORK), WORK, descriptor)
}

/// POSITIVE CONTROL — an unchanged binding is not refused.
#[test]
fn an_unchanged_binding_is_not_refused() {
    assert!(
        reload_binding_refusal(&bound(default_descriptor()), &bound(default_descriptor()))
            .is_none(),
        "an unchanged account binding must reload normally; refusing it would make the guard \
         indistinguishable from a broken reload"
    );
}

/// POSITIVE CONTROL — a change that touches no bound descriptor is not refused.
#[test]
fn an_unrelated_edit_beside_an_unchanged_binding_is_not_refused() {
    let mut edited = bound(default_descriptor());
    edited
        .backends
        .get_mut("drive")
        .expect("fixture backend")
        .headers
        .insert("X-Trace".to_string(), "on".to_string());

    assert!(
        reload_binding_refusal(&bound(default_descriptor()), &edited).is_none(),
        "an edit that leaves every referenced descriptor identical must not be refused"
    );
}

/// A CHANGED ISSUER CANNOT REUSE THE OLD CREDENTIALS.
#[test]
fn a_changed_descriptor_issuer_is_refused() {
    let refusal = reload_binding_refusal(
        &bound(default_descriptor()),
        &bound(descriptor(
            "https://accounts.evil.invalid",
            RESOURCE,
            &["https://www.googleapis.com/auth/drive.readonly"],
        )),
    )
    .expect("a new trusted issuer invalidates every lease minted under the old one");
    assert!(
        refusal.contains(WORK),
        "the refusal must name the descriptor: {refusal}"
    );
}

/// A CHANGED RESOURCE CANNOT REUSE THE OLD CREDENTIALS.
///
/// The resource is half of the five-field account key and the audience the
/// credential is scoped to, so reusing a lease across it would address a
/// different account with the same handle.
#[test]
fn a_changed_descriptor_resource_is_refused() {
    assert!(
        reload_binding_refusal(
            &bound(default_descriptor()),
            &bound(descriptor(
                ISSUER,
                "https://www.googleapis.invalid/gmail/v1",
                &["https://www.googleapis.com/auth/drive.readonly"],
            )),
        )
        .is_some(),
        "the account key's resource changed; the old lease addresses a different account"
    );
}

/// CHANGED REQUESTED SCOPES CANNOT REUSE THE OLD CREDENTIALS.
#[test]
fn changed_descriptor_scopes_are_refused() {
    assert!(
        reload_binding_refusal(
            &bound(default_descriptor()),
            &bound(descriptor(
                ISSUER,
                RESOURCE,
                &[
                    "https://www.googleapis.com/auth/drive.readonly",
                    "https://www.googleapis.com/auth/drive",
                ],
            )),
        )
        .is_some(),
        "a broader scope set is a different authorization, not a refreshed token"
    );
}

/// A CHANGED ACCOUNT REFERENCE IS REFUSED.
///
/// Repointing a live backend at a different account is a different person's
/// credential. The installed strategy is keyed by the descriptor it was built
/// from, so a silent repoint would either keep the old account or dispatch with
/// none.
#[test]
fn a_changed_account_reference_is_refused() {
    let old = bound(default_descriptor());
    let mut new = bound(default_descriptor());
    new.backends
        .get_mut("drive")
        .expect("fixture backend")
        .account = Some("personal-gmail".to_string());

    assert!(
        reload_binding_refusal(&old, &new).is_some(),
        "a backend repointed at another account must not keep dispatching with the old one"
    );
}

/// BINDING A PREVIOUSLY UNBOUND BACKEND IS REFUSED.
///
/// Nothing installed a strategy for it, so the reload would leave a backend that
/// declares a managed account and cannot serve one. Refusing before any registry
/// mutation is the only outcome that leaves the running gateway coherent.
#[test]
fn newly_binding_a_backend_to_an_account_is_refused() {
    assert!(
        reload_binding_refusal(
            &config(None, WORK, default_descriptor()),
            &bound(default_descriptor())
        )
        .is_some(),
        "a binding added by a reload has no installed strategy behind it"
    );
}

/// REMOVING A REFERENCED DESCRIPTOR IS REFUSED.
#[test]
fn removing_a_referenced_descriptor_is_refused() {
    assert!(
        reload_binding_refusal(
            &bound(default_descriptor()),
            &config(Some(WORK), "personal-gmail", default_descriptor()),
        )
        .is_some(),
        "a bound backend whose descriptor disappeared must not keep its old credentials"
    );
}
