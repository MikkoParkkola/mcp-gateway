// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Reload of `accounts.descriptors` bindings — STAGE A, behavioural RED.
//!
//! WHY THIS FILE COMPILES AGAINST THE FROZEN SNAPSHOT. Every symbol used here
//! already exists (`compute_diff`, `LiveConfig`, `Config`, the
//! `personal_accounts::config` DTOs). Registering this module ALONE therefore
//! produces an honest behavioural RED — two failing assertions on a build that
//! succeeds — rather than a compile error. No production edit is needed to make
//! it fail, and nothing here fakes the failure.
//!
//! WHAT IT PINS.
//!
//! 1. A reload must rebuild a bound backend from the EFFECTIVE compiled
//!    configuration. Today `classify_backends` copies the RAW `BackendConfig`,
//!    so a managed backend re-registered by a reload loses the
//!    `identity_propagation` its descriptor compiled to and dispatches with no
//!    per-user credential at all. That is the silent loss of managed
//!    propagation.
//!
//! 2. A change to a descriptor a live backend is bound to must be VISIBLE to
//!    the reload machinery. `accounts` is absent from both `MetaFields` and
//!    `tracked_sections`, so today an issuer swap on a referenced descriptor is
//!    invisible: no diff, no restart notice, and the old credentials keep being
//!    reused under a descriptor that no longer describes them.
//!
//! The third test is the POSITIVE CONTROL: two identical configurations must
//! stay an empty patch with nothing pending, so tests 1 and 2 cannot pass by
//! making every reload look dirty.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

use crate::config::{BackendConfig, Config, TransportConfig};
use crate::config_reload::{LiveConfig, compute_diff};
use crate::identity_propagation::PropagationStrategyKind;
use crate::personal_accounts::config::{
    AccountDescriptor, AccountsConfig, AccountsLimits, DescriptorMode,
};

/// The descriptor id both the MCP backend and (in the sibling REST suite) a
/// capability reference. Synthetic.
const WORK: &str = "work-gmail";
const OAUTH_ISSUER: &str = "https://accounts.google.invalid";
const OTHER_ISSUER: &str = "https://accounts.evil.invalid";
const RESOURCE: &str = "https://www.googleapis.invalid/drive/v3";

/// A structurally complete `personal_managed` descriptor. `issuer` is a
/// parameter because an issuer swap is the exact change test 2 drives.
fn descriptor(issuer: &str) -> AccountDescriptor {
    AccountDescriptor {
        mode: DescriptorMode::PersonalManaged,
        provider: "google".to_string(),
        resource: Some(RESOURCE.to_string()),
        issuer: Some(issuer.to_string()),
        authorization_endpoint: Some(format!("{issuer}/o/oauth2/v2/auth")),
        token_endpoint: Some(format!("{issuer}/token")),
        revocation_endpoint: None,
        client_id: Some("synthetic-google-client".to_string()),
        client_secret_ref: Some("env:FIXTURE_ACCOUNT_CLIENT_SECRET".to_string()),
        redirect_uri: Some("https://gateway.example.invalid/oauth/callback".to_string()),
        scopes: Some(vec![
            "https://www.googleapis.com/auth/drive.readonly".to_string(),
        ]),
        send_resource_parameter: Some(false),
        external_strategy: None,
    }
}

/// Synthetic store settings. Nothing here opens them: the reload diff reads the
/// `descriptors` map only.
fn accounts(issuer: &str) -> AccountsConfig {
    AccountsConfig {
        adapters: Vec::new(),
        schema_version: "accounts.v1".to_string(),
        enabled: true,
        deployment: "single_process".to_string(),
        instance_id: "reload-tests".to_string(),
        store_dir: PathBuf::from("/synthetic/fixture/accounts/records"),
        authority_dir: PathBuf::from("/synthetic/fixture/accounts/authority"),
        current_key_id: "current".to_string(),
        keys: BTreeMap::from([(
            "current".to_string(),
            "env:FIXTURE_ACCOUNT_STORE_KEY".to_string(),
        )]),
        descriptors: Some(
            BTreeMap::from([(WORK.to_string(), descriptor(issuer))])
                .into_iter()
                .collect(),
        ),
        limits: AccountsLimits::default(),
    }
}

fn bound_backend() -> BackendConfig {
    BackendConfig {
        enabled: true,
        account: Some(WORK.to_string()),
        transport: TransportConfig::Http {
            http_url: "https://drive.invalid/mcp".to_string(),
            streamable_http: true,
            protocol_version: None,
        },
        ..BackendConfig::default()
    }
}

/// A configuration declaring the descriptor, with or without the backend bound
/// to it.
fn config(issuer: &str, with_backend: bool) -> Config {
    let mut backends = HashMap::new();
    if with_backend {
        backends.insert("drive".to_string(), bound_backend());
    }
    Config {
        backends,
        accounts: Some(accounts(issuer)),
        ..Config::default()
    }
}

/// RED 1 — the reload must hand `apply_patch` the EFFECTIVE configuration.
///
/// `apply_patch` constructs the replacement `Backend` straight from the config
/// in the patch. If that config is the raw one, the rebuilt backend carries no
/// `identity_propagation`, the managed descriptor compiled to nothing on the
/// wire, and the account holder's credential is simply absent from the call the
/// gateway then makes. The assertion is on the compiled `Vault` strategy and on
/// the descriptor's own resource as the audience — the two fields custody
/// addressing and cache isolation are both derived from.
#[test]
fn reload_patch_carries_the_effective_compiled_backend_config() {
    let old = config(OAUTH_ISSUER, false);
    let new = config(OAUTH_ISSUER, true);

    let patch = compute_diff(&old, &new);

    let (name, cfg) = patch
        .backends_added
        .iter()
        .find(|(name, _)| name == "drive")
        .expect("the newly bound backend must appear in the patch");
    assert_eq!(name, "drive");

    // The raw reference survives — this half passes today and is here so the
    // failure below cannot be read as "the reference was dropped".
    assert_eq!(
        cfg.account.as_deref(),
        Some(WORK),
        "the descriptor reference must survive the diff verbatim"
    );

    let propagation = cfg.identity_propagation.as_ref().expect(
        "a reload that rebuilds a bound backend from the RAW config silently loses managed \
         propagation: the replacement would dispatch with no per-user credential at all",
    );
    assert_eq!(
        propagation.strategy,
        PropagationStrategyKind::Vault,
        "personal_managed compiles to the EXISTING Vault kind, not a new enum"
    );
    assert_eq!(
        propagation.audience, RESOURCE,
        "the audience must be the descriptor's own resource, or custody addressing and the \
         strategy's audience check disagree"
    );
    assert!(
        propagation.required,
        "a managed account has no best-effort mode"
    );
}

/// RED 2 — an issuer swap on a REFERENCED descriptor must be visible.
///
/// The backends map is byte-identical across the two configurations; only the
/// descriptor changed. `accounts` is not a tracked section today, so the reload
/// reports nothing at all and the running process keeps serving credentials
/// minted under the previous issuer. Reporting it as restart-pending is the
/// fail-closed answer this slice implements — eager authority replacement is
/// NOT implemented, and pretending otherwise is the failure mode this pins.
#[test]
fn a_changed_descriptor_issuer_is_reported_as_pending_restart() {
    let live = LiveConfig::new(config(OAUTH_ISSUER, true));
    live.set(config(OTHER_ISSUER, true));

    let pending = live.pending_restart_fields();
    assert!(
        pending.contains(&"accounts"),
        "an issuer change on a descriptor a live backend is bound to must not be invisible to \
         the reload; pending fields were {pending:?}"
    );
    assert!(
        live.restart_required(),
        "the descriptor authority changed, so the running process has NOT applied the file"
    );
}

/// POSITIVE CONTROL — an unchanged binding stays quiet.
///
/// Without this, both assertions above could be satisfied by a change that
/// marks every reload dirty, which would make `restart_required` meaningless
/// and train operators to ignore it.
#[test]
fn an_unchanged_account_binding_is_neither_diffed_nor_pending() {
    let live = LiveConfig::new(config(OAUTH_ISSUER, true));
    live.set(config(OAUTH_ISSUER, true));

    assert!(
        live.pending_restart_fields().is_empty(),
        "an unchanged accounts block must not ask for a restart"
    );
    assert!(
        compute_diff(&config(OAUTH_ISSUER, true), &config(OAUTH_ISSUER, true)).is_empty(),
        "two identical configurations must produce an empty patch"
    );
}
