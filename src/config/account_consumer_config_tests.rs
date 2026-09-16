// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Consumer-side binding of `accounts.descriptors` from configuration.
//!
//! Every case here evaluates a real `Config` through `Config::load_evaluated`
//! (which runs `validate_with_env` against the overlay the load produced) or
//! deserializes a real `capability::definition::AuthConfig`. No API that does
//! not exist today is called, so this module COMPILES against current code and
//! the failures below are semantic RED, not compile gaps.
//!
//! What the approved contract says and what current code does:
//!
//! - `BackendConfig` has no `account` field, and its `transport` is a
//!   `#[serde(flatten)]` untagged enum, so `deny_unknown_fields` is not usable
//!   there and an `account:` key is SILENTLY DROPPED. A backend that references
//!   a descriptor that does not exist therefore starts today with ordinary
//!   static-credential behaviour — the reference is not merely unenforced, it is
//!   invisible. The same holds for `AuthConfig` on the REST side.
//! - `validate_descriptors` accepts `shared`/`external` descriptors without
//!   looking at them, and `AccountDescriptor` is `deny_unknown_fields`, so an
//!   `external_strategy:` block is refused today for the WRONG reason (unknown
//!   field) rather than validated as an `IdentityPropagationConfig`. The tests
//!   assert on the contract's reason, so an unknown-field refusal cannot pass
//!   as a success.
//!
//! Two cases are deliberately GREEN today and must stay green: they are the
//! over-restriction guard for existing shared/static behaviour.
//!
//! All fixture values are synthetic. No process environment is mutated: key
//! material reaches the load through the existing `env_files` overlay, exactly
//! as `account_custody_tests.rs` does.

use super::Config;
use crate::capability::definition::AuthConfig;
use std::fs;
use std::path::{Path, PathBuf};

const CURRENT_B64: &str = "UVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVE=";
const CURRENT_VAR: &str = "ACCOUNT_CONSUMER_CURRENT_KEY";

/// A synthetic static credential. Its presence on a managed-account backend is
/// the thing under test; it is never a real token.
const STATIC_AUTHORIZATION: &str = "Bearer synthetic-static-gateway-token";

fn write_env(dir: &Path) -> PathBuf {
    let path = dir.join("keys.env");
    fs::write(&path, format!("{CURRENT_VAR}={CURRENT_B64}\n")).unwrap();
    path
}

fn quoted(path: &Path) -> String {
    serde_json::to_string(&path.to_string_lossy().as_ref()).expect("path must JSON-quote")
}

/// The store half of an enabled `accounts` block, indented for the block body.
fn store_block(dir: &Path) -> String {
    format!(
        "  schema_version: accounts.v1\n  \
         enabled: true\n  \
         deployment: single_process\n  \
         instance_id: gateway-consumer\n  \
         store_dir: {}\n  \
         authority_dir: {}\n  \
         current_key_id: current\n  \
         keys:\n    current: env:{CURRENT_VAR}\n",
        quoted(&dir.join("store")),
        quoted(&dir.join("authority")),
    )
}

/// A structurally complete `personal_managed` descriptor (approved table rows
/// 424-428), so nothing below is refused for a missing-field reason.
fn managed_descriptor(id: &str, provider: &str) -> String {
    format!(
        "    {id}:\n      \
         mode: personal_managed\n      \
         provider: {provider}\n      \
         resource: https://api.example.invalid/\n      \
         issuer: https://issuer.example.invalid\n      \
         authorization_endpoint: https://issuer.example.invalid/authorize\n      \
         token_endpoint: https://issuer.example.invalid/token\n      \
         client_id: synthetic-client-id\n      \
         redirect_uri: https://gateway.example.invalid/callback\n      \
         scopes:\n        - https://api.example.invalid/scope.read\n      \
         send_resource_parameter: true\n"
    )
}

fn external_descriptor(id: &str, provider: &str, strategy: &str) -> String {
    format!(
        "    {id}:\n      \
         mode: external\n      \
         provider: {provider}\n      \
         resource: https://external.example.invalid/\n      \
         issuer: https://issuer.example.invalid\n      \
         external_strategy:\n        \
         strategy: {strategy}\n        \
         audience: https://external.example.invalid/\n        \
         session_mode: stateless\n        \
         required: true\n        \
         token_exchange_endpoint: https://issuer.example.invalid/exchange\n"
    )
}

fn shared_descriptor(id: &str, provider: &str) -> String {
    format!("    {id}:\n      mode: shared\n      provider: {provider}\n")
}

/// Write a config whose `accounts` block carries `descriptors` and whose
/// `backends` block is supplied verbatim, then evaluate it through the real
/// load path (`load_evaluated` runs `validate_with_env`).
fn evaluate(dir: &Path, port: u16, descriptors: &str, backends: &str) -> crate::Result<()> {
    let env_path = write_env(dir);
    let body = format!(
        "env_files:\n  - {}\nserver:\n  port: {port}\naccounts:\n{}  descriptors:\n{descriptors}{backends}",
        quoted(&env_path),
        store_block(dir),
    );
    let path = dir.join(format!("config-{port}.yaml"));
    fs::write(&path, body).unwrap();
    Config::load_evaluated(Some(path.as_path())).map(|_| ())
}

/// The error text of a load that must fail, or a named panic when it succeeds.
fn refusal_text(result: crate::Result<()>, what: &str) -> String {
    match result {
        Ok(()) => panic!("{what} must refuse load"),
        Err(error) => error.to_string(),
    }
}

fn serialized(path: &Path) -> serde_json::Value {
    let evaluated = Config::load_evaluated(Some(path)).expect("config must evaluate");
    serde_json::to_value(&evaluated.config).expect("Config must serialize")
}

// ── Unresolved / conflicting references ───────────────────────────────────────

/// CONTRACT: `BackendConfig.account` names an `accounts.descriptors` MAP KEY.
/// A name that is not a key is a startup refusal — it is not the backend
/// registry name, the provider name, an email or a display name, and it must
/// not degrade to static-credential dispatch.
///
/// CURRENT CODE: no `account` field exists, the key is dropped by serde, and
/// the gateway starts with a backend that silently uses its static headers.
/// Semantic RED.
#[test]
fn backend_account_naming_no_descriptor_key_must_refuse_load() {
    let root = tempfile::TempDir::new().unwrap();
    // `work-gmail` IS a declared descriptor; `google` is its PROVIDER and
    // `gmail-backend` is its BACKEND REGISTRY NAME. Neither is a descriptor
    // key, so both references below must be refused.
    let descriptors = managed_descriptor("work-gmail", "google");

    for (port, reference) in [(18711, "google"), (18712, "gmail-backend")] {
        let backends = format!(
            "backends:\n  gmail-backend:\n    http_url: https://backend.example.invalid/mcp\n    account: {reference}\n"
        );
        let text = refusal_text(
            evaluate(root.path(), port, &descriptors, &backends),
            &format!("backend account reference '{reference}', which is not a descriptor key,"),
        );
        assert!(
            text.contains(reference),
            "refusal must name the unresolved reference '{reference}': {text}"
        );
        assert!(
            text.contains("descriptor") || text.contains("account"),
            "refusal must say the reference is an account descriptor id: {text}"
        );
    }
}

/// CONTRACT: `account` and a second `identity_propagation` declaration on the
/// same backend are two different answers to "how is this backend
/// authenticated". Declaring both is a conflict, refused at load; otherwise
/// whichever one a resolver happened to read first would silently win.
///
/// CURRENT CODE: `account` is dropped, the `identity_propagation` block alone
/// validates, and load succeeds. Semantic RED.
#[test]
fn account_plus_identity_propagation_on_one_backend_is_a_conflict() {
    let root = tempfile::TempDir::new().unwrap();
    let descriptors = managed_descriptor("work-gmail", "google");
    let backends = "backends:\n  gmail-backend:\n    \
         http_url: https://backend.example.invalid/mcp\n    \
         account: work-gmail\n    \
         identity_propagation:\n      \
         strategy: signed_assertion\n      \
         audience: https://backend.example.invalid/\n      \
         session_mode: stateless\n      \
         required: true\n";

    let text = refusal_text(
        evaluate(root.path(), 18713, &descriptors, backends),
        "a backend declaring both account and identity_propagation",
    );
    assert!(
        text.contains("gmail-backend"),
        "refusal must name the conflicting backend: {text}"
    );
    assert!(
        text.contains("account") && text.contains("identity_propagation"),
        "refusal must name BOTH declarations, so the operator knows which to delete: {text}"
    );
}

// ── Managed consumers reject shared / static credentials ──────────────────────

/// CONTRACT: a `personal_managed` consumer must reject `shared_account = true`
/// and any static Authorization override. A managed account is one human's
/// token under custody; a shared-account flag beside it, or a static header the
/// transport would send anyway, means some caller gets a credential that is not
/// theirs.
///
/// CURRENT CODE: neither pairing is inspected (the `account` key is invisible),
/// so both configs start. Semantic RED, one refusal per hazard.
#[test]
fn managed_account_backend_refuses_shared_account_and_static_authorization() {
    let root = tempfile::TempDir::new().unwrap();
    let descriptors = managed_descriptor("work-gmail", "google");

    let shared_flag = "backends:\n  gmail-backend:\n    \
         http_url: https://backend.example.invalid/mcp\n    \
         account: work-gmail\n    \
         oauth:\n      enabled: true\n      shared_account: true\n";
    let shared_text = refusal_text(
        evaluate(root.path(), 18714, &descriptors, shared_flag),
        "a personal_managed account with shared_account=true",
    );
    assert!(
        shared_text.contains("shared_account"),
        "refusal must name shared_account: {shared_text}"
    );
    assert!(
        shared_text.contains("work-gmail") || shared_text.contains("gmail-backend"),
        "refusal must name the managed account or its backend: {shared_text}"
    );

    let static_header = format!(
        "backends:\n  gmail-backend:\n    \
         http_url: https://backend.example.invalid/mcp\n    \
         account: work-gmail\n    \
         headers:\n      Authorization: {STATIC_AUTHORIZATION}\n"
    );
    let static_text = refusal_text(
        evaluate(root.path(), 18715, &descriptors, &static_header),
        "a personal_managed account with a static Authorization override",
    );
    assert!(
        static_text.contains("Authorization"),
        "refusal must name the overriding header: {static_text}"
    );
    assert!(
        !static_text.contains(STATIC_AUTHORIZATION),
        "the refusal must not echo the credential value: {static_text}"
    );
}

// ── External mode strategy validation ─────────────────────────────────────────

/// CONTRACT: `external` mode carries `external_strategy` as the EXISTING
/// `IdentityPropagationConfig`, and only `signed_assertion` or `token_exchange`
/// are accepted there. `vault` is the compilation target of `personal_managed`,
/// not something an external descriptor may request; `passthrough` mints
/// nothing and is not an external minting strategy.
///
/// CURRENT CODE: `AccountDescriptor` is `deny_unknown_fields` and has no
/// `external_strategy`, so BOTH halves below fail today — the valid one is
/// refused, and the invalid one is refused for the wrong reason. The assertions
/// pin the contract's reason, so an unknown-field error cannot pass as success.
/// Semantic RED both ways.
#[test]
fn external_descriptor_strategy_accepts_only_minting_strategies() {
    let root = tempfile::TempDir::new().unwrap();
    let backends = "backends:\n  external-backend:\n    \
         http_url: https://external.example.invalid/mcp\n    \
         account: partner-api\n";

    for (port, strategy) in [(18716, "signed_assertion"), (18717, "token_exchange")] {
        let descriptors = external_descriptor("partner-api", "partner", strategy);
        evaluate(root.path(), port, &descriptors, backends).unwrap_or_else(|error| {
            panic!("external descriptor with {strategy} must load, got: {error}")
        });
    }

    for (port, strategy) in [(18718, "vault"), (18719, "passthrough")] {
        let descriptors = external_descriptor("partner-api", "partner", strategy);
        let text = refusal_text(
            evaluate(root.path(), port, &descriptors, backends),
            &format!("an external descriptor requesting strategy {strategy}"),
        );
        assert!(
            text.contains("external_strategy"),
            "refusal must name external_strategy, not an unknown-field parse error: {text}"
        );
        assert!(
            text.contains("signed_assertion") && text.contains("token_exchange"),
            "refusal must say which strategies external mode allows: {text}"
        );
    }
}

// ── Mixed external + managed must coexist ─────────────────────────────────────

/// CONTRACT: dispatch is PER BACKEND. An `external` descriptor minting a
/// token-exchange credential and a `personal_managed` descriptor compiling to
/// `PropagationStrategyKind::Vault` are two different strategies in one config,
/// and neither substitutes for the other. The process-wide
/// `validate_single_minting_strategy_kind` refusal is exactly what per-backend
/// descriptor dispatch replaces.
///
/// CURRENT CODE: the config is refused (unknown `external_strategy` field), and
/// even without that nothing would bind either backend to its descriptor.
/// Semantic RED. This is also the over-restriction guard for the new path: a
/// valid mixed config must LOAD, not be rejected for tidiness.
#[test]
fn mixed_external_and_personal_managed_descriptors_load_together() {
    let root = tempfile::TempDir::new().unwrap();
    let descriptors = format!(
        "{}{}",
        external_descriptor("partner-api", "partner", "token_exchange"),
        managed_descriptor("work-gmail", "google"),
    );
    let backends = "backends:\n  \
         external-backend:\n    http_url: https://external.example.invalid/mcp\n    account: partner-api\n  \
         gmail-backend:\n    http_url: https://backend.example.invalid/mcp\n    account: work-gmail\n";

    evaluate(root.path(), 18720, &descriptors, backends)
        .expect("a valid mixed external + personal_managed config must load");
}

/// CONTRACT: two descriptors may share one `provider` and stay distinct
/// accounts — the descriptor KEY is the identity, the provider is not. A config
/// declaring `work-gmail` and `personal-gmail`, both `google`, on two backends
/// must load; refusing it would make a second account of the same provider
/// unconfigurable.
///
/// CURRENT CODE: the references are dropped, so this passes vacuously today. It
/// is the anti-over-restriction guard that must still hold once the reference
/// is enforced, and it is the config-level companion to the resolver test that
/// keeps the two descriptors' tokens apart.
#[test]
fn two_descriptors_of_one_provider_are_distinct_accounts() {
    let root = tempfile::TempDir::new().unwrap();
    let descriptors = format!(
        "{}{}",
        managed_descriptor("personal-gmail", "google"),
        managed_descriptor("work-gmail", "google"),
    );
    let backends = "backends:\n  \
         work-backend:\n    http_url: https://work.example.invalid/mcp\n    account: work-gmail\n  \
         personal-backend:\n    http_url: https://personal.example.invalid/mcp\n    account: personal-gmail\n";

    evaluate(root.path(), 18721, &descriptors, backends)
        .expect("two descriptors sharing a provider must remain configurable");
}

// ── Positive reference survives evaluation ────────────────────────────────────

/// CONTRACT: a resolved `account` reference is part of the backend's
/// configuration and must survive parse and re-serialization, so a config
/// rewrite cannot quietly demote a managed backend to static credentials.
///
/// CURRENT CODE: the key is dropped at parse, so the re-serialized backend has
/// no `account` at all. Semantic RED, and the honest proof that the
/// unresolved-reference test above is not merely about error text: today the
/// reference does not reach `Config` in any form.
#[test]
fn resolved_account_reference_survives_config_round_trip() {
    let root = tempfile::TempDir::new().unwrap();
    let env_path = write_env(root.path());
    let body = format!(
        "env_files:\n  - {}\nserver:\n  port: 18722\naccounts:\n{}  descriptors:\n{}backends:\n  gmail-backend:\n    http_url: https://backend.example.invalid/mcp\n    account: work-gmail\n",
        quoted(&env_path),
        store_block(root.path()),
        managed_descriptor("work-gmail", "google"),
    );
    let path = root.path().join("round-trip.yaml");
    fs::write(&path, body).unwrap();

    let dumped = serialized(&path);
    assert_eq!(
        dumped["accounts"]["descriptors"]["work-gmail"]["mode"], "personal_managed",
        "the descriptor itself must survive: {dumped}"
    );
    assert_eq!(
        dumped["backends"]["gmail-backend"]["account"], "work-gmail",
        "the backend's account reference must survive parse and re-serialization: {dumped}"
    );
}

// ── REST capability side ──────────────────────────────────────────────────────

/// CONTRACT: a REST capability's `auth.account` names the same
/// `accounts.descriptors` key, and its `oauth:<provider>` credential key must
/// MATCH the referenced descriptor's `provider`. A capability keyed
/// `oauth:slack` pointing at a `google` descriptor is a refusal, not a
/// best-effort lookup.
///
/// CURRENT CODE: `AuthConfig` has no `account` field, so the reference is
/// dropped at deserialization and no provider comparison is even possible. This
/// test proves the drop against the real DTO and compiles today; the control
/// assertions show the same document IS being read. Semantic RED. The
/// comparison itself needs the field to exist first — the exact expected
/// validator signature is recorded in `manifest.json`.
#[test]
fn rest_capability_auth_account_reference_is_not_dropped() {
    let document = serde_json::json!({
        "required": true,
        "type": "oauth",
        "key": "oauth:google",
        "account": "work-gmail",
        "shared_account": false,
    });

    let auth: AuthConfig =
        serde_json::from_value(document).expect("capability auth block must deserialize");

    // Control: the document really is being read, so the assertion below is
    // about the missing binding and not about a mis-shaped fixture.
    assert_eq!(auth.key, "oauth:google");
    assert!(!auth.shared_account);

    let round_tripped = serde_json::to_value(&auth).expect("AuthConfig must serialize");
    assert_eq!(
        round_tripped.get("account").and_then(|v| v.as_str()),
        Some("work-gmail"),
        "auth.account must survive into the capability's own configuration; while it is \
         dropped, no oauth:<provider> vs descriptor.provider comparison can be made at all: \
         {round_tripped}"
    );
}

// ── Over-restriction guards (GREEN today, must stay GREEN) ────────────────────

/// EXISTING BEHAVIOUR: a `shared` descriptor beside a backend that uses the
/// EXISTING `identity_propagation` block, with no `account` reference anywhere,
/// is an ordinary config today and must keep loading. Per-backend descriptor
/// dispatch must not tighten a configuration that never opted into descriptors.
#[test]
fn shared_descriptor_beside_existing_identity_propagation_still_loads() {
    let root = tempfile::TempDir::new().unwrap();
    let descriptors = shared_descriptor("team-bot", "slack");
    let backends = "backends:\n  slack-backend:\n    \
         http_url: https://slack.example.invalid/mcp\n    \
         identity_propagation:\n      \
         strategy: signed_assertion\n      \
         audience: https://slack.example.invalid/\n      \
         session_mode: per_user\n      \
         required: true\n";

    evaluate(root.path(), 18723, &descriptors, backends)
        .expect("existing identity_propagation beside a shared descriptor must keep loading");
}

/// EXISTING BEHAVIOUR: a backend with a static Authorization header and an
/// enabled `shared_account` OAuth client, in a config with NO `accounts` block
/// at all, is untouched by this increment — it must still load and still
/// round-trip its header. The managed-account refusal above must be scoped to
/// managed accounts, not to static credentials in general.
#[test]
fn static_credentials_without_any_accounts_block_are_unaffected() {
    let root = tempfile::TempDir::new().unwrap();
    let body = format!(
        "server:\n  port: 18724\nbackends:\n  legacy-backend:\n    \
         http_url: https://legacy.example.invalid/mcp\n    \
         headers:\n      Authorization: {STATIC_AUTHORIZATION}\n    \
         oauth:\n      enabled: true\n      shared_account: true\n"
    );
    let path = root.path().join("legacy.yaml");
    fs::write(&path, body).unwrap();

    let dumped = serialized(&path);
    assert_eq!(
        dumped["backends"]["legacy-backend"]["headers"]["Authorization"], STATIC_AUTHORIZATION,
        "existing static credential behaviour must be preserved verbatim: {dumped}"
    );
    assert_eq!(
        dumped["backends"]["legacy-backend"]["oauth"]["shared_account"], true,
        "an explicit shared account stays explicitly shared: {dumped}"
    );
    match dumped.get("accounts") {
        None | Some(serde_json::Value::Null) => {}
        Some(other) => panic!("an omitted accounts block must stay absent, got {other}"),
    }
}

#[path = "account_consumer_config_tests/fail_closed.rs"]
mod fail_closed;

#[path = "account_consumer_config_tests/raw_vault.rs"]
mod raw_vault;
