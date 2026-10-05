// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! RED integration tests for the `accounts.adapters` GATEWAY CONFIG contract.
//!
//! SCOPE. Configuration only. Nothing here starts a server, opens custody,
//! touches a bridge/OIDC identity path, or asserts any browser-side behaviour.
//! No adapter runtime API is referenced, because none exists yet and a test
//! bound to an invented symbol would not compile.
//!
//! WHAT IS DRIVEN, AND ONLY THROUGH PUBLIC API:
//!   * `serde` parsing of the public `mcp_gateway::config::Config`, whose
//!     `accounts: Option<AccountsConfig>` field and `AccountsConfig` type are
//!     both public re-exports;
//!   * `Config::validate_with_env` with the config's own `Config::env_overlay`;
//!   * `Config::load_evaluated`, the SHIPPED load path, for the two cases at the
//!     end of this file. Those are there because parse-then-validate is not what
//!     a gateway runs: the load path resolves `env:` secrets INTO the config
//!     first, and a check that compares reference text has to run before it. A
//!     test that only drove `validate_with_env` could not have seen that, and
//!     nothing in this file should be read as covering the load path except
//!     those two.
//!
//! CONTRACT SOURCE — VERBATIM. The approved design excerpt supplied with this
//! task states, for `accounts.adapters`:
//!
//! > Explicit list, default empty; each Open WebUI adapter has kind
//! > `openwebui_signed_header`, unique `installation_id`, fixed `header`,
//! > `issuer` literal `open-webui`, `hmac_secret_ref` using env:, nonempty
//! > `allowed_api_key_names`, `max_lifetime_seconds` default 300 and
//! > `clock_skew_seconds` default 30
//!
//! and, in prose:
//!
//! > Adapter assertions are considered only after successful gateway
//! > authentication with a named API key in that adapter's allowlist [...]
//! > The configured assertion header cannot be Authorization or a reserved
//! > gateway identity header. Use at least 32 random secret bytes; reject
//! > secret reuse with gateway authentication or store keys.
//!
//! Every fixture below uses exactly those field names and that LIST shape.
//! A previous revision of this file invented a map of named adapters with
//! `user_header`, `clients` and a `lifetimes` sub-block; none of those spellings
//! is approved and none appears here. No ceiling on `max_lifetime_seconds`
//! beyond the approved default is asserted anywhere, because the approved
//! document states no such ceiling.
//!
//! WHY THESE ARE RED TODAY. `AccountsConfig` is `#[serde(deny_unknown_fields)]`
//! and carries no `adapters` field, so EVERY fixture below is refused today at
//! parse time with the same blanket "unknown field `adapters`". That makes the
//! naive "malformed input is rejected" assertion pass for entirely the wrong
//! reason, so no negative test here settles for "an error happened":
//! [`assert_refused_naming`] fails the test when the refusal is the blanket
//! unknown-field one, and each case then requires the refusal to NAME the thing
//! that is actually wrong with it. Symmetrically, the acceptance cases require a
//! valid block to survive a serialize round-trip, so a parser that merely
//! IGNORED `adapters` (the other plausible wrong implementation) cannot be
//! mistaken for a passing one either.
//!
//! ENVIRONMENT AND SECRETS — STATED LIMITS, NOT CLAIMS.
//!   * No test here writes, sets or mutates any environment variable.
//!   * `Config::env_overlay` is the config's own overlay accessor and MAY read
//!     process environment and/or declared `env_files`. These fixtures declare
//!     no `env_files` and no assertion depends on the VALUE of any variable, so
//!     the tests are insensitive to whatever the overlay does or does not read.
//!   * `hmac_secret_ref` fixtures name a variable that is deliberately never
//!     required to exist; the assertions are about the REFERENCE SHAPE
//!     (`env:` prefix, presence) only.
//!   * OUT OF SCOPE, EXPLICITLY: the approved rules "at least 32 random secret
//!     bytes" and "reject secret reuse with gateway authentication or store
//!     keys" are properties of RESOLVED secret MATERIAL, not of the reference
//!     string. They require the resolver to actually read the environment. All
//!     fixtures here set `accounts.enabled: false`, and if a disabled store
//!     skips secret resolution then those two rules are unreachable from this
//!     file by construction. They are therefore NOT asserted here and remain
//!     owed by a separate env-backed test that enables the store; this file
//!     must not be read as evidence that they hold.

#[path = "openwebui_adapter_config/acceptance.rs"]
mod acceptance;
#[path = "openwebui_adapter_config/auth_separation.rs"]
mod auth_separation;
#[path = "openwebui_adapter_config/refusals.rs"]
mod refusals;

use mcp_gateway::{config::Config, gateway::test_helpers::write_owner_only};

/// A complete, otherwise-valid `accounts` block with `adapters` spliced in.
///
/// `enabled: false` keeps the fixture free of any resolved secret material (see
/// module docs). The two directories are absolute, `..`-free and disjoint,
/// which is what the existing directory rules require, so nothing but the
/// `adapters` subtree can be the reason a fixture is refused.
fn config_yaml(adapters: &str) -> String {
    let yaml = format!(
        "\
accounts:
  schema_version: accounts.v1
  enabled: false
  deployment: single_process
  instance_id: openwebui-adapter-config-red
  store_dir: /var/lib/mcp-gateway/accounts/store
  authority_dir: /var/lib/mcp-gateway/accounts/authority
  current_key_id: primary
  keys:
    primary: env:OPENWEBUI_ADAPTER_CONFIG_RED_KEY
{adapters}"
    );
    if !adapters.is_empty() {
        let tree: serde_yaml::Value = serde_yaml::from_str(&yaml).expect("syntactic YAML fixture");
        assert!(
            tree["accounts"].get("adapters").is_some(),
            "adapter fixture must be nested under accounts"
        );
        assert!(
            tree.get("adapters").is_none(),
            "adapter fixture must not be a root config field"
        );
    }
    yaml
}

/// The canonical, well-formed adapter list, every approved field written out.
const VALID_ADAPTERS: &str = "\
\x20 adapters:
    - kind: openwebui_signed_header
      installation_id: owui-prod-1
      header: X-OpenWebUI-Assertion
      issuer: open-webui
      hmac_secret_ref: env:OPENWEBUI_ADAPTER_HMAC
      allowed_api_key_names:
        - owui-gateway-key
      max_lifetime_seconds: 300
      clock_skew_seconds: 30
";

/// Parse and then validate, returning the first refusal as a string.
///
/// Both stages are collapsed on purpose: an implementation may legitimately
/// refuse a malformed adapter at either one (a bad `kind` is naturally a serde
/// refusal, a duplicate `installation_id` naturally a validation refusal), and
/// a test that demanded a particular stage would be pinning an implementation
/// choice rather than the configuration contract.
fn refusal_reason(yaml: &str) -> String {
    match serde_yaml::from_str::<Config>(yaml) {
        Err(error) => error.to_string(),
        Ok(config) => match config.validate_with_env(&config.env_overlay()) {
            Err(error) => error.to_string(),
            Ok(()) => panic!("configuration was accepted but must be refused:\n{yaml}"),
        },
    }
}

/// Require a refusal that names what is wrong, not today's blanket one.
///
/// The blanket refusal is checked for explicitly rather than left to the needle
/// list: without this, every negative test in this file would pass on the
/// CURRENT parser, which knows nothing about adapters at all and rejects the
/// whole block sight unseen.
fn assert_refused_naming(yaml: &str, needles: &[&str]) {
    let reason = refusal_reason(yaml).to_lowercase();
    assert!(
        !reason.contains("unknown field `adapters`") && !reason.contains("unknown field: adapters"),
        "refused only because `accounts.adapters` is not a known field yet, \
         which is not the contract being asserted: {reason}"
    );
    assert!(
        needles.iter().any(|needle| reason.contains(needle)),
        "refusal does not name the offending configuration ({needles:?}): {reason}"
    );
}

/// Round-trip a config and hand back the `accounts` subtree as a value.
fn accounts_roundtrip(yaml: &str) -> serde_yaml::Value {
    let config: Config = serde_yaml::from_str(yaml)
        .unwrap_or_else(|error| panic!("valid configuration was refused: {error}\n{yaml}"));
    config
        .validate_with_env(&config.env_overlay())
        .unwrap_or_else(|error| panic!("valid configuration failed validation: {error}"));
    let value: serde_yaml::Value =
        serde_yaml::to_value(&config).expect("configuration must re-serialize");
    value
        .get("accounts")
        .cloned()
        .expect("accounts block must survive a serialize round-trip")
}

/// The `adapters` value as a sequence, which is the approved shape.
fn adapters_sequence(accounts: &serde_yaml::Value) -> Vec<serde_yaml::Value> {
    accounts
        .get("adapters")
        .and_then(serde_yaml::Value::as_sequence)
        .unwrap_or_else(|| {
            panic!("`accounts.adapters` must round-trip as a LIST, got: {accounts:?}")
        })
        .clone()
}
