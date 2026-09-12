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

use mcp_gateway::config::Config;

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

// ── Acceptance ────────────────────────────────────────────────────────────────

/// A valid adapter entry is accepted AND preserved, field for field.
///
/// Preservation is asserted through the round-trip, so a parser that accepted
/// `adapters` by ignoring it — dropping the operator's header name, issuer,
/// secret reference and API-key allowlist on the floor — fails here instead of
/// passing.
#[test]
fn a_valid_adapter_entry_is_accepted_and_preserved_through_a_round_trip() {
    let yaml = config_yaml(VALID_ADAPTERS);
    let accounts = accounts_roundtrip(&yaml);
    let adapters = adapters_sequence(&accounts);
    assert_eq!(
        adapters.len(),
        1,
        "the single configured adapter must survive"
    );
    let adapter = &adapters[0];

    let expected: serde_yaml::Value = serde_yaml::from_str(
        "\
kind: openwebui_signed_header
installation_id: owui-prod-1
header: X-OpenWebUI-Assertion
issuer: open-webui
hmac_secret_ref: env:OPENWEBUI_ADAPTER_HMAC
allowed_api_key_names:
  - owui-gateway-key
max_lifetime_seconds: 300
clock_skew_seconds: 30
",
    )
    .expect("expectation fixture parses");

    for (key, want) in expected.as_mapping().expect("mapping fixture") {
        let got = adapter
            .get(key)
            .unwrap_or_else(|| panic!("adapter field {key:?} was dropped by the round-trip"));
        assert_eq!(got, want, "adapter field {key:?} was rewritten");
    }
}

/// The two approved defaults are exactly 300 and 30 seconds.
///
/// Omitting both optional fields must yield those values and not, say, a zero,
/// an unbounded lifetime, or some other number: the approved document fixes
/// them, and a wrong default silently widens the accepted assertion window on
/// every deployment that does not spell them out.
#[test]
fn omitted_lifetime_and_skew_take_the_approved_defaults() {
    let yaml = config_yaml(
        "\
\x20 adapters:
    - kind: openwebui_signed_header
      installation_id: owui-prod-1
      header: X-OpenWebUI-Assertion
      issuer: open-webui
      hmac_secret_ref: env:OPENWEBUI_ADAPTER_HMAC
      allowed_api_key_names:
        - owui-gateway-key
",
    );
    let accounts = accounts_roundtrip(&yaml);
    let adapters = adapters_sequence(&accounts);
    let adapter = &adapters[0];

    assert_eq!(
        adapter
            .get("max_lifetime_seconds")
            .and_then(serde_yaml::Value::as_u64),
        Some(300),
        "`max_lifetime_seconds` must default to the approved 300 seconds"
    );
    assert_eq!(
        adapter
            .get("clock_skew_seconds")
            .and_then(serde_yaml::Value::as_u64),
        Some(30),
        "`clock_skew_seconds` must default to the approved 30 seconds"
    );
}

/// The operator-chosen assertion header name is carried verbatim.
///
/// The approved contract fixes the FIELD name (`header`), not the deployment's
/// chosen HTTP field spelling. A parser that normalised the case, or that only
/// honoured one blessed vendor header, fails here.
#[test]
fn the_configured_assertion_header_name_is_carried_verbatim() {
    let yaml = config_yaml(
        "\
\x20 adapters:
    - kind: openwebui_signed_header
      installation_id: owui-eu-2
      header: X-Acme-Portal-Assertion
      issuer: open-webui
      hmac_secret_ref: env:OPENWEBUI_ADAPTER_HMAC_EU
      allowed_api_key_names:
        - portal-key
",
    );
    let accounts = accounts_roundtrip(&yaml);
    let header = adapters_sequence(&accounts)[0]
        .get("header")
        .and_then(serde_yaml::Value::as_str)
        .map(str::to_owned)
        .expect("configured header name must survive a round-trip");
    assert_eq!(
        header, "X-Acme-Portal-Assertion",
        "the operator's header name must be carried byte for byte"
    );
}

/// Several API key names may be allowlisted for one installation, in order.
///
/// The allowlist is what gates the adapter ("considered only after successful
/// gateway authentication with a named API key in that adapter's allowlist"),
/// so silently collapsing or reordering it changes who may assert identities.
#[test]
fn a_multi_entry_api_key_allowlist_is_preserved_in_order() {
    let yaml = config_yaml(
        "\
\x20 adapters:
    - kind: openwebui_signed_header
      installation_id: owui-prod-1
      header: X-OpenWebUI-Assertion
      issuer: open-webui
      hmac_secret_ref: env:OPENWEBUI_ADAPTER_HMAC
      allowed_api_key_names:
        - owui-gateway-key
        - owui-gateway-key-rotating
",
    );
    let accounts = accounts_roundtrip(&yaml);
    let names = adapters_sequence(&accounts)[0]
        .get("allowed_api_key_names")
        .and_then(serde_yaml::Value::as_sequence)
        .expect("allowlist must survive a round-trip")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("allowlist entries are strings")
                .to_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(names, ["owui-gateway-key", "owui-gateway-key-rotating"]);
}

/// Two independent installations may coexist as two list entries.
#[test]
fn two_distinct_installations_are_accepted_side_by_side() {
    let yaml = config_yaml(
        "\
\x20 adapters:
    - kind: openwebui_signed_header
      installation_id: owui-prod-1
      header: X-OpenWebUI-Assertion
      issuer: open-webui
      hmac_secret_ref: env:OPENWEBUI_ADAPTER_HMAC_PROD
      allowed_api_key_names:
        - prod-key
    - kind: openwebui_signed_header
      installation_id: owui-staging-1
      header: X-OpenWebUI-Assertion
      issuer: open-webui
      hmac_secret_ref: env:OPENWEBUI_ADAPTER_HMAC_STAGING
      allowed_api_key_names:
        - staging-key
",
    );
    let accounts = accounts_roundtrip(&yaml);
    let adapters = adapters_sequence(&accounts);
    assert_eq!(adapters.len(), 2, "both installations must be preserved");
    let ids = adapters
        .iter()
        .map(|adapter| {
            adapter
                .get("installation_id")
                .and_then(serde_yaml::Value::as_str)
                .expect("installation_id survives")
                .to_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(ids, ["owui-prod-1", "owui-staging-1"]);
}

/// An explicitly empty list is accepted and stays empty — it is the approved
/// default, so writing it out must not be a different configuration from
/// omitting it.
#[test]
fn an_explicitly_empty_adapter_list_is_accepted() {
    let yaml = config_yaml("  adapters: []\n");
    let accounts = accounts_roundtrip(&yaml);
    assert!(
        adapters_sequence(&accounts).is_empty(),
        "an empty adapter list must stay empty: {accounts:?}"
    );
}

/// Omitted `adapters` keeps the legacy configuration exactly as written.
///
/// This is the compatibility half of the contract and the sentinel for every
/// negative case below: it proves the surrounding fixture is otherwise valid,
/// so a refusal elsewhere in this file is about `adapters` and nothing else.
#[test]
fn an_absent_adapter_block_leaves_the_legacy_accounts_config_untouched() {
    let yaml = config_yaml("");
    let accounts = accounts_roundtrip(&yaml);

    let adapters = accounts.get("adapters");
    assert!(
        adapters.is_none()
            || adapters
                .and_then(serde_yaml::Value::as_sequence)
                .is_some_and(|list| list.is_empty()),
        "an absent adapters block must default to nothing, not to a populated \
         entry: {accounts:?}"
    );
    assert_eq!(
        accounts
            .get("instance_id")
            .and_then(serde_yaml::Value::as_str),
        Some("openwebui-adapter-config-red"),
        "legacy accounts fields must be preserved unchanged"
    );
    assert_eq!(
        accounts
            .get("keys")
            .and_then(|keys| keys.get("primary"))
            .and_then(serde_yaml::Value::as_str),
        Some("env:OPENWEBUI_ADAPTER_CONFIG_RED_KEY"),
        "a key reference must stay a reference through a rewrite"
    );
}

// ── Refusals: shape ───────────────────────────────────────────────────────────

/// `adapters` is a LIST. A map of named adapters is refused rather than
/// quietly accepted, because the approved contract has no adapter-name key and
/// an implementation that took both shapes would have two identity namespaces.
#[test]
fn a_map_shaped_adapters_block_is_refused() {
    let yaml = config_yaml(
        "\
\x20 adapters:
    openwebui_main:
      kind: openwebui_signed_header
      installation_id: owui-prod-1
      header: X-OpenWebUI-Assertion
      issuer: open-webui
      hmac_secret_ref: env:OPENWEBUI_ADAPTER_HMAC
      allowed_api_key_names:
        - owui-gateway-key
",
    );
    assert_refused_naming(&yaml, &["sequence", "list", "expected a sequence", "map"]);
}

// ── Refusals: kind and issuer ─────────────────────────────────────────────────

/// An unrecognised `kind` is refused by name. The approved set has exactly one
/// member; silently treating an unknown one as that member would run a
/// deployment under an integration its operator never declared.
#[test]
fn a_malformed_adapter_kind_is_refused() {
    let yaml = config_yaml(
        "\
\x20 adapters:
    - kind: openwebui
      installation_id: owui-prod-1
      header: X-OpenWebUI-Assertion
      issuer: open-webui
      hmac_secret_ref: env:OPENWEBUI_ADAPTER_HMAC
      allowed_api_key_names:
        - owui-gateway-key
",
    );
    assert_refused_naming(&yaml, &["kind", "openwebui_signed_header", "variant"]);
}

/// A missing `kind` is refused rather than defaulted, for the same reason.
#[test]
fn an_adapter_without_a_kind_is_refused() {
    let yaml = config_yaml(
        "\
\x20 adapters:
    - installation_id: owui-prod-1
      header: X-OpenWebUI-Assertion
      issuer: open-webui
      hmac_secret_ref: env:OPENWEBUI_ADAPTER_HMAC
      allowed_api_key_names:
        - owui-gateway-key
",
    );
    assert_refused_naming(&yaml, &["kind", "missing"]);
}

/// The `issuer` is the LITERAL `open-webui`. A different issuer is refused.
///
/// The issuer is what a signed assertion is bound to; accepting an alternative
/// spelling would let assertions minted for some other issuer identity be
/// verified as Open WebUI's, which is exactly the confusion the literal exists
/// to prevent.
#[test]
fn a_wrong_issuer_is_refused() {
    let yaml = config_yaml(
        "\
\x20 adapters:
    - kind: openwebui_signed_header
      installation_id: owui-prod-1
      header: X-OpenWebUI-Assertion
      issuer: open-webui-eu
      hmac_secret_ref: env:OPENWEBUI_ADAPTER_HMAC
      allowed_api_key_names:
        - owui-gateway-key
",
    );
    assert_refused_naming(&yaml, &["issuer", "open-webui"]);
}

/// The literal is exact: a case variant is not the approved issuer either.
#[test]
fn an_issuer_differing_only_in_case_is_refused() {
    let yaml = config_yaml(
        "\
\x20 adapters:
    - kind: openwebui_signed_header
      installation_id: owui-prod-1
      header: X-OpenWebUI-Assertion
      issuer: Open-WebUI
      hmac_secret_ref: env:OPENWEBUI_ADAPTER_HMAC
      allowed_api_key_names:
        - owui-gateway-key
",
    );
    assert_refused_naming(&yaml, &["issuer", "open-webui"]);
}

/// An empty `issuer` is refused rather than read as "any issuer".
#[test]
fn an_empty_issuer_is_refused() {
    let yaml = config_yaml(
        "\
\x20 adapters:
    - kind: openwebui_signed_header
      installation_id: owui-prod-1
      header: X-OpenWebUI-Assertion
      issuer: \"\"
      hmac_secret_ref: env:OPENWEBUI_ADAPTER_HMAC
      allowed_api_key_names:
        - owui-gateway-key
",
    );
    assert_refused_naming(&yaml, &["issuer", "empty", "open-webui"]);
}

// ── Refusals: hmac_secret_ref ─────────────────────────────────────────────────

/// A MISSING `hmac_secret_ref` is refused.
///
/// There is no default signing secret and no unsigned mode in the approved
/// contract: an adapter without a secret reference either cannot verify
/// anything or, worse, would have to accept assertions unverified.
#[test]
fn an_adapter_without_an_hmac_secret_ref_is_refused() {
    let yaml = config_yaml(
        "\
\x20 adapters:
    - kind: openwebui_signed_header
      installation_id: owui-prod-1
      header: X-OpenWebUI-Assertion
      issuer: open-webui
      allowed_api_key_names:
        - owui-gateway-key
",
    );
    assert_refused_naming(&yaml, &["hmac_secret_ref", "secret", "missing"]);
}

/// An inline literal secret is refused: the reference must use `env:`.
///
/// This is a reference-SHAPE rule and is the only secret rule this file can
/// assert (see the module's out-of-scope note); it keeps signing material out
/// of the configuration file itself.
#[test]
fn an_inline_literal_hmac_secret_is_refused() {
    let yaml = config_yaml(
        "\
\x20 adapters:
    - kind: openwebui_signed_header
      installation_id: owui-prod-1
      header: X-OpenWebUI-Assertion
      issuer: open-webui
      hmac_secret_ref: s3cret-material-written-inline
      allowed_api_key_names:
        - owui-gateway-key
",
    );
    assert_refused_naming(&yaml, &["hmac_secret_ref", "env:", "reference", "literal"]);
}

/// An `env:` prefix with no variable name is refused: it references nothing.
#[test]
fn an_hmac_secret_ref_with_an_empty_variable_name_is_refused() {
    let yaml = config_yaml(
        "\
\x20 adapters:
    - kind: openwebui_signed_header
      installation_id: owui-prod-1
      header: X-OpenWebUI-Assertion
      issuer: open-webui
      hmac_secret_ref: \"env:\"
      allowed_api_key_names:
        - owui-gateway-key
",
    );
    assert_refused_naming(&yaml, &["hmac_secret_ref", "env:", "empty", "variable"]);
}

// ── Refusals: installation_id ─────────────────────────────────────────────────

/// A duplicated `installation_id` across two entries is refused.
///
/// The approved contract requires it to be UNIQUE. It is what distinguishes one
/// deployment's users from another's; two adapters claiming the same id make two
/// populations indistinguishable downstream, which is a cross-installation
/// identity collision, not a cosmetic duplicate.
#[test]
fn a_duplicate_installation_id_across_adapters_is_refused() {
    let yaml = config_yaml(
        "\
\x20 adapters:
    - kind: openwebui_signed_header
      installation_id: owui-prod-1
      header: X-OpenWebUI-Assertion
      issuer: open-webui
      hmac_secret_ref: env:OPENWEBUI_ADAPTER_HMAC_A
      allowed_api_key_names:
        - key-a
    - kind: openwebui_signed_header
      installation_id: owui-prod-1
      header: X-OpenWebUI-Assertion
      issuer: open-webui
      hmac_secret_ref: env:OPENWEBUI_ADAPTER_HMAC_B
      allowed_api_key_names:
        - key-b
",
    );
    assert_refused_naming(
        &yaml,
        &["installation", "owui-prod-1", "duplicate", "unique"],
    );
}

/// An empty `installation_id` is refused for the same reason a duplicated one
/// is: it cannot distinguish one deployment's users from another's.
#[test]
fn an_empty_installation_id_is_refused() {
    let yaml = config_yaml(
        "\
\x20 adapters:
    - kind: openwebui_signed_header
      installation_id: \"\"
      header: X-OpenWebUI-Assertion
      issuer: open-webui
      hmac_secret_ref: env:OPENWEBUI_ADAPTER_HMAC
      allowed_api_key_names:
        - owui-gateway-key
",
    );
    assert_refused_naming(&yaml, &["installation", "empty", "nonempty"]);
}

/// A missing `installation_id` is refused rather than defaulted.
#[test]
fn an_absent_installation_id_is_refused() {
    let yaml = config_yaml(
        "\
\x20 adapters:
    - kind: openwebui_signed_header
      header: X-OpenWebUI-Assertion
      issuer: open-webui
      hmac_secret_ref: env:OPENWEBUI_ADAPTER_HMAC
      allowed_api_key_names:
        - owui-gateway-key
",
    );
    assert_refused_naming(&yaml, &["installation", "missing"]);
}

// ── Refusals: header ──────────────────────────────────────────────────────────

/// `Authorization` as the configured assertion header is refused.
///
/// The approved contract says so outright. The adapter header carries an
/// ASSERTED user id from a trusted front end; `Authorization` carries the
/// caller's own credential. Letting the former be spelled as the latter would
/// let a caller-supplied credential header be read as an identity assertion.
#[test]
fn authorization_as_the_configured_header_is_refused() {
    let yaml = config_yaml(
        "\
\x20 adapters:
    - kind: openwebui_signed_header
      installation_id: owui-prod-1
      header: Authorization
      issuer: open-webui
      hmac_secret_ref: env:OPENWEBUI_ADAPTER_HMAC
      allowed_api_key_names:
        - owui-gateway-key
",
    );
    assert_refused_naming(&yaml, &["authorization", "header", "reserved"]);
}

/// The refusal is on the header NAME, not on its casing: HTTP field names are
/// case-insensitive, so `authorization` must be refused exactly as
/// `Authorization` is.
#[test]
fn authorization_as_the_configured_header_is_refused_case_insensitively() {
    let yaml = config_yaml(
        "\
\x20 adapters:
    - kind: openwebui_signed_header
      installation_id: owui-prod-1
      header: authorization
      issuer: open-webui
      hmac_secret_ref: env:OPENWEBUI_ADAPTER_HMAC
      allowed_api_key_names:
        - owui-gateway-key
",
    );
    assert_refused_naming(&yaml, &["authorization", "header", "reserved"]);
}

/// A reserved gateway identity header is refused, as the approved contract
/// requires: a front end must not be able to overwrite a header the gateway
/// itself owns and sets.
#[test]
fn a_reserved_gateway_identity_header_is_refused() {
    let yaml = config_yaml(
        "\
\x20 adapters:
    - kind: openwebui_signed_header
      installation_id: owui-prod-1
      header: Cookie
      issuer: open-webui
      hmac_secret_ref: env:OPENWEBUI_ADAPTER_HMAC
      allowed_api_key_names:
        - owui-gateway-key
",
    );
    assert_refused_naming(&yaml, &["cookie", "header", "reserved", "forbidden"]);
}

/// An empty header name is refused: there is no such HTTP field, and an empty
/// value would otherwise mean "match nothing" or "match anything" depending on
/// the lookup, neither of which an operator asked for.
#[test]
fn an_empty_header_name_is_refused() {
    let yaml = config_yaml(
        "\
\x20 adapters:
    - kind: openwebui_signed_header
      installation_id: owui-prod-1
      header: \"\"
      issuer: open-webui
      hmac_secret_ref: env:OPENWEBUI_ADAPTER_HMAC
      allowed_api_key_names:
        - owui-gateway-key
",
    );
    assert_refused_naming(&yaml, &["header", "empty", "nonempty"]);
}

/// A syntactically impossible header name is refused: a value with a space is
/// not a valid HTTP field name and could never be matched at runtime.
#[test]
fn a_header_name_that_is_not_a_valid_http_field_name_is_refused() {
    let yaml = config_yaml(
        "\
\x20 adapters:
    - kind: openwebui_signed_header
      installation_id: owui-prod-1
      header: \"X OpenWebUI Assertion\"
      issuer: open-webui
      hmac_secret_ref: env:OPENWEBUI_ADAPTER_HMAC
      allowed_api_key_names:
        - owui-gateway-key
",
    );
    assert_refused_naming(&yaml, &["header", "invalid", "name"]);
}

// ── Refusals: allowed_api_key_names ───────────────────────────────────────────

/// An empty `allowed_api_key_names` is refused rather than read as "allow all".
///
/// The approved contract requires it NONEMPTY, and it is the whole reason the
/// asserted identity can be trusted: it names WHICH authenticated API keys may
/// assert one. An empty list meaning "any key" would turn the safest-looking
/// configuration into the most permissive one.
#[test]
fn an_empty_api_key_allowlist_is_refused() {
    let yaml = config_yaml(
        "\
\x20 adapters:
    - kind: openwebui_signed_header
      installation_id: owui-prod-1
      header: X-OpenWebUI-Assertion
      issuer: open-webui
      hmac_secret_ref: env:OPENWEBUI_ADAPTER_HMAC
      allowed_api_key_names: []
",
    );
    assert_refused_naming(&yaml, &["allowed_api_key_names", "empty", "nonempty"]);
}

/// An absent allowlist is refused too — for the same reason an empty one is.
/// Omission must not be a quieter way of spelling "allow all".
#[test]
fn an_absent_api_key_allowlist_is_refused() {
    let yaml = config_yaml(
        "\
\x20 adapters:
    - kind: openwebui_signed_header
      installation_id: owui-prod-1
      header: X-OpenWebUI-Assertion
      issuer: open-webui
      hmac_secret_ref: env:OPENWEBUI_ADAPTER_HMAC
",
    );
    assert_refused_naming(&yaml, &["allowed_api_key_names", "missing", "nonempty"]);
}

/// An empty API key NAME inside the allowlist is refused: it names no key, and
/// an implementation matching it loosely would match an unnamed caller.
#[test]
fn an_empty_api_key_name_in_the_allowlist_is_refused() {
    let yaml = config_yaml(
        "\
\x20 adapters:
    - kind: openwebui_signed_header
      installation_id: owui-prod-1
      header: X-OpenWebUI-Assertion
      issuer: open-webui
      hmac_secret_ref: env:OPENWEBUI_ADAPTER_HMAC
      allowed_api_key_names:
        - \"\"
",
    );
    assert_refused_naming(&yaml, &["api_key", "api key", "empty", "nonempty"]);
}

// ── Refusals: lifetime and skew ───────────────────────────────────────────────

/// A zero `max_lifetime_seconds` is refused.
///
/// This is NOT an invented ceiling: the approved prose requires `exp` to exceed
/// `iat` WITHIN the maximum lifetime, so a maximum of zero admits no assertion
/// at all and can only be an operator mistake. No upper bound on this field is
/// asserted anywhere in this file, because the approved document states none.
#[test]
fn a_zero_max_lifetime_is_refused() {
    let yaml = config_yaml(
        "\
\x20 adapters:
    - kind: openwebui_signed_header
      installation_id: owui-prod-1
      header: X-OpenWebUI-Assertion
      issuer: open-webui
      hmac_secret_ref: env:OPENWEBUI_ADAPTER_HMAC
      allowed_api_key_names:
        - owui-gateway-key
      max_lifetime_seconds: 0
",
    );
    assert_refused_naming(&yaml, &["max_lifetime_seconds", "positive", "zero"]);
}

/// A negative `max_lifetime_seconds` is refused. Durations are unsigned in this
/// contract, so this is a parse-level refusal that must still name the
/// offending field rather than the whole unknown block.
#[test]
fn a_negative_max_lifetime_is_refused() {
    let yaml = config_yaml(
        "\
\x20 adapters:
    - kind: openwebui_signed_header
      installation_id: owui-prod-1
      header: X-OpenWebUI-Assertion
      issuer: open-webui
      hmac_secret_ref: env:OPENWEBUI_ADAPTER_HMAC
      allowed_api_key_names:
        - owui-gateway-key
      max_lifetime_seconds: -1
",
    );
    assert_refused_naming(
        &yaml,
        &["max_lifetime_seconds", "invalid", "negative", "u64"],
    );
}

/// A negative `clock_skew_seconds` is refused for the same reason. A skew
/// window is a magnitude; a negative one has no meaning, and treating it as an
/// offset would shift the accepted time window in an unintended direction.
#[test]
fn a_negative_clock_skew_is_refused() {
    let yaml = config_yaml(
        "\
\x20 adapters:
    - kind: openwebui_signed_header
      installation_id: owui-prod-1
      header: X-OpenWebUI-Assertion
      issuer: open-webui
      hmac_secret_ref: env:OPENWEBUI_ADAPTER_HMAC
      allowed_api_key_names:
        - owui-gateway-key
      clock_skew_seconds: -1
",
    );
    assert_refused_naming(&yaml, &["clock_skew_seconds", "invalid", "negative", "u64"]);
}

// ── Refusals: unknown fields ──────────────────────────────────────────────────

/// An unknown field inside an adapter is refused, matching the surrounding
/// `accounts` block's existing `deny_unknown_fields` posture and the approved
/// rule that unknown fields reject startup: a typo'd knob must not be silently
/// inert.
#[test]
fn an_unknown_field_inside_an_adapter_is_refused() {
    let yaml = config_yaml(
        "\
\x20 adapters:
    - kind: openwebui_signed_header
      installation_id: owui-prod-1
      header: X-OpenWebUI-Assertion
      issuer: open-webui
      hmac_secret_ref: env:OPENWEBUI_ADAPTER_HMAC
      allowed_api_key_names:
        - owui-gateway-key
      trust_all_api_keys: true
",
    );
    assert_refused_naming(&yaml, &["trust_all_api_keys", "unknown field"]);
}

/// The unapproved spellings of the earlier draft are refused as unknown fields.
///
/// This pins the correction: `user_header`, `clients` and `lifetimes` were never
/// part of the approved contract, and an implementation that accepted them as
/// aliases would leave two ways to configure who may assert an identity.
#[test]
fn the_unapproved_draft_field_spellings_are_refused() {
    let yaml = config_yaml(
        "\
\x20 adapters:
    - kind: openwebui_signed_header
      installation_id: owui-prod-1
      user_header: X-OpenWebUI-Assertion
      issuer: open-webui
      hmac_secret_ref: env:OPENWEBUI_ADAPTER_HMAC
      clients:
        - owui-gateway-client
      lifetimes:
        session_ttl_seconds: 900
",
    );
    assert_refused_naming(
        &yaml,
        &["user_header", "clients", "lifetimes", "unknown field"],
    );
}

// ── Gateway authentication separation, through the public API ─────────────────
//
// The fixtures above are all `enabled: false`, so the MATERIAL half of the
// approved "reject secret reuse with gateway authentication" rule is unreachable
// from them (see the module docs). The cases below close exactly that gap and
// nothing more:
//
//   * the store is `enabled: true`, so secrets are actually resolved;
//   * material reaches the load through an `env_files` overlay written into a
//     temporary directory — NO test here reads, sets or mutates a process
//     environment variable, and every value is obvious fixture filler, never a
//     real credential;
//   * the adapter and the gateway API key name TWO DIFFERENT variables holding
//     the SAME value, which is precisely the case a reference-name comparison
//     cannot see.
//
// Still configuration only: no server starts, no custody opens, and the
// directories below are deliberately never created.

/// Fixture filler, 32 ASCII bytes. Not a credential and not random: these tests
/// assert comparison behaviour, and randomness is a property of the operator's
/// secret, not of this file.
fn filler_32(tag: char) -> String {
    std::iter::repeat(tag).take(32).collect()
}

/// Base64 of 32 bytes, the shape `accounts.keys` requires.
fn store_key_b64(byte: u8) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode([byte; 32])
}

/// An enabled-store config whose adapter and gateway API key resolve through an
/// `env_files` overlay, with `gateway_key` deciding whether they collide.
fn enabled_store_yaml(dir: &std::path::Path, adapter_secret: &str, gateway_key: &str) -> String {
    let env_path = dir.join("adapter-separation.env");
    std::fs::write(
        &env_path,
        format!(
            "OWUI_SEP_STORE_KEY={}\nOWUI_SEP_ADAPTER_HMAC={adapter_secret}\n\
             OWUI_SEP_GATEWAY_KEY={gateway_key}\n",
            store_key_b64(0x41),
        ),
    )
    .expect("fixture env file must be writable");

    format!(
        "\
env_files:
  - {}
server:
  port: 18777
auth:
  enabled: true
  api_keys:
    - name: owui-gateway-key
      key: env:OWUI_SEP_GATEWAY_KEY
accounts:
  schema_version: accounts.v1
  enabled: true
  deployment: single_process
  instance_id: openwebui-adapter-separation
  store_dir: /var/lib/mcp-gateway/accounts/store
  authority_dir: /var/lib/mcp-gateway/accounts/authority
  current_key_id: primary
  keys:
    primary: env:OWUI_SEP_STORE_KEY
  adapters:
    - kind: openwebui_signed_header
      installation_id: owui-prod-1
      header: X-OpenWebUI-Assertion
      issuer: open-webui
      hmac_secret_ref: env:OWUI_SEP_ADAPTER_HMAC
      allowed_api_key_names:
        - owui-gateway-key
",
        env_path.display(),
    )
}

/// Two DIFFERENT variables holding the SAME value are one secret, and the public
/// validation entry point must refuse it.
///
/// This is the case the structural reference check provably cannot catch: the
/// two references are textually distinct. A gateway whose adapter signing key is
/// also its API key has one trust domain where the approved contract requires
/// two — an assertion could then be minted by anyone holding the API key.
#[test]
fn different_references_holding_the_same_material_are_refused_by_validate_with_env() {
    let shared = filler_32('g');
    let dir = tempfile::TempDir::new().expect("temp dir");
    let yaml = enabled_store_yaml(dir.path(), &shared, &shared);

    let config: Config =
        serde_yaml::from_str(&yaml).unwrap_or_else(|error| panic!("fixture must parse: {error}"));
    let error = config
        .validate_with_env(&config.env_overlay())
        .expect_err("an adapter secret equal to a gateway api key must be refused");

    let rendered = error.to_string();
    let lower = rendered.to_lowercase();
    assert!(
        lower.contains("adapters[0]") && lower.contains("hmac_secret_ref"),
        "refusal must name the offending adapter and field: {rendered}"
    );
    assert!(
        lower.contains("gateway") && lower.contains("auth.api_keys[0]"),
        "refusal must name the gateway credential it collides with: {rendered}"
    );
    assert!(
        !rendered.contains(&shared) && !rendered.contains(&store_key_b64(0x41)),
        "refusal must name configuration coordinates, never secret material: {rendered}"
    );
}

/// The positive control for the case above: the SAME enabled-store fixture with
/// distinct material is accepted.
///
/// Without this, the refusal above could be caused by anything else in an
/// enabled block — a store key, a directory, the overlay — rather than by the
/// reuse it claims to be about.
#[test]
fn distinct_adapter_and_gateway_material_is_accepted_by_validate_with_env() {
    let dir = tempfile::TempDir::new().expect("temp dir");
    let yaml = enabled_store_yaml(dir.path(), &filler_32('a'), &filler_32('b'));

    let config: Config =
        serde_yaml::from_str(&yaml).unwrap_or_else(|error| panic!("fixture must parse: {error}"));
    config
        .validate_with_env(&config.env_overlay())
        .unwrap_or_else(|error| {
            panic!("separated adapter and gateway material must be accepted: {error}")
        });
}

/// One variable named by BOTH an adapter and a gateway credential is refused
/// even with the store disabled.
///
/// This is the structural half reaching the public API: an operator who wires
/// one variable into both places must learn at load time, not on the day they
/// enable the store. The store stays `enabled: false`, so no store key is
/// resolved; the aliased variable itself must exist, because gateway auth
/// validation resolves `auth.bearer_token` before the adapter rules run, and a
/// missing variable would fail the fixture for an unrelated reason. It is
/// supplied by a temporary `env_files` overlay holding synthetic 32-byte
/// material — the process environment is never mutated.
#[test]
fn one_variable_named_by_both_an_adapter_and_a_bearer_token_is_refused_while_disabled() {
    let dir = tempfile::TempDir::new().expect("temp dir");
    let env_path = dir.path().join("adapter-alias.env");
    let aliased = filler_32('z');
    std::fs::write(&env_path, format!("OWUI_SEP_ALIASED={aliased}\n"))
        .expect("fixture env file must be writable");

    let yaml = format!(
        "\
env_files:
  - {}
server:
  port: 18778
auth:
  enabled: true
  bearer_token: env:OWUI_SEP_ALIASED
{}",
        env_path.display(),
        config_yaml(
            "\
\x20 adapters:
    - kind: openwebui_signed_header
      installation_id: owui-prod-1
      header: X-OpenWebUI-Assertion
      issuer: open-webui
      hmac_secret_ref: env:OWUI_SEP_ALIASED
      allowed_api_key_names:
        - owui-gateway-key
"
        )
    );

    let config: Config =
        serde_yaml::from_str(&yaml).unwrap_or_else(|error| panic!("fixture must parse: {error}"));
    let error = config
        .validate_with_env(&config.env_overlay())
        .expect_err("one variable named in both places is one secret");

    let lower = error.to_string().to_lowercase();
    assert!(
        lower.contains("adapters[0]") && lower.contains("auth.bearer_token"),
        "refusal must name both sides of the alias: {error}"
    );
}

// ── The SHIPPED load path, not just the validation entry point ────────────────
//
// The three cases above drive `serde_yaml::from_str` + `validate_with_env`
// directly. That composition is NOT what a gateway runs: `Config::load_evaluated`
// resolves `env:` secret references INTO the config — inlining
// `auth.bearer_token` and `auth.api_keys[].key` — and only then validates. On
// that path the structural alias check was handed a gateway credential that no
// longer said `env:` anything, so it matched nothing; and with the store
// disabled the material half is skipped by design. One variable named by both an
// adapter and a gateway credential was therefore accepted in silence by the only
// entry point that actually loads a gateway.
//
// The tests below go through `Config::load_evaluated` against a real file, which
// is the only way to exercise that ordering. Neither of them mutates the process
// environment: material arrives through an `env_files` overlay in a temporary
// directory, and every value is obvious filler.

/// Write a config file and the env file it declares, returning the config path.
///
/// `store_dir`/`authority_dir` are deliberately never created: this is still
/// configuration only, and nothing here opens custody.
fn write_load_fixture(
    dir: &std::path::Path,
    bearer_ref: &str,
    adapter_ref: &str,
    env_body: &str,
) -> std::path::PathBuf {
    let env_path = dir.join("adapter-load.env");
    std::fs::write(&env_path, env_body).expect("fixture env file must be writable");

    let config_path = dir.join("config.yaml");
    std::fs::write(
        &config_path,
        format!(
            "\
env_files:
  - {}
server:
  port: 18779
auth:
  enabled: true
  bearer_token: {bearer_ref}
accounts:
  schema_version: accounts.v1
  enabled: false
  deployment: single_process
  instance_id: openwebui-adapter-load-order
  store_dir: /var/lib/mcp-gateway/accounts/store
  authority_dir: /var/lib/mcp-gateway/accounts/authority
  current_key_id: primary
  keys:
    primary: env:OWUI_LOAD_STORE_KEY
  adapters:
    - kind: openwebui_signed_header
      installation_id: owui-prod-1
      header: X-OpenWebUI-Assertion
      issuer: open-webui
      hmac_secret_ref: {adapter_ref}
      allowed_api_key_names:
        - owui-gateway-key
",
            env_path.display(),
        ),
    )
    .expect("fixture config must be writable");
    config_path
}

/// THE REGRESSION. One variable named by both the adapter and the bearer token
/// must be refused by `Config::load_evaluated` even with the store disabled.
///
/// This fails on a load path that inlines the bearer token before running the
/// structural separation check, because by then `auth.bearer_token` holds
/// filler text rather than `env:OWUI_LOAD_ALIASED` and the two references
/// cannot be compared as references. The disabled store means the material
/// comparison — the only other thing that could catch it — does not run, so
/// nothing else stands behind this.
#[test]
fn load_evaluated_refuses_one_variable_shared_by_an_adapter_and_the_bearer_token() {
    let dir = tempfile::TempDir::new().expect("temp dir");
    let aliased = filler_32('z');
    let config_path = write_load_fixture(
        dir.path(),
        "env:OWUI_LOAD_ALIASED",
        "env:OWUI_LOAD_ALIASED",
        &format!(
            "OWUI_LOAD_STORE_KEY={}\nOWUI_LOAD_ALIASED={aliased}\n",
            store_key_b64(0x41),
        ),
    );

    let error = Config::load_evaluated(Some(&config_path))
        .expect_err("one variable named by both an adapter and gateway auth is one secret");

    let rendered = error.to_string();
    let lower = rendered.to_lowercase();
    assert!(
        lower.contains("adapters[0]") && lower.contains("auth.bearer_token"),
        "refusal must name both sides of the alias: {rendered}"
    );
    assert!(
        !rendered.contains(&aliased),
        "refusal must name configuration coordinates, never secret material: {rendered}"
    );
}

/// The positive control for the case above, through the SAME load path: two
/// DISTINCT references are accepted, the adapter reference survives as a
/// reference, and the variable it names is reported among the secret references.
///
/// Without this, the refusal above could be caused by anything the load path
/// does with an `accounts` block rather than by the alias it claims to be about.
/// The `secret_refs` assertion is the second half: an adapter secret is a
/// startup-only secret exactly like an account key, so a reload comparing those
/// names across overlays must be able to see it rotate.
#[test]
fn load_evaluated_accepts_distinct_references_and_reports_the_adapter_variable() {
    let dir = tempfile::TempDir::new().expect("temp dir");
    let config_path = write_load_fixture(
        dir.path(),
        "env:OWUI_LOAD_BEARER",
        "env:OWUI_LOAD_ADAPTER_HMAC",
        &format!(
            "OWUI_LOAD_STORE_KEY={}\nOWUI_LOAD_BEARER={}\nOWUI_LOAD_ADAPTER_HMAC={}\n",
            store_key_b64(0x41),
            filler_32('b'),
            filler_32('a'),
        ),
    );

    let evaluated = Config::load_evaluated(Some(&config_path))
        .unwrap_or_else(|error| panic!("separated references must load: {error}"));

    assert!(
        evaluated.secret_refs.contains("OWUI_LOAD_ADAPTER_HMAC"),
        "the adapter signing variable must be reported as a secret reference: {:?}",
        evaluated.secret_refs
    );
    assert!(
        evaluated.secret_refs.contains("OWUI_LOAD_BEARER"),
        "the existing gateway reference must still be reported: {:?}",
        evaluated.secret_refs
    );

    let dumped: serde_yaml::Value =
        serde_yaml::to_value(&evaluated.config).expect("loaded config must re-serialize");
    let hmac_ref = dumped["accounts"]["adapters"][0]["hmac_secret_ref"]
        .as_str()
        .expect("adapter reference must survive the load");
    assert_eq!(
        hmac_ref, "env:OWUI_LOAD_ADAPTER_HMAC",
        "an adapter secret reference must stay a reference, never be inlined"
    );
    assert!(
        !serde_yaml::to_string(&dumped)
            .expect("re-serialize")
            .contains(&filler_32('a')),
        "a rewrite must not carry adapter signing material"
    );
}
