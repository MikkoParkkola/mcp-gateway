// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Adapter entries that are accepted and preserved through a round trip.

use super::*;

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
                .is_some_and(std::vec::Vec::is_empty),
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
