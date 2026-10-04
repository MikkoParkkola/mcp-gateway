// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Adapter entries refused for shape, kind, issuer, secret reference, installation id, header, allowlist, lifetime or unknown fields.

use super::*;

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
/// verified as Open `WebUI`'s, which is exactly the confusion the literal exists
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
