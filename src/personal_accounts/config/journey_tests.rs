// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! T-CFG (design §10, §11.2): the hosted journey configuration contract.
//!
//! Every refusal starts from ONE valid hosted block and perturbs one axis, and
//! asserts the rule's own phrase. `AccountsConfig` is `deny_unknown_fields`, so
//! before `hosted` existed every fixture here was refused as "unknown field
//! `hosted`"; an `is_err()` assertion would have been green against the old
//! code and would pin nothing.

use super::super::{AccountsConfig, SecretOverlay, resolve, validate_descriptors};

const KEY_B64: &str = "UVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVE=";

/// Synthetic material only; never written to the process environment.
struct Overlay;

impl SecretOverlay for Overlay {
    fn resolve(&self, name: &str) -> Option<String> {
        match name {
            "JOURNEY_KEY" => Some(KEY_B64.to_string()),
            "ADAPTER_A" => Some("a".repeat(40)),
            "ADAPTER_B" => Some("b".repeat(40)),
            _ => None,
        }
    }
}

const BASE: &str = r#"
schema_version: accounts.v1
enabled: true
deployment: single_process
instance_id: gateway-a
store_dir: /srv/accounts/store
authority_dir: /srv/accounts/authority
current_key_id: current
keys:
  current: env:JOURNEY_KEY
hosted:
  public_origin: "https://chat.example.com"
  return_paths: ["/"]
adapters:
  - kind: openwebui_signed_header
    installation_id: spark-owui
    header: X-OpenWebUI-Assertion
    issuer: open-webui
    hmac_secret_ref: env:ADAPTER_A
    allowed_api_key_names: [owui]
    session:
      user_endpoint: "http://127.0.0.1:8090/api/v1/auths/"
      cookie_name: token
descriptors:
  google-workspace:
    mode: personal_managed
    provider: google
    issuer: "https://accounts.google.com"
    resource: "https://www.googleapis.com/"
    authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth"
    token_endpoint: "https://oauth2.googleapis.com/token"
    client_id: web-client
    client_secret_ref: "env:GOOGLE_OAUTH_CLIENT_SECRET"
    redirect_uri: "https://chat.example.com/accounts/v1/callback"
    scopes: ["https://www.googleapis.com/auth/gmail.readonly"]
    send_resource_parameter: false
    authorize_extra: { access_type: offline, prompt: consent }
"#;

/// The second adapter a two-bridge case appends, with a distinct secret so the
/// existing reuse rule cannot be what refuses it.
const SECOND_BRIDGE: &str = r#"
  - kind: openwebui_signed_header
    installation_id: other-owui
    header: X-Other-Assertion
    issuer: open-webui
    hmac_secret_ref: env:ADAPTER_B
    allowed_api_key_names: [other]
    session:
      user_endpoint: "https://owui.example.com/api/v1/auths/"
"#;

/// `BASE` with exactly one substitution. Panics if `from` is absent, so a
/// fixture edit can never silently turn a negative case into the valid block.
#[track_caller]
fn with(from: &str, to: &str) -> String {
    assert!(BASE.contains(from), "fixture lacks {from:?}");
    BASE.replacen(from, to, 1)
}

/// `BASE` with no hosted block, no session block and no `authorize_extra`:
/// the shape every configuration written before this slice has.
fn without_hosted() -> String {
    with(
        "hosted:\n  public_origin: \"https://chat.example.com\"\n  return_paths: [\"/\"]\n",
        "",
    )
    .replacen(
        "    session:\n      user_endpoint: \"http://127.0.0.1:8090/api/v1/auths/\"\n      cookie_name: token\n",
        "",
        1,
    )
    .replacen(
        "    authorize_extra: { access_type: offline, prompt: consent }\n",
        "",
        1,
    )
}

/// Parse, then the structural pass, then the enabled-store resolution: the
/// same order `Config::validate_with_env` runs them in.
fn check(yaml: &str) -> Result<(), String> {
    let accounts: AccountsConfig = serde_yaml::from_str(yaml).map_err(|e| e.to_string())?;
    validate_descriptors(Some(&accounts)).map_err(|e| e.to_string())?;
    resolve(Some(&accounts), &Overlay)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

#[track_caller]
fn refused(yaml: &str, phrase: &str) {
    match check(yaml) {
        Ok(()) => panic!("accepted; expected a refusal naming {phrase:?}"),
        Err(message) => assert!(
            message.contains(phrase),
            "refused for the wrong reason: {message:?}, expected {phrase:?}"
        ),
    }
}

#[test]
fn a_minimal_hosted_block_with_one_session_bridge_is_accepted() {
    // GIVEN the reference deployment shape of design §10; WHEN validated;
    // THEN nothing refuses it.
    assert_eq!(check(BASE), Ok(()));
}

#[test]
fn an_https_user_endpoint_and_an_ipv6_loopback_literal_are_accepted() {
    for endpoint in [
        "https://owui.example.com/api/v1/auths/",
        "http://[::1]:8090/api/v1/auths/",
    ] {
        let yaml = with("http://127.0.0.1:8090/api/v1/auths/", endpoint);
        assert_eq!(check(&yaml), Ok(()), "{endpoint}");
    }
}

#[test]
fn a_block_without_hosted_is_accepted_and_rewrites_without_the_new_fields() {
    // GIVEN a configuration as written before this slice.
    let yaml = without_hosted();
    for absent in ["hosted", "session", "authorize_extra"] {
        assert!(!yaml.contains(absent), "fixture still carries {absent}");
    }
    // THEN it validates, and a rewrite does not grow lines it never carried.
    assert_eq!(check(&yaml), Ok(()));
    let accounts: AccountsConfig = serde_yaml::from_str(&yaml).expect("parses");
    let rewritten = serde_yaml::to_string(&accounts).expect("serializes");
    for absent in ["hosted", "session", "authorize_extra"] {
        assert!(!rewritten.contains(absent), "rewrite grew {absent}");
    }
}

#[test]
fn the_hosted_only_caps_do_not_apply_without_hosted() {
    // An uppercase account id, a long issuer and a long key id are all valid
    // today; the R2-5/R3-1 caps must not reach a config without hosted.
    let long_key = "k".repeat(65);
    let yaml = without_hosted()
        .replacen("google-workspace:", "Google_Workspace.X:", 1)
        .replacen(
            "issuer: \"https://accounts.google.com\"",
            &format!("issuer: \"https://accounts.google.com/{}\"", "p".repeat(300)),
            1,
        )
        .replacen("current_key_id: current", &format!("current_key_id: {long_key}"), 1)
        .replacen("  current: env:JOURNEY_KEY", &format!("  {long_key}: env:JOURNEY_KEY"), 1);
    assert!(yaml.contains(&format!("  {long_key}: env:")) && yaml.contains("Google_Workspace.X"));
    assert_eq!(check(&yaml), Ok(()));
}

const ORIGIN: &str = "public_origin: \"https://chat.example.com\"";
const ORIGIN_RULE: &str = "public_origin must be an https origin";

#[test]
fn public_origin_that_is_not_a_bare_https_origin_is_refused() {
    for origin in [
        "http://chat.example.com",
        "https://chat.example.com/",
        "https://chat.example.com/owui",
        "https://chat.example.com?q=1",
        "https://user@chat.example.com",
        "https://chat.example.com:443",
        "chat.example.com",
    ] {
        refused(
            &with(ORIGIN, &format!("public_origin: \"{origin}\"")),
            ORIGIN_RULE,
        );
    }
}

/// One `return_paths` entry, written as a YAML double-quoted scalar so escapes
/// such as `\t` and `\\` reach the parser as the bytes the case names.
fn return_path(entry: &str) -> String {
    with("return_paths: [\"/\"]", &format!("return_paths: [\"{entry}\"]"))
}

#[test]
fn an_empty_return_paths_list_is_refused() {
    refused(
        &with("return_paths: [\"/\"]", "return_paths: []"),
        "return_paths must be nonempty",
    );
}

#[test]
fn a_return_path_that_is_not_single_slash_absolute_is_refused() {
    // `//evil` is protocol-relative in a browser; a scheme or a relative path
    // is not a path on this origin at all.
    for entry in ["//evil.example", "https://evil.example", "evil", "", "javascript:x"] {
        refused(&return_path(entry), "must start with exactly one /");
    }
}

#[test]
fn a_return_path_with_a_backslash_is_refused() {
    // `/\evil.example` is normalised to `//evil.example` by browsers.
    for entry in ["/\\\\evil.example", "/a\\\\b"] {
        refused(&return_path(entry), "must not contain a backslash");
    }
}

#[test]
fn a_return_path_with_a_query_fragment_control_space_or_percent_is_refused() {
    for entry in ["/a?b", "/a#b", "/a\\tb", "/a\\u0000", "/a b", "/a%0a", "/a%2F", "/\\u007f"] {
        refused(&return_path(entry), "must be printable ASCII");
    }
}

#[test]
fn a_return_path_over_256_bytes_is_refused_and_256_is_accepted() {
    let at_cap = format!("/{}", "a".repeat(255));
    assert_eq!(check(&return_path(&at_cap)), Ok(()));
    let over = format!("/{}", "a".repeat(256));
    refused(&return_path(&over), "at most 256 bytes");
}

const ENDPOINT: &str = "http://127.0.0.1:8090/api/v1/auths/";
const ENDPOINT_RULE: &str = "session.user_endpoint must be https, or http on a loopback IP literal";

#[test]
fn a_user_endpoint_that_is_plain_http_off_loopback_is_refused() {
    for endpoint in [
        "http://owui.example.com/api/v1/auths/",
        "http://localhost:8090/api/v1/auths/",
        "http://10.0.0.5:8090/api/v1/auths/",
        "https://user:pw@owui.example.com/api/v1/auths/",
        "ftp://127.0.0.1/api",
        "not a url",
    ] {
        refused(&with(ENDPOINT, endpoint), ENDPOINT_RULE);
    }
}

#[test]
fn a_cookie_name_that_is_not_a_cookie_token_is_refused() {
    for name in ["\"\"", "\"a b\"", "\"a;b\"", "\"a=b\""] {
        refused(
            &with("cookie_name: token", &format!("cookie_name: {name}")),
            "session.cookie_name must be a nonempty cookie token",
        );
    }
}

#[test]
fn a_second_session_bridge_adapter_is_refused() {
    // The adapter list sits directly above `descriptors:`.
    let yaml = with(
        "descriptors:",
        &format!("{}\ndescriptors:", SECOND_BRIDGE.trim_matches('\n')),
    );
    // Positive control: the same second adapter without a session block is
    // fine, so what refuses below is the bridge count, not the adapter.
    let second_session =
        "\n    session:\n      user_endpoint: \"https://owui.example.com/api/v1/auths/\"";
    assert!(yaml.contains(second_session));
    assert_eq!(check(&yaml.replacen(second_session, "", 1)), Ok(()));
    refused(&yaml, "exactly one adapter with a session block");
}

#[test]
fn hosted_with_no_session_bridge_is_refused() {
    refused(
        &with(
            "    session:\n      user_endpoint: \"http://127.0.0.1:8090/api/v1/auths/\"\n      cookie_name: token\n",
            "",
        ),
        "exactly one adapter with a session block",
    );
}

#[test]
fn a_session_block_without_hosted_is_refused_as_inert() {
    refused(
        &with(
            "hosted:\n  public_origin: \"https://chat.example.com\"\n  return_paths: [\"/\"]\n",
            "",
        ),
        "session requires accounts.hosted",
    );
}

#[test]
fn a_managed_redirect_uri_off_the_hosted_callback_is_refused() {
    for uri in [
        "https://chat.example.com/oauth/callback",
        "https://other.example.com/accounts/v1/callback",
        "https://chat.example.com/accounts/v1/callback/",
    ] {
        refused(
            &with("https://chat.example.com/accounts/v1/callback", uri),
            "redirect_uri must equal hosted.public_origin + /accounts/v1/callback",
        );
    }
}

#[test]
fn a_managed_account_id_over_64_bytes_or_outside_the_charset_is_refused() {
    let at_cap = "a".repeat(64);
    assert_eq!(check(&with("google-workspace:", &format!("{at_cap}:"))), Ok(()));
    for id in ["a".repeat(65), "Google".into(), "a.b".into(), "a/b".into()] {
        refused(
            &with("google-workspace:", &format!("\"{id}\":")),
            "account id must be at most 64 bytes of [a-z0-9_-]",
        );
    }
}

#[test]
fn a_managed_issuer_over_256_bytes_is_refused() {
    let issuer = |len: usize| {
        let base = "https://accounts.google.com/";
        format!("issuer: \"{base}{}\"", "p".repeat(len - base.len()))
    };
    let from = "issuer: \"https://accounts.google.com\"";
    assert_eq!(check(&with(from, &issuer(256))), Ok(()));
    refused(&with(from, &issuer(257)), "issuer must be at most 256 bytes");
}

#[test]
fn a_key_id_over_64_bytes_or_outside_the_charset_is_refused_under_hosted() {
    // R3-1: the key id becomes a record's `digest_key_id`, so every id in
    // `accounts.keys` is capped, the current one included.
    let rekey = |id: &str| {
        with("current_key_id: current", &format!("current_key_id: \"{id}\""))
            .replacen("  current: env:JOURNEY_KEY", &format!("  \"{id}\": env:JOURNEY_KEY"), 1)
    };
    assert_eq!(check(&rekey(&"K.9_-".repeat(12))), Ok(()));
    for id in ["k".repeat(65), "a b".into(), "a/b".into(), "é".into()] {
        refused(&rekey(&id), "key ids must be at most 64 bytes of [A-Za-z0-9._-]");
    }
}

/// `BASE` with one `accounts.limits` field set.
fn limit(field: &str, value: &str) -> String {
    with("adapters:", &format!("limits:\n  {field}: {value}\nadapters:"))
}

#[test]
fn each_journey_limit_accepts_one_and_refuses_zero() {
    for field in [
        "journeys_total",
        "journeys_per_user",
        "starts_per_minute_per_user",
        "journeys_created_per_minute",
    ] {
        assert_eq!(check(&limit(field, "1")), Ok(()), "{field}");
        refused(
            &limit(field, "0"),
            &format!("accounts.limits.{field} must be a positive integer"),
        );
    }
}

#[test]
fn a_negative_journey_limit_is_refused_at_parse() {
    for field in ["journeys_total", "journeys_per_user", "starts_per_minute_per_user", "journeys_created_per_minute"] {
        refused(&limit(field, "-1"), "invalid value: integer `-1`");
    }
}

#[test]
fn a_journeys_total_whose_derived_byte_cap_overflows_is_refused() {
    // records_max = 4 x journeys_total, byte cap = records_max x RECORD_MAX x 2
    // (design §5.1): a total that cannot carry that product is not a bound.
    refused(
        &limit("journeys_total", &usize::MAX.to_string()),
        "accounts.limits.journeys_total must be a positive integer",
    );
}

#[test]
fn an_unknown_field_under_each_new_block_is_refused_by_name() {
    for (from, to, name) in [
        ("  return_paths: [\"/\"]", "  return_paths: [\"/\"]\n  bogus_hosted: 1", "bogus_hosted"),
        ("      cookie_name: token", "      cookie_name: token\n      bogus_session: 1", "bogus_session"),
        ("prompt: consent }", "prompt: consent, bogus_extra: x }", "bogus_extra"),
    ] {
        refused(&with(from, to), &format!("unknown field `{name}`"));
    }
    refused(&limit("bogus_limit", "1"), "unknown field `bogus_limit`");
}

#[test]
fn authorize_extra_accepts_only_the_closed_values() {
    let from = "authorize_extra: { access_type: offline, prompt: consent }";
    let all = "authorize_extra: { access_type: online, prompt: select_account, include_granted_scopes: true }";
    assert_eq!(check(&with(from, all)), Ok(()));
    assert_eq!(check(&with(from, "authorize_extra: { prompt: none }")), Ok(()));
    for (value, variant) in [
        ("{ access_type: forever }", "unknown variant `forever`"),
        ("{ prompt: login }", "unknown variant `login`"),
        ("{ include_granted_scopes: maybe }", "expected a boolean"),
    ] {
        refused(&with(from, &format!("authorize_extra: {value}")), variant);
    }
}

#[test]
fn authorize_extra_on_a_non_managed_descriptor_is_refused_as_inert() {
    let yaml = without_hosted().replacen(
        "descriptors:\n",
        "descriptors:\n  wiki:\n    mode: shared\n    provider: wiki\n    authorize_extra: { prompt: consent }\n",
        1,
    );
    assert!(yaml.contains("  wiki:\n"));
    refused(&yaml, "authorize_extra is valid only on mode personal_managed");
}
