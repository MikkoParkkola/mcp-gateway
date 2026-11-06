// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows for the capability execution context: loopback allowance, the
//! host and cleartext tests, and the shared refusal guard.

use super::*;

/// A URL names a host only when its host is present. A pin: url 2.5.8
/// parses `foo:///rpc` (a non-special scheme with an empty authority) with
/// no host (`host()` is `None`), so `host().is_some()` already treats an
/// empty authority as no host. A url release that returned an empty
/// domain there would turn this row red.
#[test]
fn only_a_named_host_counts_as_one() {
    for (url, named) in [
        ("foo:///rpc", false),
        ("foo://api.invalid/rpc", true),
        ("file:///tmp/rpc", false),
        ("http://api.invalid", true),
        ("rpc-path-only", false),
        ("http://[::1/rpc", false),
    ] {
        assert_eq!(names_a_host(url), named, "{url}");
    }
}

/// What `record_refusal` leaves on a fresh delivery's record for `error`
/// under `test`.
async fn recorded_effect(error: Error, test: RefusalTest<'_>) -> Option<serde_json::Value> {
    let facts = crate::gateway::delivery_facts::scope(async {
        record_refusal(&error, test);
        crate::gateway::delivery_facts::snapshot()
    })
    .await;
    let mut fields = serde_json::Map::new();
    crate::gateway::delivery_facts::record_fields(facts.as_ref(), false, &mut fields);
    fields.get("response_effect").cloned()
}

/// The shared guard records a policy refusal and nothing else: an SSRF
/// refusal under `Destination`, a cleartext refusal of a URL that names a
/// host under `Cleartext`. A configuration error records no refusal under
/// either, on every site that uses it, the token endpoint included.
#[tokio::test]
async fn the_refusal_guard_records_only_a_policy_refusal() {
    let ssrf = || {
        Error::Protocol(format!(
            "{}: host targets a private address",
            crate::security::ssrf::SSRF_BLOCKED
        ))
    };
    let config = || Error::Config("URL has no host".to_string());
    let refused = Some(serde_json::Value::from("refused"));
    let delivered = Some(serde_json::Value::from("delivered"));
    let cases = [
        (
            "destination, SSRF refusal",
            ssrf(),
            RefusalTest::Destination,
            true,
        ),
        (
            "destination, configuration error",
            config(),
            RefusalTest::Destination,
            false,
        ),
        (
            "cleartext, named host",
            config(),
            RefusalTest::Cleartext("http://api.invalid/x"),
            true,
        ),
        (
            "cleartext, no host",
            config(),
            RefusalTest::Cleartext("file:///tmp/x"),
            false,
        ),
        (
            "cleartext, unparsable",
            config(),
            RefusalTest::Cleartext("http://[::1/x"),
            false,
        ),
    ];
    let mut fails = Vec::new();
    for (case, error, test, expect) in cases {
        let effect = recorded_effect(error, test).await;
        // A fresh cell is vouched with effect Delivered (the Default of
        // DeliveryFacts), and record_fields writes a vouched cell's effect
        // in every case, so nothing refused reads "delivered", not absent.
        let ok = if expect {
            effect == refused
        } else {
            effect == delivered
        };
        if !ok {
            fails.push(format!("{case}: response_effect {effect:?}"));
        }
    }
    assert!(fails.is_empty(), "{fails:#?}");
}

/// No hostless token endpoint passes the cleartext check, so the
/// destination guard after it never sees one. `https:///x` is not
/// hostless: a special scheme skips the empty authority, so it names
/// host `x`.
#[test]
fn the_cleartext_check_refuses_every_hostless_endpoint() {
    for url in [
        "https:///",
        "http:///",
        "file:///x",
        "foo:///x",
        "rpc-path-only",
        "http://[::1/x",
    ] {
        assert!(
            require_tls_for_credentials(url).is_err(),
            "{url} passed the cleartext check"
        );
    }
    assert_eq!(
        url::Url::parse("https:///x")
            .ok()
            .as_ref()
            .and_then(url::Url::host_str),
        Some("x"),
        "premise: https:///x names host x"
    );
}

#[test]
fn default_context_keeps_loopback_blocked() {
    assert!(
        validate_capability_url_for_context(
            "http://127.0.0.1:39400/fixture",
            &CapabilityExecutionContext::default()
        )
        .is_err()
    );
}

#[test]
fn isolated_loopback_context_bypasses_only_loopback_ip_literals() {
    let context = CapabilityExecutionContext::default().with_isolated_loopback_egress();

    assert!(
        validate_capability_url_for_context("http://127.0.0.1:39400/fixture", &context).is_ok()
    );
    assert!(validate_capability_url_for_context("http://10.0.0.1/fixture", &context).is_err());
    assert!(!url_targets_loopback_ip("http://localhost:39400/fixture"));
}

/// Capability-side ADR-008 INV-2 parity tests.
///
/// `google_calendar_capability` names Google Calendar as the concrete
/// motivating example from the gap report (`oauth:google`, no
/// `shared_account`, `exposure` left at the `Shared` default) — the exact
/// shape that let any caller ride a shared gateway-held OAuth login.
fn google_calendar_capability(
    shared_account: bool,
    exposure_personal: bool,
) -> CapabilityDefinition {
    let exposure_yaml = if exposure_personal {
        "metadata:\n  exposure: personal\n  identity_owner:\n    authority: cloudflare_access\n    subject: owner-1\n"
    } else {
        ""
    };
    let shared_yaml = if shared_account {
        "  shared_account: true\n"
    } else {
        ""
    };
    crate::capability::parse_capability(&format!(
        "name: google_calendar_list_events\n\
         description: List events on a Google Calendar\n\
         auth:\n\
         \x20 required: true\n\
         \x20 type: bearer\n\
         \x20 key: oauth:google\n\
         {shared_yaml}\
         {exposure_yaml}\
         providers:\n\
         \x20 primary:\n\
         \x20   service: rest\n\
         \x20   config:\n\
         \x20     base_url: https://www.googleapis.com\n\
         \x20     path: /calendar/v3/calendars/primary/events\n\
         \x20     method: GET\n"
    ))
    .expect("fixture capability must parse")
}

#[test]
fn oauth_isolation_refuses_shared_gateway_oauth_on_multi_user_gateway_with_no_per_user_cred() {
    let cap = google_calendar_capability(false, false);
    let err = validate_oauth_isolation(&cap, &CapabilityExecutionContext::default(), true)
        .expect_err("shared oauth:<provider> credential on a multi-user gateway must be refused");
    assert!(err.to_string().contains("not isolated per user"), "{err}");
}

#[test]
fn oauth_isolation_allows_shared_oauth_on_single_user_gateway() {
    let cap = google_calendar_capability(false, false);
    assert!(
        validate_oauth_isolation(&cap, &CapabilityExecutionContext::default(), false).is_ok(),
        "single-user gateways have no cross-user caller to leak credentials to"
    );
}

#[test]
fn oauth_isolation_allows_operator_blessed_shared_account() {
    let cap = google_calendar_capability(true, false);
    assert!(
        validate_oauth_isolation(&cap, &CapabilityExecutionContext::default(), true).is_ok(),
        "auth.shared_account = true is the explicit opt-in for a genuinely shared login"
    );
}

#[test]
fn oauth_isolation_allows_personal_capability_with_matching_caller_identity() {
    let cap = google_calendar_capability(false, true);
    let context = CapabilityExecutionContext::with_caller_identity(GrantSubject::for_test(
        "cloudflare_access",
        "owner-1",
        None,
    ));
    assert!(
        validate_oauth_isolation(&cap, &context, true).is_ok(),
        "a resolved caller identity on a personal capability proves per-user isolation \
         (validate_personal_capability_identity already checked owner match upstream)"
    );
}

#[test]
fn personal_owner_check_ignores_the_display_label() {
    // The capability file labels its owner for humans; the caller's label
    // is whatever its transport supplied. Only (authority, subject) is
    // identity, so the two labels differing must not refuse the owner.
    let cap = google_calendar_capability(false, true);
    let context = CapabilityExecutionContext::with_caller_identity(GrantSubject::for_test(
        "cloudflare_access",
        "owner-1",
        Some("owner@example.com".to_string()),
    ));
    validate_personal_capability_identity(&cap, &context)
        .expect("the owner is the owner whatever either side calls them");
}

#[test]
fn oauth_isolation_ignores_non_oauth_credentials() {
    let cap = crate::capability::parse_capability(
        "name: env_backed_capability\n\
         description: Uses a plain env-var credential, not a shared OAuth login\n\
         auth:\n\
         \x20 required: true\n\
         \x20 type: bearer\n\
         \x20 key: env:SOME_API_KEY\n\
         providers:\n\
         \x20 primary:\n\
         \x20   service: rest\n\
         \x20   config:\n\
         \x20     base_url: https://example.invalid\n\
         \x20     path: /widgets\n\
         \x20     method: GET\n",
    )
    .expect("fixture capability must parse");
    assert!(
        validate_oauth_isolation(&cap, &CapabilityExecutionContext::default(), true).is_ok(),
        "guard is scoped to oauth:<provider> keys; non-OAuth credentials are per-capability \
         secrets already, not a shared gateway-held login"
    );
}
