// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Acceptance-criterion tests for MIK-7272 §3.10 — the authorization-server
//! requirements MCP 2026-07-28 places on a client.
//!
//! Plan: `docs/requirements/RELEASE-4.0.0-test-plan.md` §"Increment 9".
//!
//! These apply to the gateway acting as an **OAuth client** to a backend, which
//! it does: it runs an authorization-code flow and registers itself
//! dynamically. They were omitted entirely from the first draft of the release
//! scope and put back by review.

use mcp_gateway::oauth::client::{registration_body, storage_key};

#[test]
fn ac_oauth_2_dynamic_registration_declares_an_application_type() {
    // Required by this revision, and not cosmetic. OpenID Connect defaults an
    // unstated `application_type` to `web`, which constrains redirect URIs to
    // https and no literal loopback address — exactly what a locally-running
    // gateway registers. Saying `native` is what makes the registration mean
    // what this client is.
    let body = registration_body("weather", "http://127.0.0.1:39400/oauth/callback");

    assert_eq!(
        body["application_type"], "native",
        "a loopback redirect belongs to a native client; leaving it unstated \
         defaults to web and the registration is refused or silently narrowed"
    );
}

#[test]
fn ac_oauth_2_the_existing_registration_fields_are_unchanged() {
    // The regression. This body is sent to every authorization server the
    // gateway registers with; a field that changed shape here would break a
    // registration that works today.
    let body = registration_body("weather", "http://127.0.0.1:39400/oauth/callback");

    assert_eq!(body["client_name"], "MCP Gateway - weather");
    assert_eq!(
        body["redirect_uris"][0],
        "http://127.0.0.1:39400/oauth/callback"
    );
    assert_eq!(body["grant_types"][0], "authorization_code");
    assert_eq!(body["response_types"][0], "code");
    assert_eq!(body["token_endpoint_auth_method"], "none");
}

#[test]
fn ac_oauth_3_credentials_are_keyed_by_the_issuer_that_granted_them() {
    // The rule: a client MUST key persisted credentials by the issuer
    // identifier, MUST NOT reuse them with a different authorization server,
    // and MUST re-register when the authorization server changes.
    //
    // Keyed by backend alone, moving a backend from one authorization server to
    // another silently reuses a client id the new server never issued — and the
    // failure is a confusing rejection at some later point rather than a
    // re-registration.
    let a = storage_key("weather", "https://auth.example.com");
    let b = storage_key("weather", "https://auth.other.com");

    assert_ne!(
        a, b,
        "the same backend behind a different authorization server is a \
         different credential, and must not be served the first one"
    );
}

#[test]
fn ac_oauth_3_the_same_issuer_yields_the_same_key() {
    // The other half: keying must be stable, or the gateway re-registers on
    // every restart and pops a browser tab each time.
    assert_eq!(
        storage_key("weather", "https://auth.example.com"),
        storage_key("weather", "https://auth.example.com")
    );
}

#[test]
fn ac_oauth_3_two_backends_on_one_issuer_stay_separate() {
    // An issuer may serve many backends, and their credentials are not
    // interchangeable.
    assert_ne!(
        storage_key("weather", "https://auth.example.com"),
        storage_key("payments", "https://auth.example.com")
    );
}
