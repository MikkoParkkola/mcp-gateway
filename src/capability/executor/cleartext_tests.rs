// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A capability that injects a credential sends it only to `https://`, or to
//! `http://` on a loopback host: refused at load where the URL is literal, and
//! at send time for every protocol and for the OAuth refresh, where it is not.

use serde_json::json;

use crate::capability::{
    CapabilityDefinition, CapabilityExecutionContext, CapabilityExecutor, parse_capability,
    validate_capability,
};

fn capability(url_line: &str, auth_required: bool) -> CapabilityDefinition {
    parse_capability(&format!(
        "
name: cleartext_probe
description: probe
providers:
  primary:
    service: rest
    config:
      {url_line}
      path: /v1/items
      method: GET
auth:
  required: {auth_required}
  type: bearer
  key: env:MCP_GW_CLEARTEXT_PROBE
"
    ))
    .expect("parses")
}

fn load_error(url_line: &str) -> String {
    validate_capability(&capability(url_line, true))
        .expect_err(url_line)
        .to_string()
}

#[test]
fn a_credential_bearing_cleartext_base_url_is_refused_at_load() {
    let error = load_error("base_url: http://api.example.com");
    assert!(
        error.contains("providers.primary.config.base_url"),
        "{error}"
    );
    assert!(error.contains("https"), "{error}");
    assert!(!error.contains("api.example.com"), "URL echoed: {error}");
}

#[test]
fn a_credential_bearing_cleartext_endpoint_is_refused_at_load() {
    let error = load_error("endpoint: http://api.example.com/v1/items");
    assert!(
        error.contains("providers.primary.config.endpoint"),
        "{error}"
    );
}

#[test]
fn loopback_https_templated_and_credential_free_urls_still_load() {
    for (url_line, auth_required) in [
        // The carve-out: loopback never leaves the machine.
        ("base_url: http://127.0.0.1:8000", true),
        ("base_url: http://localhost:8000", true),
        ("base_url: http://[::1]:8000", true),
        ("base_url: https://api.example.com", true),
        // No credential is injected: number_facts and its like keep working.
        ("base_url: http://numbersapi.com", false),
        // Not a URL until a caller fills it: the send-time check owns it.
        ("base_url: \"{base}\"", true),
    ] {
        validate_capability(&capability(url_line, auth_required))
            .unwrap_or_else(|e| panic!("{url_line} (auth {auth_required}): {e}"));
    }
}

#[test]
fn a_trailing_dot_localhost_is_not_loopback_at_load() {
    let error = load_error("base_url: http://localhost.:8000");
    assert!(
        error.contains("providers.primary.config.base_url"),
        "{error}"
    );
}

/// The URL is only known once a caller fills it, so load cannot refuse it.
/// The refusal comes before the credential is fetched or any byte is sent.
#[tokio::test]
async fn a_templated_cleartext_url_is_refused_at_send_time() {
    let cap = capability("base_url: \"http://{host}\"", true);
    let provider = cap.providers.named.get("primary").expect("primary");
    let error = CapabilityExecutor::new()
        .execute_provider_with_context(
            &cap,
            provider,
            &json!({"host": "off-machine.invalid"}),
            &CapabilityExecutionContext::default(),
        )
        .await
        .expect_err("cleartext with a credential")
        .to_string();
    assert!(error.contains("cleartext"), "{error}");
    assert!(
        !error.contains("off-machine.invalid"),
        "URL echoed: {error}"
    );
}

/// The capability OAuth refresh posts a refresh token (and a client secret
/// when one is set) to the token endpoint.
#[tokio::test]
async fn a_cleartext_token_endpoint_never_receives_the_refresh_token() {
    let dir = tempfile::tempdir().unwrap();
    let storage = crate::oauth::TokenStorage::new(dir.path().to_path_buf()).unwrap();
    let error = CapabilityExecutor::new()
        .perform_token_refresh(
            "cleartext",
            "REFRESH_SECRET",
            "http://off-machine.invalid/token",
            &storage,
            None,
            &CapabilityExecutionContext::default(),
        )
        .await
        .expect_err("cleartext token endpoint")
        .to_string();
    assert!(error.contains("cleartext"), "{error}");
}
