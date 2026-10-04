// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #1943: remote backends that run without signed provenance.

use super::super::{Config, RemoteServerSigningConfig};

/// A config from `backends` YAML plus an optional `remote_server_signing`
/// block; not validated, so metadata presence is what is tested here.
fn config(backends: &str, signing: &str) -> Config {
    let yaml = format!("{signing}\nbackends:\n{backends}");
    serde_yaml::from_str(&yaml).expect("test config parses")
}

const METADATA: &str = r#"
security:
  remote_server_signing:
    backends:
      api:
        subject: spiffe://example.test/api
        issuer: unit-test
        issued_at: "2026-05-06T00:00:00Z"
        key_id: k
        signature: c2ln
"#;

const REQUIRED: &str = "
security:
  remote_server_signing:
    require_for_remote_backends: true
";

const HTTP_API: &str = "  api:\n    http_url: https://api.example.test/mcp\n";

#[test]
fn provenance_is_not_required_by_default() {
    assert!(!RemoteServerSigningConfig::default().require_for_remote_backends);
    let config = config(HTTP_API, "");
    assert!(
        !config
            .security
            .remote_server_signing
            .require_for_remote_backends
    );
}

#[test]
fn an_http_backend_without_metadata_is_unverified() {
    assert_eq!(config(HTTP_API, "").unverified_remote_backends(), ["api"]);
}

#[test]
fn a_backend_with_metadata_is_not_listed() {
    assert!(
        config(HTTP_API, METADATA)
            .unverified_remote_backends()
            .is_empty()
    );
}

#[test]
fn nothing_is_listed_while_provenance_is_required() {
    assert!(
        config(HTTP_API, REQUIRED)
            .unverified_remote_backends()
            .is_empty()
    );
}

#[test]
fn a_disabled_backend_is_not_listed() {
    let backends = "  api:\n    enabled: false\n    http_url: https://api.example.test/mcp\n";
    assert!(config(backends, "").unverified_remote_backends().is_empty());
}

#[test]
fn a_stdio_backend_is_not_remote() {
    let backends = "  local:\n    command: npx some-server\n";
    assert!(config(backends, "").unverified_remote_backends().is_empty());
    assert_eq!(config(backends, "").remote_provenance_warning(), None);
}

#[test]
fn a_websocket_backend_without_metadata_is_unverified() {
    let backends = "  live:\n    ws_url: wss://live.example.test/mcp\n";
    assert_eq!(config(backends, "").unverified_remote_backends(), ["live"]);
}

#[cfg(feature = "a2a")]
#[test]
fn an_a2a_backend_without_metadata_is_unverified() {
    let backends = "  agent:\n    a2a_url: https://agent.example.test/a2a\n";
    assert_eq!(config(backends, "").unverified_remote_backends(), ["agent"]);
}

#[test]
fn the_warning_names_every_unverified_backend_in_order() {
    let backends = "  zeta:\n    http_url: https://z.example.test/mcp\n  alpha:\n    http_url: https://a.example.test/mcp\n";
    let config = config(backends, "");
    assert_eq!(config.unverified_remote_backends(), ["alpha", "zeta"]);
    let warning = config.remote_provenance_warning().expect("a warning");
    assert!(warning.contains("alpha, zeta"), "{warning}");
    assert!(
        warning.contains("security.remote_server_signing.require_for_remote_backends"),
        "{warning}"
    );
}

#[test]
fn only_the_backend_without_metadata_is_listed() {
    let backends = "  api:\n    http_url: https://api.example.test/mcp\n  other:\n    http_url: https://other.example.test/mcp\n";
    assert_eq!(
        config(backends, METADATA).unverified_remote_backends(),
        ["other"]
    );
}

/// The posture treats a backend with a metadata entry as verified. That holds
/// only because config load verifies every entry even with the flag off.
#[test]
fn metadata_that_fails_verification_fails_the_load_with_the_flag_off() {
    let config = config(HTTP_API, METADATA);
    assert!(
        !config
            .security
            .remote_server_signing
            .require_for_remote_backends
    );
    assert!(config.validate_remote_backend_provenance().is_err());
}
