//! MIK-7222: credential-disclosure sweep. Canary through every diagnostic helper.
//! If a helper is reverted to echo its input, these fail.

use mcp_gateway::config::TransportConfig;
use mcp_gateway::discovery::{DiscoveredServer, DiscoverySource, ServerMetadata};
use mcp_gateway::security::{
    diagnostic_url, safe_http_status_error, safe_oauth_http_error, summarize_stdio_command,
};
use reqwest::StatusCode;

const CANARY: &str = "SENTINEL_SWEEP_7222";

#[test]
fn sweep1_stdio_quoting_uses_summary_not_argv() {
    let cmd = format!("npx --api-key {CANARY} -y @scope/pkg");
    let out = summarize_stdio_command(&cmd);
    assert!(!out.contains(CANARY), "{out}");
    assert!(out.starts_with("npx"), "{out}");
}

#[test]
fn sweep2_oauth_error_body_is_not_reachable_as_token_json() {
    // RFC 6749 §5.2 error responses are `error` / `error_description`, not
    // access_token. Keep P2. The body is still untrusted — a helper that
    // interpolates it would leak a buggy AS echo of client_secret.
    let body = format!("{{\"error\":\"invalid_client\",\"client_secret\":\"{CANARY}\"}}");
    let out = safe_oauth_http_error("Client credentials failed", StatusCode::UNAUTHORIZED, &body);
    assert!(!out.contains(CANARY), "{out}");
    assert!(out.contains("HTTP 401"), "{out}");
}

#[test]
fn sweep4_discovery_json_redacts_command_and_url() {
    let server = DiscoveredServer {
        name: "leaky".into(),
        description: "d".into(),
        source: DiscoverySource::Environment,
        transport: TransportConfig::Stdio {
            command: format!("node --token {CANARY} server.js"),
            cwd: None,
            protocol_version: None,
        },
        metadata: ServerMetadata::default(),
    };
    let json = server.diagnostic_value().to_string();
    assert!(!json.contains(CANARY), "{json}");
    let http = DiscoveredServer {
        name: "http".into(),
        description: "d".into(),
        source: DiscoverySource::Environment,
        transport: TransportConfig::Http {
            http_url: format!("https://user:{CANARY}@api.example.com/mcp?t={CANARY}"),
            streamable_http: false,
            protocol_version: None,
        },
        metadata: ServerMetadata::default(),
    };
    let json = http.diagnostic_value().to_string();
    assert!(!json.contains(CANARY), "{json}");
    assert!(json.contains("https://api.example.com"), "{json}");
}

#[test]
fn sweep5_canary_through_every_helper() {
    let url = format!("https://user:{CANARY}@svc.example.com/path/{CANARY}?t={CANARY}");
    assert!(!diagnostic_url(&url).contains(CANARY));

    let body = format!("{{\"access_token\":\"{CANARY}\"}}");
    assert!(
        !safe_http_status_error(StatusCode::FORBIDDEN, &body)
            .to_string()
            .contains(CANARY)
    );
    assert!(!safe_oauth_http_error("x", StatusCode::FORBIDDEN, &body).contains(CANARY));
    assert!(!summarize_stdio_command(&format!("cmd --secret {CANARY}")).contains(CANARY));

    let expired = safe_http_status_error(
        StatusCode::BAD_REQUEST,
        &format!("{{\"code\":-32015,\"message\":\"Session not found {CANARY}\"}}"),
    );
    assert!(expired.to_string().contains("session expired"), "{expired}");
    assert!(!expired.to_string().contains(CANARY));
}
