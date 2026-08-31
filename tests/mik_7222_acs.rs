//! MIK-7222: credential-disclosure sweep. Canary through every diagnostic helper.
//! If a helper is reverted to echo its input, these fail.

use mcp_gateway::config::TransportConfig;
use mcp_gateway::discovery::{DiscoveredServer, DiscoverySource, ServerMetadata};
use mcp_gateway::security::{
    diagnostic_url, request_error_category, safe_http_status_error, safe_oauth_http_error,
    safe_reqwest_message, summarize_stdio_command,
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
    assert!(
        json.contains("\"http_url\""),
        "JSON must keep nested TransportConfig keys, got {json}"
    );

    let yaml_stdio = server.redacted_for_diagnostics();
    match &yaml_stdio.transport {
        TransportConfig::Stdio { command, .. } => {
            assert!(!command.contains(CANARY), "{command}");
            assert!(command.contains("argument(s) redacted"), "{command}");
        }
        other => panic!("expected stdio, got {other:?}"),
    }
    let yaml_http = http.redacted_for_diagnostics();
    match &yaml_http.transport {
        TransportConfig::Http { http_url, .. } => {
            assert!(!http_url.contains(CANARY), "{http_url}");
            assert!(http_url.contains("https://api.example.com"), "{http_url}");
        }
        other => panic!("expected http, got {other:?}"),
    }
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

#[tokio::test]
async fn sweep_decode_error_must_not_echo_url_credentials() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let body = b"not-json";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        use tokio::io::AsyncWriteExt;
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.write_all(body).await;
    });

    // reqwest lifts userinfo into Basic auth and strips it from Error Display.
    // Query parameters stay (reqwest 0.13 docs: "an API key as a query parameter").
    let url = format!("http://127.0.0.1:{}/token?api_key={CANARY}", addr.port());
    let err = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .expect("send")
        .json::<serde_json::Value>()
        .await
        .expect_err("malformed body must fail decode");
    assert!(
        err.to_string().contains(CANARY),
        "fixture is only useful if Display would leak; got {}",
        err
    );
    let safe = safe_reqwest_message("Failed to parse token response", &err);
    assert!(!safe.contains(CANARY), "{safe}");
    assert_eq!(request_error_category(&err), "response parse failed");
}
