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

/// A fallback provider sends the same credential as the primary, so a
/// cleartext fallback is refused at load even behind an `https://` primary.
#[test]
fn a_credential_bearing_cleartext_fallback_is_refused_at_load() {
    let error = validate_capability(
        &parse_capability(
            "
name: cleartext_probe
description: probe
providers:
  primary:
    service: rest
    config:
      base_url: https://api.example.com
      path: /v1/items
      method: GET
  fallback:
    - service: rest
      config:
        base_url: http://mirror.example.com
        path: /v1/items
        method: GET
auth:
  required: true
  type: bearer
  key: env:MCP_GW_CLEARTEXT_PROBE
",
        )
        .expect("parses"),
    )
    .expect_err("a cleartext fallback is refused")
    .to_string();
    assert!(
        error.contains("providers.fallback[0].config.base_url"),
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
    let storage =
        std::sync::Arc::new(crate::oauth::TokenStorage::new(dir.path().to_path_buf()).unwrap());
    let error = CapabilityExecutor::new()
        .refresh_provider_token(
            "cleartext",
            "http://off-machine.invalid/token",
            &storage,
            &CapabilityExecutionContext::default(),
        )
        .await
        .expect_err("cleartext token endpoint")
        .to_string();
    assert!(error.contains("cleartext"), "{error}");
}

/// A loopback listener that counts connections and answers each `200 OK`.
async fn answering_listener() -> (u16, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = std::sync::Arc::clone(&seen);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf).await;
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await;
        }
    });
    (port, seen)
}

/// Loopback is the carve-out because it stays on the machine, so the
/// operator's `capabilities.egress_proxy` never carries a loopback request.
#[tokio::test]
async fn a_loopback_capability_request_bypasses_the_egress_proxy() {
    use std::sync::atomic::Ordering;
    let (proxy, via_proxy) = answering_listener().await;
    let (server, direct) = answering_listener().await;
    let proxy_url = url::Url::parse(&format!("http://127.0.0.1:{proxy}")).unwrap();
    super::super::client::build(Some(&proxy_url))
        .get(format!("http://127.0.0.1:{server}/v1"))
        .send()
        .await
        .expect("the loopback server answers");
    assert_eq!(via_proxy.load(Ordering::SeqCst), 0, "the proxy carried it");
    assert_eq!(direct.load(Ordering::SeqCst), 1);
}

/// A 307/308 re-sends the body and custom credential headers, so a request
/// that started on loopback (or TLS) is not followed to cleartext off this
/// machine. The target is a public literal, so no SSRF rule refuses it first.
#[tokio::test]
async fn a_redirect_from_loopback_to_cleartext_off_machine_is_refused() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf).await;
            let _ = stream
                .write_all(
                    b"HTTP/1.1 307 Temporary Redirect\r\nLocation: http://93.184.215.14/v1\r\n\
                      Content-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
        }
    });
    let sent = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        super::super::client::build(None)
            .get(format!("http://127.0.0.1:{port}/v1"))
            .send(),
    )
    .await
    .expect("refused before any connection off the machine");
    let error = sent.expect_err("the cleartext hop is refused");
    assert!(
        format!("{error:?}").contains("capability redirect to cleartext"),
        "{error:?}"
    );
}

/// GraphQL and JSON-RPC inject the same credential, so they refuse the same
/// URL, before the credential is read. A public literal passes the SSRF check,
/// so only the cleartext rule can refuse it.
#[tokio::test]
async fn graphql_and_jsonrpc_refuse_a_cleartext_endpoint_at_send_time() {
    use super::super::rest::{ExecutionContext, ProtocolExecutor};
    let executor = CapabilityExecutor::new();
    for service in ["graphql", "jsonrpc"] {
        let cap = parse_capability(&format!(
            "
name: cleartext_{service}
description: probe
providers:
  primary:
    service: {service}
    config:
      endpoint: http://93.184.215.14/rpc
      method: probe
      body: \"{{ probe }}\"
auth:
  required: true
  type: bearer
  key: env:MCP_GW_CLEARTEXT_PROBE
"
        ))
        .expect("parses");
        let config = cap.providers.named["primary"].protocol_config();
        let ctx = ExecutionContext {
            capability: &cap,
            timeout_secs: 10,
            context: CapabilityExecutionContext::default(),
        };
        let result = if service == "graphql" {
            let graphql = super::GraphqlExecutor {
                executor: &executor,
            };
            graphql.execute(&config, json!({}), &ctx).await
        } else {
            let jsonrpc = super::super::jsonrpc::JsonRpcExecutor {
                executor: &executor,
            };
            jsonrpc.execute(&config, json!({}), &ctx).await
        };
        let error = result.expect_err(service).to_string();
        assert!(error.contains("cleartext"), "{service}: {error}");
    }
}

/// MIK-7958: a capability without `auth.required` whose header, query or body
/// template fills in a `{env.X}`/`{keychain.X}` secret sends that secret too.
fn templated_secret(url_line: &str, template_line: &str) -> CapabilityDefinition {
    parse_capability(&format!(
        "
name: template_secret_probe
description: probe
providers:
  primary:
    service: rest
    config:
      {url_line}
      path: /v1/items
      method: POST
      {template_line}
"
    ))
    .expect("parses")
}

#[test]
fn a_secret_in_a_header_query_or_body_template_refuses_cleartext_at_load() {
    for (template_line, field) in [
        (
            "headers: {X-Api-Key: \"{env.MCP_GW_7958_KEY}\"}",
            "providers.primary.config.headers.X-Api-Key",
        ),
        (
            "params: {key: \"{keychain.mik7958}\"}",
            "providers.primary.config.params.key",
        ),
        (
            "body: {auth: {token: \"Bearer {env.MCP_GW_7958_KEY}\"}}",
            "providers.primary.config.body",
        ),
    ] {
        let cap = templated_secret("base_url: http://api.example.com", template_line);
        let error = validate_capability(&cap)
            .expect_err(template_line)
            .to_string();
        assert!(error.contains("template_secret_probe"), "{error}");
        assert!(error.contains(field), "{template_line}: {error}");
        assert!(
            error.contains("providers.primary.config.base_url"),
            "{error}"
        );
        assert!(error.contains("https://"), "{error}");
        assert!(!error.contains("api.example.com"), "URL echoed: {error}");
    }
}

#[test]
fn a_template_secret_on_https_or_loopback_and_a_caller_value_on_http_still_load() {
    for (url_line, template_line) in [
        (
            "base_url: https://api.example.com",
            "headers: {X-Api-Key: \"{env.K}\"}",
        ),
        (
            "base_url: http://127.0.0.1:8000",
            "params: {key: \"{keychain.k}\"}",
        ),
        // A caller parameter is not a secret the gateway holds.
        (
            "base_url: http://api.example.com",
            "headers: {X-Q: \"{q}\"}",
        ),
        // `{env.}` names nothing; the resolver leaves it as written.
        (
            "base_url: http://api.example.com",
            "params: {k: \"{env.}\"}",
        ),
    ] {
        validate_capability(&templated_secret(url_line, template_line))
            .unwrap_or_else(|e| panic!("{url_line} / {template_line}: {e}"));
    }
}

/// The URL is filled per call, so the refusal is at send time, and it comes
/// before the secret is read: an unset variable would otherwise be the error.
#[tokio::test]
async fn a_template_secret_to_a_templated_cleartext_url_is_refused_before_the_read() {
    for template_line in [
        "headers: {X-Api-Key: \"{env.MCP_GW_7958_UNSET}\"}",
        "params: {key: \"{env.MCP_GW_7958_UNSET}\"}",
        "body: {items: [{token: \"{env.MCP_GW_7958_UNSET}\"}]}",
        "body_content_type: text/plain\n      body: \"key={env.MCP_GW_7958_UNSET}\"",
    ] {
        let cap = templated_secret("base_url: \"http://{host}\"", template_line);
        let provider = cap.providers.named.get("primary").expect("primary");
        let error = CapabilityExecutor::new()
            .execute_provider_with_context(
                &cap,
                provider,
                &json!({"host": "off-machine.invalid"}),
                &CapabilityExecutionContext::default(),
            )
            .await
            .expect_err(template_line)
            .to_string();
        assert!(error.contains("cleartext"), "{template_line}: {error}");
        assert!(!error.contains("is not set"), "secret read first: {error}");
        assert!(
            !error.contains("off-machine.invalid"),
            "URL echoed: {error}"
        );
    }
}

#[tokio::test]
async fn graphql_and_jsonrpc_refuse_a_header_secret_over_cleartext_before_the_read() {
    use super::super::rest::{ExecutionContext, ProtocolExecutor};
    let executor = CapabilityExecutor::new();
    for service in ["graphql", "jsonrpc"] {
        let cap = parse_capability(&format!(
            "
name: template_secret_{service}
description: probe
providers:
  primary:
    service: {service}
    config:
      endpoint: http://93.184.215.14/rpc
      method: probe
      body: \"{{ probe }}\"
      headers: {{X-Api-Key: \"{{env.MCP_GW_7958_UNSET}}\"}}
"
        ))
        .expect("parses");
        let config = cap.providers.named["primary"].protocol_config();
        let ctx = ExecutionContext {
            capability: &cap,
            timeout_secs: 10,
            context: CapabilityExecutionContext::default(),
        };
        let result = if service == "graphql" {
            let graphql = super::GraphqlExecutor {
                executor: &executor,
            };
            graphql.execute(&config, json!({}), &ctx).await
        } else {
            let jsonrpc = super::super::jsonrpc::JsonRpcExecutor {
                executor: &executor,
            };
            jsonrpc.execute(&config, json!({}), &ctx).await
        };
        let error = result.expect_err(service).to_string();
        assert!(error.contains("cleartext"), "{service}: {error}");
        assert!(!error.contains("is not set"), "{service}: {error}");
    }
}

/// No shipped capability is refused by either cleartext rule, and
/// `number_facts` (plain `http://`, no secret) still loads.
#[test]
fn every_shipped_capability_still_passes_the_cleartext_rules() {
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("readable").flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "yaml" || e == "yml") {
                out.push(path);
            }
        }
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("capabilities");
    let mut files = Vec::new();
    walk(&root, &mut files);
    let mut checked = 0;
    for path in &files {
        let yaml = std::fs::read_to_string(path).expect("readable");
        let Ok(cap) = parse_capability(&yaml) else {
            continue;
        };
        checked += 1;
        if let Err(e) = validate_capability(&cap) {
            assert!(
                !e.to_string().contains("cleartext"),
                "{}: {e}",
                path.display()
            );
        }
    }
    assert!(checked > 50, "only {checked} capabilities parsed");
    let facts = std::fs::read_to_string(root.join("knowledge/number_facts.yaml"))
        .expect("number_facts ships");
    validate_capability(&parse_capability(&facts).expect("parses")).expect("number_facts loads");
}
