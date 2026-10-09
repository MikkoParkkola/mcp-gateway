// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! E5-T23 (MIK-7570.SESSION.1): `mcp-gateway dashboard-link` sends the admin
//! credential straight to the gateway, never through a proxy named in the
//! environment. `HTTP_PROXY`/`ALL_PROXY` would otherwise carry the bearer off
//! the machine even for a loopback URL.
//!
//! Driven through the built binary because the proxy comes from the process
//! environment, which a library test cannot set without `unsafe`.

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::http::{HeaderMap, StatusCode};

/// A listener on loopback serving `app`; returns its base URL.
async fn serve(app: axum::Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move { axum::serve(listener, app).await });
    format!("http://{addr}")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_credential_bypasses_an_environment_proxy() {
    // The gateway stand-in: a link for the right bearer only.
    let gateway = serve(axum::Router::new().route(
        "/ui/api/dashboard-link",
        axum::routing::post(|headers: HeaderMap| async move {
            let ok =
                headers.get("authorization").and_then(|v| v.to_str().ok()) == Some("Bearer tok");
            if ok {
                Ok(axum::Json(serde_json::json!({
                    "link": "http://127.0.0.1:39400/dashboard?bootstrap=abc"
                })))
            } else {
                Err(StatusCode::FORBIDDEN)
            }
        }),
    ))
    .await;

    // The proxy stand-in: counts every request it is handed and fails it.
    let hits = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&hits);
    let proxy = serve(axum::Router::new().fallback(move || {
        let seen = Arc::clone(&seen);
        async move {
            seen.fetch_add(1, Ordering::SeqCst);
            StatusCode::BAD_GATEWAY
        }
    }))
    .await;

    let home = tempfile::tempdir().expect("temp dir");
    let out = tokio::task::spawn_blocking(move || {
        gateway_bin::command(home.path(), gateway_bin::Inherit::Environment)
            .args(["dashboard-link", "--url", &gateway])
            .env("MCP_GATEWAY_TOKEN", "tok")
            .env("HTTP_PROXY", &proxy)
            .env("http_proxy", &proxy)
            .env("ALL_PROXY", &proxy)
            .env("all_proxy", &proxy)
            .env_remove("NO_PROXY")
            .env_remove("no_proxy")
            .env("MCP_GATEWAY_CONFIG_DIR", home.path())
            .output()
            .expect("the command runs")
    })
    .await
    .expect("join");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "the request went through the proxy; stderr: {stderr}"
    );
    assert!(
        out.status.success(),
        "exit {:?}; stderr: {stderr}",
        out.status
    );
    assert!(
        stdout.contains("/dashboard?bootstrap=abc"),
        "stdout: {stdout}"
    );
}

/// An mTLS gateway stand-in requiring a client certificate, its PKI written
/// to `dir` (`ca.crt`, `client.crt`, `client.key`, and an unrelated
/// `other-ca.crt`). Returns the base URL and
/// a count of requests that reached the handler.
async fn mtls_gateway(dir: &std::path::Path) -> (String, Arc<AtomicUsize>) {
    use mcp_gateway::mtls::{CaParams, CertGenerator, LeafCertParams, MtlsConfig};
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let ca = CertGenerator::init_ca(&CaParams {
        cn: "link CA",
        validity_days: 1,
    })
    .expect("CA");
    let leaf = |cn: &str, san: &[&str]| {
        CertGenerator::issue_leaf(
            &LeafCertParams {
                cn,
                ou: None,
                san_dns: san.iter().map(ToString::to_string).collect(),
                san_uris: vec![],
                validity_days: 1,
            },
            &ca.cert_pem,
            &ca.key_pem,
        )
        .expect("leaf")
    };
    for (cert, stem) in [
        (leaf("gateway", &["127.0.0.1"]), "server"),
        (leaf("operator", &[]), "client"),
    ] {
        CertGenerator::write_to_dir(&cert, dir, stem).expect("files");
    }
    CertGenerator::write_to_dir(&ca, dir, "ca").expect("CA files");
    // A CA the listener's certificate does not chain to.
    let other = CertGenerator::init_ca(&CaParams {
        cn: "other CA",
        validity_days: 1,
    })
    .expect("other CA");
    CertGenerator::write_to_dir(&other, dir, "other-ca").expect("other CA files");
    let path = |name: &str| dir.join(name).to_string_lossy().into_owned();
    let tls = mcp_gateway::mtls::build_tls_config(&MtlsConfig {
        enabled: true,
        server_cert: path("server.crt"),
        server_key: path("server.key"),
        ca_cert: path("ca.crt"),
        require_client_cert: true,
        ..Default::default()
    })
    .expect("the listener serve builds");

    let hits = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&hits);
    let app = axum::Router::new().route(
        "/ui/api/dashboard-link",
        axum::routing::post(move |headers: HeaderMap| {
            let seen = Arc::clone(&seen);
            async move {
                seen.fetch_add(1, Ordering::SeqCst);
                if headers.get("authorization").and_then(|v| v.to_str().ok()) == Some("Bearer tok")
                {
                    Ok(axum::Json(serde_json::json!({
                        "link": "https://127.0.0.1:1/dashboard?bootstrap=abc"
                    })))
                } else {
                    Err(StatusCode::FORBIDDEN)
                }
            }
        }),
    );
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let base = format!("https://{}", listener.local_addr().expect("addr"));
    let config = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(tls));
    let server = axum_server::from_tcp_rustls(listener, config).expect("TLS listener");
    tokio::spawn(async move { server.serve(app.into_make_service()).await });
    (base, hits)
}

/// #1832 acceptance, through the built binary: against an mTLS listener that
/// requires a client certificate, the command gets a link when given the CA
/// and a client identity, and is refused without the identity before the
/// bearer reaches the handler.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_command_reaches_a_listener_that_requires_a_client_certificate() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (base, hits) = mtls_gateway(dir.path()).await;
    let path = |name: &str| dir.path().join(name).to_string_lossy().into_owned();

    let home = tempfile::tempdir().expect("home");
    let run = |identity: bool| {
        let mut cmd = gateway_bin::command(home.path(), gateway_bin::Inherit::Environment);
        cmd.args([
            "dashboard-link",
            "--url",
            &base,
            "--ca-cert",
            &path("ca.crt"),
        ]);
        if identity {
            cmd.args([
                "--client-cert",
                &path("client.crt"),
                "--client-key",
                &path("client.key"),
            ]);
        }
        cmd.env("MCP_GATEWAY_TOKEN", "tok")
            .env_remove("MCP_GATEWAY_CLIENT_CERT")
            .env_remove("MCP_GATEWAY_CLIENT_KEY")
            .env_remove("MCP_GATEWAY_CA_CERT")
            .env("MCP_GATEWAY_CONFIG_DIR", home.path());
        cmd
    };
    let (mut with_identity, mut without) = (run(true), run(false));
    let (ok, refused) = tokio::task::spawn_blocking(move || {
        (
            with_identity.output().expect("runs"),
            without.output().expect("runs"),
        )
    })
    .await
    .expect("join");

    let stderr = String::from_utf8_lossy(&ok.stderr);
    assert!(
        ok.status.success(),
        "exit {:?}; stderr: {stderr}",
        ok.status
    );
    assert!(
        String::from_utf8_lossy(&ok.stdout).contains("/dashboard?bootstrap=abc"),
        "stderr: {stderr}"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(!refused.status.success(), "no identity succeeded");
    assert!(stderr.contains("--client-cert"), "stderr: {stderr}");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "the bearer reached the handler"
    );
}

/// #1832: a named CA is the ONLY root. The default roots trust the
/// listener's CA, set on the child only: through `SSL_CERT_FILE` on Linux and
/// the debug-only `MCP_GATEWAY_TEST_TRUST_CA` everywhere (macOS reads its
/// keychain; MIK-8188). That reaches the listener (the precondition), and
/// naming another CA with `--ca-cert` then fails, where merging it with the
/// default roots would succeed. The client identity comes from
/// `MCP_GATEWAY_CLIENT_CERT`/`_KEY`, covering those bindings.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_named_ca_replaces_the_system_roots() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (base, hits) = mtls_gateway(dir.path()).await;
    let path = |name: &str| dir.path().join(name).to_string_lossy().into_owned();
    let home = tempfile::tempdir().expect("home");
    let run = |ca_flag: Option<String>| {
        let mut cmd = gateway_bin::command(home.path(), gateway_bin::Inherit::Environment);
        cmd.args(["dashboard-link", "--url", &base]);
        if let Some(ca) = ca_flag {
            cmd.args(["--ca-cert", &ca]);
        }
        cmd.env("MCP_GATEWAY_TOKEN", "tok")
            .env("MCP_GATEWAY_CLIENT_CERT", path("client.crt"))
            .env("MCP_GATEWAY_CLIENT_KEY", path("client.key"))
            .env_remove("MCP_GATEWAY_CA_CERT")
            .env("SSL_CERT_FILE", path("ca.crt"))
            .env("MCP_GATEWAY_TEST_TRUST_CA", path("ca.crt"))
            .env_remove("SSL_CERT_DIR")
            .env("MCP_GATEWAY_CONFIG_DIR", home.path());
        cmd
    };
    let (mut system, mut named) = (run(None), run(Some(path("other-ca.crt"))));
    let (system, named) = tokio::task::spawn_blocking(move || {
        (
            system.output().expect("runs"),
            named.output().expect("runs"),
        )
    })
    .await
    .expect("join");

    let stderr = String::from_utf8_lossy(&system.stderr);
    assert!(
        system.status.success(),
        "precondition: the default roots reach the listener; stderr: {stderr}"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    let stderr = String::from_utf8_lossy(&named.stderr);
    assert!(
        !named.status.success(),
        "--ca-cert was merged with the system roots"
    );
    assert!(
        stderr.to_lowercase().contains("certificate"),
        "stderr: {stderr}"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "the bearer reached the handler"
    );
}

/// #1832, the path DEPLOYMENT documents: no `--url` and no `--ca-cert`. The
/// config `serve` uses supplies the address and `mtls.ca_cert` as the only
/// root; the identity flags are all the operator passes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_config_path_needs_only_the_identity_flags() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (base, hits) = mtls_gateway(dir.path()).await;
    let path = |name: &str| dir.path().join(name).to_string_lossy().into_owned();
    let port = base.rsplit(':').next().expect("port");
    let config = dir.path().join("gateway.yaml");
    // Owner-only on every platform: the gateway refuses a config others can read.
    mcp_gateway::gateway::test_helpers::write_owner_only(
        &config,
        format!(
            "server:\n  host: 127.0.0.1\n  port: {port}\nmtls:\n  enabled: true\n  \
             server_cert: {}\n  server_key: {}\n  ca_cert: {}\n  require_client_cert: true\n",
            path("server.crt"),
            path("server.key"),
            path("ca.crt"),
        ),
    )
    .expect("config");
    // The gateway refuses a config other users can read.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600))
            .expect("chmod 600");
    }
    let home = tempfile::tempdir().expect("home");
    let mut cmd = gateway_bin::command(home.path(), gateway_bin::Inherit::Environment);
    cmd.args(["--config", &config.to_string_lossy(), "dashboard-link"])
        .args(["--client-cert", &path("client.crt")])
        .args(["--client-key", &path("client.key")])
        .env("MCP_GATEWAY_TOKEN", "tok")
        .env_remove("MCP_GATEWAY_CLIENT_CERT")
        .env_remove("MCP_GATEWAY_CLIENT_KEY")
        .env_remove("MCP_GATEWAY_CA_CERT")
        .env("MCP_GATEWAY_CONFIG_DIR", home.path());
    let out = tokio::task::spawn_blocking(move || cmd.output().expect("runs"))
        .await
        .expect("join");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "exit {:?}; stderr: {stderr}",
        out.status
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("/dashboard?bootstrap=abc"),
        "stderr: {stderr}"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}
