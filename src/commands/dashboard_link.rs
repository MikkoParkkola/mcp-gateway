// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `mcp-gateway dashboard-link`: ask a running gateway for a fresh dashboard
//! link, so re-entry after a session ends needs no restart.
//!
//! The admin credential comes from the environment only. An argument would
//! land in shell history and in every process listing on the machine.

use std::path::PathBuf;
use std::process::ExitCode;

/// The environment variable the admin credential is read from.
pub(crate) const TOKEN_ENV: &str = "MCP_GATEWAY_TOKEN";

/// The TLS material the operator named on the command line (or in the
/// matching environment variables).
#[derive(Debug, Default, Clone)]
pub struct LinkTlsFlags {
    /// PEM client certificate presented to the listener.
    pub client_cert: Option<PathBuf>,
    /// PEM private key for `client_cert`.
    pub client_key: Option<PathBuf>,
    /// PEM CA the server certificate must chain to.
    pub ca_cert: Option<PathBuf>,
}

/// What the link request trusts and presents.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LinkTls {
    /// The only roots the server certificate may chain to; `None` keeps the
    /// built-in roots.
    pub(crate) ca: Option<PathBuf>,
    /// Client certificate and key files.
    pub(crate) identity: Option<(PathBuf, PathBuf)>,
}

/// The credential in [`TOKEN_ENV`], read through `lookup`.
///
/// # Errors
///
/// A message naming [`TOKEN_ENV`] when it is unset or blank.
pub(crate) fn read_token(lookup: impl Fn(&str) -> Option<String>) -> Result<String, String> {
    // Not trimmed: credentials compare byte for byte, so rewriting one would
    // turn a valid key into a refused one. Only a blank value is missing.
    lookup(TOKEN_ENV)
        .filter(|t| !t.trim().is_empty())
        .ok_or_else(|| {
            format!(
                "{TOKEN_ENV} is not set. Export the gateway's bearer token or an admin API \
                 key in {TOKEN_ENV}; it is never read from the command line."
            )
        })
}

/// The gateway to ask: `--url` when given, otherwise the listener the config
/// describes (`https` when it serves TLS).
///
/// Unlike `stats`, a config that fails to load is an error, not a fallback to
/// the default address: this command sends an admin credential, and a guessed
/// address may belong to something else.
///
/// # Errors
///
/// The config load failure, when no `--url` was given.
pub fn dashboard_link_base(
    url: Option<String>,
    flags: LinkTlsFlags,
    load: impl FnOnce() -> Result<mcp_gateway::config::Config, String>,
    port_override: Option<u16>,
    host_override: Option<&str>,
) -> Result<(String, LinkTls), String> {
    let _ = (flags.client_cert, flags.client_key, flags.ca_cert);
    if let Some(url) = url {
        return Ok((url, LinkTls::default()));
    }
    let mut config = load().map_err(|e| format!("could not load the config ({e}); pass --url"))?;
    if let Some(port) = port_override {
        config.server.port = port;
    }
    if let Some(host) = host_override {
        config.server.host = host.to_string();
    }
    let base = super::default_stats_url(&config.server.host, config.server.port);
    let base = if config.mtls.enabled {
        base.replacen("http://", "https://", 1)
    } else {
        base
    };
    Ok((base, LinkTls::default()))
}

/// Refuse a target the admin credential must not be sent to: plain `http://`
/// to anything but a loopback address would put the bearer on the network.
///
/// # Errors
///
/// A message naming the target and asking for `https://` or a loopback URL.
pub(crate) fn check_target(base: &str) -> Result<(), String> {
    let url = reqwest::Url::parse(base).map_err(|e| format!("not a URL: {base} ({e})"))?;
    match url.scheme() {
        "https" => return Ok(()),
        "http" => {}
        other => {
            return Err(format!(
                "unsupported scheme {other}: in {base}; use https:// or http://"
            ));
        }
    }
    let loopback = match url.host() {
        Some(url::Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    };
    if loopback {
        Ok(())
    } else {
        Err(format!(
            "refusing to send the admin credential in cleartext to {base}; \
             use https:// or a loopback address"
        ))
    }
}

/// Ask the gateway at `base` for a fresh link.
///
/// # Errors
///
/// A message carrying the gateway's status or the transport failure.
pub(crate) async fn fetch_link(base: &str, token: &str, tls: &LinkTls) -> Result<String, String> {
    let _ = (&tls.ca, &tls.identity);
    check_target(base)?;
    let endpoint = format!("{}/ui/api/dashboard-link", base.trim_end_matches('/'));
    // Direct, never through an environment proxy: an HTTP_PROXY would carry the
    // credential off this machine even to a loopback URL. No redirects either:
    // `check_target` vetted only this URL, and a same-host, same-port hop
    // (https to http) would keep the bearer.
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| format!("could not build the HTTP client: {e}"))?;
    let response = client
        .post(&endpoint)
        .timeout(std::time::Duration::from_secs(30))
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| format!("could not reach the gateway at {base}: {e}"))?;
    let status = response.status();
    let body: serde_json::Value = response.json().await.unwrap_or_default();
    if !status.is_success() {
        let reason = body["error"].as_str().unwrap_or("no reason given");
        return Err(format!("the gateway answered {status}: {reason}"));
    }
    body["link"]
        .as_str()
        .map(ToString::to_string)
        .ok_or_else(|| "the gateway's answer carried no link".to_string())
}

/// Run the command against the gateway at `base`.
pub async fn run_dashboard_link_command(base: &str, tls: &LinkTls) -> ExitCode {
    let result = match read_token(|name| std::env::var(name).ok()) {
        Ok(token) => fetch_link(base, &token, tls).await,
        Err(message) => Err(message),
    };
    match result {
        Ok(link) => {
            println!("{link}");
            eprintln!("Opens once, from this machine only.");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("dashboard-link: {message}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{LinkTls, LinkTlsFlags, TOKEN_ENV, read_token};

    fn no_flags() -> LinkTlsFlags {
        LinkTlsFlags::default()
    }

    /// No TLS material: the pre-#1832 request.
    async fn fetch_link(base: &str, token: &str) -> Result<String, String> {
        super::fetch_link(base, token, &LinkTls::default()).await
    }

    #[test]
    fn the_base_url_never_falls_back_past_a_config_that_failed_to_load() {
        use super::dashboard_link_base;
        let explicit = dashboard_link_base(
            Some("http://h:1".into()),
            no_flags(),
            || Err("x".into()),
            None,
            None,
        );
        assert_eq!(
            explicit.map(|(base, _)| base).as_deref(),
            Ok("http://h:1"),
            "--url wins without a load"
        );

        let failed = dashboard_link_base(None, no_flags(), || Err("bad yaml".into()), None, None)
            .expect_err("a config that fails to load is not replaced by defaults");
        assert!(
            failed.contains("bad yaml") && failed.contains("--url"),
            "{failed}"
        );

        let mut config = mcp_gateway::config::Config::default();
        config.server.port = 4100;
        let plain = dashboard_link_base(None, no_flags(), || Ok(config.clone()), None, None);
        assert_eq!(
            plain.map(|(base, _)| base).as_deref(),
            Ok("http://127.0.0.1:4100")
        );
        config.mtls.enabled = true;
        config.mtls.require_client_cert = false;
        let tls = dashboard_link_base(None, no_flags(), || Ok(config.clone()), Some(4200), None);
        assert_eq!(
            tls.map(|(base, _)| base).as_deref(),
            Ok("https://127.0.0.1:4200")
        );
    }

    /// E5-T21: the credential never goes out in cleartext to the network.
    #[test]
    fn cleartext_is_refused_off_loopback() {
        use super::check_target;
        for refused in [
            "http://10.0.0.5:39400",
            "http://gateway.example",
            "HTTP://192.0.2.1:1",
        ] {
            let err = check_target(refused).expect_err(refused);
            assert!(err.contains("cleartext"), "{refused}: {err}");
        }
        for allowed in [
            "http://127.0.0.1:39400",
            "http://localhost:39400/",
            "http://[::1]:39400",
            "https://gateway.example",
        ] {
            assert_eq!(check_target(allowed), Ok(()), "{allowed}");
        }
        let odd = check_target("ftp://127.0.0.1:1").expect_err("an unknown scheme");
        assert!(odd.contains("unsupported scheme"), "{odd}");
    }

    /// E5-T21b: `fetch_link` refuses before sending anything: 192.0.2.1 is a
    /// documentation address, so a request would hang, not answer.
    #[tokio::test]
    async fn fetch_link_refuses_cleartext_before_sending() {
        let out = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            fetch_link("http://192.0.2.1:9", "tok"),
        )
        .await
        .expect("refused at once, no connection attempted");
        let err = out.expect_err("cleartext target");
        assert!(err.contains("cleartext"), "{err}");
    }

    #[test]
    fn the_token_comes_from_the_named_variable_only() {
        let token = read_token(|name| (name == TOKEN_ENV).then(|| "tok".to_string()));
        assert_eq!(token.as_deref(), Ok("tok"));

        let missing = read_token(|_| None).expect_err("no variable, no token");
        assert!(missing.contains(TOKEN_ENV), "{missing}");

        let blank = read_token(|_| Some("  ".to_string())).expect_err("blank is unset");
        assert!(blank.contains(TOKEN_ENV), "{blank}");

        let padded = read_token(|_| Some(" tok ".to_string()));
        assert_eq!(
            padded.as_deref(),
            Ok(" tok "),
            "a credential is passed as given"
        );
    }

    /// An in-process gateway stand-in: answers the link only for `tok`.
    async fn stand_in() -> String {
        use axum::http::{HeaderMap, StatusCode};
        let app = axum::Router::new().route(
            "/ui/api/dashboard-link",
            axum::routing::post(|headers: HeaderMap| async move {
                let ok = headers.get("authorization").and_then(|v| v.to_str().ok())
                    == Some("Bearer tok");
                if ok {
                    Ok(axum::Json(serde_json::json!({
                        "link": "http://127.0.0.1:39400/dashboard?bootstrap=abc"
                    })))
                } else {
                    Err(StatusCode::FORBIDDEN)
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move { axum::serve(listener, app).await });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn the_link_is_fetched_with_the_credential_as_a_bearer() {
        let base = stand_in().await;
        assert_eq!(
            fetch_link(&base, "tok").await.as_deref(),
            Ok("http://127.0.0.1:39400/dashboard?bootstrap=abc")
        );
        let refused = fetch_link(&format!("{base}/"), "wrong")
            .await
            .expect_err("a refused credential is an error");
        assert!(refused.contains("403"), "{refused}");
    }

    /// A redirect is never followed: the next hop was not checked by
    /// `check_target`, and a same-host, same-port hop keeps the bearer.
    #[tokio::test]
    async fn a_redirect_is_not_followed() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        let hits = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&hits);
        let hop = axum::Router::new().fallback(move || {
            let seen = Arc::clone(&seen);
            async move {
                seen.fetch_add(1, Ordering::SeqCst);
                axum::Json(serde_json::json!({ "link": "http://127.0.0.1:1/dashboard" }))
            }
        });
        let hop_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let hop_url = format!(
            "http://{}/ui/api/dashboard-link",
            hop_listener.local_addr().expect("addr")
        );
        tokio::spawn(async move { axum::serve(hop_listener, hop).await });
        let redirector = axum::Router::new().fallback(move || {
            let location = hop_url.clone();
            async move {
                (
                    axum::http::StatusCode::TEMPORARY_REDIRECT,
                    [(axum::http::header::LOCATION, location)],
                )
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let base = format!("http://{}", listener.local_addr().expect("addr"));
        tokio::spawn(async move { axum::serve(listener, redirector).await });

        let refused = fetch_link(&base, "tok")
            .await
            .expect_err("a redirect is an error, not a link");
        assert!(refused.contains("307"), "{refused}");
        assert_eq!(hits.load(Ordering::SeqCst), 0, "the redirect was followed");
    }
}
