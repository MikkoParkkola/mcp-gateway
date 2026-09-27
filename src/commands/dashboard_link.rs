// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `mcp-gateway dashboard-link`: ask a running gateway for a fresh dashboard
//! link, so re-entry after a session ends needs no restart.
//!
//! The admin credential comes from the environment only. An argument would
//! land in shell history and in every process listing on the machine.

use std::process::ExitCode;

/// The environment variable the admin credential is read from.
pub(crate) const TOKEN_ENV: &str = "MCP_GATEWAY_TOKEN";

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
    load: impl FnOnce() -> Result<mcp_gateway::config::Config, String>,
    port_override: Option<u16>,
    host_override: Option<&str>,
) -> Result<String, String> {
    if let Some(url) = url {
        return Ok(url);
    }
    let mut config = load().map_err(|e| format!("could not load the config ({e}); pass --url"))?;
    if let Some(port) = port_override {
        config.server.port = port;
    }
    if let Some(host) = host_override {
        config.server.host = host.to_string();
    }
    let base = super::default_stats_url(&config.server.host, config.server.port);
    Ok(if config.mtls.enabled {
        base.replacen("http://", "https://", 1)
    } else {
        base
    })
}

/// Ask the gateway at `base` for a fresh link.
///
/// # Errors
///
/// A message carrying the gateway's status or the transport failure.
pub(crate) async fn fetch_link(base: &str, token: &str) -> Result<String, String> {
    let endpoint = format!("{}/ui/api/dashboard-link", base.trim_end_matches('/'));
    let response = reqwest::Client::new()
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
pub async fn run_dashboard_link_command(base: &str) -> ExitCode {
    let result = match read_token(|name| std::env::var(name).ok()) {
        Ok(token) => fetch_link(base, &token).await,
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
    use super::{TOKEN_ENV, fetch_link, read_token};

    #[test]
    fn the_base_url_never_falls_back_past_a_config_that_failed_to_load() {
        use super::dashboard_link_base;
        let explicit =
            dashboard_link_base(Some("http://h:1".into()), || Err("x".into()), None, None);
        assert_eq!(
            explicit.as_deref(),
            Ok("http://h:1"),
            "--url wins without a load"
        );

        let failed = dashboard_link_base(None, || Err("bad yaml".into()), None, None)
            .expect_err("a config that fails to load is not replaced by defaults");
        assert!(
            failed.contains("bad yaml") && failed.contains("--url"),
            "{failed}"
        );

        let mut config = mcp_gateway::config::Config::default();
        config.server.port = 4100;
        let plain = dashboard_link_base(None, || Ok(config.clone()), None, None);
        assert_eq!(plain.as_deref(), Ok("http://127.0.0.1:4100"));
        config.mtls.enabled = true;
        let tls = dashboard_link_base(None, || Ok(config.clone()), Some(4200), None);
        assert_eq!(tls.as_deref(), Ok("https://127.0.0.1:4200"));
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
}
