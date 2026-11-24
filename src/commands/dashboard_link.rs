// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `mcp-gateway dashboard-link`: ask a running gateway for a fresh dashboard
//! link, so re-entry after a session ends needs no restart.
//!
//! The admin credential comes from the environment only. An argument would
//! land in shell history and in every process listing on the machine.

use std::path::PathBuf;
use std::process::ExitCode;

use mcp_gateway::cli::dashboard_link::DashboardLinkTls;

/// The environment variable the admin credential is read from.
pub(crate) const TOKEN_ENV: &str = "MCP_GATEWAY_TOKEN";

/// A missing credential and an explicitly blank setting have different exits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TokenError {
    Missing,
    Blank,
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => write!(
                formatter,
                "{TOKEN_ENV} is not set. Export the gateway's bearer token or an admin API \
                 key in {TOKEN_ENV}; it is never read from the command line."
            ),
            Self::Blank => write!(formatter, "{TOKEN_ENV} is empty."),
        }
    }
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
/// Distinguishes an unset [`TOKEN_ENV`] from an explicitly blank value.
pub(crate) fn read_token(lookup: impl Fn(&str) -> Option<String>) -> Result<String, TokenError> {
    // Not trimmed: credentials compare byte for byte, so rewriting one would
    // turn a valid key into a refused one.
    match lookup(TOKEN_ENV) {
        None => Err(TokenError::Missing),
        Some(token) if token.trim().is_empty() => Err(TokenError::Blank),
        Some(token) => Ok(token),
    }
}

/// The gateway to ask: `--gateway` (or `MCP_GATEWAY_URL`) when given, otherwise the listener the config
/// describes (`https` when it serves TLS).
///
/// Unlike `stats`, a config that fails to load is an error, not a fallback to
/// the default address: this command sends an admin credential, and a guessed
/// address may belong to something else.
///
/// # Errors
///
/// The config load failure, when no `--gateway` was given.
pub fn dashboard_link_base(
    url: Option<String>,
    flags: DashboardLinkTls,
    load: impl FnOnce() -> Result<mcp_gateway::config::Config, String>,
    port_override: Option<u16>,
    host_override: Option<&str>,
) -> Result<(String, LinkTls), String> {
    let identity = match (flags.client_cert, flags.client_key) {
        (Some(cert), Some(key)) => Some((cert, key)),
        (None, None) => None,
        _ => return Err("--client-cert and --client-key go together".to_string()),
    };
    // `--gateway` describes the target: no config is read, so its trust anchor
    // is `--ca-cert` or the built-in roots.
    if let Some(url) = url {
        let ca = flags.ca_cert;
        return Ok((url, LinkTls { ca, identity }));
    }
    let mut config =
        load().map_err(|e| format!("could not load the config ({e}); pass --gateway"))?;
    if let Some(port) = port_override {
        config.server.port = port;
    }
    if let Some(host) = host_override {
        config.server.host = host.to_string();
    }
    let base = super::default_stats_url(&config.server.host, config.server.port);
    let mtls = &config.mtls;
    if !mtls.enabled {
        return Ok((
            base,
            LinkTls {
                ca: flags.ca_cert,
                identity,
            },
        ));
    }
    let base = base.replacen("http://", "https://", 1);
    if mtls.require_client_cert && identity.is_none() {
        return Err(format!(
            "{base} requires a client certificate (mtls.require_client_cert); pass \
             --client-cert and --client-key, or set MCP_GATEWAY_CLIENT_CERT and \
             MCP_GATEWAY_CLIENT_KEY"
        ));
    }
    // The listener's own CA when none is named. It becomes the only root, so
    // a public CA cannot vouch for this name; a server certificate from a
    // public CA is reached with `--gateway` instead.
    let ca = flags
        .ca_cert
        .or_else(|| (!mtls.ca_cert.is_empty()).then(|| PathBuf::from(&mtls.ca_cert)));
    Ok((base, LinkTls { ca, identity }))
}

/// Refuse a target the admin credential must not be sent to: plain `http://`
/// to anything but a loopback address would put the bearer on the network.
///
/// # Errors
///
/// A message naming the target and asking for `https://` or a loopback URL.
pub(crate) fn check_target(base: &str) -> Result<(), String> {
    let shown = mcp_gateway::security::sanitize::redact_url_for_diagnostics(base);
    let url = reqwest::Url::parse(base).map_err(|e| format!("not a URL: {shown} ({e})"))?;
    match url.scheme() {
        "https" => return Ok(()),
        "http" => {}
        other => {
            return Err(format!(
                "unsupported scheme {other}: in {shown}; use https:// or http://"
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
            "refusing to send the admin credential in cleartext to {shown}; \
             use https:// or a loopback address"
        ))
    }
}

#[path = "dashboard_link_admin.rs"]
mod admin;

use super::cli_exit::{
    CliError, CliExit, CliOutcome, Request, StdoutRule, emit, emit_to, resolve_token,
};
#[cfg(test)]
pub(crate) use admin::admin_call_url_with_options;
pub(crate) use admin::{
    AdminBody, AdminCallError, AdminClientOptions, AdminFailureKind, AdminResponse, AdminStream,
    Remedies, UNSUPPORTED_REMEDY, admin_call, admin_call_url, admin_stream_url, fetch_link,
    gateway_reason, origin_of, redact_body, refusal, transport,
};

/// `mcp-gateway events dead-letters`: the request the arguments describe.
///
/// # Errors
///
/// A usage message when the arguments do not name a request.
pub(crate) fn dead_letters_request(
    args: &mcp_gateway::cli::events::DeadLettersArgs,
) -> Result<(reqwest::Method, String), String> {
    use mcp_gateway::cli::events::DeadLetterAction;
    const BASE: &str = "/ui/api/events/dead-letters";
    let enc = |v: &str| url::form_urlencoded::byte_serialize(v.as_bytes()).collect::<String>();
    match (args.action, args.id.as_deref(), args.all) {
        (DeadLetterAction::List, None, false) => {
            let mut query = Vec::new();
            if let Some(s) = &args.subscription {
                query.push(format!("subscription={}", enc(s)));
            }
            if let Some(r) = &args.reason {
                query.push(format!("reason={}", enc(r)));
            }
            let query = if query.is_empty() {
                String::new()
            } else {
                format!("?{}", query.join("&"))
            };
            Ok((reqwest::Method::GET, format!("{BASE}{query}")))
        }
        (DeadLetterAction::Replay, Some(id), false) => {
            Ok((reqwest::Method::POST, format!("{BASE}/{}/replay", enc(id))))
        }
        (DeadLetterAction::Replay, None, true) => {
            let subscription = args
                .subscription
                .as_deref()
                .ok_or("replay --all needs --subscription")?;
            Ok((
                reqwest::Method::POST,
                format!("{BASE}/replay?all=1&subscription={}", enc(subscription)),
            ))
        }
        _ => Err("use `list`, `replay ID` or `replay --all --subscription S`".to_string()),
    }
}

/// `mcp-gateway dashboard-link`: resolve the gateway, then ask it for a link.
pub async fn run_dashboard_link_args(
    args: mcp_gateway::cli::dashboard_link::DashboardLinkArgs,
    load: impl FnOnce() -> Result<mcp_gateway::config::Config, String>,
    port_override: Option<u16>,
    host_override: Option<&str>,
) -> ExitCode {
    let token = read_token(|name| std::env::var(name).ok());
    // Stderr unlocked: the fetch awaits before anything prints, and a held lock would stall other threads' writes.
    let exit = print_dashboard_link(
        args,
        load,
        port_override,
        host_override,
        token,
        &mut std::io::stdout(),
        &mut std::io::stderr(),
    )
    .await;
    ExitCode::from(exit.code())
}

/// `dashboard-link` once its token is read: the outcome, printed through the shared emitter in the run's form, so a
/// failed stdout write is the shared JSON error under `--json` too (MIK-9764.JSONF.1, design D5).
pub(crate) async fn print_dashboard_link(
    args: mcp_gateway::cli::dashboard_link::DashboardLinkArgs,
    load: impl FnOnce() -> Result<mcp_gateway::config::Config, String>,
    port_override: Option<u16>,
    host_override: Option<&str>,
    token: Result<String, TokenError>,
    stdout: &mut impl std::io::Write,
    stderr: &mut impl std::io::Write,
) -> CliExit {
    let secret = token.as_deref().unwrap_or_default().to_owned();
    let json = args.json;
    let out = dashboard_link_outcome(args, load, port_override, host_override, token).await;
    emit_to(&out, json, &[&secret], stdout, stderr)
}

/// `mcp-gateway events ...`: resolve the gateway like `dashboard-link`, then
/// run the subcommand.
pub async fn run_events_command(
    args: mcp_gateway::cli::events::EventsArgs,
    load: impl FnOnce() -> Result<mcp_gateway::config::Config, String>,
    port_override: Option<u16>,
    host_override: Option<&str>,
) -> ExitCode {
    let mcp_gateway::cli::events::EventsCommand::DeadLetters(args) = args.command;
    let token = read_token(|name| std::env::var(name).ok());
    let secret = token.as_deref().unwrap_or_default().to_owned();
    let out = events_outcome(&args, load, port_override, host_override, token).await;
    emit(&out, false, &[&secret])
}

/// The first two checks of every remote command (design D4): resolve the gateway (2), then the token (unset 3,
/// empty 2, a control character 2). A resolution error is gated on the token when one is set: a config error can
/// quote the config, which can hold it.
///
/// # Errors
///
/// The outcome to print when either check fails.
pub(crate) fn resolved(
    url: Option<String>,
    tls: DashboardLinkTls,
    load: impl FnOnce() -> Result<mcp_gateway::config::Config, String>,
    port_override: Option<u16>,
    host_override: Option<&str>,
    token: Result<String, TokenError>,
    render: crate::cli::output::Render,
) -> Result<(String, LinkTls, String), CliOutcome> {
    let json = render == crate::cli::output::Render::Json;
    let secret = token.as_deref().unwrap_or_default().to_owned();
    let (base, tls) =
        dashboard_link_base(url, tls, load, port_override, host_override).map_err(|message| {
            CliError::new(
                CliExit::Usage,
                message,
                "Check the gateway settings, then retry.",
            )
            .outcome(json, &[&secret])
        })?;
    let token =
        resolve_token(token, &origin_of(&base)).map_err(|error| error.outcome(json, &[&secret]))?;
    Ok((base, tls, token))
}

/// What `dashboard-link` prints and exits with for `token`: the link on stdout, the note on stderr, or the
/// failure on the shared table.
pub(crate) async fn dashboard_link_outcome(
    args: mcp_gateway::cli::dashboard_link::DashboardLinkArgs,
    load: impl FnOnce() -> Result<mcp_gateway::config::Config, String>,
    port_override: Option<u16>,
    host_override: Option<&str>,
    token: Result<String, TokenError>,
) -> CliOutcome {
    let render = crate::cli::output::Render::from_json_flag(args.json);
    let json = render == crate::cli::output::Render::Json;
    let (base, tls, token) = match resolved(
        args.gateway.url,
        args.tls,
        load,
        port_override,
        host_override,
        token,
        render,
    ) {
        Ok(resolved) => resolved,
        Err(out) => return out,
    };
    match fetch_link(&base, &token, &tls).await {
        Ok(link) => {
            // Under `--json` the document goes through the same RefuseToken gate, which then also scans its
            // decoded strings (design D9).
            let stdout = if json {
                #[derive(serde::Serialize)]
                struct View<'a> {
                    url: &'a str,
                }
                match crate::cli::output::document(&View { url: &link }) {
                    Ok(doc) => doc,
                    Err(why) => {
                        return CliError::new(
                            CliExit::LocalFailure,
                            format!("Could not print the link: {why}"),
                            "Repeat the command.",
                        )
                        .outcome(json, &[&token]);
                    }
                }
            } else {
                format!("{link}\n")
            };
            CliOutcome::success(
                stdout.into_bytes(),
                "Opens once, from this machine only.\n",
                json,
                &[&token],
                StdoutRule::RefuseToken,
            )
        }
        Err(error) => error.outcome(json, &[&token]),
    }
}

/// What `events dead-letters` prints and exits with for `token`: the gateway's answer on stdout, or the failure
/// on the shared table. A replay is a mutation (design D3).
pub(crate) async fn events_outcome(
    args: &mcp_gateway::cli::events::DeadLettersArgs,
    load: impl FnOnce() -> Result<mcp_gateway::config::Config, String>,
    port_override: Option<u16>,
    host_override: Option<&str>,
    token: Result<String, TokenError>,
) -> CliOutcome {
    use mcp_gateway::cli::events::DeadLetterAction;
    let (base, tls, token) = match resolved(
        args.gateway.url.clone(),
        args.tls.clone(),
        load,
        port_override,
        host_override,
        token,
        crate::cli::output::Render::Text,
    ) {
        Ok(resolved) => resolved,
        Err(out) => return out,
    };
    let (method, path) = match dead_letters_request(args) {
        Ok(request) => request,
        Err(message) => {
            return CliError::new(
                CliExit::Usage,
                message,
                "Use list, replay ID, or replay --all --subscription S.",
            )
            .outcome(false, &[&token]);
        }
    };
    let (request, not_found) = match (args.action, args.all) {
        (DeadLetterAction::List, _) => (Request::Read, UNSUPPORTED_REMEDY.to_string()),
        (DeadLetterAction::Replay, false) => (
            Request::Mutation,
            "Check the dead-letter ID with events dead-letters list, then retry.".to_string(),
        ),
        (DeadLetterAction::Replay, true) => (
            Request::Mutation,
            format!(
                "Check the subscription with events dead-letters list --subscription {}, then retry.",
                args.subscription.as_deref().unwrap_or_default()
            ),
        ),
    };
    let remedies = Remedies {
        not_found,
        ..Remedies::read(&base)
    };
    match admin_call(method, &base, &path, &token, &tls, request, &remedies).await {
        Ok(body) => CliOutcome::success(
            format!(
                "{}\n",
                serde_json::to_string_pretty(&body).unwrap_or_default()
            )
            .into_bytes(),
            "",
            false,
            &[&token],
            StdoutRule::RefuseToken,
        ),
        Err(error) => error.outcome(false, &[&token]),
    }
}

#[cfg(tp2)]
#[cfg(test)]
#[path = "dashboard_link_tests.rs"]
mod tests;
