// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `mcp-gateway dashboard-link`: ask a running gateway for a fresh dashboard
//! link, so re-entry after a session ends needs no restart.
//!
//! The admin credential comes from the environment only. An argument would
//! land in shell history and in every process listing on the machine.

use crate::cli::stdout::print;

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
    // `--url` describes the target: no config is read, so its trust anchor
    // is `--ca-cert` or the built-in roots.
    if let Some(url) = url {
        let ca = flags.ca_cert;
        return Ok((url, LinkTls { ca, identity }));
    }
    let mut config = load().map_err(|e| format!("could not load the config ({e}); pass --url"))?;
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
    // public CA is reached with `--url` instead.
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

#[cfg(test)]
pub(crate) use admin::admin_call_url_with_options;
pub(crate) use admin::{
    AdminCallError, AdminClientOptions, AdminFailureKind, AdminResponse, AdminStream, admin_call,
    admin_call_url, admin_stream_url, fetch_link, gateway_reason, redact_body,
};

/// Printed instead of an answer the redactor cannot make safe.
const UNSAFE_ANSWER: &str = "the gateway's answer could not be printed safely";

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
    emit(&dashboard_link_args_output(args, load, port_override, host_override, token).await)
}

/// What `dashboard-link` prints for `token`. A resolution error comes before a
/// token error, as before; with a token set it passes the output gate too,
/// because a config error can quote the config, which can hold the token.
async fn dashboard_link_args_output(
    args: mcp_gateway::cli::dashboard_link::DashboardLinkArgs,
    load: impl FnOnce() -> Result<mcp_gateway::config::Config, String>,
    port_override: Option<u16>,
    host_override: Option<&str>,
    token: Result<String, TokenError>,
) -> Printed {
    const PREFIX: &str = "dashboard-link";
    let base = dashboard_link_base(args.url, args.tls, load, port_override, host_override);
    match (base, token) {
        (Ok((base, tls)), Ok(token)) => dashboard_link_output(&base, &tls, &token).await,
        (Err(message), Ok(token)) => gate(PREFIX, &token, Err(message)),
        (Err(message), Err(_)) => unmasked(PREFIX, &message),
        (Ok(_), Err(error)) => unmasked(PREFIX, &error.to_string()),
    }
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
    emit(&events_args_output(&args, load, port_override, host_override, token).await)
}

/// What `events dead-letters` prints for `token`, resolving like
/// [`dashboard_link_args_output`].
async fn events_args_output(
    args: &mcp_gateway::cli::events::DeadLettersArgs,
    load: impl FnOnce() -> Result<mcp_gateway::config::Config, String>,
    port_override: Option<u16>,
    host_override: Option<&str>,
    token: Result<String, TokenError>,
) -> Printed {
    const PREFIX: &str = "events dead-letters";
    let base = dashboard_link_base(
        args.url.clone(),
        args.tls.clone(),
        load,
        port_override,
        host_override,
    );
    match (base, token) {
        (Ok((base, tls)), Ok(token)) => dead_letters_output(&base, &tls, args, &token).await,
        (Err(message), Ok(token)) => gate(PREFIX, &token, Err(message)),
        (Err(message), Err(_)) => unmasked(PREFIX, &message),
        (Ok(_), Err(error)) => unmasked(PREFIX, &error.to_string()),
    }
}

/// A failure printed when no token is set, so there is nothing to mask.
fn unmasked(prefix: &str, message: &str) -> Printed {
    Printed {
        stdout: String::new(),
        stderr: format!("{prefix}: {message}\n"),
        ok: false,
    }
}

/// What `events dead-letters` prints, through the output gate.
async fn dead_letters_output(
    base: &str,
    tls: &LinkTls,
    args: &mcp_gateway::cli::events::DeadLettersArgs,
    token: &str,
) -> Printed {
    let result = match dead_letters_request(args) {
        Ok((method, path)) => admin_call(method, base, &path, token, tls).await,
        Err(message) => Err(message),
    };
    let result = result.map(|body| {
        let json = serde_json::to_string_pretty(&body).unwrap_or_default();
        (format!("{json}\n"), "")
    });
    gate("events dead-letters", token, result)
}

/// What one `dashboard-link` or `events` run prints once the token is read,
/// and whether it succeeded.
#[derive(Debug)]
struct Printed {
    stdout: String,
    stderr: String,
    ok: bool,
}

/// The one output gate once the token is read. Stdout still holding the token
/// (JSON syntax, which the JSON redactor cannot mask) is refused, and the
/// whole stderr text passes the shared redactor as the last step, so no
/// prefix, status, note or transport detail is printed unredacted.
fn gate(prefix: &str, token: &str, result: Result<(String, &str), String>) -> Printed {
    let result = result.and_then(|(stdout, note)| {
        if stdout.contains(token) {
            Err(UNSAFE_ANSWER.to_string())
        } else {
            Ok((stdout, note))
        }
    });
    let (stdout, line, ok) = match result {
        Ok((stdout, note)) => (stdout, note.to_string(), true),
        Err(message) => (String::new(), format!("{prefix}: {message}"), false),
    };
    // Checked as printed, newline included: a token ending in a newline
    // would otherwise form only after the check.
    let stderr = if line.is_empty() {
        line
    } else {
        token_free(&format!("{line}\n"), token)
    };
    Printed { stdout, stderr, ok }
}

/// `text` through the shared redactor, which keeps the first marker whose
/// output holds no token and fails closed to empty output when none does.
/// If the token is still there whatever the redactor did, one fixed sentence
/// instead, or nothing if even that holds the token (the api command's rule).
fn token_free(text: &str, token: &str) -> String {
    let newline = if text.ends_with('\n') { "\n" } else { "" };
    let text = mcp_gateway::cli::redact::text(text, &[token.to_string()]);
    if !text.contains(token) {
        return text;
    }
    let sentence =
        format!("A message could not be printed without exposing the credential.{newline}");
    if sentence.contains(token) {
        String::new()
    } else {
        sentence
    }
}

/// Write a run's output: stdout through the CLI's `print!`, which ends the
/// process cleanly when the reader has gone.
fn emit(out: &Printed) -> ExitCode {
    print!("{}", out.stdout);
    eprint!("{}", out.stderr);
    if out.ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// What `dashboard-link` prints, through the output gate.
async fn dashboard_link_output(base: &str, tls: &LinkTls, token: &str) -> Printed {
    let result = fetch_link(base, token, tls)
        .await
        .map(|link| (format!("{link}\n"), "Opens once, from this machine only."));
    gate("dashboard-link", token, result)
}

#[cfg(tp2)]
#[cfg(test)]
#[path = "dashboard_link_tests.rs"]
mod tests;
