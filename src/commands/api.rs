// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `mcp-gateway api METHOD PATH`: one request to a running gateway's admin
//! API, authenticated by `MCP_GATEWAY_TOKEN`, printing the gateway's JSON.

use std::future::Future;
use std::io::{Read, Write};
use std::process::ExitCode;

use mcp_gateway::cli::api::{ApiArgs, ApiMethod};

use super::dashboard_link::{
    AdminResponse, LinkTls, TOKEN_ENV, admin_call_url, check_target, dashboard_link_base,
    read_token,
};

const NO_CREDENTIAL: &str =
    "set MCP_GATEWAY_TOKEN, or run `mcp-gateway login` once it ships in this release's second part";

/// The command's exit contract, mapped to process codes in one place.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ApiExit {
    Ok,
    Http,
    Usage,
    Transport,
    Credential,
}

impl ApiExit {
    pub(crate) const fn code(self) -> u8 {
        match self {
            Self::Ok => 0,
            Self::Http => 1,
            Self::Usage => 2,
            Self::Transport => 3,
            Self::Credential => 4,
        }
    }
}

/// The credential's origin, retained for the later `auth status` command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CredentialSource {
    Environment,
    #[allow(dead_code, reason = "keychain profiles arrive with login")]
    Keychain,
}

/// A validated request. Deliberately not `Debug`: it owns the bearer.
pub(crate) struct ApiRequest {
    pub(crate) method: reqwest::Method,
    pub(crate) url: reqwest::Url,
    pub(crate) token: String,
    pub(crate) tls: LinkTls,
    pub(crate) body: Option<serde_json::Value>,
}

/// Output is captured before printing, so tests need no process globals.
pub(crate) struct ApiOutcome {
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: String,
    pub(crate) exit: ApiExit,
}

impl ApiOutcome {
    fn error(exit: ApiExit, message: &str) -> Self {
        Self {
            stdout: Vec::new(),
            stderr: format!("api: {message}\n"),
            exit,
        }
    }

    fn redact_stderr(mut self, token: &str) -> Self {
        if !token.is_empty() {
            self.stderr = self.stderr.replace(token, "[REDACTED]");
        }
        self
    }
}

/// `mcp-gateway api ...`: resolve the gateway like `dashboard-link`, then send
/// the one request through its shared transport.
pub async fn run_api_command(
    args: ApiArgs,
    load: impl FnOnce() -> Result<mcp_gateway::config::Config, String>,
    port_override: Option<u16>,
    host_override: Option<&str>,
) -> ExitCode {
    let token = match read_token(|name| std::env::var(name).ok()) {
        Ok(token) => token,
        Err(_) => {
            eprintln!("api: {NO_CREDENTIAL}");
            return ExitCode::from(ApiExit::Credential.code());
        }
    };
    let outcome = match dashboard_link_base(
        args.url.clone(),
        args.tls.clone(),
        load,
        port_override,
        host_override,
    ) {
        Ok((base, tls)) => {
            run_api_with(
                &args,
                &base,
                &tls,
                |name| (name == TOKEN_ENV).then(|| token.clone()),
                || {
                    let mut input = String::new();
                    std::io::stdin()
                        .read_to_string(&mut input)
                        .map_err(|e| format!("could not read standard input: {e}"))?;
                    Ok(input)
                },
                |request| async move {
                    admin_call_url(
                        request.method,
                        request.url,
                        &request.token,
                        &request.tls,
                        request.body.as_ref(),
                    )
                    .await
                },
            )
            .await
        }
        Err(message) => ApiOutcome::error(ApiExit::Usage, &message).redact_stderr(&token),
    };
    if let Err(error) = std::io::stdout().lock().write_all(&outcome.stdout) {
        if error.kind() == std::io::ErrorKind::BrokenPipe {
            return ExitCode::from(outcome.exit.code());
        }
        eprintln!("api: could not write output: {error}");
        return ExitCode::from(ApiExit::Transport.code());
    }
    eprint!("{}", outcome.stderr);
    ExitCode::from(outcome.exit.code())
}

/// Environment, standard input and transport are explicit seams. Validation
/// completes before `send` can receive the credential.
pub(crate) async fn run_api_with<F, Fut>(
    args: &ApiArgs,
    base: &str,
    tls: &LinkTls,
    lookup: impl Fn(&str) -> Option<String>,
    stdin: impl FnOnce() -> Result<String, String>,
    send: F,
) -> ApiOutcome
where
    F: FnOnce(ApiRequest) -> Fut,
    Fut: Future<Output = Result<AdminResponse, String>>,
{
    let (token, _source) = match read_token(lookup) {
        Ok(token) => (token, CredentialSource::Environment),
        Err(_) => return ApiOutcome::error(ApiExit::Credential, NO_CREDENTIAL),
    };
    let url = match api_url(base, &args.path) {
        Ok(url) => url,
        Err(message) => return ApiOutcome::error(ApiExit::Usage, &message).redact_stderr(&token),
    };
    if let Err(message) = check_target(url.as_str()) {
        return ApiOutcome::error(ApiExit::Transport, &message).redact_stderr(&token);
    }
    let body = match read_data(args.data.as_deref(), stdin) {
        Ok(body) => body,
        Err(message) => return ApiOutcome::error(ApiExit::Usage, &message).redact_stderr(&token),
    };
    let method = match args.method {
        ApiMethod::Get => reqwest::Method::GET,
        ApiMethod::Post => reqwest::Method::POST,
        ApiMethod::Put => reqwest::Method::PUT,
        ApiMethod::Patch => reqwest::Method::PATCH,
        ApiMethod::Delete => reqwest::Method::DELETE,
    };
    match send(ApiRequest {
        method,
        url,
        token: token.clone(),
        tls: tls.clone(),
        body,
    })
    .await
    {
        Ok(response) => render_response(response, &token),
        Err(message) => ApiOutcome::error(ApiExit::Transport, &message),
    }
    .redact_stderr(&token)
}

/// Judge the same WHATWG-normalised URL the transport will send.
fn api_url(base: &str, path: &str) -> Result<reqwest::Url, String> {
    let base = reqwest::Url::parse(base).map_err(|e| format!("invalid gateway base URL: {e}"))?;
    if !matches!(base.path(), "" | "/") || base.query().is_some() || base.fragment().is_some() {
        return Err(
            "the gateway base URL must have no path other than /, query or fragment".into(),
        );
    }
    let url = base
        .join(path)
        .map_err(|e| format!("invalid API path: {e}"))?;
    let encoded = url.path().to_ascii_lowercase();
    if !url.path().starts_with("/ui/api/")
        || &url[url::Position::BeforePath..url::Position::AfterQuery] != path
        || url.fragment().is_some()
        || url.scheme() != base.scheme()
        || url.host() != base.host()
        || url.port_or_known_default() != base.port_or_known_default()
        || encoded.contains("%2f")
        || encoded.contains("%5c")
    {
        return Err(
            "PATH must stay under /ui/api/ on the gateway, without URL normalisation or encoded separators"
                .into(),
        );
    }
    Ok(url)
}

fn read_data(
    data: Option<&str>,
    stdin: impl FnOnce() -> Result<String, String>,
) -> Result<Option<serde_json::Value>, String> {
    let Some(data) = data else { return Ok(None) };
    let data = if data == "-" {
        stdin()?
    } else if let Some(path) = data.strip_prefix('@') {
        std::fs::read_to_string(path)
            .map_err(|e| format!("could not read JSON file {path}: {e}"))?
    } else {
        data.to_string()
    };
    serde_json::from_str(&data)
        .map(Some)
        .map_err(|e| format!("--data must contain JSON: {e}"))
}

/// Redact decoded strings so JSON escaping cannot hide a credential, and a
/// credential that resembles JSON punctuation cannot corrupt the output.
fn redact_json(value: &mut serde_json::Value, token: &str) {
    match value {
        serde_json::Value::String(text) => *text = text.replace(token, "[REDACTED]"),
        serde_json::Value::Array(values) => {
            for value in values {
                redact_json(value, token);
            }
        }
        serde_json::Value::Object(entries) => {
            for (key, mut value) in std::mem::take(entries) {
                redact_json(&mut value, token);
                entries.insert(key.replace(token, "[REDACTED]"), value);
            }
        }
        _ => {}
    }
}

/// Keep a non-JSON response byte-for-byte except for an echoed credential.
fn redact_bytes(bytes: &[u8], token: &str) -> Vec<u8> {
    let mut safe = Vec::new();
    let mut remaining = bytes;
    while let Some(at) = remaining
        .windows(token.len())
        .position(|part| part == token.as_bytes())
    {
        safe.extend_from_slice(&remaining[..at]);
        safe.extend_from_slice(b"[REDACTED]");
        remaining = &remaining[at + token.len()..];
    }
    safe.extend_from_slice(remaining);
    safe
}

fn render_response(response: AdminResponse, token: &str) -> ApiOutcome {
    let status = response.status;
    let mut json = serde_json::from_slice::<serde_json::Value>(&response.body).ok();
    let mut stdout = Vec::new();
    if let Some(body) = &mut json {
        redact_json(body, token);
        stdout = serde_json::to_vec_pretty(body).unwrap_or_default();
        stdout.push(b'\n');
    }
    if status.is_success() {
        return ApiOutcome {
            stdout: if json.is_some() {
                stdout
            } else {
                redact_bytes(&response.body, token)
            },
            stderr: if json.is_some() {
                String::new()
            } else {
                format!("api: the gateway answered {status} with a non-JSON body\n")
            },
            exit: ApiExit::Ok,
        };
    }
    let reason = json
        .as_ref()
        .and_then(|body| body["reason"].as_str().or_else(|| body["error"].as_str()))
        .unwrap_or("no reason given");
    let mut stderr = format!("api: the gateway answered {status}: {reason}\n");
    let exit = match status {
        reqwest::StatusCode::UNAUTHORIZED => {
            stderr.push_str(
                "api: the credential was refused (not recognised, revoked or expired): run `mcp-gateway login` or set MCP_GATEWAY_TOKEN\n",
            );
            ApiExit::Credential
        }
        reqwest::StatusCode::FORBIDDEN => {
            stderr.push_str("api: the credential is valid but may not use this route\n");
            ApiExit::Credential
        }
        _ => ApiExit::Http,
    };
    ApiOutcome {
        stdout,
        stderr,
        exit,
    }
}
