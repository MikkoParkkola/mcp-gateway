// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! One authenticated API request: native success data on stdout, exit-table
//! errors only on stderr.

use std::fmt::Write as _;
use std::future::Future;
use std::io::Read;
use std::process::ExitCode;

use mcp_gateway::cli::api::{ApiArgs, ApiMethod};
use mcp_gateway::cli::redact;
use serde_json::Value;

use super::cli_exit::{
    CliError, CliExit, CliOutcome, PROTOCOL_MESSAGE, PROTOCOL_REMEDY, Request, StdoutRule,
    UNCERTAIN_MESSAGE, UNCERTAIN_REMEDY, UNSAFE_BODY_MESSAGE, UNSAFE_BODY_REMEDY, gateway_code,
    known_not_run, resolve_token, safe_text, status_kind, token_remedy, transport_failure,
    unsafe_target,
};
use super::dashboard_link::{
    AdminBody, AdminCallError, AdminResponse, LinkTls, TOKEN_ENV, admin_call_url, check_target,
    dashboard_link_base, gateway_reason, read_token,
};
use crate::gateway::routes;

const BODY_LIMIT: u64 = 16 * 1024 * 1024;

#[path = "api_stream.rs"]
mod stream;

/// A validated request. Deliberately not Debug: it owns the bearer.
pub(crate) struct ApiRequest {
    pub(crate) method: reqwest::Method,
    pub(crate) url: reqwest::Url,
    pub(crate) token: String,
    pub(crate) tls: LinkTls,
    pub(crate) body: Option<AdminBody>,
    pub(crate) if_match: Option<reqwest::header::HeaderValue>,
}

/// Resolve the gateway like dashboard-link, then send one request through
/// the shared transport. Resolution also supplies the origin in remedies.
pub async fn run_api_command(
    args: ApiArgs,
    load: impl FnOnce() -> Result<mcp_gateway::config::Config, String>,
    port_override: Option<u16>,
    host_override: Option<&str>,
) -> ExitCode {
    let token = std::env::var(TOKEN_ENV).ok();
    let redaction = token.as_deref().unwrap_or_default();
    let outcome = if let Err(error) = method(&args.method, redaction) {
        error.outcome(args.json, &[redaction])
    } else {
        match dashboard_link_base(
            args.gateway.url.clone(),
            args.tls.clone(),
            load,
            port_override,
            host_override,
        ) {
            Ok((base, tls)) if stream::streamed(&base, &args.path) => {
                stream::run_production(&args, &base, &tls, token.clone()).await
            }
            Ok((base, tls)) => {
                run_api_with(
                    &args,
                    &base,
                    &tls,
                    |name| {
                        if name == TOKEN_ENV {
                            token.clone()
                        } else {
                            None
                        }
                    },
                    || {
                        let mut input = Vec::new();
                        std::io::stdin()
                            .take(BODY_LIMIT + 1)
                            .read_to_end(&mut input)
                            .map_err(|e| e.to_string())?;
                        Ok(input)
                    },
                    |request| async move {
                        admin_call_url(
                            request.method,
                            request.url,
                            &request.token,
                            &request.tls,
                            request.body.as_ref(),
                            request.if_match.as_ref(),
                        )
                        .await
                    },
                )
                .await
            }
            Err(message) => CliError::new(
                CliExit::Usage,
                message,
                "Check the gateway settings, then retry.",
            )
            .outcome(args.json, &[redaction]),
        }
    };
    super::cli_exit::emit(&outcome, args.json, &[redaction])
}

/// Validation completes before send can receive the credential.
pub(crate) async fn run_api_with<F, Fut>(
    args: &ApiArgs,
    base: &str,
    tls: &LinkTls,
    lookup: impl Fn(&str) -> Option<String>,
    stdin: impl FnOnce() -> Result<Vec<u8>, String>,
    send: F,
) -> CliOutcome
where
    F: FnOnce(ApiRequest) -> Fut,
    Fut: Future<Output = Result<AdminResponse, AdminCallError>>,
{
    let credential = read_token(lookup);
    let redaction = credential.as_deref().unwrap_or_default();
    let method = match method(&args.method, redaction) {
        Ok(method) => method,
        Err(error) => return error.outcome(args.json, &[redaction]),
    };
    let url = match api_url(base, &args.path) {
        Ok(url) => url,
        Err(error) => return error.outcome(args.json, &[redaction]),
    };
    if let Err(error) = stream::check_args(args, &url) {
        return error.outcome(args.json, &[redaction]);
    }
    let origin = url.origin().ascii_serialization();
    let token = match resolve_token(credential, &origin) {
        Ok(token) => token,
        Err(error) => return error.outcome(args.json, &[""]),
    };
    let if_match = match args.if_match.as_deref().map(|value| {
        if value.chars().any(char::is_control) {
            return None;
        }
        reqwest::header::HeaderValue::from_str(value).ok()
    }) {
        Some(None) => {
            return CliError::new(
                CliExit::Usage,
                "If-Match value is not a valid header value.",
                "Pass the revision api GET printed.",
            )
            .outcome(args.json, &[token.as_str()]);
        }
        Some(Some(value)) => Some(value),
        None => None,
    };
    let body = match read_data(args.data.as_deref(), stdin)
        .and_then(|data| data.map(|data| body_of(&method, &url, data)).transpose())
    {
        Ok(body) => body,
        Err(error) => return error.outcome(args.json, &[token.as_str()]),
    };
    let request = if method == reqwest::Method::GET {
        Request::Read
    } else {
        Request::Mutation
    };
    match send(ApiRequest {
        method: method.clone(),
        url,
        token: token.clone(),
        tls: tls.clone(),
        body,
        if_match,
    })
    .await
    {
        Ok(response) => render_response(
            &response,
            &token,
            args.json,
            &origin,
            (&args.path, &method),
            request,
        ),
        Err(error) => {
            transport_failure(error, request, &token).outcome(args.json, &[token.as_str()])
        }
    }
}

/// The api command on its production send, for rows outside `commands` that
/// drive it against a real gateway router (the router's own tests).
#[cfg(test)]
pub(crate) async fn run_api_for_tests(
    args: &ApiArgs,
    base: &str,
    bearer: &str,
    stdin: Vec<u8>,
) -> CliOutcome {
    let lookup = |name: &str| (name == TOKEN_ENV).then(|| bearer.to_owned());
    run_api_with(
        args,
        base,
        &LinkTls::default(),
        lookup,
        move || Ok(stdin),
        |sent| async move {
            let ApiRequest {
                method,
                url,
                token,
                tls,
                body,
                if_match,
            } = sent;
            admin_call_url(method, url, &token, &tls, body.as_ref(), if_match.as_ref()).await
        },
    )
    .await
}

fn method(method: &ApiMethod, token: &str) -> Result<reqwest::Method, CliError> {
    Ok(match method {
        ApiMethod::Get => reqwest::Method::GET,
        ApiMethod::Post => reqwest::Method::POST,
        ApiMethod::Put => reqwest::Method::PUT,
        ApiMethod::Patch => reqwest::Method::PATCH,
        ApiMethod::Delete => reqwest::Method::DELETE,
        ApiMethod::Unsupported(value) => {
            let value = redact::text(value, &[token.to_string()]);
            return Err(CliError::new(
                CliExit::Usage,
                format!("Unsupported API method {value:?}."),
                "Use GET, POST, PUT, PATCH or DELETE.",
            ));
        }
    })
}

fn unsafe_path() -> CliError {
    CliError::new(
        CliExit::Usage,
        "API path is outside the unchanged /ui/api/ boundary.",
        "Use an unchanged relative path beginning /ui/api/.",
    )
}

/// Judge the same WHATWG-normalised URL the transport will send.
fn api_url(base: &str, path: &str) -> Result<reqwest::Url, CliError> {
    check_target(base).map_err(|_| unsafe_target())?;
    let base = reqwest::Url::parse(base).map_err(|_| unsafe_target())?;
    if !matches!(base.path(), "" | "/") || base.query().is_some() || base.fragment().is_some() {
        return Err(CliError::new(
            CliExit::Usage,
            "Gateway URL must have no path, query or fragment.",
            "Use the gateway's origin only, for example https://gateway.example:8443.",
        ));
    }
    let url = base.join(path).map_err(|_| unsafe_path())?;
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
        return Err(unsafe_path());
    }
    Ok(url)
}

/// Whether the router runs a capability save (PUT on one capability, its
/// `?validate` query included) or a validate (POST on its validate route) for
/// `url`: the two routes that take raw YAML. Matched segment by segment against
/// the router's own patterns; a `{name}` segment is one non-empty segment.
fn takes_yaml(method: &reqwest::Method, url: &reqwest::Url) -> bool {
    let route = match *method {
        reqwest::Method::PUT => routes::UI_CAPABILITY,
        reqwest::Method::POST => routes::UI_CAPABILITY_VALIDATE,
        _ => return false,
    };
    matches_route(route, url.path())
}

/// Whether `path` (no query) is one route pattern: as many segments, literal
/// segments equal, a `{name}` segment one non-empty segment.
fn matches_route(route: &str, path: &str) -> bool {
    let want: Vec<&str> = route.split('/').collect();
    let got: Vec<&str> = path.split('/').collect();
    want.len() == got.len()
        && want.iter().zip(&got).all(|(want, got)| {
            if want.starts_with('{') {
                !got.is_empty()
            } else {
                want == got
            }
        })
}

/// The body `data` is sent as: its bytes unchanged on a YAML route, parsed
/// JSON everywhere else.
fn body_of(
    method: &reqwest::Method,
    url: &reqwest::Url,
    data: Vec<u8>,
) -> Result<AdminBody, CliError> {
    if takes_yaml(method, url) {
        return Ok(AdminBody::Yaml(data));
    }
    serde_json::from_slice(&data)
        .map(AdminBody::Json)
        .map_err(|_| {
            CliError::new(
                CliExit::Usage,
                "Request body is not valid JSON.",
                "Send JSON: only the capability save and validate routes take YAML.",
            )
        })
}

/// The `--data` bytes from stdin (`-`), a file (`@path`) or the argument
/// itself, refused above 16 MiB.
fn read_data(
    data: Option<&str>,
    stdin: impl FnOnce() -> Result<Vec<u8>, String>,
) -> Result<Option<Vec<u8>>, CliError> {
    let Some(data) = data else { return Ok(None) };
    let data = if data == "-" {
        stdin().map_err(|_| {
            CliError::new(
                CliExit::LocalFailure,
                "Could not read request body from stdin.",
                "Supply readable request bytes on stdin, then retry.",
            )
        })?
    } else if let Some(path) = data.strip_prefix('@') {
        std::fs::File::open(path)
            .and_then(|file| {
                let mut input = Vec::new();
                file.take(BODY_LIMIT + 1).read_to_end(&mut input)?;
                Ok(input)
            })
            .map_err(|_| {
                CliError::new(
                    CliExit::LocalFailure,
                    format!("Could not read request body from {path}."),
                    format!("Make {path} readable, then retry."),
                )
            })?
    } else {
        data.as_bytes().to_vec()
    };
    if data.len() as u64 > BODY_LIMIT {
        return Err(CliError::new(
            CliExit::Usage,
            "Request body exceeds 16 MiB.",
            "Send a smaller body.",
        ));
    }
    Ok(Some(data))
}

fn response_request_id(body: &Value, response: &AdminResponse, token: &str) -> Option<String> {
    match body.get("request_id") {
        Some(Value::String(id)) => safe_text(id, token),
        Some(Value::Null) => None,
        _ => response
            .headers
            .get("x-request-id")
            .and_then(|id| id.to_str().ok())
            .and_then(|id| safe_text(id, token)),
    }
}

/// Receipt fields are reviewed diagnostics, not an arbitrary body dump.
fn receipt_diagnostic(body: &Value, token: &str) -> Option<String> {
    #[derive(serde::Serialize)]
    struct Receipt {
        name: String,
        revoked: bool,
        revision: String,
    }
    let receipt = body.get("receipt")?;
    let receipt = Receipt {
        name: safe_text(receipt.get("name")?.as_str()?, token)?,
        revoked: receipt.get("revoked")?.as_bool()?,
        revision: safe_text(receipt.get("revision")?.as_str()?, token)?,
    };
    serde_json::to_string(&receipt).ok()
}

fn gateway_failure(
    response: &AdminResponse,
    body: &Value,
    token: &str,
    origin: &str,
    (path, method): (&str, &reqwest::Method),
    request: Request,
) -> Option<CliError> {
    let status = response.status;
    let reason = gateway_reason(body).and_then(|reason| safe_text(reason, token));
    let code = gateway_code(body);
    let disposition = body["disposition"].as_str();
    let explicit_uncertainty = disposition == Some("may_have_run")
        || matches!(code.as_deref(), Some("state_uncertain" | "may_have_run"));
    let not_run = known_not_run(status, body) && !explicit_uncertainty;
    // The kind is the shared decision (design D1); the messages stay api's.
    let kind = status_kind(status, body, request)?;
    let ambiguous = kind == CliExit::UncertainOutcome && !explicit_uncertainty;
    let mut failure = if kind == CliExit::UncertainOutcome {
        CliError::new(
            kind,
            if explicit_uncertainty {
                reason
                    .as_deref()
                    .unwrap_or(if disposition == Some("may_have_run") {
                        "may_have_run"
                    } else {
                        UNCERTAIN_MESSAGE
                    })
            } else {
                UNCERTAIN_MESSAGE
            },
            UNCERTAIN_REMEDY,
        )
    } else if code.as_deref() == Some("unsupported_version") {
        CliError::new(
            kind,
            "The gateway API version is unsupported.",
            "Use a CLI and gateway that support the same UI API version.",
        )
    } else if status.is_success() {
        // A success that status_kind fails is one known not to have run.
        CliError::new(
            kind,
            reason
                .as_deref()
                .unwrap_or("The gateway failed before running the operation."),
            "Resolve the gateway error, then retry.",
        )
    } else {
        let (fallback, remedy) = http_refusal(
            response,
            code.as_deref(),
            origin,
            path,
            method,
            token,
            not_run,
        );
        CliError::new(kind, reason.as_deref().unwrap_or(fallback), remedy)
    };
    if !ambiguous
        && let Some(code) = code.and_then(|code| safe_text(&code, token))
        && code != failure.message
    {
        let _ = write!(failure.remedy, " Gateway reason: {code}.");
    }
    if failure.kind == CliExit::UncertainOutcome
        && let Some(recovery) = body["recovery"]
            .as_str()
            .and_then(|text| safe_text(text, token))
    {
        let _ = write!(failure.remedy, " {recovery}");
    }
    if status == reqwest::StatusCode::NOT_FOUND
        && failure.kind == CliExit::NotFound
        && reason
            .as_deref()
            .is_some_and(|text| text.starts_with("Backend '") || text.starts_with("Backend \""))
    {
        failure.remedy =
            "List gateway backends and choose an existing name before retrying.".to_string();
    }
    if disposition == Some("may_have_run") {
        failure.remedy.push_str(" Disposition: may_have_run.");
        if let Some(receipt) = receipt_diagnostic(body, token) {
            let _ = write!(failure.remedy, " Receipt: {receipt}.");
        }
    }
    failure.http_status = Some(status.as_u16());
    failure.request_id = response_request_id(body, response, token);
    Some(failure)
}

fn http_refusal(
    response: &AdminResponse,
    code: Option<&str>,
    origin: &str,
    path: &str,
    method: &reqwest::Method,
    token: &str,
    not_run: bool,
) -> (&'static str, String) {
    match response.status {
        reqwest::StatusCode::UNAUTHORIZED => (
            "The gateway rejected this credential.",
            token_remedy(origin),
        ),
        reqwest::StatusCode::FORBIDDEN => (
            "This credential is not permitted to perform this operation.",
            format!("Use a token permitted to perform this operation for {origin}, then retry."),
        ),
        reqwest::StatusCode::NOT_FOUND => (
            "API path was not found.",
            "Check the path against docs/api/stable-ui-routes.md.".to_string(),
        ),
        reqwest::StatusCode::CONFLICT if code == Some("name_taken") => (
            PROTOCOL_MESSAGE,
            "Choose an unused key name, then retry.".to_string(),
        ),
        reqwest::StatusCode::CONFLICT if code == Some("stale") => {
            // A stale delete retries the delete on a fresh load; any other
            // stale write redoes its change on the fresh text.
            let remedy = if *method == reqwest::Method::DELETE {
                precondition_remedy(method, path, token)
            } else {
                reload_and_save(path, token)
            };
            (PROTOCOL_MESSAGE, remedy)
        }
        reqwest::StatusCode::PRECONDITION_REQUIRED => {
            (PROTOCOL_MESSAGE, precondition_remedy(method, path, token))
        }
        reqwest::StatusCode::UNPROCESSABLE_ENTITY => (
            PROTOCOL_MESSAGE,
            "Correct the request body using the gateway's validation details.".to_string(),
        ),
        reqwest::StatusCode::TOO_MANY_REQUESTS => {
            let seconds = response
                .headers
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok());
            let interval = seconds.map_or_else(String::new, |s| format!(" ({s} s)"));
            (
                PROTOCOL_MESSAGE,
                format!("Wait for the gateway's Retry-After interval{interval} before retrying."),
            )
        }
        _ if response.status.is_server_error() && not_run => (
            "The gateway failed before running the operation.",
            "Resolve the gateway error, then retry.".to_string(),
        ),
        _ => (PROTOCOL_MESSAGE, PROTOCOL_REMEDY.to_string()),
    }
}

/// Any 428 the recipes below do not fit.
const GENERIC_PRECONDITION: &str = "Send the request with If-Match set to the current revision.";

/// The request's path without its query, redacted: a remedy quotes it back.
fn quoted_path(path: &str, token: &str) -> String {
    redact::text(path.split('?').next().unwrap_or(path), &[token.to_string()])
}

/// Recovery from a stale or missing revision: a fresh load, the change made
/// again on its text, and that load's revision, so a write someone else made
/// in between survives instead of being overwritten.
fn reload_and_save(path: &str, token: &str) -> String {
    let path = quoted_path(path, token);
    format!(
        "Run api GET {path} again, apply your change to the text it returns, and save that with --if-match set to the revision it printed."
    )
}

/// A 428's remedy: a capability save or delete names the load that prints
/// the revision; every other request keeps the generic sentence.
fn precondition_remedy(method: &reqwest::Method, path: &str, token: &str) -> String {
    if !matches_route(
        routes::UI_CAPABILITY,
        path.split('?').next().unwrap_or(path),
    ) {
        return GENERIC_PRECONDITION.to_owned();
    }
    match *method {
        reqwest::Method::PUT => reload_and_save(path, token),
        reqwest::Method::DELETE => {
            let path = quoted_path(path, token);
            format!(
                "Run api GET {path}, confirm it is the version you mean to remove, and delete with --if-match set to the revision it printed."
            )
        }
        _ => GENERIC_PRECONDITION.to_owned(),
    }
}

fn render_response(
    response: &AdminResponse,
    token: &str,
    json_output: bool,
    origin: &str,
    target: (&str, &reqwest::Method),
    request: Request,
) -> CliOutcome {
    let mut json = serde_json::from_slice::<Value>(&response.body).ok();
    if let Some(error) = gateway_failure(
        response,
        json.as_ref().unwrap_or(&Value::Null),
        token,
        origin,
        target,
        request,
    ) {
        return error.outcome(json_output, &[token]);
    }
    let (stdout, mut note) = if let Some(body) = &mut json {
        if !super::dashboard_link::redact_body(body, token) {
            return CliError::new(
                CliExit::LocalFailure,
                UNSAFE_BODY_MESSAGE,
                UNSAFE_BODY_REMEDY,
            )
            .outcome(json_output, &[token]);
        }
        let mut stdout = serde_json::to_vec_pretty(body).unwrap_or_default();
        stdout.push(b'\n');
        (stdout, String::new())
    } else {
        let checked = String::from_utf8_lossy(&response.body);
        let stdout = match std::str::from_utf8(&response.body) {
            Ok(text) => redact::text(text, &[token.to_string()]).into_bytes(),
            Err(_) if token.is_empty() || !checked.contains(token) => response.body.clone(),
            Err(_) => {
                return CliError::new(
                    CliExit::LocalFailure,
                    UNSAFE_BODY_MESSAGE,
                    UNSAFE_BODY_REMEDY,
                )
                .outcome(json_output, &[token]);
            }
        };
        (
            stdout,
            format!(
                "api: the gateway answered {} with a non-JSON body\n",
                response.status
            ),
        )
    };
    // api's body already passed its entry-loss check above; the note is redacted and gated by `success`.
    // The CLI prints no headers, so the revision a conditional write needs is
    // shown here, as the gateway sent it.
    if let Some(revision) = response
        .headers
        .get(reqwest::header::ETAG)
        .and_then(|value| value.to_str().ok())
    {
        let _ = writeln!(
            note,
            "api: revision {revision}; to change this resource, send it with --if-match."
        );
    }
    CliOutcome::success(
        stdout,
        &note,
        json_output,
        &[token],
        StdoutRule::RedactedJsonBody,
    )
}
