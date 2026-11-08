// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! One authenticated API request: native success data on stdout, exit-table
//! errors only on stderr.

use std::fmt::Write as _;
use std::future::Future;
use std::io::{Read, Write};
use std::process::ExitCode;

use mcp_gateway::cli::api::{ApiArgs, ApiMethod};
use mcp_gateway::cli::redact;
use serde_json::Value;

use super::dashboard_link::{
    AdminCallError, AdminFailureKind, AdminResponse, LinkTls, TOKEN_ENV, TokenError,
    admin_call_url, check_target, dashboard_link_base, gateway_reason, read_token,
};

const BODY_LIMIT: u64 = 16 * 1024 * 1024;

const UNCERTAIN_MESSAGE: &str = "The gateway may have applied this change.";
const UNCERTAIN_REMEDY: &str =
    "Inspect the gateway state before retrying; this command did not retry.";
const UNSAFE_BODY_MESSAGE: &str = "The response could not be printed safely.";
const UNSAFE_BODY_REMEDY: &str = "The response was received but could not be printed safely; inspect the gateway state before sending the request again.";
const PROTOCOL_MESSAGE: &str = "The gateway returned an invalid response.";
const PROTOCOL_REMEDY: &str = "Check the gateway response against UI API 1.";

/// Exit table E. Each kind has one process code, independent of HTTP status.
/// What an error becomes when its rendering would still contain the token.
const UNPRINTABLE_ERROR: &str =
    "error: The error report could not be printed without exposing the credential.\n";

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) enum ApiExit {
    Ok,
    LocalFailure,
    Usage,
    AuthRefused,
    NotFound,
    Network,
    Gateway,
    #[allow(dead_code, reason = "reserved by the shared exit table")]
    Declined,
    UncertainOutcome,
    #[allow(dead_code, reason = "reserved by the shared exit table")]
    Interrupted,
}

impl ApiExit {
    pub(crate) const fn code(self) -> u8 {
        match self {
            Self::Ok => 0,
            Self::LocalFailure => 1,
            Self::Usage => 2,
            Self::AuthRefused => 3,
            Self::NotFound => 4,
            Self::Network => 5,
            Self::Gateway => 6,
            Self::Declined => 7,
            Self::UncertainOutcome => 8,
            Self::Interrupted => 130,
        }
    }
}

/// A validated request. Deliberately not Debug: it owns the bearer.
pub(crate) struct ApiRequest {
    pub(crate) method: reqwest::Method,
    pub(crate) url: reqwest::Url,
    pub(crate) token: String,
    pub(crate) tls: LinkTls,
    pub(crate) body: Option<Value>,
    pub(crate) if_match: Option<reqwest::header::HeaderValue>,
}

/// Output is captured before printing, so tests need no process globals.
pub(crate) struct ApiOutcome {
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: String,
    pub(crate) exit: ApiExit,
}

struct ApiError {
    kind: ApiExit,
    message: String,
    remedy: String,
    http_status: Option<u16>,
    request_id: Option<String>,
}

impl ApiError {
    fn new(kind: ApiExit, message: impl Into<String>, remedy: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            remedy: remedy.into(),
            http_status: None,
            request_id: None,
        }
    }

    fn outcome(self, json: bool, token: &str) -> ApiOutcome {
        // Redact values before serialization: a token resembling JSON
        // punctuation must never replace JSON syntax.
        let message = redact::text(&self.message, &[token.to_string()]);
        let remedy = redact::text(&self.remedy, &[token.to_string()]);
        let request_id = self
            .request_id
            .map(|id| redact::text(&id, &[token.to_string()]));
        let stderr = if json {
            let error = serde_json::json!({
                "schema_version": 1,
                "error": {
                    "kind": self.kind,
                    "message": message,
                    "remedy": remedy,
                    "http_status": self.http_status,
                    "request_id": request_id,
                },
            });
            format!("{error}\n")
        } else {
            format!("error: {message}\n{remedy}\n")
        };
        // Fixed fields (kind, schema_version, http_status) are never
        // redacted, so a token equal to one of them would still show. Then
        // print one fixed token-free sentence instead of the report, or
        // nothing if even that sentence contains the token.
        let stderr = if !token.is_empty() && stderr.contains(token) {
            if UNPRINTABLE_ERROR.contains(token) {
                String::new()
            } else {
                UNPRINTABLE_ERROR.to_string()
            }
        } else {
            stderr
        };
        ApiOutcome {
            stdout: Vec::new(),
            stderr,
            exit: self.kind,
        }
    }
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
        error.outcome(args.json, redaction)
    } else {
        match dashboard_link_base(
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
            Err(message) => ApiError::new(
                ApiExit::Usage,
                message,
                "Check the gateway settings, then retry.",
            )
            .outcome(args.json, redaction),
        }
    };
    ExitCode::from(
        write_outcome(
            &outcome,
            args.json,
            redaction,
            &mut std::io::stdout().lock(),
            &mut std::io::stderr().lock(),
        )
        .code(),
    )
}

/// Keep output failures in the same error sink as all other API failures.
pub(crate) fn write_outcome(
    outcome: &ApiOutcome,
    json: bool,
    token: &str,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> ApiExit {
    if let Err(error) = stdout.write_all(&outcome.stdout) {
        if error.kind() == std::io::ErrorKind::BrokenPipe {
            return ApiExit::Ok;
        }
        let failure = ApiError::new(
            ApiExit::LocalFailure,
            "Could not write command output.",
            "Check the output destination before repeating the command.",
        )
        .outcome(json, token);
        let _ = stderr.write_all(failure.stderr.as_bytes());
        return failure.exit;
    }
    if stderr.write_all(outcome.stderr.as_bytes()).is_err() {
        return ApiExit::LocalFailure;
    }
    outcome.exit
}

/// Validation completes before send can receive the credential.
pub(crate) async fn run_api_with<F, Fut>(
    args: &ApiArgs,
    base: &str,
    tls: &LinkTls,
    lookup: impl Fn(&str) -> Option<String>,
    stdin: impl FnOnce() -> Result<Vec<u8>, String>,
    send: F,
) -> ApiOutcome
where
    F: FnOnce(ApiRequest) -> Fut,
    Fut: Future<Output = Result<AdminResponse, AdminCallError>>,
{
    let credential = read_token(lookup);
    let redaction = credential.as_deref().unwrap_or_default();
    let method = match method(&args.method, redaction) {
        Ok(method) => method,
        Err(error) => return error.outcome(args.json, redaction),
    };
    let url = match api_url(base, &args.path) {
        Ok(url) => url,
        Err(error) => return error.outcome(args.json, redaction),
    };
    let origin = url.origin().ascii_serialization();
    let token = match credential {
        Ok(token) => token,
        Err(TokenError::Missing) => {
            return ApiError::new(
                ApiExit::AuthRefused,
                "No gateway credential is available.",
                login_remedy(&origin),
            )
            .outcome(args.json, "");
        }
        Err(TokenError::Blank) => {
            return ApiError::new(
                ApiExit::Usage,
                "MCP_GATEWAY_TOKEN is empty.",
                "Unset or replace MCP_GATEWAY_TOKEN, then retry.",
            )
            .outcome(args.json, "");
        }
    };
    let if_match = match args.if_match.as_deref().map(|value| {
        if value.chars().any(char::is_control) {
            return None;
        }
        reqwest::header::HeaderValue::from_str(value).ok()
    }) {
        Some(None) => {
            return ApiError::new(
                ApiExit::Usage,
                "If-Match value is not a valid header value.",
                "Pass the ETag exactly as the gateway returned it.",
            )
            .outcome(args.json, &token);
        }
        Some(Some(value)) => Some(value),
        None => None,
    };
    let body = match read_data(args.data.as_deref(), stdin) {
        Ok(body) => body,
        Err(error) => return error.outcome(args.json, &token),
    };
    let mutation = method != reqwest::Method::GET;
    match send(ApiRequest {
        method,
        url,
        token: token.clone(),
        tls: tls.clone(),
        body,
        if_match,
    })
    .await
    {
        Ok(response) => {
            render_response(&response, &token, args.json, &origin, &args.path, mutation)
        }
        Err(error) => transport_failure(error, mutation, &token).outcome(args.json, &token),
    }
}

fn method(method: &ApiMethod, token: &str) -> Result<reqwest::Method, ApiError> {
    Ok(match method {
        ApiMethod::Get => reqwest::Method::GET,
        ApiMethod::Post => reqwest::Method::POST,
        ApiMethod::Put => reqwest::Method::PUT,
        ApiMethod::Patch => reqwest::Method::PATCH,
        ApiMethod::Delete => reqwest::Method::DELETE,
        ApiMethod::Unsupported(value) => {
            let value = redact::text(value, &[token.to_string()]);
            return Err(ApiError::new(
                ApiExit::Usage,
                format!("Unsupported API method {value:?}."),
                "Use GET, POST, PUT, PATCH or DELETE.",
            ));
        }
    })
}

fn unsafe_target() -> ApiError {
    ApiError::new(
        ApiExit::Usage,
        "Gateway URL must use HTTPS or loopback HTTP.",
        "Use an HTTPS gateway URL or a loopback HTTP URL.",
    )
}

fn unsafe_path() -> ApiError {
    ApiError::new(
        ApiExit::Usage,
        "API path is outside the unchanged /ui/api/ boundary.",
        "Use an unchanged relative path beginning /ui/api/.",
    )
}

/// Judge the same WHATWG-normalised URL the transport will send.
fn api_url(base: &str, path: &str) -> Result<reqwest::Url, ApiError> {
    check_target(base).map_err(|_| unsafe_target())?;
    let base = reqwest::Url::parse(base).map_err(|_| unsafe_target())?;
    if !matches!(base.path(), "" | "/") || base.query().is_some() || base.fragment().is_some() {
        return Err(ApiError::new(
            ApiExit::Usage,
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

fn read_data(
    data: Option<&str>,
    stdin: impl FnOnce() -> Result<Vec<u8>, String>,
) -> Result<Option<Value>, ApiError> {
    let Some(data) = data else { return Ok(None) };
    let data = if data == "-" {
        stdin().map_err(|_| {
            ApiError::new(
                ApiExit::LocalFailure,
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
                ApiError::new(
                    ApiExit::LocalFailure,
                    format!("Could not read request body from {path}."),
                    format!("Make {path} readable, then retry."),
                )
            })?
    } else {
        data.as_bytes().to_vec()
    };
    if data.len() as u64 > BODY_LIMIT {
        return Err(ApiError::new(
            ApiExit::Usage,
            "Request body exceeds 16 MiB.",
            "Send a smaller body.",
        ));
    }
    serde_json::from_slice(&data).map(Some).map_err(|_| {
        ApiError::new(
            ApiExit::Usage,
            "Request body is not valid JSON.",
            "Correct the JSON or select the body's actual Content-Type.",
        )
    })
}

fn login_remedy(origin: &str) -> String {
    format!("Run mcp-gateway login --gateway {origin}, then retry.")
}

fn transport_failure(error: AdminCallError, mutation: bool, token: &str) -> ApiError {
    let mut failure = match error.kind {
        AdminFailureKind::Target => unsafe_target(),
        AdminFailureKind::LocalIo | AdminFailureKind::Settings => ApiError::new(
            if error.kind == AdminFailureKind::LocalIo {
                ApiExit::LocalFailure
            } else {
                ApiExit::Usage
            },
            error.detail,
            "Check the gateway hostname, CA and client identity files, then retry.",
        ),
        AdminFailureKind::Dns => ApiError::new(
            ApiExit::Network,
            "Gateway host could not be resolved.",
            "Check the gateway hostname and DNS settings, then retry.",
        ),
        AdminFailureKind::Connect => ApiError::new(
            ApiExit::Network,
            "Could not connect to the gateway.",
            "Check the gateway address and listener, then retry.",
        ),
        AdminFailureKind::Tls => ApiError::new(
            ApiExit::Network,
            "Gateway TLS verification failed.",
            "Check the gateway hostname, CA and client identity files, then retry.",
        ),
        AdminFailureKind::ResponseTooLarge => ApiError::new(
            if mutation {
                ApiExit::UncertainOutcome
            } else {
                ApiExit::Network
            },
            "Gateway response exceeded 16 MiB.",
            "Narrow the request or read the data in smaller pages.",
        ),
        AdminFailureKind::ResponseLost if mutation => ApiError::new(
            ApiExit::UncertainOutcome,
            UNCERTAIN_MESSAGE,
            UNCERTAIN_REMEDY,
        ),
        AdminFailureKind::ResponseLost => ApiError::new(
            ApiExit::Network,
            "Gateway response was interrupted.",
            "Repeat the read request.",
        ),
    };
    failure.http_status = error.status.map(|s| s.as_u16());
    failure.request_id = error.request_id.and_then(|id| safe_text(&id, token));
    failure
}

/// Only bounded, single-line diagnostic values from known fields are shown.
fn safe_text(text: &str, token: &str) -> Option<String> {
    let text = redact::text(text, &[token.to_string()]);
    (!text.is_empty() && text.len() <= 4096 && !text.chars().any(char::is_control)).then_some(text)
}

fn gateway_code(body: &Value) -> Option<String> {
    let value = body
        .get("error")
        .and_then(|error| error.get("code"))
        .or_else(|| body.get("error").filter(|error| error.is_string()));
    match value {
        Some(Value::Number(code)) => Some(code.to_string()),
        Some(Value::String(code))
            if !code.is_empty()
                && code.len() <= 128
                && code
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.')) =>
        {
            Some(code.clone())
        }
        _ => None,
    }
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

fn known_not_run(status: reqwest::StatusCode, body: &Value) -> bool {
    body["disposition"].as_str() == Some("not_run")
        || (status == reqwest::StatusCode::SERVICE_UNAVAILABLE
            && body["jsonrpc"].as_str() == Some("2.0")
            && body["error"]["code"].as_i64() == Some(-32003)
            && body["error"]["message"].is_string()
            && body.get("id") == Some(&Value::Null))
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
    path: &str,
    mutation: bool,
) -> Option<ApiError> {
    let status = response.status;
    let reason = gateway_reason(body).and_then(|reason| safe_text(reason, token));
    let code = gateway_code(body);
    let disposition = body["disposition"].as_str();
    let explicit_uncertainty = disposition == Some("may_have_run")
        || matches!(code.as_deref(), Some("state_uncertain" | "may_have_run"));
    let not_run = known_not_run(status, body) && !explicit_uncertainty;
    let ambiguous = mutation && status.is_server_error() && !not_run && !explicit_uncertainty;
    let mut failure = if explicit_uncertainty || ambiguous {
        ApiError::new(
            ApiExit::UncertainOutcome,
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
        ApiError::new(
            ApiExit::Gateway,
            "The gateway API version is unsupported.",
            "Use a CLI and gateway that support the same UI API version.",
        )
    } else if status.is_success() && not_run {
        ApiError::new(
            ApiExit::Gateway,
            reason
                .as_deref()
                .unwrap_or("The gateway failed before running the operation."),
            "Resolve the gateway error, then retry.",
        )
    } else if status.is_success() {
        return None;
    } else {
        let (kind, fallback, remedy) =
            http_refusal(response, code.as_deref(), origin, path, token, not_run);
        ApiError::new(kind, reason.as_deref().unwrap_or(fallback), remedy)
    };
    if !ambiguous
        && let Some(code) = code.and_then(|code| safe_text(&code, token))
        && code != failure.message
    {
        let _ = write!(failure.remedy, " Gateway reason: {code}.");
    }
    if failure.kind == ApiExit::UncertainOutcome
        && let Some(recovery) = body["recovery"]
            .as_str()
            .and_then(|text| safe_text(text, token))
    {
        let _ = write!(failure.remedy, " {recovery}");
    }
    if status == reqwest::StatusCode::NOT_FOUND
        && failure.kind == ApiExit::NotFound
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
    token: &str,
    not_run: bool,
) -> (ApiExit, &'static str, String) {
    match response.status {
        reqwest::StatusCode::UNAUTHORIZED => (
            ApiExit::AuthRefused,
            "The gateway rejected this credential.",
            login_remedy(origin),
        ),
        reqwest::StatusCode::FORBIDDEN => (
            ApiExit::AuthRefused,
            "This credential is not permitted to perform this operation.",
            format!(
                "Use an entitled credential; run mcp-gateway login --gateway {origin} with an account permitted to perform this operation, then retry."
            ),
        ),
        reqwest::StatusCode::NOT_FOUND => (
            ApiExit::NotFound,
            "API path was not found.",
            "Check the path against docs/api/stable-ui-routes.md.".to_string(),
        ),
        reqwest::StatusCode::CONFLICT if code == Some("name_taken") => (
            ApiExit::Gateway,
            PROTOCOL_MESSAGE,
            "Choose an unused key name, then retry.".to_string(),
        ),
        reqwest::StatusCode::CONFLICT if code == Some("stale") => {
            let name = path
                .strip_prefix("/ui/api/capabilities/")
                .and_then(|rest| rest.split(['/', '?']).next())
                .unwrap_or("x");
            let name = redact::text(name, &[token.to_string()]);
            (
                ApiExit::Gateway,
                PROTOCOL_MESSAGE,
                format!(
                    "Read capability {name:?} again and reapply the edit using its current revision."
                ),
            )
        }
        reqwest::StatusCode::PRECONDITION_REQUIRED => (
            ApiExit::Gateway,
            PROTOCOL_MESSAGE,
            "Send the request with If-Match set to the current revision.".to_string(),
        ),
        reqwest::StatusCode::UNPROCESSABLE_ENTITY => (
            ApiExit::Gateway,
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
                ApiExit::Gateway,
                PROTOCOL_MESSAGE,
                format!("Wait for the gateway's Retry-After interval{interval} before retrying."),
            )
        }
        _ if response.status.is_server_error() && not_run => (
            ApiExit::Gateway,
            "The gateway failed before running the operation.",
            "Resolve the gateway error, then retry.".to_string(),
        ),
        _ => (
            ApiExit::Gateway,
            PROTOCOL_MESSAGE,
            PROTOCOL_REMEDY.to_string(),
        ),
    }
}

fn object_entry_count(value: &Value) -> usize {
    match value {
        Value::Object(entries) => {
            entries.len() + entries.values().map(object_entry_count).sum::<usize>()
        }
        Value::Array(items) => items.iter().map(object_entry_count).sum(),
        _ => 0,
    }
}

fn render_response(
    response: &AdminResponse,
    token: &str,
    json_output: bool,
    origin: &str,
    path: &str,
    mutation: bool,
) -> ApiOutcome {
    let mut json = serde_json::from_slice::<Value>(&response.body).ok();
    if let Some(error) = gateway_failure(
        response,
        json.as_ref().unwrap_or(&Value::Null),
        token,
        origin,
        path,
        mutation,
    ) {
        return error.outcome(json_output, token);
    }
    let (stdout, stderr) = if let Some(body) = &mut json {
        let entries = object_entry_count(body);
        redact::json(body, &[token.to_string()]);
        if object_entry_count(body) < entries {
            return ApiError::new(
                ApiExit::LocalFailure,
                UNSAFE_BODY_MESSAGE,
                UNSAFE_BODY_REMEDY,
            )
            .outcome(json_output, token);
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
                return ApiError::new(
                    ApiExit::LocalFailure,
                    UNSAFE_BODY_MESSAGE,
                    UNSAFE_BODY_REMEDY,
                )
                .outcome(json_output, token);
            }
        };
        (
            stdout,
            redact::text(
                &format!(
                    "api: the gateway answered {} with a non-JSON body\n",
                    response.status
                ),
                &[token.to_string()],
            ),
        )
    };
    ApiOutcome {
        stdout,
        stderr,
        exit: ApiExit::Ok,
    }
}
