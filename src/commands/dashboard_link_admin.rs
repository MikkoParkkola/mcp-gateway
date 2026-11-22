// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The admin transport shared by `dashboard-link`, `events` and `api`: one
//! request to a gateway's admin API under the target and TLS policy, and its
//! answer or error, redacted.

use std::path::Path;

use super::super::cli_exit::{
    CliError, CliExit, PROTOCOL_MESSAGE, PROTOCOL_REMEDY, Request, UNCERTAIN_MESSAGE,
    UNCERTAIN_REMEDY, UNSAFE_BODY_MESSAGE, UNSAFE_BODY_REMEDY, status_kind, token_remedy,
    transport_failure,
};
use super::{LinkTls, check_target};

/// The remedy for a 404 to a command whose route the gateway may lack (design D4).
pub(crate) const UNSUPPORTED_REMEDY: &str =
    "Check that the gateway supports this command (update the gateway or the CLI), then retry.";

/// The remedy lines that differ per command (design D4).
pub(crate) struct Remedies {
    /// The origin the token sentences name: scheme, host and port only (see [`origin_of`]).
    pub(crate) origin: String,
    /// The remedy for a 404.
    pub(crate) not_found: String,
    /// The remedy for an answer lost to a read.
    pub(crate) lost_read: &'static str,
}

/// The origin of `base` as api names it in remedies, so userinfo, a path or a query token in `--url` never
/// reaches stderr; a fixed phrase when `base` has no such origin.
pub(crate) fn origin_of(base: &str) -> String {
    reqwest::Url::parse(base)
        .ok()
        .map(|url| url.origin())
        .filter(url::Origin::is_tuple)
        .map_or_else(
            || "the configured gateway".to_string(),
            |origin| origin.ascii_serialization(),
        )
}

impl Remedies {
    /// A read's remedies for the gateway at `base`.
    pub(crate) fn read(base: &str) -> Self {
        Self {
            origin: origin_of(base),
            not_found: UNSUPPORTED_REMEDY.to_string(),
            lost_read: "Repeat the read request.",
        }
    }
}

/// Ask the gateway at `base` for a fresh link. Not a mutation (design D3): a retry mints another link.
///
/// # Errors
///
/// The failure on the shared table; an answer with no link is a protocol error (6).
pub(crate) async fn fetch_link(base: &str, token: &str, tls: &LinkTls) -> Result<String, CliError> {
    let remedies = Remedies {
        lost_read: "Repeat the request; each run mints a new one-time link.",
        ..Remedies::read(base)
    };
    let body = admin_call(
        reqwest::Method::POST,
        base,
        "/ui/api/dashboard-link",
        token,
        tls,
        Request::Read,
        &remedies,
    )
    .await?;
    body["link"]
        .as_str()
        .map(ToString::to_string)
        .ok_or_else(|| CliError::new(CliExit::Gateway, PROTOCOL_MESSAGE, PROTOCOL_REMEDY))
}

/// One admin request to the gateway at `base` (design D2): the JSON answer of a success, redacted.
///
/// # Errors
///
/// The failure on the shared table: a transport failure with api's messages, a refusal with D4's, a success
/// without a JSON body (api's protocol sentences, or the uncertain-outcome ones for a mutation), or a redaction
/// that would lose an entry (api's unsafe-body sentences). Every one prints through `CliError::outcome`.
pub(crate) async fn admin_call(
    method: reqwest::Method,
    base: &str,
    path: &str,
    token: &str,
    tls: &LinkTls,
    request: Request,
    remedies: &Remedies,
) -> Result<serde_json::Value, CliError> {
    let endpoint = format!("{}{path}", base.trim_end_matches('/'));
    let sent = send_admin_request(
        method,
        &endpoint,
        token,
        tls,
        None,
        None,
        &AdminClientOptions::default(),
    )
    .await;
    let response = match sent {
        Ok(response) => read_admin_response(response, &endpoint, tls).await,
        Err(error) => Err(error),
    }
    .map_err(|error| transport(error, request, token, remedies, tls))?;
    if let Some(refused) = refusal(&response, request, remedies) {
        return Err(refused);
    }
    let mut body: serde_json::Value = serde_json::from_slice(&response.body).unwrap_or_default();
    if body.is_null() {
        return Err(match request {
            Request::Read => CliError::new(CliExit::Gateway, PROTOCOL_MESSAGE, PROTOCOL_REMEDY),
            // A 2xx without a usable body cannot tell what the replay did.
            Request::Mutation => CliError::new(
                CliExit::UncertainOutcome,
                UNCERTAIN_MESSAGE,
                UNCERTAIN_REMEDY,
            ),
        });
    }
    if !redact_body(&mut body, token) {
        return Err(CliError::new(
            CliExit::LocalFailure,
            UNSAFE_BODY_MESSAGE,
            UNSAFE_BODY_REMEDY,
        ));
    }
    Ok(body)
}

/// api's transport failure with D4's command differences: a lost answer to a read takes the command's remedy, an
/// oversized answer to a mutation (which may have run) takes the uncertain-outcome sentences, and an https call
/// names the TLS flags it did not pass.
pub(crate) fn transport(
    error: AdminCallError,
    request: Request,
    token: &str,
    remedies: &Remedies,
    tls: &LinkTls,
) -> CliError {
    let kind = error.kind;
    let mut failure = transport_failure(error, request, token);
    match (kind, request) {
        (AdminFailureKind::ResponseLost, Request::Read) => {
            failure.remedy = remedies.lost_read.to_string();
        }
        (AdminFailureKind::ResponseTooLarge, Request::Mutation) => {
            failure.message = UNCERTAIN_MESSAGE.to_string();
            failure.remedy = UNCERTAIN_REMEDY.to_string();
        }
        _ => {}
    }
    // The flags a failed https call did not pass, as the commands said before the shared shape (fixed text: the
    // gate is unchanged). A settings failure prints its detail, which already carries them.
    if matches!(
        kind,
        AdminFailureKind::Dns
            | AdminFailureKind::Connect
            | AdminFailureKind::Tls
            | AdminFailureKind::ResponseLost
    ) {
        for hint in missing_tls_flags(&remedies.origin, tls) {
            failure.remedy.push(' ');
            failure.remedy.push_str(&hint[..1].to_uppercase());
            failure.remedy.push_str(&hint[1..]);
            failure.remedy.push('.');
        }
    }
    failure
}

/// D4's refusal for an answer `status_kind` fails: "The gateway answered HTTP <number>: <reason>" plus the
/// Retry-After part (the number only: a reason phrase could equal the token), with the remedy of its kind.
/// `None` for a success.
pub(crate) fn refusal(
    response: &AdminResponse,
    request: Request,
    remedies: &Remedies,
) -> Option<CliError> {
    let parsed = serde_json::from_slice::<serde_json::Value>(&response.body);
    let kind = status_kind(
        response.status,
        parsed.as_ref().unwrap_or(&serde_json::Value::Null),
        request,
    )?;
    // api's safe_text bounds: a reason holding a control character (a newline, a terminal escape) or over 4 KiB
    // is named, never printed; the token is redacted later, by the gate.
    let reason = match &parsed {
        Ok(body) => match gateway_reason(body) {
            None | Some("") => "no reason given",
            Some(reason) if reason.len() > 4096 || reason.chars().any(char::is_control) => {
                "its reason cannot be printed"
            }
            Some(reason) => reason,
        },
        Err(_) => "its error body is not JSON",
    };
    let wait = match response.headers.get(reqwest::header::RETRY_AFTER) {
        None => String::new(),
        Some(value) => match value
            .to_str()
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
        {
            Some(secs) => format!("; retry after {secs} s"),
            None => "; retry after: unreadable".to_owned(),
        },
    };
    let origin = &remedies.origin;
    let remedy = match kind {
        CliExit::AuthRefused if response.status == reqwest::StatusCode::FORBIDDEN => {
            format!("Use a token permitted to perform this operation for {origin}, then retry.")
        }
        CliExit::AuthRefused => token_remedy(origin),
        CliExit::NotFound => remedies.not_found.clone(),
        CliExit::UncertainOutcome => UNCERTAIN_REMEDY.to_string(),
        _ => "Resolve the gateway error, then retry.".to_string(),
    };
    let mut failure = CliError::new(
        kind,
        format!(
            "The gateway answered HTTP {}: {reason}{wait}",
            response.status.as_u16()
        ),
        remedy,
    );
    failure.http_status = Some(response.status.as_u16());
    Some(failure)
}

/// Redact the token out of `body` with the shared redactor. `false` when the
/// redaction lost an entry (a key renamed onto another), so the body can no
/// longer be printed faithfully. Shared with the api command's success path
/// (approved by the lead on 2026-11-16), so the refusal lives in one place.
pub(crate) fn redact_body(body: &mut serde_json::Value, token: &str) -> bool {
    let entries = object_entry_count(body);
    mcp_gateway::cli::redact::json(body, &[token.to_string()]);
    object_entry_count(body) == entries
}

fn object_entry_count(value: &serde_json::Value) -> usize {
    match value {
        serde_json::Value::Object(entries) => {
            entries.len() + entries.values().map(object_entry_count).sum::<usize>()
        }
        serde_json::Value::Array(items) => items.iter().map(object_entry_count).sum(),
        _ => 0,
    }
}

/// The server's reason across its structured, JSON-RPC and flat error shapes.
pub(crate) fn gateway_reason(body: &serde_json::Value) -> Option<&str> {
    body["message"]
        .as_str()
        .or_else(|| body["error"]["message"].as_str())
        .or_else(|| body["error"].as_str())
        .or_else(|| body["reason"].as_str())
}

/// Classifications retained before transport errors become diagnostic strings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AdminFailureKind {
    Target,
    LocalIo,
    Settings,
    Dns,
    Connect,
    Tls,
    ResponseLost,
    ResponseTooLarge,
}

/// A transport failure and any response metadata received before it failed.
#[derive(Debug)]
pub(crate) struct AdminCallError {
    pub(crate) kind: AdminFailureKind,
    pub(crate) detail: String,
    pub(crate) status: Option<reqwest::StatusCode>,
    pub(crate) request_id: Option<String>,
}

impl AdminCallError {
    fn new(kind: AdminFailureKind, detail: String) -> Self {
        Self {
            kind,
            detail,
            status: None,
            request_id: None,
        }
    }
}

impl std::fmt::Display for AdminCallError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.detail)
    }
}

/// The status and unmodified body, including an unsuccessful HTTP answer.
pub(crate) struct AdminResponse {
    pub(crate) status: reqwest::StatusCode,
    pub(crate) headers: reqwest::header::HeaderMap,
    pub(crate) body: Vec<u8>,
}

pub(crate) struct AdminClientOptions {
    pub(crate) connect_timeout: std::time::Duration,
    /// The whole request's limit: 30 s for a buffered call; `None` for a
    /// streamed one, whose caller keeps its own deadlines.
    pub(crate) total: Option<std::time::Duration>,
}

impl Default for AdminClientOptions {
    fn default() -> Self {
        Self {
            connect_timeout: std::time::Duration::from_secs(10),
            total: Some(std::time::Duration::from_secs(30)),
        }
    }
}

/// A request body: JSON, or a capability's YAML sent as its bytes.
#[derive(PartialEq)]
pub(crate) enum AdminBody {
    Json(serde_json::Value),
    Yaml(Vec<u8>),
}

/// Prints a YAML body's size only: a capability may hold a credential
/// reference, so its text never reaches a log or a failed assertion.
impl std::fmt::Debug for AdminBody {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json(value) => formatter.debug_tuple("Json").field(value).finish(),
            Self::Yaml(bytes) => formatter
                .debug_struct("Yaml")
                .field("bytes", &bytes.len())
                .finish(),
        }
    }
}

/// Send the exact URL the caller validated, optionally carrying a body.
///
/// # Errors
///
/// A refused target, TLS setup failure, or failure to send or read the answer.
pub(crate) async fn admin_call_url(
    method: reqwest::Method,
    endpoint: reqwest::Url,
    token: &str,
    tls: &LinkTls,
    body: Option<&AdminBody>,
    if_match: Option<&reqwest::header::HeaderValue>,
) -> Result<AdminResponse, AdminCallError> {
    admin_call_url_with_options(
        method,
        endpoint,
        token,
        tls,
        body,
        if_match,
        &AdminClientOptions::default(),
    )
    .await
}

pub(crate) async fn admin_call_url_with_options(
    method: reqwest::Method,
    endpoint: reqwest::Url,
    token: &str,
    tls: &LinkTls,
    body: Option<&AdminBody>,
    if_match: Option<&reqwest::header::HeaderValue>,
    options: &AdminClientOptions,
) -> Result<AdminResponse, AdminCallError> {
    let response = send_admin_request(
        method,
        endpoint.as_str(),
        token,
        tls,
        body,
        if_match,
        options,
    )
    .await?;
    read_admin_response(response, endpoint.as_str(), tls).await
}

async fn read_admin_response(
    mut response: reqwest::Response,
    endpoint: &str,
    tls: &LinkTls,
) -> Result<AdminResponse, AdminCallError> {
    let status = response.status();
    let headers = response.headers().clone();
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| AdminCallError {
        kind: AdminFailureKind::ResponseLost,
        detail: transport_error(endpoint, error, tls),
        status: Some(status),
        request_id: headers
            .get("x-request-id")
            .and_then(|value| value.to_str().ok())
            .map(ToString::to_string),
    })? {
        if chunk.len() > 16 * 1024 * 1024 - body.len() {
            return Err(AdminCallError {
                kind: AdminFailureKind::ResponseTooLarge,
                detail: "Gateway response exceeded 16 MiB.".to_string(),
                status: Some(status),
                request_id: headers
                    .get("x-request-id")
                    .and_then(|value| value.to_str().ok())
                    .map(ToString::to_string),
            });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(AdminResponse {
        status,
        headers,
        body,
    })
}

/// The live answer of a streamed admin request: status and headers, and the
/// body as chunks. A body read error carries the response metadata, as a
/// buffered read's does.
pub(crate) struct AdminStream {
    pub(crate) status: reqwest::StatusCode,
    pub(crate) headers: reqwest::header::HeaderMap,
    pub(crate) body: futures::stream::BoxStream<'static, Result<bytes::Bytes, AdminCallError>>,
}

/// Send a streamed admin request: the same target check, client and TLS
/// policy as a buffered call, `options.total` deciding whether a total limit
/// applies, and the body left unread for the caller.
///
/// # Errors
///
/// A refused target, TLS setup failure, or failure to send.
pub(crate) async fn admin_stream_url(
    method: reqwest::Method,
    endpoint: reqwest::Url,
    token: &str,
    tls: &LinkTls,
    options: &AdminClientOptions,
) -> Result<AdminStream, AdminCallError> {
    use futures::StreamExt;
    let response =
        send_admin_request(method, endpoint.as_str(), token, tls, None, None, options).await?;
    let status = response.status();
    let headers = response.headers().clone();
    let request_id = headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string);
    let (endpoint, tls) = (endpoint.to_string(), tls.clone());
    let body = response
        .bytes_stream()
        .map(move |chunk| {
            chunk.map_err(|error| AdminCallError {
                kind: AdminFailureKind::ResponseLost,
                detail: transport_error(&endpoint, error, &tls),
                status: Some(status),
                request_id: request_id.clone(),
            })
        })
        .boxed();
    Ok(AdminStream {
        status,
        headers,
        body,
    })
}

/// Share target checks and TLS policy across admin callers.
async fn send_admin_request(
    method: reqwest::Method,
    endpoint: &str,
    token: &str,
    tls: &LinkTls,
    body: Option<&AdminBody>,
    if_match: Option<&reqwest::header::HeaderValue>,
    options: &AdminClientOptions,
) -> Result<reqwest::Response, AdminCallError> {
    check_target(endpoint)
        .map_err(|detail| AdminCallError::new(AdminFailureKind::Target, detail))?;
    // Direct, never through an environment proxy: an HTTP_PROXY would carry the
    // credential off this machine even to a loopback URL. No redirects either:
    // `check_target` vetted only this URL, and a same-host, same-port hop
    // (https to http) would keep the bearer.
    let mut builder = reqwest::Client::builder()
        .connect_timeout(options.connect_timeout)
        .no_proxy()
        .retry(reqwest::retry::never())
        .redirect(reqwest::redirect::Policy::none());
    // A named CA is the only root (#1832); the test roots join only the
    // default roots, so a named CA replaces them too.
    builder = match &tls.ca {
        Some(ca) => builder.tls_certs_only(read_roots(ca)?),
        None => crate::debug_trust_roots::extra_roots(builder),
    };
    if let Some((cert, key)) = &tls.identity {
        builder = builder.identity(read_identity(cert, key)?);
    }
    let client = builder.build().map_err(|error| {
        AdminCallError::new(
            AdminFailureKind::Settings,
            format!("could not build the HTTP client: {error}"),
        )
    })?;
    let mut request = client.request(method, endpoint).bearer_auth(token);
    if let Some(total) = options.total {
        request = request.timeout(total);
    }
    match body {
        Some(AdminBody::Json(value)) => request = request.json(value),
        // The web shell's own type for these routes.
        Some(AdminBody::Yaml(bytes)) => {
            request = request
                .header(reqwest::header::CONTENT_TYPE, "application/x-yaml")
                .body(bytes.clone());
        }
        None => {}
    }
    if let Some(value) = if_match {
        request = request.header(reqwest::header::IF_MATCH, value);
    }
    request.send().await.map_err(|error| {
        AdminCallError::new(
            send_failure_kind(&error),
            transport_error(endpoint, error, tls),
        )
    })
}

/// Connect errors precede HTTP dispatch; other send failures may follow it.
fn send_failure_kind(error: &reqwest::Error) -> AdminFailureKind {
    if error.is_builder() {
        return AdminFailureKind::Settings;
    }
    if error.is_dns() {
        return AdminFailureKind::Dns;
    }
    if !error.is_connect() {
        return AdminFailureKind::ResponseLost;
    }
    if tls_in_chain(std::error::Error::source(error)) {
        return AdminFailureKind::Tls;
    }
    AdminFailureKind::Connect
}

/// Whether a rustls error sits among `first` and its causes. An `io::Error`'s `source()` skips the error it wraps
/// (it returns that error's own source), so the walk steps into an `io::Error` through `get_ref` and into anything
/// else through `source()`: one path, each node once. A real handshake failure nests two `io::Error`s (hyper's
/// `Connect` error, `io::Error(Other)`, `io::Error(InvalidData)`, rustls `InvalidCertificate`) that `source()` alone
/// never reaches.
fn tls_in_chain(first: Option<&(dyn std::error::Error + 'static)>) -> bool {
    // A step bound stops a chain whose source() loops; real chains are under ten deep.
    const MAX_STEPS: usize = 128;
    let mut cause = first;
    for _ in 0..MAX_STEPS {
        let Some(error) = cause else { return false };
        if error.is::<rustls::Error>() {
            return true;
        }
        cause = match error.downcast_ref::<std::io::Error>() {
            Some(io) => io
                .get_ref()
                .map(|inner| inner as &(dyn std::error::Error + 'static)),
            None => error.source(),
        };
    }
    false
}

fn read_file(path: &Path) -> Result<Vec<u8>, AdminCallError> {
    std::fs::read(path).map_err(|error| {
        AdminCallError::new(
            AdminFailureKind::LocalIo,
            format!("could not read {}: {error}", path.display()),
        )
    })
}

/// The CA bundle at `path`, which must hold at least one certificate.
fn read_roots(path: &Path) -> Result<Vec<reqwest::Certificate>, AdminCallError> {
    let roots = reqwest::Certificate::from_pem_bundle(&read_file(path)?).map_err(|error| {
        AdminCallError::new(
            AdminFailureKind::Settings,
            format!("{}: not a PEM certificate bundle ({error})", path.display()),
        )
    })?;
    if roots.is_empty() {
        return Err(AdminCallError::new(
            AdminFailureKind::Settings,
            format!("{}: holds no PEM certificate", path.display()),
        ));
    }
    Ok(roots)
}

/// The client identity from a PEM certificate file and a PEM key file.
fn read_identity(cert: &Path, key: &Path) -> Result<reqwest::Identity, AdminCallError> {
    let mut pem = read_file(cert)?;
    // Two files that each lack a final newline still concatenate to PEM.
    pem.push(b'\n');
    pem.extend(read_file(key)?);
    reqwest::Identity::from_pem(&pem).map_err(|error| {
        AdminCallError::new(
            AdminFailureKind::Settings,
            format!(
                "{} with {}: not a PEM certificate and private key ({error})",
                cert.display(),
                key.display()
            ),
        )
    })
}

/// A transport failure with its causes, and on `https` the TLS material the
/// operator did not give.
fn transport_error(base: &str, error: reqwest::Error, tls: &LinkTls) -> String {
    use std::fmt::Write as _;
    // Neither `--url` nor the error's own request URL may carry userinfo or a
    // query token to the terminal.
    let shown = mcp_gateway::security::sanitize::redact_url_for_diagnostics(base);
    let error = error.without_url();
    let mut message = format!("could not reach the gateway at {shown}: {error}");
    let mut cause = std::error::Error::source(&error);
    while let Some(inner) = cause {
        let _ = write!(message, ": {inner}");
        cause = inner.source();
    }
    for hint in missing_tls_flags(base, tls) {
        message.push_str("; ");
        message.push_str(hint);
    }
    message
}

/// On an `https` target, what to pass for the TLS material the run did not give: the hints a transport failure
/// carries, in its detail and in the commands' remedy (design delta, the lead 2026-11-17).
fn missing_tls_flags(base: &str, tls: &LinkTls) -> Vec<&'static str> {
    let mut hints = Vec::new();
    if base
        .get(..8)
        .is_some_and(|s| s.eq_ignore_ascii_case("https://"))
    {
        if tls.identity.is_none() {
            hints.push(
                "if the listener requires a client certificate \
                 (mtls.require_client_cert), pass --client-cert and --client-key",
            );
        }
        if tls.ca.is_none() {
            hints.push("if its certificate comes from a private CA, pass --ca-cert");
        }
    }
    hints
}

#[cfg(tp2)]
#[cfg(test)]
#[path = "dashboard_link_admin_tests.rs"]
mod tests;
