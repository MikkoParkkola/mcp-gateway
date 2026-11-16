// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The admin transport shared by `dashboard-link`, `events` and `api`: one
//! request to a gateway's admin API under the target and TLS policy, and its
//! answer or error, redacted.

use std::path::Path;

use super::{LinkTls, UNSAFE_ANSWER, check_target, token_free};

/// Ask the gateway at `base` for a fresh link.
///
/// # Errors
///
/// A message carrying the gateway's status or the transport failure.
pub(crate) async fn fetch_link(base: &str, token: &str, tls: &LinkTls) -> Result<String, String> {
    let body = admin_call(
        reqwest::Method::POST,
        base,
        "/ui/api/dashboard-link",
        token,
        tls,
    )
    .await?;
    body["link"]
        .as_str()
        .map(ToString::to_string)
        .ok_or_else(|| token_free("the gateway's answer carried no link", token))
}

/// One admin request to the gateway at `base`; the JSON answer of a success,
/// redacted.
///
/// # Errors
///
/// A message carrying the gateway's status and reason, or the transport
/// failure, redacted as a whole (status text included: a token equal to
/// "404" or "OK"), so no caller can print the token from it. The commands'
/// output gate redacts each printed line again.
pub(crate) async fn admin_call(
    method: reqwest::Method,
    base: &str,
    path: &str,
    token: &str,
    tls: &LinkTls,
) -> Result<serde_json::Value, String> {
    admin_call_raw(method, base, path, token, tls)
        .await
        .map_err(|message| token_free(&message, token))
}

async fn admin_call_raw(
    method: reqwest::Method,
    base: &str,
    path: &str,
    token: &str,
    tls: &LinkTls,
) -> Result<serde_json::Value, String> {
    let endpoint = format!("{}{path}", base.trim_end_matches('/'));
    let response = send_admin_request(
        method,
        &endpoint,
        token,
        tls,
        None,
        None,
        &AdminClientOptions::default(),
    )
    .await
    .map_err(|error| error.to_string())?;
    let response = read_admin_response(response, &endpoint, tls)
        .await
        .map_err(|error| match error.kind {
            AdminFailureKind::ResponseTooLarge => "the gateway answer exceeded 16 MiB".to_string(),
            _ => error.to_string(),
        })?;
    let status = response.status;
    let mut body: serde_json::Value = serde_json::from_slice(&response.body).unwrap_or_default();
    if !status.is_success() {
        let reason = gateway_reason(&body).unwrap_or("no reason given");
        return Err(format!("the gateway answered {status}: {reason}"));
    }
    if body.is_null() {
        return Err(format!("the gateway answered {status} with no JSON body"));
    }
    // The answer is redacted here, so every caller (the link included) reads
    // the redacted body.
    if !redact_body(&mut body, token) {
        return Err(UNSAFE_ANSWER.to_string());
    }
    Ok(body)
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

/// Send the exact URL the caller validated, optionally carrying a JSON body.
///
/// # Errors
///
/// A refused target, TLS setup failure, or failure to send or read the answer.
pub(crate) async fn admin_call_url(
    method: reqwest::Method,
    endpoint: reqwest::Url,
    token: &str,
    tls: &LinkTls,
    body: Option<&serde_json::Value>,
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
    body: Option<&serde_json::Value>,
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
    body: Option<&serde_json::Value>,
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
    if let Some(body) = body {
        request = request.json(body);
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
    let mut cause = std::error::Error::source(error);
    while let Some(inner) = cause {
        let tls_error = inner.is::<rustls::Error>()
            || inner
                .downcast_ref::<std::io::Error>()
                .and_then(std::io::Error::get_ref)
                .is_some_and(<dyn std::error::Error + Send + Sync>::is::<rustls::Error>);
        if tls_error {
            return AdminFailureKind::Tls;
        }
        cause = inner.source();
    }
    AdminFailureKind::Connect
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
    if base
        .get(..8)
        .is_some_and(|s| s.eq_ignore_ascii_case("https://"))
    {
        if tls.identity.is_none() {
            message.push_str(
                "; if the listener requires a client certificate \
                 (mtls.require_client_cert), pass --client-cert and --client-key",
            );
        }
        if tls.ca.is_none() {
            message.push_str("; if its certificate comes from a private CA, pass --ca-cert");
        }
    }
    message
}
