// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `POST /ui/api/key-server/audit/lookup-email`: the admin forward lookup. An
//! admin types an email; the key server's retained `token.issued` rows whose
//! keyed `email_hash` matches come back. No reverse table exists: the email
//! is hashed with the installation key for the one request and never stored,
//! logged or echoed.
//!
//! The next page is asked for with a sealed token alone: the token carries the
//! keyed hash, the window and the log position, sealed by the continuation
//! keyring and bound to the credential principal that got it, so the email is
//! sent once and never again.
//!
//! Order matters: admission (gateway-wide admin only), the shared budget, the
//! bounded body, the request's shape, the limit, the key server and log, and
//! only then the email is hashed or the token opened, then the blocking scan.
//! Every refusal that is not about the token comes before the token is
//! opened, so no other answer tells a holder whether a token is genuine.

use std::sync::Arc;

use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, FixedOffset};
use serde::Deserialize;
use serde_json::{Value, json};

use super::reader::{Cursor, Limits, Line, read_page};
use super::{DEFAULT_LIMIT, MAX_LIMIT, PAGE_SCAN_BYTES, blocking};
use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::router::Charge;
use crate::gateway::ui::AppState;
use crate::gateway::ui::admin_audit::attach_lookup;
use crate::gateway::ui::errors::flat_error;
use crate::gateway::ui::guard::Guard;
use crate::key_server::email_hash::{self, EmailHashKey};
use crate::protocol::continuation::Payload;

/// The most bytes of request body read; a lookup carries an email, a cursor
/// and two timestamps.
const MAX_BODY: usize = 8 * 1024;
/// The longest `from` or `to` accepted: an RFC 3339 time is far shorter.
const MAX_TIME: usize = 64;
/// The longest email accepted, as in RFC 5321.
const MAX_EMAIL: usize = 320;

/// The request body. Unknown fields are refused.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    email: Option<String>,
    limit: Option<usize>,
    cursor: Option<String>,
    from: Option<String>,
    to: Option<String>,
}

/// One refusal of a request that was admitted: fixed words, never the input.
fn refuse(status: StatusCode, message: &'static str) -> Response {
    flat_error(status, message).into_response()
}

fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Stamp the outcome on the request's own audit record: an operation and a
/// fixed outcome, counts, never the email.
fn finish(mut response: Response, outcome: &'static str, results: usize, scanned: u64) -> Response {
    attach_lookup(&mut response, outcome, results, scanned);
    no_store(response)
}

fn parse_time(text: &str) -> Option<DateTime<FixedOffset>> {
    DateTime::parse_from_rfc3339(text).ok()
}

/// A sealed page token lives this long, and a chain of pages from the first
/// one no longer than the ceiling.
const CHAIN_CEILING_SECS: u64 = 900;
/// A token longer than this is refused before anything is decoded.
const PAGE_TOKEN_MAX_LEN: usize = 2048;

/// Everything the next page needs, sealed in the token. No email. No `Debug`:
/// the keyed hash of a person's email is not for a log.
#[derive(serde::Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PageScope {
    pub(super) hash: String,
    pub(super) version: u64,
    pub(super) key_id: String,
    pub(super) from: Option<String>,
    pub(super) to: Option<String>,
    pub(super) pos: Cursor,
    /// When the first page of this search was answered.
    pub(super) born: u64,
}

/// A scope that opened, and what spending its token needs.
pub(super) struct Opened {
    pub(super) scope: PageScope,
    jti: String,
    expires_at: u64,
}

impl Opened {
    /// Whether the token is still inside its own expiry and its chain's
    /// ceiling at `now`. Opening judged this at the start of the request; a
    /// page that waited for a reader slot and a scan is judged again at the
    /// moment it would be delivered.
    pub(super) fn alive_at(&self, now: u64) -> bool {
        now <= self.expires_at && now <= self.scope.born.saturating_add(CHAIN_CEILING_SECS)
    }
}

/// The digest a token binds to; `None` when the caller has nothing to bind to,
/// in which case no token is minted or opened. One function for both, so they
/// cannot disagree.
///
/// A bearer or API key binds to its credential principal. Every dashboard
/// session carries the same constant principal, so a session binds to its own
/// cookie handle instead (hashed, never sent anywhere): two browser sessions
/// cannot open each other's tokens.
fn cursor_principal(
    client: Option<&AuthenticatedClient>,
    headers: &axum::http::HeaderMap,
) -> Option<String> {
    use crate::security::audit::CredentialKind;
    let client = client?;
    let principal = client.credential_principal()?;
    let digest = |tag: &str, material: &str| {
        crate::hashing::sha256_hex(format!("{tag}\0{material}").as_bytes())
    };
    match client.credential_kind {
        // Every dashboard session carries the same principal: its own cookie
        // handle is what tells two sessions apart. An empty handle is no
        // session.
        CredentialKind::DashboardSession => {
            let handle = crate::gateway::auth::session_cookie_value(headers)?;
            (!handle.is_empty()).then(|| digest("dashboard-session", &handle))
        }
        // A digest of the one secret the caller presented.
        CredentialKind::StaticBearer
        | CredentialKind::ApiKey
        | CredentialKind::KeyServerToken
        | CredentialKind::OidcBearer => {
            Some(digest("credential-principal", principal.storage_form()))
        }
        // Nothing to bind a token to: no token is minted or opened.
        CredentialKind::None | CredentialKind::LocalTransport => None,
    }
}

/// Seal `scope` for `principal`, valid from `now`; `None` when it cannot be
/// sealed (no principal, or the keyring refuses).
pub(super) fn seal(
    state: &AppState,
    principal: &str,
    scope: &PageScope,
    now: u64,
) -> Option<String> {
    if principal.is_empty() {
        return None;
    }
    let json = serde_json::to_string(scope).ok()?;
    let payload = Payload::mint_lookup(principal.to_owned(), json, now);
    let token = state.continuation.keyring().mint(&payload).ok()?;
    // A token `open` would refuse for its length is not issued.
    (token.len() <= PAGE_TOKEN_MAX_LEN).then_some(token)
}

/// Open `token` for `principal`, or `None`: one answer for every reason it
/// would not open (malformed, tampered, another process or principal, another
/// purpose, expired, past the chain ceiling, a hash key or version that is no
/// longer current). No reason is logged or counted.
pub(super) fn open(
    state: &AppState,
    principal: &str,
    token: &str,
    now: u64,
    key: &EmailHashKey,
) -> Option<Opened> {
    if principal.is_empty() || token.is_empty() || token.len() > PAGE_TOKEN_MAX_LEN {
        return None;
    }
    let payload = state.continuation.keyring().open(token, now).ok()?;
    let scope: PageScope = serde_json::from_str(payload.lookup_scope_for(principal).ok()?).ok()?;
    let shaped =
        scope.hash.len() == key.hash("").len() && scope.hash.bytes().all(|b| b.is_ascii_hexdigit());
    let from = scope.from.as_deref().map(parse_time);
    let to = scope.to.as_deref().map(parse_time);
    let window_ok = match (from, to) {
        (Some(None), _) | (_, Some(None)) => false,
        (Some(Some(f)), Some(Some(t))) => f <= t,
        _ => true,
    };
    let current = scope.version == u64::from(email_hash::VERSION) && scope.key_id == key.key_id();
    let young = scope.born <= now && now <= scope.born.saturating_add(CHAIN_CEILING_SECS);
    (shaped && window_ok && current && young).then(|| Opened {
        jti: payload.jti.clone(),
        expires_at: payload.expires_at,
        scope,
    })
}

/// Spend the token of `opened`: true once, false for every later try.
async fn spend(state: &AppState, opened: &Opened, now: u64) -> bool {
    state
        .continuation
        .ledger()
        .consume(&opened.jti, opened.expires_at, now)
        .await
}

/// Whether `entry` is an issuance row of this hash, key and version, inside
/// the window.
fn matches(
    line: &Line,
    hash: &str,
    version: u64,
    key_id: &str,
    window: (Option<DateTime<FixedOffset>>, Option<DateTime<FixedOffset>>),
) -> bool {
    let e = &line.entry;
    if e.get("event").and_then(Value::as_str) != Some("token.issued") {
        return false;
    }
    let Some(id) = e.get("identity") else {
        return false;
    };
    let same = id.get("email_hash").and_then(Value::as_str) == Some(hash)
        && id.get("email_hash_version").and_then(Value::as_u64) == Some(version)
        && id.get("email_hash_key_id").and_then(Value::as_str) == Some(key_id);
    if !same {
        return false;
    }
    let at = e
        .get("timestamp")
        .and_then(Value::as_str)
        .and_then(parse_time);
    match (window.0, window.1, at) {
        (None, None, _) => true,
        (_, _, None) => false,
        (from, to, Some(t)) => from.is_none_or(|f| t >= f) && to.is_none_or(|u| t <= u),
    }
}

/// The allowlisted row a match becomes: no email, name or groups exist in a
/// retained issuance row, and none of its other fields is copied blindly.
fn row_of(line: &Line) -> Value {
    let e = &line.entry;
    let id = e.get("identity");
    let pick = |v: Option<&Value>, k: &str| v.and_then(|v| v.get(k)).cloned();
    json!({
        "timestamp": e.get("timestamp").cloned(),
        "token_jti": e.get("token_jti").cloned(),
        "subject": pick(id, "subject"),
        "issuer": pick(id, "issuer"),
        "backends": e.get("backends").cloned(),
        "tools": e.get("tools").cloned(),
        "segment": line.segment,
    })
}

/// Everything a scan needs, owned so it can move onto the blocking pool.
struct Scan {
    state: Arc<AppState>,
    /// The caller's principal digest; `None` mints no token.
    principal: Option<String>,
    log: std::path::PathBuf,
    hash: String,
    key_id: String,
    from: Option<String>,
    to: Option<String>,
    /// Where the first page of this search began, carried forward.
    born: u64,
    /// `None` on a first page.
    start: Option<Cursor>,
    limit: usize,
}

/// Read one page of retained rows. A read that fails is an error answer, never
/// an empty result: an empty result must mean no retained row matched.
fn scan(s: &Scan) -> Response {
    let version = u64::from(email_hash::VERSION);
    let window = (
        s.from.as_deref().and_then(parse_time),
        s.to.as_deref().and_then(parse_time),
    );
    let page = read_page(
        &s.log,
        None,
        s.start.as_ref(),
        Limits {
            matches: s.limit,
            bytes: PAGE_SCAN_BYTES,
        },
        |line| matches(line, &s.hash, version, &s.key_id, window),
    );
    let Ok(page) = page else {
        return finish(
            refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                "the retained audit log could not be read",
            ),
            "unreadable",
            0,
            0,
        );
    };
    let rows: Vec<Value> = page.lines.iter().map(row_of).collect();
    let next = match page.next {
        None => None,
        Some(pos) => {
            let scope = PageScope {
                hash: s.hash.clone(),
                version,
                key_id: s.key_id.clone(),
                from: s.from.clone(),
                to: s.to.clone(),
                pos,
                born: s.born,
            };
            let token = s
                .principal
                .as_deref()
                .zip(crate::clock::unix_secs().ok())
                .and_then(|(p, minted)| seal(&s.state, p, &scope, minted));
            let Some(token) = token else {
                return finish(
                    refuse(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "a page token cannot be issued now",
                    ),
                    "unavailable",
                    0,
                    0,
                );
            };
            Some(token)
        }
    };
    let body = json!({
        "rows": rows,
        "next_cursor": next,
        "scan_exhausted": page.scan_exhausted,
        "cursor_reset": page.cursor_reset,
        "unreadable": page.unreadable.len(),
        "scope": "retained",
    });
    finish(
        (StatusCode::OK, Json(body)).into_response(),
        "ok",
        rows.len(),
        page.bytes_examined,
    )
}

fn throttled(retry_after_secs: u64) -> Response {
    let mut response = refuse(
        StatusCode::TOO_MANY_REQUESTS,
        "too many email lookups; retry later",
    );
    if let Ok(value) = HeaderValue::from_str(&retry_after_secs.to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    finish(response, "throttled", 0, 0)
}

/// How long the body may take to arrive once the caller is admitted and has
/// paid: a slow body holds a connection, not a permit.
const BODY_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

/// Read the body: the listener's configured size cap applies (the extractor
/// reads through it), the lookup's own 8 KiB limit is judged on what arrived,
/// and the whole read has a deadline. Called only after admission and the
/// budget, so an unauthorized or over-budget caller's body is never waited
/// for.
pub(super) async fn read_body(request: axum::extract::Request) -> Result<Bytes, Box<Response>> {
    use axum::extract::FromRequest as _;
    let read = Bytes::from_request(request, &());
    let too_large = || {
        Box::new(finish(
            refuse(
                StatusCode::PAYLOAD_TOO_LARGE,
                "the request body is too large",
            ),
            "bad_request",
            0,
            0,
        ))
    };
    match tokio::time::timeout(BODY_DEADLINE, read).await {
        Ok(Ok(bytes)) if bytes.len() <= MAX_BODY => Ok(bytes),
        Ok(Ok(_) | Err(_)) => Err(too_large()),
        Err(_) => Err(Box::new(finish(
            refuse(
                StatusCode::REQUEST_TIMEOUT,
                "the request body took too long",
            ),
            "bad_request",
            0,
            0,
        ))),
    }
}

/// A request is an email or a cursor, never both and never neither, and a
/// next page takes its window from the cursor.
fn check_shape(
    email: Option<&str>,
    cursor: Option<&str>,
    window: (&Option<String>, &Option<String>),
) -> Result<(), &'static str> {
    if email.is_some() == cursor.is_some() {
        return Err("send an email, or the cursor of the previous page, not both");
    }
    if cursor.is_some() && (window.0.is_some() || window.1.is_some()) {
        return Err("a next page takes its window from the cursor");
    }
    Ok(())
}

/// What only a first page is judged on: the email and its window.
fn check_first_page(raw: &str, from: Option<&str>, to: Option<&str>) -> Result<(), &'static str> {
    let email = raw.trim();
    if email.is_empty() || email.len() > MAX_EMAIL || email.chars().any(char::is_control) {
        return Err("the email is not valid");
    }
    if from.is_some_and(|t| t.len() > MAX_TIME) || to.is_some_and(|t| t.len() > MAX_TIME) {
        return Err("from and to must be RFC 3339 times");
    }
    let (Some(window_from), Some(window_to)) = (
        from.map_or(Some(None), |t| parse_time(t).map(Some)),
        to.map_or(Some(None), |t| parse_time(t).map(Some)),
    ) else {
        return Err("from and to must be RFC 3339 times");
    };
    match (window_from, window_to) {
        (Some(f), Some(t)) if f > t => Err("from must not be after to"),
        _ => Ok(()),
    }
}

fn bad_token() -> Response {
    finish(
        refuse(
            StatusCode::BAD_REQUEST,
            "the page token is not valid; run the lookup again",
        ),
        "bad_request",
        0,
        0,
    )
}

/// What a lookup cannot run without: the key server, its log's path and the
/// clock. Each is its own refusal, and none is about a token.
fn what_it_needs(
    state: &AppState,
) -> Result<(Arc<crate::key_server::KeyServer>, std::path::PathBuf, u64), Box<Response>> {
    let refused =
        |status, message, outcome| Box::new(finish(refuse(status, message), outcome, 0, 0));
    let ks = state.key_server.clone().ok_or_else(|| {
        refused(
            StatusCode::NOT_FOUND,
            "no key server is running",
            "not_found",
        )
    })?;
    let log = state.transparency_log.as_ref().ok_or_else(|| {
        refused(
            StatusCode::NOT_FOUND,
            "no transparency log is configured",
            "not_found",
        )
    })?;
    let now = crate::clock::unix_secs().map_err(|_| {
        refused(
            StatusCode::SERVICE_UNAVAILABLE,
            "the clock cannot be read",
            "unavailable",
        )
    })?;
    Ok((ks, log.path(), now))
}

/// What a request resolves to once it is judged: the search it runs.
struct Resolved {
    hash: String,
    /// `None` on a first page.
    start: Option<Cursor>,
    born: u64,
    from: Option<String>,
    to: Option<String>,
    /// The token to spend once its page is read; `None` on a first page.
    opened: Option<Opened>,
}

/// A first page hashes the email, which goes no further: the suspended handler
/// owns only the hash while it waits for a reader slot. A next page opens its
/// token, last of all the checks. Both or neither of email and token was
/// refused earlier.
fn resolve(
    ask: (Option<String>, Option<String>),
    window: (Option<String>, Option<String>),
    (state, key): (&AppState, &EmailHashKey),
    principal: Option<&str>,
    now: u64,
) -> Result<Resolved, Box<Response>> {
    match ask {
        (Some(raw), None) => Ok(Resolved {
            hash: key.hash(raw.trim()),
            start: None,
            born: now,
            from: window.0,
            to: window.1,
            opened: None,
        }),
        (None, Some(token)) => {
            let opened = principal
                .and_then(|p| open(state, p, &token, now, key))
                .ok_or_else(|| Box::new(bad_token()))?;
            Ok(Resolved {
                hash: opened.scope.hash.clone(),
                start: Some(opened.scope.pos.clone()),
                born: opened.scope.born,
                from: opened.scope.from.clone(),
                to: opened.scope.to.clone(),
                opened: Some(opened),
            })
        }
        _ => Err(Box::new(bad_token())),
    }
}

pub(super) async fn lookup(
    State(state): State<Arc<AppState>>,
    guard: Guard,
    request: axum::extract::Request,
) -> Response {
    if let Err(refused) = guard.admit() {
        return refused.into_response();
    }
    let principal = cursor_principal(guard.client.as_ref(), request.headers());
    telemetry_metrics::counter!("mcp_key_server_lookup_attempts_total").increment(1);
    if let Charge::Throttled { retry_after_secs } = state.process.lookup_budget().charge() {
        telemetry_metrics::counter!("mcp_key_server_lookup_throttled_total").increment(1);
        return throttled(retry_after_secs);
    }
    let bad = |message: &'static str| {
        finish(
            refuse(StatusCode::BAD_REQUEST, message),
            "bad_request",
            0,
            0,
        )
    };
    let body = match read_body(request).await {
        Ok(body) => body,
        Err(refusal) => return *refusal,
    };
    let parsed = serde_json::from_slice::<Request>(&body);
    drop(body);
    let Ok(Request {
        email: raw,
        limit,
        cursor: token,
        from,
        to,
    }) = parsed
    else {
        return bad("the body must be a JSON object with an email or a cursor");
    };
    if let Err(message) = check_shape(raw.as_deref(), token.as_deref(), (&from, &to)) {
        return bad(message);
    }
    let (from, to) = (from.as_deref(), to.as_deref());
    if let Some(raw) = raw.as_deref()
        && let Err(message) = check_first_page(raw, from, to)
    {
        return bad(message);
    }
    let limit = limit.unwrap_or(DEFAULT_LIMIT);
    if limit == 0 || limit > MAX_LIMIT {
        return bad("limit is out of range");
    }
    let (ks, log_path, now) = match what_it_needs(&state) {
        Ok(found) => found,
        Err(refusal) => return *refusal,
    };
    let Resolved {
        hash,
        start,
        born,
        from,
        to,
        opened,
    } = match resolve(
        (raw, token),
        (from.map(str::to_owned), to.map(str::to_owned)),
        (&state, &ks.email_key),
        principal.as_deref(),
        now,
    ) {
        Ok(resolved) => resolved,
        Err(refusal) => return *refusal,
    };
    let job = Scan {
        state: Arc::clone(&state),
        principal,
        log: log_path,
        key_id: ks.email_key.key_id(),
        hash,
        from,
        to,
        born,
        start,
        limit,
    };
    let response = blocking(state.process.activity_reads(), move || scan(&job)).await;
    // The token is spent by the page it served, after that page was read: a
    // throttle, a failed read or a body that never arrived left it intact.
    if let Some(opened) = opened
        && response.status() == StatusCode::OK
    {
        let delivered = crate::clock::unix_secs().unwrap_or(u64::MAX);
        if !opened.alive_at(delivered) || !spend(&state, &opened, delivered).await {
            return bad_token();
        }
    }
    response
}
