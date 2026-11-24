// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The api command's streamed answers, bounded event streams and raw
//! downloads, and the output rules both paths share.
//!
//! Streaming is chosen by route before sending: the event stream and the
//! activity export, the only UI API routes that answer a stream or a
//! download. It is confirmed by a 2xx status and an allowlisted type; any
//! other answer takes the buffered path unchanged. Every byte printed passes
//! the credential redactor one whole line (or one whole event) at a time: a
//! credential holds no CR or LF, so no occurrence spans a line, and no
//! partial line is ever printed unscanned.

use std::future::Future;
use std::io::Write;
use std::time::{Duration, Instant};

use futures::StreamExt;
use mcp_gateway::cli::api::ApiArgs;
use mcp_gateway::cli::redact;
use serde_json::{Value, json};

use super::super::dashboard_link::{
    AdminCallError, AdminClientOptions, AdminFailureKind, AdminResponse, AdminStream, LinkTls,
    admin_stream_url, read_token, redact_body,
};
use super::{CliError, CliExit, CliOutcome, api_url, method, render_response, resolve_token};
use crate::gateway::routes;

/// A pending line or event may hold as much as a whole buffered answer, so
/// no export that prints today fails when streamed.
const PENDING_LIMIT: usize = 16 * 1024 * 1024;

/// The waits on a streamed answer. Fixed in production; tests shorten them.
pub(super) struct Deadlines {
    /// Send to response headers.
    pub(super) headers: Duration,
    /// Longest gap with no bytes.
    pub(super) stall: Duration,
    /// The stream route: longest wait for the next complete event.
    pub(super) event: Duration,
    /// The whole streamed answer: reads, writes and flushes alike.
    pub(super) stream_total: Duration,
    pub(super) download_total: Duration,
    /// A non-streamed answer on a streamed route keeps today's 30 s total.
    pub(super) fallback_total: Duration,
}

impl Default for Deadlines {
    fn default() -> Self {
        let s30 = Duration::from_secs(30);
        Self {
            headers: s30,
            stall: s30,
            event: s30,
            stream_total: Duration::from_secs(300),
            download_total: Duration::from_secs(600),
            fallback_total: s30,
        }
    }
}

/// How an answer is read, chosen from the route before sending.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Mode {
    /// Every other route: read whole, today's path.
    Buffered,
    /// `GET /ui/api/stream`: events, bounded by `--limit`.
    Stream,
    /// `GET /ui/api/activity/export`: lines, passed through.
    Download,
}

fn mode_of(url: &reqwest::Url) -> Mode {
    let path = url.path();
    if path == routes::UI_STREAM {
        Mode::Stream
    } else if path == routes::UI_ACTIVITY_EXPORT {
        Mode::Download
    } else {
        Mode::Buffered
    }
}

/// Whether a GET of `path` on `base` is one of the two streamed routes.
pub(super) fn streamed(base: &str, path: &str) -> bool {
    api_url(base, path).is_ok_and(|url| mode_of(&url) != Mode::Buffered)
}

/// `--limit` belongs to the stream route, which needs it.
pub(super) fn check_args(args: &ApiArgs, url: &reqwest::Url) -> Result<(), CliError> {
    let stream = mode_of(url) == Mode::Stream;
    let usage = |message: &str, remedy: &str| Err(CliError::new(CliExit::Usage, message, remedy));
    if stream && args.limit.is_none() {
        return usage(
            "The event stream needs --limit.",
            "Add --limit N to print N events, then retry.",
        );
    }
    if !stream && args.limit.is_some() {
        return usage(
            "--limit applies only to /ui/api/stream.",
            "Remove --limit, or ask for /ui/api/stream.",
        );
    }
    // The streamed sender carries no body and no If-Match; both routes are
    // GET-only, so a request that sets either is refused, never sent without.
    if mode_of(url) != Mode::Buffered {
        let flag = if args.data.is_some() {
            Some("--data")
        } else if args.if_match.is_some() {
            Some("--if-match")
        } else {
            None
        };
        if let Some(flag) = flag {
            return Err(CliError::new(
                CliExit::Usage,
                format!("{flag} does not apply to {}.", url.path()),
                format!("Remove {flag}, then retry."),
            ));
        }
    }
    Ok(())
}

/// One streamed request, validated before the credential reaches the sender.
pub(super) struct StreamRequest {
    pub(super) method: reqwest::Method,
    pub(super) url: reqwest::Url,
    pub(super) token: String,
    pub(super) tls: LinkTls,
}

/// The production sender: the shared client and policy, with no total limit
/// on the request (the caller's [`Deadlines`] bound it instead).
pub(super) async fn send(request: StreamRequest) -> Result<AdminStream, AdminCallError> {
    send_with(request, AdminClientOptions::default()).await
}

/// The sender over `base` options: whatever total limit `base` carries, a
/// streamed request drops it (R14 drives this with a test-sized total).
async fn send_with(
    request: StreamRequest,
    base: AdminClientOptions,
) -> Result<AdminStream, AdminCallError> {
    let options = AdminClientOptions {
        total: None,
        ..base
    };
    admin_stream_url(
        request.method,
        request.url,
        &request.token,
        &request.tls,
        &options,
    )
    .await
}

/// The command's streamed path, printing to stdout as answers arrive.
pub(super) async fn run_production(
    args: &ApiArgs,
    base: &str,
    tls: &LinkTls,
    token: Option<String>,
) -> CliOutcome {
    let lookup = |name: &str| {
        (name == super::super::dashboard_link::TOKEN_ENV)
            .then(|| token.clone())
            .flatten()
    };
    run_streamed_with(
        args,
        base,
        tls,
        lookup,
        std::io::stdout(),
        &Deadlines::default(),
        send,
    )
    .await
}

/// Cuts a download into complete lines, each keeping its LF; the rest waits.
#[derive(Default)]
struct Lines {
    pending: Vec<u8>,
}

impl Lines {
    /// The complete lines `chunk` ends, in order; `None` once a line, complete
    /// or pending, passes [`PENDING_LIMIT`], so it is never printed unscanned.
    fn push(&mut self, chunk: &[u8]) -> Option<Vec<Vec<u8>>> {
        // The pending bytes hold no LF, so the scan starts at the new chunk;
        // one pass and one drain, as splitting per line would copy the rest
        // once per line.
        let mut scan = self.pending.len();
        self.pending.extend_from_slice(chunk);
        let mut done = Vec::new();
        let mut start = 0;
        while let Some(at) = self.pending[scan..].iter().position(|&b| b == b'\n') {
            let end = scan + at;
            if end - start > PENDING_LIMIT {
                return None;
            }
            done.push(self.pending[start..=end].to_vec());
            start = end + 1;
            scan = start;
        }
        self.pending.drain(..start);
        (self.pending.len() <= PENDING_LIMIT).then_some(done)
    }

    /// The last line when the body ends without a final LF.
    fn finish(&mut self) -> Option<Vec<u8>> {
        (!self.pending.is_empty()).then(|| std::mem::take(&mut self.pending))
    }
}

/// One line as printed: masked when it is UTF-8; unchanged when it is not and
/// holds no credential (today's buffered rule); `None` when it is not UTF-8
/// and holds the credential.
fn masked_line(line: &[u8], token: &str) -> Option<Vec<u8>> {
    match std::str::from_utf8(line) {
        Ok(text) => checked(&redact::text(text, &[token.to_owned()]), text, token),
        Err(_) if !line.windows(token.len()).any(|w| w == token.as_bytes()) => Some(line.to_vec()),
        Err(_) => None,
    }
}

/// A masked piece as printed, or `None`. The redactor tries each marker and,
/// when every one would leave the token (a token found in all of them), fails
/// closed to empty output, which would pass as an emptied line or event; that
/// refuses instead. The token check backs the redactor's own guarantee.
fn checked(masked: &str, input: &str, token: &str) -> Option<Vec<u8>> {
    let emptied = masked.is_empty() && !input.is_empty();
    (!emptied && !masked.contains(token)).then(|| masked.as_bytes().to_vec())
}

/// One dispatched event-stream event.
#[derive(Debug, PartialEq, Eq)]
struct Event {
    name: String,
    id: Option<String>,
    data: String,
}

/// The event-stream rules this command needs (WHATWG HTML, server-sent
/// events): CR, LF and CRLF line ends (a CRLF split across chunks is one),
/// a leading BOM dropped, comments ignored, `event`, `data` and `id` fields,
/// a persistent last id, and a block without data dispatching nothing.
#[derive(Default)]
struct Events {
    line: Vec<u8>,
    after_cr: bool,
    started: bool,
    data: String,
    has_data: bool,
    name: String,
    last_id: String,
}

impl Events {
    /// The events `chunk` completes; `None` once a pending line or event
    /// passes [`PENDING_LIMIT`].
    fn push(&mut self, chunk: &[u8]) -> Option<Vec<Event>> {
        let mut done = Vec::new();
        for &byte in chunk {
            let after_cr = std::mem::replace(&mut self.after_cr, byte == b'\r');
            match byte {
                b'\n' if after_cr => {}
                b'\r' | b'\n' => {
                    let line = std::mem::take(&mut self.line);
                    if let Some(event) = self.end_line(&line) {
                        done.push(event);
                    }
                }
                _ => self.line.push(byte),
            }
            if self.line.len() > PENDING_LIMIT || self.data.len() > PENDING_LIMIT {
                return None;
            }
        }
        Some(done)
    }

    fn end_line(&mut self, raw: &[u8]) -> Option<Event> {
        let text = String::from_utf8_lossy(raw);
        let mut line = text.as_ref();
        if !std::mem::replace(&mut self.started, true) {
            line = line.strip_prefix('\u{feff}').unwrap_or(line);
        }
        if line.is_empty() {
            let event = std::mem::take(&mut self.name);
            let mut data = std::mem::take(&mut self.data);
            if !std::mem::replace(&mut self.has_data, false) {
                return None;
            }
            data.pop();
            return Some(Event {
                name: if event.is_empty() {
                    "message".to_owned()
                } else {
                    event
                },
                id: (!self.last_id.is_empty()).then(|| self.last_id.clone()),
                data,
            });
        }
        if line.starts_with(':') {
            return None;
        }
        let (field, value) = line.split_once(':').unwrap_or((line, ""));
        let value = value.strip_prefix(' ').unwrap_or(value);
        match field {
            "event" => value.clone_into(&mut self.name),
            "data" => {
                self.data.push_str(value);
                self.data.push('\n');
                self.has_data = true;
            }
            "id" if !value.contains('\0') => value.clone_into(&mut self.last_id),
            _ => {}
        }
        None
    }
}

/// One event as printed, masked: a one-line JSON object with `--json`, else
/// its fields as event-stream text. `None` when redaction would drop an
/// object entry (the buffered path's rule).
fn rendered(event: Event, token: &str, json_output: bool) -> Option<Vec<u8>> {
    let secrets = [token.to_owned()];
    if !json_output {
        let mut text = format!("event: {}\n", event.name);
        if let Some(id) = &event.id {
            text.push_str("id: ");
            text.push_str(id);
            text.push('\n');
        }
        for line in event.data.split('\n') {
            text.push_str("data: ");
            text.push_str(line);
            text.push('\n');
        }
        text.push('\n');
        return checked(&redact::text(&text, &secrets), &text, token);
    }
    let data = serde_json::from_str::<Value>(&event.data).unwrap_or(Value::String(event.data));
    let mut object = json!({"event": event.name, "id": event.id, "data": data});
    // The shared refusal: an entry lost to redaction is not printed short.
    if !redact_body(&mut object, token) {
        return None;
    }
    let mut line = serde_json::to_vec(&object).ok()?;
    line.push(b'\n');
    // A token equal to JSON syntax survives the value redaction.
    (!line.windows(token.len()).any(|w| w == token.as_bytes())).then_some(line)
}

/// The lower-cased MIME essence of the answer's Content-Type.
fn essence(answer: &AdminStream) -> String {
    let value = answer.headers.get(reqwest::header::CONTENT_TYPE);
    let value = value.and_then(|v| v.to_str().ok()).unwrap_or_default();
    value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
}

/// A 2xx answer of the type the route streams; anything else is buffered.
fn streamable(mode: Mode, answer: &AdminStream) -> bool {
    let essence = essence(answer);
    answer.status.is_success()
        && match mode {
            Mode::Stream => essence == "text/event-stream",
            Mode::Download => essence == "application/x-ndjson" || essence == "text/csv",
            Mode::Buffered => false,
        }
}

fn failure(kind: CliExit, message: &str, remedy: &str, json: bool, token: &str) -> CliOutcome {
    CliError::new(kind, message, remedy).outcome(json, &[token])
}

fn network(message: &str, json: bool, token: &str) -> CliOutcome {
    failure(
        CliExit::Network,
        message,
        "Check the gateway, then retry.",
        json,
        token,
    )
}

fn unsafe_body(json: bool, token: &str) -> CliOutcome {
    failure(
        CliExit::LocalFailure,
        super::UNSAFE_BODY_MESSAGE,
        super::UNSAFE_BODY_REMEDY,
        json,
        token,
    )
}

fn too_long(json: bool, token: &str) -> CliOutcome {
    failure(
        CliExit::LocalFailure,
        "A line of the answer is longer than 16 MiB.",
        "Nothing of that line was printed; narrow the request and retry.",
        json,
        token,
    )
}

/// A non-streamed answer on a streamed route, read whole within today's
/// limits (16 MiB, 30 s from the send) and rendered as any buffered answer.
async fn buffered(
    answer: AdminStream,
    until: Instant,
    token: &str,
    json: bool,
    origin: &str,
    path: &str,
) -> CliOutcome {
    let AdminStream {
        status,
        headers,
        mut body,
    } = answer;
    let mut bytes = Vec::new();
    loop {
        // Cooperative: a body that is always ready would otherwise hold its
        // worker without a break, and its task could not be cancelled.
        tokio::task::consume_budget().await;
        // Checked before each read, not only by the timeout: a body that is
        // always ready (endless empty chunks) never lets a zero wait fire.
        let now = Instant::now();
        if now >= until {
            return network(
                "The gateway did not finish its answer in time.",
                json,
                token,
            );
        }
        let wait = until.saturating_duration_since(now);
        match tokio::time::timeout(wait, body.next()).await {
            Err(_) => {
                return network(
                    "The gateway did not finish its answer in time.",
                    json,
                    token,
                );
            }
            Ok(None) => break,
            Ok(Some(Err(error))) => {
                return super::transport_failure(error, super::Request::Read, token)
                    .outcome(json, &[token]);
            }
            Ok(Some(Ok(chunk))) if bytes.len() + chunk.len() > PENDING_LIMIT => {
                let error = AdminCallError {
                    kind: AdminFailureKind::ResponseTooLarge,
                    detail: "Gateway response exceeded 16 MiB.".to_owned(),
                    status: Some(status),
                    request_id: None,
                };
                return super::transport_failure(error, super::Request::Read, token)
                    .outcome(json, &[token]);
            }
            Ok(Some(Ok(chunk))) => bytes.extend_from_slice(&chunk),
        }
    }
    let response = AdminResponse {
        status,
        headers,
        body: bytes,
    };
    let target = (path, &reqwest::Method::GET);
    render_response(&response, token, json, origin, target, super::Request::Read)
}

/// Writes and flushes one printed piece: `Ok(true)` to go on, `Ok(false)`
/// when the reader went away (a broken pipe ends the command successfully,
/// as on the buffered path), `Err` for any other write failure.
fn emit(sink: &mut impl Write, bytes: &[u8]) -> std::io::Result<bool> {
    match sink.write_all(bytes).and_then(|()| sink.flush()) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => Ok(false),
        Err(error) => Err(error),
    }
}

/// The output side of a streamed run. A thread of its own owns the sink and
/// prints one piece at a time, so a reader that stalls the pipe cannot hold
/// the command past its overall deadline: each write and flush is awaited
/// with the time left. A write still parked at the deadline stays on its
/// thread, which the process does not wait for at exit.
struct Printer {
    pieces: std::sync::mpsc::Sender<Vec<u8>>,
    acks: tokio::sync::mpsc::UnboundedReceiver<std::io::Result<bool>>,
}

/// How one piece went.
enum Print {
    /// Written and flushed.
    Done,
    /// The reader went away; the command ends successfully.
    ReaderGone,
    /// The overall deadline passed first.
    Late,
    /// Any other write failure.
    Failed,
}

impl Printer {
    fn start(mut sink: impl Write + Send + 'static) -> Self {
        let (pieces, queue) = std::sync::mpsc::channel::<Vec<u8>>();
        let (ack, acks) = tokio::sync::mpsc::unbounded_channel();
        std::thread::spawn(move || {
            for piece in queue {
                if ack.send(emit(&mut sink, &piece)).is_err() {
                    break;
                }
            }
        });
        Self { pieces, acks }
    }

    async fn print(&mut self, piece: Vec<u8>, until: Instant) -> Print {
        if self.pieces.send(piece).is_err() {
            return Print::Failed;
        }
        let left = until.saturating_duration_since(Instant::now());
        match tokio::time::timeout(left, self.acks.recv()).await {
            Err(_) => Print::Late,
            Ok(Some(Ok(true))) => Print::Done,
            Ok(Some(Ok(false))) => Print::ReaderGone,
            Ok(Some(Err(_)) | None) => Print::Failed,
        }
    }
}

fn write_failed(json: bool, token: &str) -> CliOutcome {
    failure(
        CliExit::LocalFailure,
        "Could not write command output.",
        "Check the output destination before repeating the command.",
        json,
        token,
    )
}

/// The streamed path: the same checks as the buffered one before anything is
/// sent, then the answer printed as it arrives, or read whole when it is not
/// a stream ([`streamable`]).
pub(super) async fn run_streamed_with<F, Fut>(
    args: &ApiArgs,
    base: &str,
    tls: &LinkTls,
    lookup: impl Fn(&str) -> Option<String>,
    sink: impl Write + Send + 'static,
    deadlines: &Deadlines,
    send: F,
) -> CliOutcome
where
    F: FnOnce(StreamRequest) -> Fut,
    Fut: Future<Output = Result<AdminStream, AdminCallError>>,
{
    let credential = read_token(lookup);
    let redaction = credential.as_deref().unwrap_or_default().to_owned();
    let method = match method(&args.method, &redaction) {
        Ok(method) => method,
        Err(error) => return error.outcome(args.json, &[redaction.as_str()]),
    };
    let url = match api_url(base, &args.path) {
        Ok(url) => url,
        Err(error) => return error.outcome(args.json, &[redaction.as_str()]),
    };
    if let Err(error) = check_args(args, &url) {
        return error.outcome(args.json, &[redaction.as_str()]);
    }
    let (mode, origin) = (mode_of(&url), url.origin().ascii_serialization());
    let token = match resolve_token(credential, &origin) {
        Ok(token) => token,
        Err(error) => return error.outcome(args.json, &[""]),
    };
    let started = Instant::now();
    let request = StreamRequest {
        method,
        url,
        token: token.clone(),
        tls: tls.clone(),
    };
    let answer = match tokio::time::timeout(deadlines.headers, send(request)).await {
        Ok(Ok(answer)) => answer,
        Ok(Err(error)) => {
            return super::transport_failure(error, super::Request::Read, &token)
                .outcome(args.json, &[token.as_str()]);
        }
        Err(_) => {
            return network(
                "The gateway sent no response headers in time.",
                args.json,
                &token,
            );
        }
    };
    if !streamable(mode, &answer) {
        let until = started + deadlines.fallback_total;
        return buffered(answer, until, &token, args.json, &origin, &args.path).await;
    }
    let total = if mode == Mode::Stream {
        deadlines.stream_total
    } else {
        deadlines.download_total
    };
    let printing = Printing {
        mode,
        status: answer.status,
        token: &token,
        json: args.json,
        limit: args.limit.map_or(usize::MAX, |n| n as usize),
        until: started + total,
    };
    printing
        .run(answer, &mut Printer::start(sink), deadlines)
        .await
}

/// The print loop of one streamed answer.
struct Printing<'a> {
    mode: Mode,
    status: reqwest::StatusCode,
    token: &'a str,
    json: bool,
    limit: usize,
    until: Instant,
}

impl Printing<'_> {
    async fn run(
        self,
        answer: AdminStream,
        printer: &mut Printer,
        deadlines: &Deadlines,
    ) -> CliOutcome {
        let (json, token) = (self.json, self.token);
        let mut body = answer.body;
        let (mut lines, mut events) = (Lines::default(), Events::default());
        let mut shown = 0usize;
        let mut event_due = Instant::now() + deadlines.event;
        loop {
            let now = Instant::now();
            // Checked before each read, not only by the timeout: a body that is
            // always ready (keep-alives with no event) never lets one fire.
            if now >= self.until || (self.mode == Mode::Stream && now >= event_due) {
                return network(self.late(event_due), json, token);
            }
            let mut wait = self
                .until
                .saturating_duration_since(now)
                .min(deadlines.stall);
            if self.mode == Mode::Stream {
                wait = wait.min(event_due.saturating_duration_since(now));
            }
            let chunk = match tokio::time::timeout(wait, body.next()).await {
                Err(_) => return network(self.late(event_due), json, token),
                Ok(None) => break,
                Ok(Some(Err(error))) => {
                    return super::transport_failure(error, super::Request::Read, token)
                        .outcome(json, &[token]);
                }
                Ok(Some(Ok(chunk))) => chunk,
            };
            let mut pieces = Vec::new();
            if self.mode == Mode::Stream {
                let Some(done) = events.push(&chunk) else {
                    return too_long(json, token);
                };
                for event in done.into_iter().take(self.limit - shown - pieces.len()) {
                    let Some(bytes) = rendered(event, token, json) else {
                        return unsafe_body(json, token);
                    };
                    pieces.push(bytes);
                }
                if !pieces.is_empty() {
                    event_due = Instant::now() + deadlines.event;
                }
            } else {
                let Some(done) = lines.push(&chunk) else {
                    return too_long(json, token);
                };
                for line in done {
                    let Some(bytes) = masked_line(&line, token) else {
                        return unsafe_body(json, token);
                    };
                    pieces.push(bytes);
                }
            }
            for piece in pieces {
                match printer.print(piece, self.until).await {
                    Print::Done => {}
                    Print::ReaderGone => return self.done(),
                    Print::Late => return network(self.late(event_due), json, token),
                    Print::Failed => return write_failed(json, token),
                }
                if self.mode == Mode::Stream {
                    shown += 1;
                }
            }
            if self.mode == Mode::Stream && shown >= self.limit {
                return self.done();
            }
        }
        if self.mode == Mode::Stream {
            let message = format!("The stream ended after {shown} of {} events.", self.limit);
            return network(&message, json, token);
        }
        if let Some(line) = lines.finish() {
            let Some(bytes) = masked_line(&line, token) else {
                return unsafe_body(json, token);
            };
            match printer.print(bytes, self.until).await {
                Print::Done | Print::ReaderGone => {}
                Print::Late => return network(self.late(event_due), json, token),
                Print::Failed => return write_failed(json, token),
            }
        }
        self.done()
    }

    /// Which wait ran out.
    fn late(&self, event_due: Instant) -> &'static str {
        let now = Instant::now();
        if now >= self.until {
            "The streamed answer passed its overall time limit."
        } else if self.mode == Mode::Stream && now >= event_due {
            "No event arrived in time."
        } else {
            "The gateway stopped sending."
        }
    }

    fn done(&self) -> CliOutcome {
        let note = if self.mode == Mode::Download {
            format!(
                "api: the gateway answered {} with a non-JSON body\n",
                self.status
            )
        } else {
            String::new()
        };
        // The pieces were printed as they arrived; only the note is left, redacted and gated by `success`.
        CliOutcome::success(
            Vec::new(),
            &note,
            self.json,
            &[self.token],
            super::StdoutRule::RedactedJsonBody,
        )
    }
}

#[cfg(tp2)]
#[cfg(test)]
#[path = "api_stream_tests.rs"]
mod tests;
