// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The values a backend's secret rules resolved to, and the scrub that
//! removes them from what that backend sends back (MIK-9035).
//!
//! One set per backend name, shared by every instance a reload builds under
//! that name, so a value a rotation replaced is still removed from a late
//! answer. A value is retired only once its grace has passed since it was
//! last sent ([`redaction_grace`]); a rotated env-file value is normally an
//! expired short-lived token by then. Past [`MAX_NEEDLES`] live values the
//! set fails closed rather than drop one inside its grace.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use parking_lot::RwLock;
use serde_json::Value;

use crate::protocol::{JsonRpcMessage, JsonRpcResponse};

/// The most values one backend name may hold inside their grace. Past it
/// every frame from that backend is refused rather than a value dropped.
pub(crate) const MAX_NEEDLES: usize = 1024;

/// What the refusal says when the set is full.
pub(crate) const OVERFLOW_REFUSAL: &str =
    "the backend's answer was withheld: too many distinct injected secrets to redact";

/// The shortest grace a value keeps after its last send.
const MIN_GRACE: Duration = Duration::from_secs(24 * 60 * 60);

/// How long a value stays redacted after its last send: the longest of 24 h,
/// any backend's call timeout, the response caches' lifetimes, the
/// idempotency cache's and a task's default lifetime, so an echo that a
/// call, a cache or a task can still deliver is still removed.
pub(crate) fn redaction_grace(config: &crate::config::Config) -> Duration {
    let longest_call = config
        .backends
        .values()
        .map(|backend| backend.timeout)
        .max()
        .unwrap_or_default();
    [
        MIN_GRACE,
        longest_call,
        config.cache.default_ttl,
        config.meta_mcp.cache_ttl,
        crate::idempotency::COMPLETED_TTL,
        Duration::from_millis(config.tasks.default_ttl_ms),
    ]
    .into_iter()
    .max()
    .unwrap_or(MIN_GRACE)
}

/// One value and when it was last sent. Monotonic time: a wall-clock jump
/// (NTP, a resumed laptop, a manual set) must not retire live values.
struct Held {
    value: String,
    /// The value's percent-encoded spellings that differ from it (see
    /// [`percent_forms`]): what a backend quoting it inside a URL sends back.
    encoded: Vec<String>,
    last_sent: tokio::time::Instant,
}

/// One backend name's injected values. Never printed: `Debug` names the count.
pub(crate) struct NeedleSet {
    values: RwLock<Vec<Held>>,
    grace: Duration,
    overflowed: AtomicBool,
    /// Rules already warned about a short value (ECHO.6), by name.
    short_warned: parking_lot::Mutex<std::collections::HashSet<String>>,
}

/// A value shorter than this matches ordinary text too often: redacting it
/// can blank unrelated words, so its rule is named once (ECHO.6).
const SHORT_VALUE_BYTES: usize = 8;

impl Default for NeedleSet {
    fn default() -> Self {
        Self::with_grace(MIN_GRACE)
    }
}

impl std::fmt::Debug for NeedleSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NeedleSet({} values)", self.values.read().len())
    }
}

impl NeedleSet {
    /// An empty set whose values retire `grace` after their last send.
    pub(crate) fn with_grace(grace: Duration) -> Self {
        Self {
            values: RwLock::new(Vec::new()),
            grace,
            overflowed: AtomicBool::new(false),
            short_warned: parking_lot::Mutex::default(),
        }
    }

    fn retired(&self, held: &Held, now: tokio::time::Instant) -> bool {
        now.saturating_duration_since(held.last_sent) > self.grace
    }

    /// Adds `value`, or renews its last send (empty values are never
    /// injected, so never added). Retired values are dropped first; past the
    /// bound the set fails closed and keeps every value inside its grace.
    pub(crate) fn insert(&self, backend: &str, value: &str) {
        if value.is_empty() {
            return;
        }
        let now = tokio::time::Instant::now();
        let mut values = self.values.write();
        if let Some(held) = values.iter_mut().find(|held| held.value == value) {
            held.last_sent = now;
            return;
        }
        values.retain(|held| !self.retired(held, now));
        if values.len() >= MAX_NEEDLES {
            if !self.overflowed.swap(true, Ordering::SeqCst) {
                tracing::warn!(
                    backend,
                    bound = MAX_NEEDLES,
                    grace_secs = self.grace.as_secs(),
                    "secret values rotating faster than the redaction grace allows; this \
                     backend's answers are withheld"
                );
            }
            return;
        }
        // Room again after retirement: answers flow once more.
        self.overflowed.store(false, Ordering::SeqCst);
        values.push(Held {
            value: value.to_owned(),
            encoded: percent_forms(value),
            last_sent: now,
        });
    }

    /// Warns once per rule when a value it sent is shorter than
    /// [`SHORT_VALUE_BYTES`]; names the backend and the rule, never the value.
    /// Called on a send only, so loading or seeding never warns.
    pub(crate) fn warn_if_short(&self, backend: &str, rule: &str, value: &str) {
        if value.len() < SHORT_VALUE_BYTES && self.short_warned.lock().insert(rule.to_owned()) {
            tracing::warn!(
                backend,
                rule,
                bytes = value.len(),
                "an injected secret this short is redacted wherever it appears in the backend's \
                 answers, including inside unrelated words"
            );
        }
    }

    /// Whether the set refused a value: every frame is then withheld.
    pub(crate) fn overflowed(&self) -> bool {
        self.overflowed.load(Ordering::SeqCst)
    }

    /// The values still inside their grace. A retired value is not removed
    /// from an answer: the documented residual (UPGRADING).
    fn snapshot(&self) -> Vec<String> {
        let now = tokio::time::Instant::now();
        self.values
            .read()
            .iter()
            .filter(|held| !self.retired(held, now))
            .flat_map(|held| std::iter::once(&held.value).chain(&held.encoded))
            .cloned()
            .collect()
    }
}

/// The percent-encoded spellings of `value` a backend may echo, each only
/// when it differs from `value`: form encoding (space as `+`) and RFC 3986
/// encoding (space as `%20`, every byte but `A-Za-z0-9-._~` escaped), each
/// with uppercase and with lowercase hex. Mixed-case hex within one value,
/// double encoding and base64 are not matched (register row 318).
fn percent_forms(value: &str) -> Vec<String> {
    const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";
    let form: String = url::form_urlencoded::byte_serialize(value.as_bytes()).collect();
    let mut rfc = String::with_capacity(value.len());
    for &byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            rfc.push(char::from(byte));
        } else {
            rfc.push('%');
            rfc.push(char::from(HEX_UPPER[usize::from(byte >> 4)]));
            rfc.push(char::from(HEX_UPPER[usize::from(byte & 0x0f)]));
        }
    }
    let mut forms: Vec<String> = Vec::new();
    for upper in [form, rfc] {
        let lower = lower_hex(&upper);
        for form in [upper, lower] {
            if form != value && !forms.contains(&form) {
                forms.push(form);
            }
        }
    }
    forms
}

/// `encoded` with the two hex digits after each `%` lowercased.
fn lower_hex(encoded: &str) -> String {
    let mut out = String::with_capacity(encoded.len());
    let mut after_percent = 0;
    for c in encoded.chars() {
        if c == '%' {
            after_percent = 2;
            out.push(c);
        } else if after_percent > 0 {
            after_percent -= 1;
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// What [`ingress_scrub`] did to a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scrubbed {
    /// Nothing matched.
    Clean,
    /// At least one value was replaced.
    Redacted,
    /// A notification whose method holds a value: the caller drops it.
    Withhold,
    /// The set overflowed, or an `error.code` equals a value: the caller
    /// answers with the fixed refusal instead.
    Refuse,
}

/// Removes every value in `needles` from `message`, in place: a result, an
/// error's message and data, a notification's params, and a request's params.
/// The envelope's `id` is never touched, so a response still routes.
pub(crate) fn ingress_scrub(needles: &NeedleSet, message: &mut JsonRpcMessage) -> Scrubbed {
    if needles.overflowed() {
        return Scrubbed::Refuse;
    }
    let secrets = needles.snapshot();
    if secrets.is_empty() {
        return Scrubbed::Clean;
    }
    match message {
        JsonRpcMessage::Response(response) => scrub_response(&secrets, response),
        JsonRpcMessage::Notification(notification) => {
            if secrets
                .iter()
                .any(|secret| notification.method.contains(secret.as_str()))
            {
                return Scrubbed::Withhold;
            }
            scrub_option(&secrets, &mut notification.params)
        }
        JsonRpcMessage::Request(request) => scrub_option(&secrets, &mut request.params),
    }
}

/// [`ingress_scrub`] for a response a transport parsed on its own.
pub(crate) fn scrub_response_with(needles: &NeedleSet, response: &mut JsonRpcResponse) -> Scrubbed {
    if needles.overflowed() {
        return Scrubbed::Refuse;
    }
    let secrets = needles.snapshot();
    if secrets.is_empty() {
        return Scrubbed::Clean;
    }
    scrub_response(&secrets, response)
}

/// Redacts one piece of backend text a transport hands on outside a frame
/// (a change-notice URI).
pub(crate) fn scrub_text(needles: &NeedleSet, text: &mut String) -> Scrubbed {
    if needles.overflowed() {
        return Scrubbed::Refuse;
    }
    let secrets = needles.snapshot();
    if secrets.is_empty() {
        return Scrubbed::Clean;
    }
    scrub_string(&secrets, text)
}

/// Redacts the text an error carries. Every variant is listed, not `_`, so a
/// new one is a compile-time decision here: a variant whose text a transport
/// can build from backend bytes is scrubbed; one carrying only the gateway's
/// own text, or none, is clean. A supported-version token holding a value
/// cannot be redacted without changing what it names, so it refuses.
pub(crate) fn scrub_error(needles: &NeedleSet, error: &mut crate::Error) -> Scrubbed {
    use crate::Error as E;
    if needles.overflowed() {
        return Scrubbed::Refuse;
    }
    let secrets = needles.snapshot();
    if secrets.is_empty() {
        return Scrubbed::Clean;
    }
    match error {
        E::JsonRpc {
            code,
            message,
            data,
        }
        | E::JsonRpcRetryable {
            code,
            message,
            data,
            ..
        } => {
            if code_matches(&secrets, *code) {
                return Scrubbed::Refuse;
            }
            merge(
                scrub_string(&secrets, message),
                scrub_option(&secrets, data),
            )
        }
        E::ProtocolVersionRejected { supported } => {
            let mut tokens = Value::from(supported.clone());
            if scrub_in_place(&secrets, &mut tokens) == Scrubbed::Redacted {
                Scrubbed::Refuse
            } else {
                Scrubbed::Clean
            }
        }
        E::Protocol(m)
        | E::Transport(m)
        | E::TransportPermanent(m)
        | E::TransportConnect(m)
        | E::BackendTimeout(m)
        | E::Internal(m)
        | E::OAuth(m)
        | E::Tls(m) => scrub_string(&secrets, m),
        E::Config(_)
        | E::ConfigValidation(_)
        | E::ConfigWatcher(_)
        | E::CliCredentialRefused { .. }
        | E::Forbidden { .. }
        | E::GatewayRefused { .. }
        | E::ResponseFirewallRefused
        | E::AuditUnavailable
        | E::CapabilityHashMismatch { .. }
        | E::BackendNotFound(_)
        | E::AmbiguousBackend { .. }
        | E::BackendUnavailable(_)
        | E::CircuitOpen { .. }
        | E::RateLimited(_)
        | E::IdentitySlotsExhausted { .. }
        | E::ToolNotFound(_)
        | E::AuthorizationIncomplete { .. }
        | E::AuthorizationCancelled { .. }
        | E::AuthorizationRequired { .. }
        | E::AuthorizationPending { .. }
        | E::Io(_)
        | E::Json(_)
        | E::Http(_)
        | E::Shutdown => Scrubbed::Clean,
    }
}

/// Redacts `text` in place.
fn scrub_string(secrets: &[String], text: &mut String) -> Scrubbed {
    let mut value = Value::String(std::mem::take(text));
    let outcome = scrub_in_place(secrets, &mut value);
    *text = match value {
        Value::String(redacted) => redacted,
        other => other.to_string(),
    };
    outcome
}

/// Whether an `error.code` equals a value by the shared numeric rule: the
/// same comparison a result number gets, so `0739154` matches 739154.
fn code_matches(secrets: &[String], code: i32) -> bool {
    let mut number = Value::from(code);
    scrub_in_place(secrets, &mut number) == Scrubbed::Redacted
}

fn scrub_response(secrets: &[String], response: &mut JsonRpcResponse) -> Scrubbed {
    // A signed result keeps, as sent, each top-level member the scrub
    // changes, so its chain is verified over what the backend signed
    // (DELTA-13). Cloned only for a result that carries a chain.
    let signed = response
        .result
        .as_ref()
        .and_then(|result| result.get("_meta"))
        .is_some_and(|meta| {
            meta.get(crate::security::signature_chain::CHAIN_META)
                .is_some()
        })
        .then(|| response.result.clone())
        .flatten();
    let mut outcome = scrub_option(secrets, &mut response.result);
    if outcome == Scrubbed::Redacted
        && let (Some(Value::Object(sent)), Some(Value::Object(scrubbed))) =
            (signed, response.result.as_ref())
    {
        let kept: serde_json::Map<String, Value> = sent
            .into_iter()
            .filter(|(key, value)| {
                crate::protocol::reserved_members::digest_covers(key)
                    && scrubbed.get(key) != Some(value)
            })
            .collect();
        if !kept.is_empty() {
            response.ingress_withheld = Some(Box::new(
                crate::protocol::reserved_members::Withheld::from_members(kept),
            ));
        }
    }
    if let Some(error) = response.error.as_mut() {
        if code_matches(secrets, error.code) {
            return Scrubbed::Refuse;
        }
        outcome = merge(outcome, scrub_string(secrets, &mut error.message));
        outcome = merge(outcome, scrub_option(secrets, &mut error.data));
    }
    // The envelope's version is backend text too; it is normalised, never
    // passed on as sent (design: envelope).
    if response.jsonrpc != "2.0" {
        response.jsonrpc = "2.0".to_owned();
        outcome = merge(outcome, Scrubbed::Redacted);
    }
    outcome
}

fn scrub_option(secrets: &[String], value: &mut Option<Value>) -> Scrubbed {
    value
        .as_mut()
        .map_or(Scrubbed::Clean, |value| scrub_in_place(secrets, value))
}

/// The shared renderer (strings, keys, numbers by value, overlaps merged,
/// output capped), and whether it changed anything.
fn scrub_in_place(secrets: &[String], value: &mut Value) -> Scrubbed {
    if crate::security::secret_redaction::redact_value(value, secrets) {
        Scrubbed::Redacted
    } else {
        Scrubbed::Clean
    }
}

fn merge(a: Scrubbed, b: Scrubbed) -> Scrubbed {
    if a == Scrubbed::Redacted || b == Scrubbed::Redacted {
        Scrubbed::Redacted
    } else {
        Scrubbed::Clean
    }
}

/// What a transport hands on for `answer`: its values removed, and the fixed
/// refusal in its place when the set overflowed or an `error.code` is one of
/// them.
pub(crate) fn scrub_answer(
    needles: &NeedleSet,
    answer: crate::Result<JsonRpcResponse>,
) -> crate::Result<JsonRpcResponse> {
    match answer {
        Ok(mut response) => match scrub_response_with(needles, &mut response) {
            Scrubbed::Refuse => Err(refusal(needles)),
            _ => Ok(response),
        },
        Err(mut error) => match scrub_error(needles, &mut error) {
            // The retry classification is kept: a transient refusal stays
            // transient (design: envelope).
            Scrubbed::Refuse => Err(match (refusal(needles), error) {
                (
                    crate::Error::JsonRpc { code, message, .. },
                    crate::Error::JsonRpcRetryable { status, .. },
                ) => crate::Error::JsonRpcRetryable {
                    code,
                    message,
                    status,
                    data: None,
                },
                (refused, _) => refused,
            }),
            _ => Err(error),
        },
    }
}

/// A response carrying the fixed refusal, under the answer's own `id` so the
/// caller still gets its answer.
pub(crate) fn refused_response(
    needles: &NeedleSet,
    id: Option<crate::protocol::RequestId>,
) -> JsonRpcResponse {
    let crate::Error::JsonRpc { code, message, .. } = refusal(needles) else {
        unreachable!("the refusal is a JSON-RPC error")
    };
    JsonRpcResponse::error(id, code, message)
}

/// The fixed refusal an answer is replaced with; it names no value.
fn refusal(needles: &NeedleSet) -> crate::Error {
    let message = if needles.overflowed() {
        OVERFLOW_REFUSAL
    } else {
        "the backend's answer contained a credential the gateway injected"
    };
    crate::Error::JsonRpc {
        code: -32603,
        message: message.to_owned(),
        data: None,
    }
}

#[cfg(test)]
#[path = "needles_tests.rs"]
mod tests;
