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

/// One value and when it was last sent (unix seconds, from the crate clock).
struct Held {
    value: String,
    last_sent: u64,
}

/// One backend name's injected values. Never printed: `Debug` names the count.
pub(crate) struct NeedleSet {
    values: RwLock<Vec<Held>>,
    grace: Duration,
    overflowed: AtomicBool,
}

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

/// Now, in unix seconds; a clock before the epoch reads 0 (nothing retires).
fn now_secs() -> u64 {
    crate::clock::unix_secs().unwrap_or(0)
}

impl NeedleSet {
    /// An empty set whose values retire `grace` after their last send.
    pub(crate) fn with_grace(grace: Duration) -> Self {
        Self {
            values: RwLock::new(Vec::new()),
            grace,
            overflowed: AtomicBool::new(false),
        }
    }

    fn retired(&self, held: &Held, now: u64) -> bool {
        now.saturating_sub(held.last_sent) > self.grace.as_secs()
    }

    /// Adds `value`, or renews its last send (empty values are never
    /// injected, so never added). Retired values are dropped first; past the
    /// bound the set fails closed and keeps every value inside its grace.
    pub(crate) fn insert(&self, backend: &str, value: &str) {
        if value.is_empty() {
            return;
        }
        let now = now_secs();
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
            last_sent: now,
        });
    }

    /// Whether the set refused a value: every frame is then withheld.
    pub(crate) fn overflowed(&self) -> bool {
        self.overflowed.load(Ordering::SeqCst)
    }

    /// The values still inside their grace. A retired value is not removed
    /// from an answer: the documented residual (UPGRADING).
    fn snapshot(&self) -> Vec<String> {
        let now = now_secs();
        self.values
            .read()
            .iter()
            .filter(|held| !self.retired(held, now))
            .map(|held| held.value.clone())
            .collect()
    }
}

/// What [`ingress_scrub`] did to a frame.
#[derive(Debug, PartialEq, Eq)]
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

/// Redacts a peer refusal's message and data (`Error::JsonRpc`,
/// `Error::JsonRpcRetryable`); other errors carry no backend text.
pub(crate) fn scrub_error(needles: &NeedleSet, error: &mut crate::Error) -> Scrubbed {
    if needles.overflowed() {
        return Scrubbed::Refuse;
    }
    let secrets = needles.snapshot();
    if secrets.is_empty() {
        return Scrubbed::Clean;
    }
    match error {
        crate::Error::JsonRpc { message, data, .. }
        | crate::Error::JsonRpcRetryable { message, data, .. } => {
            let mut text = Value::String(std::mem::take(message));
            let first = scrub_in_place(&secrets, &mut text);
            *message = match text {
                Value::String(redacted) => redacted,
                other => other.to_string(),
            };
            let second = scrub_option(&secrets, data);
            merge(first, second)
        }
        _ => Scrubbed::Clean,
    }
}

fn scrub_response(secrets: &[String], response: &mut JsonRpcResponse) -> Scrubbed {
    let mut outcome = scrub_option(secrets, &mut response.result);
    if let Some(error) = response.error.as_mut() {
        if secrets
            .iter()
            .any(|secret| secret == &error.code.to_string())
        {
            return Scrubbed::Refuse;
        }
        let mut text = Value::String(std::mem::take(&mut error.message));
        outcome = merge(outcome, scrub_in_place(secrets, &mut text));
        error.message = match text {
            Value::String(redacted) => redacted,
            other => other.to_string(),
        };
        outcome = merge(outcome, scrub_option(secrets, &mut error.data));
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
    // ponytail: a whole-value clone to detect a change; the one-pass matcher
    // (PR 1, DELTA-2/3) replaces it with match spans and copies only a string
    // that holds one.
    let before = value.clone();
    crate::security::secret_redaction::redact_value(value, secrets);
    if *value == before {
        Scrubbed::Clean
    } else {
        Scrubbed::Redacted
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
            Scrubbed::Refuse => Err(refusal(needles)),
            _ => Err(error),
        },
    }
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
