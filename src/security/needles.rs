// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The values a backend's secret rules resolved to, and the scrub that
//! removes them from what that backend sends back (MIK-9035).
//!
//! One set per backend name, shared by every instance a reload builds under
//! that name, so a value a rotation retired is still removed from a late
//! answer. Values are only ever added; at [`MAX_NEEDLES`] the set fails closed
//! instead of dropping one.

use std::sync::atomic::{AtomicBool, Ordering};

use parking_lot::RwLock;
use serde_json::Value;

use crate::protocol::{JsonRpcMessage, JsonRpcResponse};

/// The most distinct values one backend name may hold. Past it every frame
/// from that backend is refused rather than a value dropped.
pub(crate) const MAX_NEEDLES: usize = 1024;

/// What the refusal says when the set is full.
pub(crate) const OVERFLOW_REFUSAL: &str =
    "the backend's answer was withheld: too many distinct injected secrets to redact";

/// One backend name's injected values. Never printed: `Debug` names the count.
#[derive(Default)]
pub(crate) struct NeedleSet {
    values: RwLock<Vec<String>>,
    overflowed: AtomicBool,
}

impl std::fmt::Debug for NeedleSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NeedleSet({} values)", self.values.read().len())
    }
}

impl NeedleSet {
    /// Adds `value` (empty ones are never injected, so never added). Past the
    /// bound the set is marked overflowed and keeps every value it has.
    pub(crate) fn insert(&self, backend: &str, value: &str) {
        if value.is_empty() {
            return;
        }
        if self.values.read().iter().any(|held| held == value) {
            return;
        }
        let mut values = self.values.write();
        if values.iter().any(|held| held == value) {
            return;
        }
        if values.len() >= MAX_NEEDLES {
            if !self.overflowed.swap(true, Ordering::SeqCst) {
                tracing::warn!(
                    backend,
                    bound = MAX_NEEDLES,
                    "too many distinct injected secrets to redact; this backend's answers are withheld"
                );
            }
            return;
        }
        values.push(value.to_owned());
    }

    /// Whether the set refused a value: every frame is then withheld.
    pub(crate) fn overflowed(&self) -> bool {
        self.overflowed.load(Ordering::SeqCst)
    }

    /// The values held now.
    fn snapshot(&self) -> Vec<String> {
        self.values.read().clone()
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
