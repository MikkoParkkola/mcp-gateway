// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A backend's configured credentials pinned into its set, and stored
//! answers scrubbed on the way out against every set the registry retains.

use std::sync::atomic::Ordering;

use serde_json::Value;

use super::{
    ECHO_REFUSAL, JsonRpcResponse, Lifetime, NeedleSet, REFUSAL_CODE, SHORT_VALUE_BYTES, Scrubbed,
    refusal, refusal_message, scrub_response_with, scrub_text,
};

impl NeedleSet {
    /// Makes `secrets` the backend's configured values, as one swap: each is
    /// held for as long as it stays configured, and a value configured before
    /// but not now counts from this moment, so an echo of a just-rotated
    /// credential is still removed until its grace has passed. An inferred
    /// value too short to be safely treated as a secret is left out and its
    /// field named once; an explicit one is held at any length and named once.
    pub(crate) fn pin_configured(
        &self,
        backend: &str,
        secrets: &crate::config::configured_secrets::ConfiguredSecrets,
    ) {
        use crate::config::configured_secrets::SecretOrigin;
        let wanted: Vec<&str> = secrets
            .iter()
            .filter(|secret| {
                if secret.value.len() >= SHORT_VALUE_BYTES {
                    return true;
                }
                match secret.origin {
                    SecretOrigin::Explicit => {
                        self.warn_if_short(backend, &secret.field, &secret.value);
                        true
                    }
                    SecretOrigin::Inferred => {
                        if self.short_warned.lock().insert(secret.field.clone()) {
                            tracing::warn!(
                                backend,
                                field = %secret.field,
                                bytes = secret.value.len(),
                                "not redacted: too short to be treated as a secret; write it \
                                 as an env: reference to mark it secret"
                            );
                        }
                        false
                    }
                }
            })
            .map(|secret| secret.value.as_str())
            .collect();
        let mut values = self.values.write();
        let now = tokio::time::Instant::now();
        let mut changed = false;
        let mut overflowed = false;
        // A value no longer configured is no longer owed; one never installed
        // is protected only by the refusal, until its grace has passed.
        let mut owed = self.owed.lock();
        let before = owed.len();
        owed.retain(|due| wanted.contains(&due.as_str()));
        if owed.len() != before {
            *self.refuse_until.lock() = Some(now + self.grace);
        }
        drop(owed);
        for held in values.iter_mut() {
            if held.lifetime == Lifetime::Configured && !wanted.contains(&held.value.as_str()) {
                held.lifetime = Lifetime::Grace;
                held.last_sent = now;
                changed = true;
            }
        }
        for value in wanted {
            if let Some(held) = values.iter_mut().find(|held| held.value == value) {
                if held.lifetime != Lifetime::Configured {
                    // A value sent once and configured now is promoted, never
                    // held twice; one that had retired is back in the set.
                    held.lifetime = Lifetime::Configured;
                    held.last_sent = now;
                    changed = true;
                }
                continue;
            }
            overflowed |= self.admit(&mut values, value, Lifetime::Configured, now);
        }
        // An unpinning alone can lift the refusal: nothing else would.
        self.settle(&mut values, now);
        if changed {
            self.version.fetch_add(1, Ordering::SeqCst);
        }
        drop(values);
        if overflowed {
            self.warn_overflowed(backend);
        }
    }
}

/// Scrubs a stored answer (a response-cache hit, an idempotency replay, a
/// stored or repeated task result, a task notification) on its way out,
/// against every set in `sets`: the values current now, whatever was
/// current when it was stored. A refusal from any set replaces the answer
/// with the fixed refusal, its id kept. Run on the delivering call's task,
/// so that call's record says what was done.
pub(crate) fn scrub_stored(
    sets: &[std::sync::Arc<NeedleSet>],
    response: &mut JsonRpcResponse,
) -> Scrubbed {
    use crate::gateway::delivery_facts::{echo_redacted, echo_refusal_built};
    let mut outcome = Scrubbed::Clean;
    for set in sets {
        match scrub_response_with(set, response) {
            Scrubbed::Clean => {}
            Scrubbed::Redacted => outcome = Scrubbed::Redacted,
            Scrubbed::Refuse | Scrubbed::Withhold => {
                *response =
                    JsonRpcResponse::error(response.id.clone(), REFUSAL_CODE, refusal_message(set));
                echo_redacted();
                echo_refusal_built();
                return Scrubbed::Refuse;
            }
        }
    }
    if outcome == Scrubbed::Redacted {
        echo_redacted();
    }
    outcome
}

/// [`scrub_stored`] for a stored tool result held as a bare value: it is
/// scrubbed as a response's result. A refusal is the fixed refusal as an
/// error, and the value must not be delivered.
pub(crate) fn scrub_stored_value(
    sets: &[std::sync::Arc<NeedleSet>],
    value: &mut Value,
) -> crate::Result<Scrubbed> {
    let mut response =
        JsonRpcResponse::success(crate::protocol::RequestId::Number(0), std::mem::take(value));
    let outcome = scrub_stored(sets, &mut response);
    match (response.result, response.error) {
        (Some(result), None) => {
            *value = result;
            Ok(outcome)
        }
        (_, error) => Err(crate::Error::JsonRpc {
            code: error.as_ref().map_or(REFUSAL_CODE, |e| e.code),
            message: error.map_or_else(|| ECHO_REFUSAL.to_owned(), |e| e.message),
            data: None,
        }),
    }
}

/// [`scrub_stored`] for a stored error's message text. A refusal is the
/// fixed refusal error, and the stored error must not be delivered.
pub(crate) fn scrub_stored_text(
    sets: &[std::sync::Arc<NeedleSet>],
    text: &mut String,
) -> crate::Result<Scrubbed> {
    let mut outcome = Scrubbed::Clean;
    for set in sets {
        match scrub_text(set, text) {
            Scrubbed::Clean => {}
            Scrubbed::Redacted => outcome = Scrubbed::Redacted,
            Scrubbed::Refuse | Scrubbed::Withhold => {
                crate::gateway::delivery_facts::echo_redacted();
                crate::gateway::delivery_facts::echo_refusal_built();
                return Err(refusal(set));
            }
        }
    }
    if outcome == Scrubbed::Redacted {
        crate::gateway::delivery_facts::echo_redacted();
    }
    Ok(outcome)
}
