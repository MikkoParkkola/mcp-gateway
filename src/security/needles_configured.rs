// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A backend's configured credentials pinned into its set, and stored
//! answers scrubbed on the way out against every set the registry retains.

use std::sync::atomic::Ordering;

use serde_json::Value;

use crate::security::secret_redaction::holds_no_needle;

use super::{
    ECHO_REFUSAL, JsonRpcResponse, Lifetime, MAX_NEEDLES, NeedleSet, REFUSAL_CODE,
    SHORT_VALUE_BYTES, Scrubbed, refusal, refusal_message, scrub_response_with, scrub_text,
    sent_count,
};

/// Whether a configured value is held: an explicit one at any length, an
/// inferred one only when it is long enough to be safely treated as a
/// secret. Load counts these against its cap.
pub(crate) fn holds(secret: &crate::config::configured_secrets::ConfiguredSecret) -> bool {
    secret.origin == crate::config::configured_secrets::SecretOrigin::Explicit
        || secret.value.len() >= SHORT_VALUE_BYTES
}

/// What a pin does with values the set holds as configured that `secrets`
/// lacks.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Superseded {
    /// Left configured: the instance holding them may still be the one
    /// registered.
    Kept,
    /// Their grace starts now.
    Demoted,
}

impl NeedleSet {
    /// Adds `secrets` as configured values without demoting any: run before
    /// an instance is published, when the registration can still be refused
    /// and the instance it replaces may go on serving. [`Self::pin_configured`]
    /// runs once the instance is registered.
    pub(crate) fn add_configured(
        &self,
        backend: &str,
        secrets: &crate::config::configured_secrets::ConfiguredSecrets,
    ) {
        self.pin(backend, secrets, Superseded::Kept);
    }

    /// Makes `secrets` the backend's configured values, as one swap: each is
    /// held for as long as it stays configured, and a value configured before
    /// but not now counts from this moment, so an echo of a just-rotated
    /// credential is still removed until its grace has passed. An inferred
    /// value too short to be safely treated as a secret is left out and its
    /// field named once; an explicit one is held at any length and named once.
    /// Superseded values past the bound on sent values make the set refuse
    /// until enough of them retire, as a refused send does.
    pub(crate) fn pin_configured(
        &self,
        backend: &str,
        secrets: &crate::config::configured_secrets::ConfiguredSecrets,
    ) {
        self.pin(backend, secrets, Superseded::Demoted);
    }

    fn pin(
        &self,
        backend: &str,
        secrets: &crate::config::configured_secrets::ConfiguredSecrets,
        superseded: Superseded,
    ) {
        for secret in secrets.iter() {
            if holds(secret) {
                self.warn_if_short(backend, &secret.field, &secret.value);
            } else if self.short_warned.lock().insert(secret.field.clone()) {
                tracing::warn!(
                    backend,
                    field = %secret.field,
                    bytes = secret.value.len(),
                    "not redacted: too short to be treated as a secret; write it \
                     as an env: reference to mark it secret"
                );
            }
        }
        let wanted: Vec<&str> = secrets
            .iter()
            .filter(|secret| holds(secret))
            .map(|secret| secret.value.as_str())
            .collect();
        let mut values = self.values.write();
        let now = tokio::time::Instant::now();
        let mut changed = false;
        if superseded == Superseded::Demoted {
            for held in values.iter_mut() {
                if held.lifetime == Lifetime::Configured && !wanted.contains(&held.value.as_str()) {
                    held.lifetime = Lifetime::Grace;
                    held.last_sent = now;
                    changed = true;
                }
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
            // A configured value is always taken: never a refusal.
            let _ = self.admit(&mut values, value, Lifetime::Configured, now);
        }
        if changed {
            self.version.fetch_add(1, Ordering::SeqCst);
        }
        // Reloads that each supersede values add to the sent count: past the
        // bound the set refuses until they retire.
        let first_refusal =
            sent_count(&values) > MAX_NEEDLES && !self.overflowed.swap(true, Ordering::SeqCst);
        drop(values);
        if first_refusal {
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
///
/// A provenance seal in the answer goes out only when nothing is removed:
/// each seal was made over the stored bytes, and its readable payload
/// carries their unsalted digest, so next to a redacted body it would let a
/// client test guesses of the removed value, and it no longer covers what is
/// served. The seals come off before the scrub, which can rename the keys
/// that hold them, and the stored answer, seals included, is put back
/// whole when the scrub removes nothing. Receipts stay: they hold no digest
/// of the result.
pub(crate) fn scrub_stored(
    sets: &[std::sync::Arc<NeedleSet>],
    response: &mut JsonRpcResponse,
) -> Scrubbed {
    let sealed = response
        .result
        .as_ref()
        .filter(|result| holds_seal(result))
        .cloned();
    let removed = match (&sealed, response.result.as_mut()) {
        (Some(_), Some(result)) => mutant!("seal_nodrop", Vec::new(), drop_seals(result)),
        _ => Vec::new(),
    };
    let outcome = scrub_unsealed(sets, response);
    let Some(original) = sealed else {
        return outcome;
    };
    if outcome != Scrubbed::Clean {
        return outcome;
    }
    if mutant!(
        "seal_needle",
        true,
        removed.iter().all(|seal| {
            sets.iter()
                .all(|set| holds_no_needle(seal, &set.snapshot()))
        })
    ) {
        response.result = Some(original);
        return Scrubbed::Clean;
    }
    // A held value inside a seal itself: the seal stays off, and the answer
    // is no longer the stored one.
    crate::gateway::delivery_facts::echo_redacted();
    Scrubbed::Redacted
}

/// Whether `value` may hold a provenance seal: a `public_signature` member
/// of a `_meta.provenance`, or text naming one (a chain or playbook answer
/// carries its steps' sealed results as JSON text). Only cheap: a false
/// positive costs one copy of the answer.
fn holds_seal(value: &Value) -> bool {
    let mut pending = vec![value];
    while let Some(next) = pending.pop() {
        match next {
            Value::Object(object) => {
                if object
                    .get("_meta")
                    .and_then(|meta| meta.get("provenance"))
                    .is_some_and(|provenance| provenance.get("public_signature").is_some())
                {
                    return true;
                }
                pending.extend(object.values());
            }
            Value::Array(items) => pending.extend(items),
            Value::String(text) if text.contains("public_signature") => return true,
            _ => {}
        }
    }
    false
}

/// Remove every provenance seal from `value`, at any depth and inside JSON
/// text, and return the removed signatures. Text holding a seal is parsed,
/// unsealed and written back compact (it goes out only in an answer the scrub
/// changed). Iterative over each value; text inside text recurses once per
/// level of escaping, and each level doubles the escapes, so the depth stays
/// a few dozen at most.
fn drop_seals(value: &mut Value) -> Vec<Value> {
    let mut removed = Vec::new();
    let mut pending = vec![value];
    while let Some(next) = pending.pop() {
        match next {
            Value::Object(object) => {
                if let Some(seal) = object
                    .get_mut("_meta")
                    .and_then(|meta| meta.get_mut("provenance"))
                    .and_then(Value::as_object_mut)
                    .and_then(|provenance| provenance.remove("public_signature"))
                {
                    removed.push(seal);
                }
                pending.extend(object.values_mut());
            }
            Value::Array(items) => pending.extend(items.iter_mut()),
            Value::String(text)
                if mutant!("seal_text", false, text.contains("public_signature")) =>
            {
                if let Ok(mut inner) = serde_json::from_str::<Value>(text) {
                    let seals = drop_seals(&mut inner);
                    if !seals.is_empty() {
                        *text = inner.to_string();
                        removed.extend(seals);
                    }
                }
            }
            _ => {}
        }
    }
    removed
}

/// [`scrub_stored`] once its seals are off.
fn scrub_unsealed(sets: &[std::sync::Arc<NeedleSet>], response: &mut JsonRpcResponse) -> Scrubbed {
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
        let formed = {
            let message = response
                .error
                .as_ref()
                .map(|error| Value::String(error.message.clone()));
            let parts: Vec<&Value> = [
                response.result.as_ref(),
                message.as_ref(),
                response
                    .error
                    .as_ref()
                    .and_then(|error| error.data.as_ref()),
            ]
            .into_iter()
            .flatten()
            .collect();
            formed_by_another(sets, &parts)
        };
        echo_redacted();
        if let Some(set) = formed {
            *response =
                JsonRpcResponse::error(response.id.clone(), REFUSAL_CODE, refusal_message(set));
            echo_refusal_built();
            return Scrubbed::Refuse;
        }
    }
    outcome
}

/// The first set one of whose values the scrub formed in `parts`: each set
/// ran on what the sets before it left, and a marker written next to other
/// text can complete a value. Rescans only an answer something was removed
/// from.
fn formed_by_another<'a>(
    sets: &'a [std::sync::Arc<NeedleSet>],
    parts: &[&Value],
) -> Option<&'a std::sync::Arc<NeedleSet>> {
    let formed = sets.iter().find(|set| {
        let compiled = set.snapshot();
        parts.iter().any(|part| !holds_no_needle(part, &compiled))
    });
    if formed.is_some() {
        tracing::warn!(
            "a stored answer was refused: removing one held value from it formed another"
        );
    }
    formed
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
        if let Some(set) = formed_by_another(sets, &[&Value::String(text.clone())]) {
            crate::gateway::delivery_facts::echo_refusal_built();
            return Err(refusal(set));
        }
    }
    Ok(outcome)
}

/// Mutant-only: run `scrub`, then put back every object seal `value` held
/// before it, at the same path (a serve site that keeps its seals).
#[cfg(mutants)]
fn seal_paths(value: &Value) -> Vec<(String, Value)> {
    let mut out = Vec::new();
    let mut pending = vec![(String::new(), value)];
    while let Some((path, next)) = pending.pop() {
        match next {
            Value::Object(object) => {
                if let Some(seal) = object
                    .get("_meta")
                    .and_then(|meta| meta.get("provenance"))
                    .and_then(|provenance| provenance.get("public_signature"))
                {
                    out.push((path.clone(), seal.clone()));
                }
                for (key, item) in object {
                    let key = key.replace('~', "~0").replace('/', "~1");
                    pending.push((format!("{path}/{key}"), item));
                }
            }
            Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    pending.push((format!("{path}/{index}"), item));
                }
            }
            _ => {}
        }
    }
    out
}

#[cfg(mutants)]
fn put_seals_back(value: &mut Value, seals: Vec<(String, Value)>) {
    for (path, seal) in seals {
        if let Some(provenance) = value
            .pointer_mut(&format!("{path}/_meta/provenance"))
            .and_then(Value::as_object_mut)
        {
            provenance.insert("public_signature".to_owned(), seal);
        }
    }
}

#[cfg(mutants)]
pub(crate) fn keep_seals_value<T>(value: &mut Value, scrub: impl FnOnce(&mut Value) -> T) -> T {
    let seals = seal_paths(value);
    let out = scrub(value);
    put_seals_back(value, seals);
    out
}

#[cfg(mutants)]
pub(crate) fn keep_seals_response<T>(
    response: &mut JsonRpcResponse,
    scrub: impl FnOnce(&mut JsonRpcResponse) -> T,
) -> T {
    let seals = response.result.as_ref().map(seal_paths).unwrap_or_default();
    let out = scrub(response);
    if let Some(result) = response.result.as_mut() {
        put_seals_back(result, seals);
    }
    out
}
