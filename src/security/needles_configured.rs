// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A backend's configured credentials pinned into its set, and stored
//! answers scrubbed on the way out against every set the registry retains.

use std::sync::atomic::Ordering;

use serde_json::Value;

use crate::security::secret_redaction::holds_no_needle;
use crate::trust::seal_strip::{Strip, strip_seals};

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
/// While any set holds a value, a stored answer goes out with no provenance
/// seal, whether or not the scrub removes anything. Each seal was made over
/// the stored bytes and its readable payload carries their unsalted digest:
/// next to a redacted body it would let a client test guesses of the removed
/// value, and it would no longer cover what is served. The seals come off
/// before the scrub, which can rename the keys that hold them, in objects
/// and in JSON text alike. A redacted answer holding text that names a seal
/// but will not parse, so a seal may remain in it, is refused. Receipts
/// stay: they hold no digest of the result. Keeping seals on answers the
/// scrub leaves alone was tried and dropped: every way of proving the answer
/// unchanged had a hole (numbers, renamed keys, rewritten text).
///
/// Threat model: the leak is a digest the gateway itself computed over the
/// unredacted result. Only the gateway writes such a seal, as a
/// `_meta.provenance.public_signature` member of a result, or inside the
/// chain and playbook step JSON text `serde_json` writes (which never escapes
/// a key). A seal a backend wrote, escaped or not, or anything in an error
/// body, carries no digest the gateway made over this result, and a backend
/// that wants to leak its own output can do so directly; neither is in
/// scope here.
pub(crate) fn scrub_stored(
    sets: &[std::sync::Arc<NeedleSet>],
    response: &mut JsonRpcResponse,
) -> Scrubbed {
    let armed = sets.iter().any(|set| !set.snapshot().is_empty());
    let strip = match response.result.as_mut() {
        Some(result) if armed => strip_seals(result),
        // A value added after the check above can still redact this answer:
        // nothing was stripped, so a redaction is refused below.
        Some(_) => Strip {
            complete: false,
            removed: false,
        },
        None => Strip {
            complete: true,
            removed: false,
        },
    };
    let outcome = scrub_unsealed(sets, response);
    if outcome == Scrubbed::Redacted && !strip.complete {
        use crate::gateway::delivery_facts::echo_refusal_built;
        let message = sets
            .first()
            .map_or(ECHO_REFUSAL, |set| refusal_message(set));
        *response = JsonRpcResponse::error(response.id.clone(), REFUSAL_CODE, message);
        echo_refusal_built();
        return Scrubbed::Refuse;
    }
    outcome
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
