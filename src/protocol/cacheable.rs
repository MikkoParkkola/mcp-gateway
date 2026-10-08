// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Cacheability of a result, and how completed results are told from interim
//! ones (MCP 2026-07-28).

use serde_json::Value;

/// Who may reuse a cached response.
///
/// From the schema: `public` means *"the response does not contain
/// user-specific data. Any client or intermediary (e.g., shared gateway,
/// caching proxy) MAY cache the response and serve it across authorization
/// contexts."* `private` means it *"MAY be cached and reused only within the
/// same authorization context. Caches MUST NOT be shared across authorization
/// contexts."*
///
/// Read that first sentence again from a gateway's position: `public` is a
/// claim about **every future caller**, made by a server that has seen exactly
/// one. So the burden runs one way — a response is private unless it provably
/// does not depend on who asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheScope {
    /// Uninhabited until a method is proven invariant across authorization
    /// contexts: no expression builds this value, so the gateway cannot claim
    /// `public`. Allowing it one day means replacing the payload with a proof
    /// type, a design change that review will see (MIK-7211.PARENT.6).
    Public(std::convert::Infallible),
    /// Reusable only within the authorization context that fetched it.
    Private,
}

impl CacheScope {
    /// The wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public(never) => match never {},
            Self::Private => "private",
        }
    }
}

/// The methods this gateway has assessed, and what each one warrants.
///
/// Every row is private and the default below is private too, so the table
/// changes no answer today. What it carries is which methods were *assessed*:
/// without it, a method nobody considered and a method considered and found
/// caller-dependent are the same silence, and a later `public` is a default
/// nobody had to argue for rather than an edit someone has to make.
const SCOPE_TABLE: &[(&str, CacheScope)] = &[
    // Lists: filtered by the presented credential's scope — an API key decides
    // which backends, prompts and resources a caller is shown.
    ("tools/list", CacheScope::Private),
    ("prompts/list", CacheScope::Private),
    ("resources/list", CacheScope::Private),
    ("resources/templates/list", CacheScope::Private),
    // Not a list: reachability of a URI is decided per caller, so the body is
    // too.
    ("resources/read", CacheScope::Private),
    // Discovery: the gateway's own document lists the capabilities this
    // caller is shown, and a relayed backend document may vary by credential
    // just the same (MIK-8047).
    ("server/discover", CacheScope::Private),
];

/// The methods this gateway has assessed, and what each one warrants.
///
/// Exposed because *assessed* is not observable through [`scope_for_method`]:
/// every row is private and so is the fallback, so a row that was deleted and a
/// row nobody ever wrote return the same answer. The set is the artifact the
/// criterion asks for, and reading it is the only way to ask whether a method
/// is in it.
#[must_use]
pub fn assessed_methods() -> &'static [(&'static str, CacheScope)] {
    SCOPE_TABLE
}

/// How long a client may consider a list or discovery result fresh. A
/// freshness hint, not a promise: `listChanged` notifications remain the
/// authority on change, and this only stops a client re-listing on every turn.
pub const LIST_TTL_MS: u64 = 60_000;

/// Write the `CacheableResult` pair onto a result: `ttlMs` as given and
/// `cacheScope` from `method`'s assessed scope. The one place the pair is
/// written, so the modern shaper and discovery cannot drift apart on it.
pub(crate) fn write_cache_hints(
    result: &mut serde_json::Map<String, Value>,
    method: &str,
    ttl_ms: u64,
) {
    result.insert("ttlMs".to_string(), serde_json::json!(ttl_ms));
    result.insert(
        "cacheScope".to_string(),
        Value::String(scope_for_method(method).as_str().to_string()),
    );
}

/// What `method`'s result may claim on the wire.
///
/// An unlisted method is private. That is the direction the burden runs in
/// [`CacheScope`]: `public` is a claim about callers this gateway has never
/// seen, and a method nobody assessed has nobody's proof behind it.
#[must_use]
pub fn scope_for_method(method: &str) -> CacheScope {
    assessed_methods()
        .iter()
        .find(|(name, _)| *name == method)
        .map_or(CacheScope::Private, |(_, scope)| *scope)
}

/// Whether one object carries a `cacheScope` that is not exactly `"private"`.
fn scope_off(object: &Value) -> bool {
    object
        .get("cacheScope")
        .is_some_and(|scope| scope.as_str() != Some("private"))
}

/// The retained-result slot of a raw task envelope: an object with a `taskId`
/// of any type (a malformed backend's may not be a string, MIK-7702) beside a
/// `status` the typed task wire accepts, whose `result` is an object. A
/// `taskId` and `result` alone are tool data (MIK-7734): every envelope this
/// gateway writes has a status. Only this one top-level slot is followed;
/// nested tool data is never touched.
fn task_result_slot(result: &Value) -> Option<&Value> {
    result.get("taskId")?;
    // A string only: serde also reads a unit variant from `{"completed": null}`.
    let status = result.get("status")?.as_str()?;
    serde_json::from_value::<crate::protocol::tasks::TaskStatus>(status.into()).ok()?;
    result.get("result").filter(|slot| slot.is_object())
}

/// Whether `result`, or the result a task envelope retains, claims a scope
/// other than `"private"`.
fn scope_needs_clamp(result: &Value) -> bool {
    scope_off(result) || task_result_slot(result).is_some_and(scope_off)
}

/// Make a result about to leave the gateway claim no scope but `private`.
///
/// A `cacheScope` that is not `"private"` becomes `"private"`. For `"public"`
/// that is a downgrade the specification permits; for `null`, a number or a
/// string the specification does not define it normalizes a malformed field.
/// A result with no such key is left alone (legacy results have none). Nested
/// tool data is never touched; the one slot followed is the result a raw task
/// envelope retains.
pub(crate) fn clamp_delivered_scope(result: &mut Value) {
    clamp_top_level(result);
    // One slot, never recursively: the retained result's own data is tool data.
    if task_result_slot(result).is_some_and(scope_off)
        && let Some(slot) = result.get_mut("result")
    {
        clamp_top_level(slot);
    }
}

/// Rewrite one object's own `cacheScope` to `private` when it is anything else.
fn clamp_top_level(object: &mut Value) {
    if scope_off(object)
        && let Some(object) = object.as_object_mut()
    {
        object.insert("cacheScope".to_owned(), Value::String("private".to_owned()));
    }
}

/// `serialize_with` for a wire slot that carries a result: serializes the
/// value as [`clamp_delivered_scope`] would leave it.
#[expect(
    clippy::ref_option,
    reason = "serde's serialize_with passes the field as &Option<Value>"
)]
pub(crate) fn serialize_delivered_result<S: serde::Serializer>(
    result: &Option<Value>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    use serde::Serialize;
    match result {
        Some(value) if scope_needs_clamp(value) => {
            let mut clamped = value.clone();
            clamp_delivered_scope(&mut clamped);
            clamped.serialize(serializer)
        }
        Some(value) => value.serialize(serializer),
        None => serializer.serialize_none(),
    }
}

/// `serialize_with` for `JsonRpcError.data`: diagnostic data, not a result, so
/// only its own top-level `cacheScope` is clamped; nothing it nests is
/// followed, task-shaped or not (MIK-7702).
#[expect(
    clippy::ref_option,
    reason = "serde's serialize_with passes the field as &Option<Value>"
)]
pub(crate) fn serialize_delivered_error_data<S: serde::Serializer>(
    data: &Option<Value>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    use serde::Serialize;
    match data {
        Some(value) if scope_off(value) => {
            let mut clamped = value.clone();
            clamp_top_level(&mut clamped);
            clamped.serialize(serializer)
        }
        Some(value) => value.serialize(serializer),
        None => serializer.serialize_none(),
    }
}

/// Clamp the `result` and `error.data` of one JSON-RPC response; requests
/// (a string `method`, MIK-7734) and notifications (no `id`) pass unchanged.
/// A `method` that is not a string makes no request, so `"method": null` on a
/// response cannot opt it out of the clamp.
fn clamp_response_envelope(payload: &mut Value) {
    if payload.get("id").is_none() || payload.get("method").is_some_and(Value::is_string) {
        return;
    }
    if let Some(result) = payload.get_mut("result") {
        clamp_delivered_scope(result);
    }
    // Error data is not a cacheable result, but it claims no scope either
    // (MIK-7702).
    if let Some(data) = payload.pointer_mut("/error/data") {
        clamp_top_level(data);
    }
}

/// The SSE `data` of a `message` event: the payload as text, with the `result`
/// and `error.data` of a JSON-RPC response, or of each response in a batch,
/// clamped by [`clamp_delivered_scope`].
pub(crate) fn message_event_data(payload: &Value) -> String {
    let mut clamped = payload.clone();
    match &mut clamped {
        Value::Array(batch) => batch.iter_mut().for_each(clamp_response_envelope),
        single => clamp_response_envelope(single),
    }
    clamped.to_string()
}

/// The `resultType` of a result, defaulting as the specification requires.
///
/// > Clients **MUST** treat results from earlier-protocol servers that omit the
/// > field as `"complete"`.
///
/// Every pre-2026 backend omits it. Reading the absence as anything else would
/// make every legacy backend's answer unusable, which is why the default is
/// specified rather than left to the implementer.
///
/// That default covers an **omitted** field and nothing else. A field that is
/// present but not a string — `null`, a number, an object — is a malformed
/// result, not a legacy one, and answering `"complete"` for it would let a
/// backend opt out of the finality check by sending the field wrong. Those
/// return `""`, which no specified `resultType` can equal.
#[must_use]
pub fn result_type_of(result: &Value) -> &str {
    match result.get("resultType") {
        None => "complete",
        Some(present) => present.as_str().unwrap_or(""),
    }
}

/// Whether `result` is a finished answer, and so safe to cache and replay.
///
/// Anything else — `"input_required"` above all — is a step in an exchange that
/// is still running. Replaying one from a cache returns the *request* rather
/// than the answer, and the call can never finish. Because
/// [`result_type_of`] defaults a missing field to `"complete"`, every
/// pre-2026 backend's result stays cacheable, as the specification requires.
#[must_use]
pub fn is_final(result: &Value) -> bool {
    result_type_of(result) == "complete"
}

/// Whether `result` is an error (`isError: true`), and so never cached.
///
/// An error is not an answer worth replaying. A gateway refusal (rate limit,
/// open breaker, failed connect) is transient by nature, and a backend's own
/// tool error may clear on the next call; served from a cache, either outlives
/// its cause for the whole TTL and answers every call sharing the key (F26:
/// one 10 ms throttle became 960 replayed refusals). Every response cache asks
/// this in its `set`, beside [`is_final`], so no store site can forget it.
///
/// The response caches that call it are `crate::cache::ResponseCache` (the
/// meta route) and the capability executor's cache. A new cache of tool
/// results must call it too.
#[must_use]
pub(crate) fn is_error(result: &Value) -> bool {
    result.get("isError").and_then(Value::as_bool) == Some(true)
}

#[cfg(test)]
mod tests {
    use super::is_error;
    use serde_json::json;

    /// Only a boolean `true` is an error; an absent, `false` or non-boolean
    /// `isError` stays cacheable, so an ordinary answer is never refused.
    #[test]
    fn only_a_boolean_true_is_error() {
        assert!(is_error(&json!({"isError": true, "content": []})));
        assert!(!is_error(&json!({"isError": false, "content": []})));
        assert!(!is_error(&json!({"content": []})));
        assert!(!is_error(&json!({"isError": "true"})));
        assert!(!is_error(&json!({"isError": 1})));
        assert!(!is_error(&json!([true])));
    }

    /// MIK-8047: a discovery document carries `cacheScope` on both routes, so
    /// its scope is decided in the table rather than defaulted.
    #[test]
    fn discovery_has_an_assessed_row() {
        assert!(
            super::assessed_methods()
                .iter()
                .any(|(name, _)| *name == "server/discover"),
            "server/discover is emitted with a cacheScope but has no assessed row"
        );
    }
}

#[cfg(test)]
mod clamp_tests;
