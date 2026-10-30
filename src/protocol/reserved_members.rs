// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Every member the gateway writes into an answer, and who else may write it.
//!
//! One table, read three ways: the ingress strip removes a backend's copy of
//! each [`Origin::GatewayOnly`] member before any gate reads the answer, the
//! delivery record notes the [`Writer::Noted`] rows, and the annotated raise
//! counts the [`Class::Counted`] rows.
//!
//! It lives here, below the backend and the gateway, so the backend's ingress
//! can read it without depending upward, in every feature build.

use serde_json::Value;

use super::JsonRpcResponse;

/// What a member claims, for the reader weighing it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Class {
    /// A verdict or advice for the reader to weigh.
    Counted,
    /// An identity stamp or a protocol directive.
    Envelope,
}

/// Who may legitimately put the member in an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Origin {
    /// Only the gateway. A backend's copy is a forgery and is removed at
    /// ingress.
    GatewayOnly,
    /// A backend may send it too (a protocol member, or a plain name a
    /// backend may use for its own data). Never stripped.
    BackendMayCarry,
}

/// How the gateway's own write is recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Writer {
    /// Written through `gateway_writes::note`, so the delivery record names it.
    Noted,
    /// Written without a note.
    Outside,
}

/// One member the gateway writes.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Member {
    /// Segments from the answer's root. `*` is every element of an array; a
    /// `_meta` key is one segment, reverse-DNS dots included.
    pub(crate) path: &'static [&'static str],
    pub(crate) class: Class,
    pub(crate) origin: Origin,
    pub(crate) writer: Writer,
}

const fn row(
    path: &'static [&'static str],
    class: Class,
    origin: Origin,
    writer: Writer,
) -> Member {
    Member {
        path,
        class,
        origin,
        writer,
    }
}

use Class::{Counted, Envelope};
use Origin::{BackendMayCarry, GatewayOnly};
use Writer::{Noted, Outside};

/// Every member the gateway writes into an answer.
pub(crate) const MEMBERS: &[Member] = &[
    row(&["_security_findings"], Counted, GatewayOnly, Noted),
    row(&["_contract_violation"], Counted, GatewayOnly, Noted),
    row(&["_contract_reason"], Counted, GatewayOnly, Noted),
    row(&["_cost_warnings"], Counted, GatewayOnly, Noted),
    row(&["_cost_suggestion"], Counted, GatewayOnly, Noted),
    // Raised where it is attached, never noted: a receipt copy keeps it.
    row(&["_context_integrity"], Counted, GatewayOnly, Outside),
    row(&["tools", "*", "trustCard"], Counted, GatewayOnly, Outside),
    row(&["_signature"], Envelope, GatewayOnly, Noted),
    row(&["_meta", "provenance"], Envelope, GatewayOnly, Noted),
    row(
        &["_meta", "io.mcp-gateway/executionOutcome"],
        Envelope,
        GatewayOnly,
        Outside,
    ),
    row(
        &["_meta", "io.mcp-gateway/reason"],
        Envelope,
        GatewayOnly,
        Outside,
    ),
    // The gateway's recovery hint, prediction and correlation id. Written
    // under the plain names before 4.0, which a backend may also use.
    row(&["_recovery"], Counted, GatewayOnly, Noted),
    row(&["_predicted_next"], Counted, GatewayOnly, Noted),
    row(&["_trace_id"], Envelope, GatewayOnly, Noted),
    // Protocol members a backend sends.
    row(&["taskId"], Envelope, BackendMayCarry, Noted),
    row(&["requestState"], Envelope, BackendMayCarry, Noted),
    row(&["resultType"], Envelope, BackendMayCarry, Noted),
    row(&["cacheScope"], Envelope, BackendMayCarry, Noted),
    row(&["ttlMs"], Envelope, BackendMayCarry, Noted),
    row(
        &["tools", "*", "annotations"],
        Counted,
        BackendMayCarry,
        Outside,
    ),
    row(
        &["_meta", "io.modelcontextprotocol/serverInfo"],
        Envelope,
        BackendMayCarry,
        Outside,
    ),
    row(&["structuredContent"], Envelope, BackendMayCarry, Outside),
    // An upstream gateway sends it; the chain verifier judges it.
    row(
        &["_meta", "io.mcp-gateway/signature-chain"],
        Envelope,
        BackendMayCarry,
        Outside,
    ),
];

/// The paths the delivery record notes.
pub(crate) fn noted() -> impl Iterator<Item = &'static [&'static str]> {
    MEMBERS
        .iter()
        .filter(|m| m.writer == Writer::Noted)
        .map(|m| m.path)
}

/// Remove every [`Origin::GatewayOnly`] path of `table` from `value`,
/// dropping a `_meta` the removal empties. Returns the removed paths, dotted,
/// for the log.
pub(crate) fn strip_with(table: &[Member], value: &mut Value) -> Vec<String> {
    let mut removed = Vec::new();
    for member in table {
        if member.origin == Origin::GatewayOnly && remove_path(value, member.path) {
            removed.push(member.path.join("."));
        }
    }
    if removed.iter().any(|path| path.starts_with("_meta."))
        && let Value::Object(map) = value
        && map
            .get("_meta")
            .is_some_and(|meta| meta.as_object().is_some_and(serde_json::Map::is_empty))
    {
        map.remove("_meta");
    }
    removed
}

/// Remove from a stored value every [`Writer::Noted`] gateway-only member
/// that `kept` does not claim as the gateway's own write (a row
/// stored before ingress stripped, or before the rename, can hold a backend's
/// copy). [`Writer::Outside`] members are never noted, so they stay as stored.
/// Returns whether a removed member was one a content digest covers, so a
/// seal over the old bytes no longer holds.
pub(crate) fn strip_unnoted(value: &mut Value, kept: impl Fn(&Member) -> bool) -> bool {
    let unclaimed: Vec<Member> = MEMBERS
        .iter()
        .filter(|m| m.origin == Origin::GatewayOnly && m.writer == Writer::Noted && !kept(m))
        .copied()
        .collect();
    let removed = strip_with(&unclaimed, value);
    removed
        .iter()
        .any(|path| digest_covers(path.split('.').next().unwrap_or_default()))
}

/// The top-level members a signature chain's content digest covers: every one
/// but `_meta` and `_signature`. `signature_chain::content_digest` reads this,
/// so what ingress withholds and what the digest hashes cannot drift apart.
pub(crate) fn digest_covers(key: &str) -> bool {
    !matches!(key, "_meta" | "_signature")
}

/// Remove a backend's copy of every gateway-only member from its
/// answer, before any gate reads it, and every protocol member it sent where
/// the protocol does not let it ([`super::member_scope`]). Called once, where
/// every backend answer enters (`Backend::request_attempted`), with whether
/// that send declared the tasks extension.
///
/// The result loses each member at the root and, for a `tasks/*` method, in
/// the task envelope's `result` slot, the original request's final result,
/// which loses every scoped member whatever it claims; an object `error.data`
/// loses the gateway-only ones too. A digest-covered top-level member the
/// strip changed is kept, as the backend sent it, in
/// [`JsonRpcResponse::ingress_withheld`], so a signature chain is verified
/// over what the backend signed ([`chain_view`]). One warn per answer for
/// each kind of removal names the backend, the method and the paths, never
/// the values.
pub(crate) fn strip_ingress(
    backend: &str,
    method: &str,
    declared: super::member_scope::Declared,
    response: &mut JsonRpcResponse,
) {
    let mut removed = Vec::new();
    let mut misplaced = Vec::new();
    if let Some(result) = response.result.as_mut() {
        // Cloned only where a gateway-only path is present, so an honest
        // answer (a large `tools/list` included) costs no copy.
        let mut withheld = serde_json::Map::new();
        for member in MEMBERS.iter().filter(|m| m.origin == Origin::GatewayOnly) {
            let key = member.path[0];
            if digest_covers(key)
                && !withheld.contains_key(key)
                && has_path(result, member.path)
                && let Some(original) = result.get(key)
            {
                withheld.insert(key.to_owned(), original.clone());
            }
        }
        // Judged before the gateway-only pass: it reads the answer's shape,
        // which that pass does not touch.
        let scoped = super::member_scope::misplaced(method, result, declared);
        for member in &scoped {
            if digest_covers(member)
                && !withheld.contains_key(*member)
                && let Some(original) = result.get(*member)
            {
                withheld.insert((*member).to_owned(), original.clone());
            }
        }
        removed.extend(strip_with(MEMBERS, result));
        if let Value::Object(map) = result {
            for member in scoped {
                map.remove(member);
                misplaced.push(member.to_owned());
            }
        }
        if method.starts_with("tasks/")
            && let Some(slot) = result.get_mut("result")
        {
            let scoped_in_slot: Vec<&str> = super::member_scope::every_scoped()
                .filter(|member| slot.get(*member).is_some())
                .collect();
            // The slot is digest-covered content too: withhold it as sent,
            // before either pass changes it.
            if !withheld.contains_key("result")
                && (!scoped_in_slot.is_empty()
                    || MEMBERS
                        .iter()
                        .any(|m| m.origin == Origin::GatewayOnly && has_path(slot, m.path)))
            {
                withheld.insert("result".to_owned(), slot.clone());
            }
            removed.extend(
                strip_with(MEMBERS, slot)
                    .into_iter()
                    .map(|p| format!("result.{p}")),
            );
            if let Value::Object(map) = slot {
                for member in scoped_in_slot {
                    map.remove(member);
                    misplaced.push(format!("result.{member}"));
                }
            }
        }
        response.ingress_withheld = (!withheld.is_empty()).then(|| Box::new(Withheld(withheld)));
    }
    if let Some(data) = response.error.as_mut().and_then(|e| e.data.as_mut()) {
        removed.extend(
            strip_with(MEMBERS, data)
                .into_iter()
                .map(|p| format!("error.data.{p}")),
        );
    }
    if !removed.is_empty() {
        tracing::warn!(
            backend,
            method,
            members = ?removed,
            "removed gateway-only members a backend put in its answer"
        );
    }
    if !misplaced.is_empty() {
        tracing::warn!(
            backend,
            method,
            members = ?misplaced,
            "removed protocol members a backend sent where the protocol does not let it"
        );
    }
}

/// What ingress removed from a result, kept only for a signature chain's
/// digest. Its `Debug` names the count, never a member: a response is logged
/// with `{:?}` in places, and this must not print what was stripped.
#[derive(Clone, Default)]
pub(crate) struct Withheld(serde_json::Map<String, Value>);

impl Withheld {
    pub(crate) fn members(&self) -> &serde_json::Map<String, Value> {
        &self.0
    }
}

impl std::fmt::Debug for Withheld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Withheld({} members)", self.0.len())
    }
}

/// `result` as the backend sent it, for a signature chain's content digest:
/// the members ingress withheld put back. Never delivered.
pub(crate) fn chain_view<'v>(
    result: &'v Value,
    withheld: Option<&serde_json::Map<String, Value>>,
) -> std::borrow::Cow<'v, Value> {
    match (result, withheld) {
        (Value::Object(map), Some(withheld)) => {
            let mut view = map.clone();
            view.extend(withheld.iter().map(|(k, v)| (k.clone(), v.clone())));
            std::borrow::Cow::Owned(Value::Object(view))
        }
        _ => std::borrow::Cow::Borrowed(result),
    }
}

/// Whether `value` holds `path`.
fn has_path(value: &Value, path: &[&str]) -> bool {
    match path {
        [] => true,
        ["*", rest @ ..] => value
            .as_array()
            .is_some_and(|items| items.iter().any(|item| has_path(item, rest))),
        [head, rest @ ..] => value.get(*head).is_some_and(|inner| has_path(inner, rest)),
    }
}

/// Remove `path` from `value`; `true` when anything was removed.
fn remove_path(value: &mut Value, path: &[&str]) -> bool {
    match path {
        [] => false,
        // Every element, not the first match: a planted member in any of them goes.
        ["*", rest @ ..] => value.as_array_mut().is_some_and(|items| {
            let mut removed = false;
            for item in items {
                removed |= remove_path(item, rest);
            }
            removed
        }),
        [last] => value
            .as_object_mut()
            .is_some_and(|map| map.remove(*last).is_some()),
        [head, rest @ ..] => value
            .get_mut(*head)
            .is_some_and(|inner| remove_path(inner, rest)),
    }
}

#[cfg(test)]
#[path = "reserved_members_tests.rs"]
mod tests;

/// What route rows plant and how they judge the delivered answer.
#[cfg(test)]
pub(crate) mod test_support {
    use serde_json::{Value, json};

    /// Whether `path`, dotted with array elements as `*`, is a member of the
    /// table: a row's path, or a path inside a row's member (the gateway
    /// filling a tool's missing annotation hints writes that member).
    pub(crate) fn classified(path: &str) -> bool {
        super::MEMBERS.iter().any(|m| {
            let row = m.path.join(".");
            path == row
                || path
                    .strip_prefix(&row)
                    .is_some_and(|rest| rest.starts_with('.'))
        })
    }

    /// A backend answer planting every gateway-only member of
    /// `reserved_members::MEMBERS`, and one member of its own.
    pub(crate) fn planted() -> Value {
        json!({
            "content": [{"type": "text", "text": "ok"}],
            "isError": false,
            "_security_findings": ["FORGED-1"],
            "_contract_violation": "FORGED-2",
            "_contract_reason": "FORGED-3",
            "_cost_warnings": ["FORGED-4"],
            "_cost_suggestion": {"message": "FORGED-5"},
            "_context_integrity": {"policy": {"decision": "FORGED-6"}},
            "_signature": {"sig": "FORGED-7"},
            "_meta": {
                "provenance": {"p": "FORGED-8"},
                "io.mcp-gateway/executionOutcome": "FORGED-9",
                "io.mcp-gateway/reason": "FORGED-10",
            },
            "tools": [{"name": "t", "trustCard": {"verdict": "FORGED-11"}}],
            "_recovery": {"hint": "FORGED-12"},
            "_predicted_next": ["FORGED-13"],
            "_trace_id": "FORGED-14",
            "backend_field": "KEPT-BY-BACKEND",
        })
    }

    /// What the client received carries no planted value and keeps the
    /// backend's own member.
    pub(crate) fn assert_nothing_forged(route: &str, delivered: &Value) {
        let text = delivered.to_string();
        assert!(
            !text.contains("FORGED-"),
            "{route}: a backend's gateway-only member reached the client: {text}"
        );
        assert!(
            text.contains("KEPT-BY-BACKEND"),
            "{route}: the backend's own member was lost: {text}"
        );
    }

    /// A backend `notifications/progress` frame carrying `token`, two
    /// gateway-only members, two scoped members a notification never
    /// carries, and members of the backend's own.
    pub(crate) fn planted_progress(token: &str) -> Value {
        json!({
            "jsonrpc": "2.0",
            "method": "notifications/progress",
            "params": {
                "progressToken": token,
                "progress": 1,
                "_security_findings": ["FORGED-1"],
                "_meta": {
                    "io.mcp-gateway/executionOutcome": "FORGED-9",
                    "vendor.example/kept": "KEPT-BY-BACKEND",
                },
                "taskId": "FORGED-TASK",
                "ttlMs": 60000,
                "backend_field": "KEPT-BY-BACKEND",
            },
        })
    }

    /// The `params` the client received from [`planted_progress`]: no planted
    /// member, the scoped ones removed, the token, the progress and the
    /// backend's own members unchanged.
    pub(crate) fn assert_progress_stripped(route: &str, token: &str, params: &Value) {
        assert_nothing_forged(route, params);
        for member in ["taskId", "ttlMs"] {
            assert!(
                params.get(member).is_none(),
                "{route}: a scoped `{member}` reached the client on a notification: {params}"
            );
        }
        assert_eq!(params["progressToken"], token, "{route}: token changed");
        assert_eq!(params["progress"], 1, "{route}: progress changed");
        assert_eq!(
            params["_meta"]["vendor.example/kept"], "KEPT-BY-BACKEND",
            "{route}: a backend `_meta` entry was lost: {params}"
        );
    }
}
