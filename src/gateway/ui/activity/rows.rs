// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What an Activity row is. One function per kind builds it by naming its
//! fields, never by copying the entry, so a field a writer adds later is not
//! served until it is named here. Filters and the Developer scope read the
//! entry the same way.

use chrono::{DateTime, FixedOffset};
use serde_json::{Map, Value};

use super::reader::{Line, Which};
use crate::gateway::authz::BackendGrant;
use crate::security::decision_record::{Decision, read};
use crate::security::transparency_log::signature::signature_state;

/// The kinds Activity lists. Other records (identity-propagation mints and
/// refusals, event lifecycle, segment housekeeping) carry free text U2 has
/// no rule for, and are not listed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    Call,
    Config,
    AdminAction,
    /// A call an identity grant refused that has no invocation record of its
    /// own: read from its grant decision record, listed as a blocked call.
    Refusal,
}

impl Kind {
    /// A call, or a refused call read from its grant decision: the kinds that
    /// name a server, a tool and a caller.
    pub(super) const fn is_call(self) -> bool {
        matches!(self, Self::Call | Self::Refusal)
    }

    fn as_str(self) -> &'static str {
        match self {
            // A refusal is a blocked call; only its source record differs.
            Self::Call | Self::Refusal => "call",
            Self::Config => "config",
            Self::AdminAction => "admin_action",
        }
    }
}

/// A call's outcome as the feed groups it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FeedOutcome {
    Ok,
    Failed,
    Blocked,
}

impl FeedOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Failed => "failed",
            Self::Blocked => "blocked",
        }
    }
}

fn str_field<'a>(entry: &'a Value, key: &str) -> Option<&'a str> {
    entry.get(key).and_then(Value::as_str)
}

pub(super) fn kind_of(line: &Line) -> Option<Kind> {
    let e = &line.entry;
    match line.log {
        Which::Governance => {
            (str_field(e, "kind") == Some("control_plane_audit")).then_some(Kind::Config)
        }
        // A grant decision is a row only when it is a denial whose writer
        // recorded that the call got no invocation record of its own. A
        // record without the field (written before it existed) counts as
        // recorded, so no call is ever listed twice.
        Which::Invocation
            if str_field(e, "kind") == Some(crate::decisions::GRANT_DECISION_KIND) =>
        {
            (str_field(e, "outcome") == Some("denied")
                && e.get("invocation_recorded") == Some(&Value::Bool(false)))
            .then_some(Kind::Refusal)
        }
        Which::Invocation => match str_field(e, "event") {
            Some("admin_action") => Some(Kind::AdminAction),
            Some(_) => None,
            // A call record is the one kind with a request hash and no
            // event, action or type marker.
            None => (e.get("request_hash").is_some()
                && e.get("action").is_none()
                && e.get("type").is_none())
            .then_some(Kind::Call),
        },
    }
}

fn feed_outcome(entry: &Value) -> Option<FeedOutcome> {
    match str_field(entry, "outcome")? {
        "ok" => Some(FeedOutcome::Ok),
        "tool_error" | "error" => Some(FeedOutcome::Failed),
        "denied" | "invalid" => Some(FeedOutcome::Blocked),
        _ => None,
    }
}

/// A row's id: `<counter>-<16 hex of entry_hash>`, `g`-prefixed for the
/// governance log, so the receipt knows which log to seek.
pub(super) fn row_id(line: &Line) -> Option<String> {
    let counter = line.entry.get("counter")?.as_u64()?;
    let hash = str_field(&line.entry, "entry_hash")?.strip_prefix("sha256:")?;
    let prefix = hash.get(..16)?;
    Some(match line.log {
        Which::Invocation => format!("{counter}-{prefix}"),
        Which::Governance => format!("g{counter}-{prefix}"),
    })
}

fn copy(row: &mut Map<String, Value>, entry: &Value, keys: &[&str]) {
    for key in keys {
        if let Some(v) = entry.get(*key) {
            row.insert((*key).to_string(), v.clone());
        }
    }
}

/// The row for `line`, or `None` for a kind Activity does not list.
pub(super) fn row(line: &Line, secret: Option<&[u8]>) -> Option<Value> {
    let kind = kind_of(line)?;
    let e = &line.entry;
    let mut row = Map::new();
    row.insert("id".into(), row_id(line)?.into());
    row.insert("kind".into(), kind.as_str().into());
    copy(
        &mut row,
        e,
        &["counter", "timestamp", "prev_entry_hash", "entry_hash"],
    );
    row.insert(
        "signature".into(),
        serde_json::to_value(signature_state(e, secret)).unwrap_or(Value::Null),
    );
    match kind {
        Kind::Call => {
            copy(
                &mut row,
                e,
                &[
                    "error_code",
                    "server",
                    "tool",
                    "route",
                    "trace_id",
                    "request_hash",
                    "response_hash",
                ],
            );
            if let Some(o) = feed_outcome(e) {
                row.insert("outcome".into(), o.as_str().into());
            }
            let mut who = Map::new();
            if let Some(w) = e.get("who") {
                copy(
                    &mut who,
                    w,
                    &["credential_kind", "account", "authority", "subject"],
                );
            }
            row.insert("who".into(), who.into());
            let decision = read::decision_evidence(e);
            row.insert("findings".into(), findings_value(decision.as_ref()));
            if decision.is_some_and(|d| d.request_findings_truncated) {
                row.insert("findings_truncated".into(), true.into());
            }
        }
        Kind::Refusal => {
            copy(&mut row, e, &["server", "tool", "trace_id"]);
            row.insert("outcome".into(), FeedOutcome::Blocked.as_str().into());
            let mut decision = Map::new();
            copy(
                &mut decision,
                e,
                &["reason", "scope", "capability", "grant_id"],
            );
            row.insert("decision".into(), decision.into());
            let mut who = Map::new();
            if let Some(w) = e.get("who") {
                copy(&mut who, w, &["account", "authority", "subject"]);
            }
            row.insert("who".into(), who.into());
        }
        Kind::Config => {
            copy(&mut row, e, &["action", "actor_id", "target_id"]);
            row.insert("outcome".into(), "change".into());
        }
        Kind::AdminAction => {
            copy(
                &mut row,
                e,
                &["surface", "route", "method", "http_status", "tool"],
            );
            row.insert("outcome".into(), "change".into());
        }
    }
    Some(row.into())
}

/// A call's request-side findings, from its decision record alone: the
/// reader's line when there is no list to show, else the list. A record with
/// no decision predates them. The row and the receipt's decision both read
/// findings here, so the two always agree.
pub(super) fn findings_value(decision: Option<&Decision>) -> Value {
    let Some(decision) = decision else {
        return read::NOT_RECORDED_BY_VERSION.into();
    };
    read::findings_line(decision).map_or_else(
        || serde_json::to_value(&decision.request_findings).unwrap_or(Value::Null),
        Value::from,
    )
}

/// The list's filters, AND-ed. `None` is no filter on that field.
#[derive(Debug, Default, Clone)]
pub(super) struct Filter {
    pub(super) outcome: Option<FeedOutcome>,
    pub(super) server: Option<String>,
    pub(super) caller: Option<String>,
    pub(super) q: Option<String>,
    /// Exact `decision.rule_id`; a record with no readable decision has none.
    pub(super) rule: Option<String>,
    pub(super) from: Option<DateTime<FixedOffset>>,
    pub(super) to: Option<DateTime<FixedOffset>>,
}

impl Filter {
    /// Whether `line` (of `kind`) passes every filter.
    pub(super) fn matches(&self, line: &Line, kind: Kind) -> bool {
        let e = &line.entry;
        let who_account = || e.get("who").and_then(|w| str_field(w, "account"));
        if let Some(want) = self.outcome
            && (!kind.is_call() || feed_outcome(e) != Some(want))
        {
            return false;
        }
        if let Some(server) = &self.server {
            let have = match kind {
                Kind::Call | Kind::Refusal => str_field(e, "server"),
                Kind::Config => str_field(e, "target_id"),
                Kind::AdminAction => None,
            };
            if have != Some(server.as_str()) {
                return false;
            }
        }
        if let Some(caller) = &self.caller {
            let have = match kind {
                Kind::Call | Kind::Refusal | Kind::AdminAction => who_account(),
                Kind::Config => str_field(e, "actor_id"),
            };
            if have != Some(caller.as_str()) {
                return false;
            }
        }
        if let Some(q) = &self.q {
            let tool = str_field(e, "tool");
            let hit = tool.is_some_and(|t| t.contains(q.as_str()))
                || (kind.is_call() && str_field(e, "trace_id") == Some(q.as_str()));
            if !hit {
                return false;
            }
        }
        if let Some(rule) = &self.rule
            && !read::matches_rule(e, rule)
        {
            return false;
        }
        if self.from.is_some() || self.to.is_some() {
            // An untimed row is outside every time range.
            let Some(t) =
                str_field(e, "timestamp").and_then(|t| DateTime::parse_from_rfc3339(t).ok())
            else {
                return false;
            };
            if self.from.is_some_and(|from| t < from) || self.to.is_some_and(|to| t > to) {
                return false;
            }
        }
        true
    }
}

/// A Developer's own rows: calls whose verified `(authority, subject)` is the
/// caller's. Never `who.principal`, which changes on every token refresh; a
/// row with no verified subject, and every config or admin row, is no one's.
pub(super) fn owned_by(line: &Line, kind: Kind, issuer: &str, subject: &str) -> bool {
    kind.is_call()
        && line.entry.get("who").is_some_and(|w| {
            str_field(w, "authority") == Some(issuer) && str_field(w, "subject") == Some(subject)
        })
}

/// Whether a row lies inside the backend scope `backends`. Fail closed: only
/// a call names its backend (`server`). Config rows are grant and policy
/// changes and admin actions are gateway-wide, so neither is in any scope.
pub(super) fn in_scope(line: &Line, kind: Kind, backends: &[String]) -> bool {
    kind.is_call()
        && str_field(&line.entry, "server")
            .is_some_and(|server| BackendGrant::of_list(backends).admits(server))
}

#[cfg(test)]
#[path = "rows_tests.rs"]
mod tests;
