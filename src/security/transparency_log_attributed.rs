// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7116.MIN.1: one invocation record with extra attribution fields.
//!
//! The three D1 writers (meta invoke, direct route, meta pre-dispatch refusal)
//! hand their attribution here as a JSON map, so no public signature changes.

use std::io;

use chrono::Utc;
use serde_json::{Map, Value};

use super::{CorrelationKey, CorrelationSource, TransparencyLogger};
use crate::gateway::session_id::session_fp;
use crate::security::audit::{AuditEnvelope, InvocationTarget};

/// Most tenant hashes one record carries; past it the record keeps the first
/// `MAX_RECORDED_TENANTS` sorted hashes and says how many there were in
/// `tenants_total`. Bounds what attribution adds to a record (about 19 KiB),
/// so a wide tenant set cannot push a record past the append limit.
pub(crate) const MAX_RECORDED_TENANTS: usize = 1024;

/// The `route` of a settlement record ([`TransparencyLogger::log_task_settlement`]).
const TASK_RECOVERY_ROUTE: &str = "task_recovery";
/// Its `correlation_source`: the `session_id` field holds the gateway task id.
const TASK_ID_CORRELATION: &str = "task_id";

impl<'a> CorrelationKey<'a> {
    /// MIK-7215.CONTROL.3/.3a: the caller's W3C trace id, then the session
    /// id, then the id minted for this invocation. The modern HTTP route
    /// carries "no session" as `""`; an empty id is no key, or every
    /// stateless call would correlate as one (MIK-7640).
    pub(crate) fn ladder(otel: Option<&'a str>, session: Option<&'a str>, minted: &'a str) -> Self {
        match (otel, session.filter(|session| !session.is_empty())) {
            (Some(id), _) => Self {
                id,
                source: CorrelationSource::OtelTraceId,
            },
            (None, Some(id)) => Self {
                id,
                source: CorrelationSource::SessionId,
            },
            (None, None) => Self {
                id: minted,
                source: CorrelationSource::TraceId,
            },
        }
    }
}

/// What an invocation entry says about the call, beside the hashes.
struct Record<'a> {
    route: &'a str,
    correlation_source: &'a str,
    session_id: String,
    server: &'a str,
    tool: Option<&'a str>,
}

/// The invocation fields an `extra` key may not name, whether or not this
/// call's record carries them.
const INVOCATION_FIELDS: [&str; 9] = [
    "caller",
    "correlation_source",
    "request_hash",
    "response_hash",
    "route",
    "server",
    "session_id",
    "timestamp",
    "tool",
];

impl TransparencyLogger {
    /// As [`Self::log_invocation_correlated`], with `extra` fields (`tenants`,
    /// `data_classes`, ...) inside the chained, signed record.
    ///
    /// # Errors
    ///
    /// As [`Self::log_invocation_correlated`], and when an `extra` key is a
    /// chain, envelope or invocation field: attribution never overwrites what
    /// the record says about the call.
    pub(crate) fn log_invocation_attributed(
        &self,
        key: CorrelationKey<'_>,
        envelope: &AuditEnvelope,
        target: InvocationTarget<'_>,
        request_hash: &str,
        response_hash: Option<&str>,
        extra: Map<String, Value>,
    ) -> io::Result<()> {
        let fp = (key.source == CorrelationSource::SessionId).then(|| session_fp(key.id));
        let record = Record {
            route: target.route.as_str(),
            correlation_source: key.source.as_str(),
            session_id: fp.unwrap_or_else(|| key.id.into()),
            server: target.server,
            tool: target.tool,
        };
        self.append_record(record, envelope, request_hash, response_hash, extra)
    }

    /// MIN.1 gap 1: the settlement record of a recovered upstream task.
    /// Route `task_recovery`, joined to its submission record by `task_id`,
    /// which is also its correlation key. Crate-private record strings: the
    /// public `InvocationRoute` and `CorrelationSource` stay as they are.
    ///
    /// # Errors
    ///
    /// As [`Self::log_invocation_attributed`].
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn log_task_settlement(
        &self,
        task_id: &str,
        envelope: &AuditEnvelope,
        server: &str,
        tool: &str,
        request_hash: &str,
        response_hash: Option<&str>,
        mut extra: Map<String, Value>,
    ) -> io::Result<()> {
        extra.insert("task_id".into(), task_id.into());
        let record = Record {
            route: TASK_RECOVERY_ROUTE,
            correlation_source: TASK_ID_CORRELATION,
            session_id: task_id.into(),
            server,
            tool: Some(tool),
        };
        self.append_record(record, envelope, request_hash, response_hash, extra)
    }

    fn append_record(
        &self,
        record: Record<'_>,
        envelope: &AuditEnvelope,
        request_hash: &str,
        response_hash: Option<&str>,
        mut extra: Map<String, Value>,
    ) -> io::Result<()> {
        Self::reject_reserved_keys(&extra)?;
        // MIK-7646: the overflow count is derived here alone, never supplied.
        if extra.contains_key("tenants_total") {
            return Err(io::Error::other(
                "attribution field `tenants_total` is written only by the writer",
            ));
        }
        cap_tenants(&mut extra);

        // Domain fields for an invocation entry. `counter`, `prev_entry_hash`,
        // `entry_hash`, and `sig`/`key_id` are added by `append_core`.
        let mut fields = Map::new();
        // `caller` is kept for one major version as a copy of `who.account`.
        fields.insert("caller".into(), envelope.who.account().into());
        fields.insert(
            "correlation_source".into(),
            record.correlation_source.into(),
        );
        fields.insert("request_hash".into(), request_hash.into());
        // A failed call has no response to hash.
        if let Some(response_hash) = response_hash {
            fields.insert("response_hash".into(), response_hash.into());
        }
        fields.insert("route".into(), record.route.into());
        fields.insert("server".into(), record.server.into());
        fields.insert("session_id".into(), record.session_id.into());
        fields.insert("timestamp".into(), Utc::now().to_rfc3339().into());
        if let Some(tool) = record.tool {
            fields.insert("tool".into(), tool.into());
        }
        if let Some(name) = extra
            .keys()
            .find(|k| INVOCATION_FIELDS.contains(&k.as_str()))
        {
            return Err(io::Error::other(format!(
                "attribution field `{name}` would overwrite an invocation field"
            )));
        }
        fields.extend(extra);

        self.append_core(fields, envelope, false).map(|_| ())
    }
}

/// Sort `tenants` and keep at most [`MAX_RECORDED_TENANTS`], naming the true
/// count in `tenants_total` when any were dropped.
fn cap_tenants(extra: &mut Map<String, Value>) {
    let Some(Value::Array(tenants)) = extra.get_mut("tenants") else {
        return;
    };
    tenants.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
    let total = tenants.len();
    if total > MAX_RECORDED_TENANTS {
        tenants.truncate(MAX_RECORDED_TENANTS);
        extra.insert("tenants_total".into(), total.into());
    }
}
