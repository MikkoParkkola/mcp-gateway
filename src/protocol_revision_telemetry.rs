// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7218 / RFC-0060 U1: measure which MCP revisions clients speak.
//!
//! Negotiation still defaults a missing `protocolVersion` to `2024-11-05`.
//! Telemetry must not: that default would hide the unattributed share the
//! ticket requires as its own series.
//!
//! Session-keyed: the first observation for a session id wins so initialize
//! plus a later `_meta` stamp cannot double-count.

use std::collections::{BTreeMap, HashSet};
use std::sync::{Mutex, OnceLock};

use serde_json::Value;

/// Wire key for 2026 per-request protocol revision.
pub const META_PROTOCOL_VERSION: &str = "io.modelcontextprotocol/protocolVersion";
/// Wire key for 2026 per-request client identity.
pub const META_CLIENT_INFO: &str = "io.modelcontextprotocol/clientInfo";
/// Client label when neither initialize nor `_meta` named one.
pub const UNATTRIBUTED_CLIENT: &str = "unattributed";
/// Fail-fast: do not freeze the compatibility window below this attribution rate.
pub const ATTRIBUTION_FLOOR: f64 = 0.80;
/// Pre-registered retire threshold (RFC-0060 Decision 2). Written before data.
pub const RETIRE_BELOW_SHARE: f64 = 0.02;

/// Filters that make a `tools/list` result session- or tenant-specific.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ListFilters {
    /// API-key / principal assembly ran.
    pub principal: bool,
    /// Routing-profile assembly ran.
    pub profile: bool,
    /// Session-scoped assembly ran (promoted tools, session id).
    pub session: bool,
}

impl ListFilters {
    /// True when any filter that forbids `cacheScope=public` is on.
    pub fn any(self) -> bool {
        self.principal || self.profile || self.session
    }
}

/// `cacheScope` the 2026-07-28 list result would advertise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheScope {
    /// Unfiltered meta-tool skeleton only.
    Public,
    /// Anything assembled under principal, profile, or session state.
    Private,
}

impl CacheScope {
    /// Wire string the spec uses.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Private => "private",
        }
    }
}

/// One `tools/list` shadow observation. Never attached to the live response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolsListShadow {
    /// Whether a principal filter ran.
    pub principal: bool,
    /// Whether a profile filter ran.
    pub profile: bool,
    /// Whether a session filter ran.
    pub session: bool,
    /// Scope the decision table would emit. Not sent to the client in this spike.
    pub would_emit_cache_scope: CacheScope,
}

/// Process-wide counters plus the session ids already counted.
#[derive(Debug, Default)]
pub struct Registry {
    seen_sessions: HashSet<String>,
    by_revision: BTreeMap<String, u64>,
    by_client: BTreeMap<String, u64>,
    unattributed: u64,
    total: u64,
    shadows: Vec<ToolsListShadow>,
}

/// Snapshot for `/metrics` tests and the Linear table.
#[derive(Debug, Clone, PartialEq)]
pub struct Snapshot {
    /// Sessions whose revision was named on the wire.
    pub by_revision: BTreeMap<String, u64>,
    /// Sessions grouped by client identity (includes `unattributed`).
    pub by_client: BTreeMap<String, u64>,
    /// Sessions with no revision on either path. Own series, not a revision key.
    pub unattributed: u64,
    /// All observed sessions, attributed or not.
    pub total: u64,
}

impl Registry {
    /// Empty counters.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one inbound session. Later observations for the same id are ignored.
    pub fn observe_session(
        &mut self,
        session_id: &str,
        revision: Option<&str>,
        client: &str,
    ) -> bool {
        if !self.seen_sessions.insert(session_id.to_string()) {
            return false;
        }
        self.total += 1;
        let client = if client.is_empty() {
            UNATTRIBUTED_CLIENT
        } else {
            client
        };
        *self.by_client.entry(client.to_string()).or_insert(0) += 1;
        match revision.map(str::trim).filter(|v| !v.is_empty()) {
            Some(rev) => {
                *self.by_revision.entry(rev.to_string()).or_insert(0) += 1;
            }
            None => self.unattributed += 1,
        }
        true
    }

    /// Shadow-log one `tools/list` (not session-deduped: every list is a cache decision).
    pub fn shadow_tools_list(&mut self, filters: ListFilters) -> ToolsListShadow {
        let shadow = ToolsListShadow {
            principal: filters.principal,
            profile: filters.profile,
            session: filters.session,
            would_emit_cache_scope: cache_scope_decision(filters),
        };
        self.shadows.push(shadow.clone());
        shadow
    }

    /// Current counters.
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            by_revision: self.by_revision.clone(),
            by_client: self.by_client.clone(),
            unattributed: self.unattributed,
            total: self.total,
        }
    }

    /// Shadow log, oldest first.
    pub fn shadows(&self) -> &[ToolsListShadow] {
        &self.shadows
    }

    #[cfg(test)]
    #[allow(dead_code)]
    fn reset(&mut self) {
        *self = Self::default();
    }
}

/// Revision the client asked for. `_meta` wins when both are present.
///
/// Missing is `None`. The initialize negotiator's `2024-11-05` default is
/// deliberately not applied here.
pub fn requested_revision(
    initialize_params: Option<&Value>,
    request_meta: Option<&Value>,
) -> Option<String> {
    meta_string(request_meta, META_PROTOCOL_VERSION)
        .or_else(|| {
            initialize_params.and_then(|p| p.get("protocolVersion")?.as_str().map(str::to_string))
        })
        .filter(|s| !s.is_empty())
}

/// Client name from initialize `clientInfo` or 2026 `_meta` clientInfo.
pub fn client_identity(initialize_params: Option<&Value>, request_meta: Option<&Value>) -> String {
    client_info_name(request_meta.and_then(|m| m.get(META_CLIENT_INFO)))
        .or_else(|| client_info_name(initialize_params.and_then(|p| p.get("clientInfo"))))
        .unwrap_or_else(|| UNATTRIBUTED_CLIENT.to_string())
}

fn client_info_name(value: Option<&Value>) -> Option<String> {
    let name = value?.get("name")?.as_str()?.trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

fn meta_string(meta: Option<&Value>, key: &str) -> Option<String> {
    meta?.get(key)?.as_str().map(str::to_string)
}

/// `_meta` may sit on the JSON-RPC request root or on `params`.
pub fn request_meta<'a>(request: &'a Value, params: Option<&'a Value>) -> Option<&'a Value> {
    request
        .get("_meta")
        .or_else(|| params.and_then(|p| p.get("_meta")))
}

/// Decision table from RFC-0060: public only for the unfiltered skeleton.
pub fn cache_scope_decision(filters: ListFilters) -> CacheScope {
    if filters.any() {
        CacheScope::Private
    } else {
        CacheScope::Public
    }
}

/// Hazard the ticket wants raised: `public` advertised over filtered assembly.
pub fn public_over_filtered(filters: ListFilters, scope: CacheScope) -> bool {
    scope == CacheScope::Public && filters.any()
}

/// Attributed sessions / total. Empty window is 0.0, not NaN.
pub fn attribution_rate(snapshot: &Snapshot) -> f64 {
    if snapshot.total == 0 {
        return 0.0;
    }
    let attributed = snapshot.total.saturating_sub(snapshot.unattributed);
    attributed as f64 / snapshot.total as f64
}

/// Revisions below 2% of total. Empty or under-attributed windows return none
/// (RFC-0060 stop criterion: do not narrow on partial data).
pub fn retire_revisions(snapshot: &Snapshot) -> Vec<String> {
    if snapshot.total == 0 || attribution_rate(snapshot) < ATTRIBUTION_FLOOR {
        return Vec::new();
    }
    let total = snapshot.total as f64;
    snapshot
        .by_revision
        .iter()
        .filter(|(_, n)| (**n as f64 / total) < RETIRE_BELOW_SHARE)
        .map(|(rev, _)| rev.clone())
        .collect()
}

/// Markdown table for the Linear comment. Unattributed is its own row, not a revision.
pub fn distribution_table(snapshot: &Snapshot) -> String {
    let mut rows = String::from("| revision | sessions | share |\n| --- | ---: | ---: |\n");
    for (rev, n) in &snapshot.by_revision {
        rows.push_str(&format!(
            "| {rev} | {n} | {:.1}% |\n",
            share(*n, snapshot.total)
        ));
    }
    rows.push_str(&format!(
        "| unattributed | {} | {:.1}% |\n",
        snapshot.unattributed,
        share(snapshot.unattributed, snapshot.total)
    ));
    rows.push_str(&format!("| total | {} | 100% |\n", snapshot.total));
    rows
}

fn share(n: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        (n as f64 / total as f64) * 100.0
    }
}

fn global() -> &'static Mutex<Registry> {
    static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(Registry::new()))
}

/// Record one inbound session on the process registry.
pub fn observe_inbound(
    session_id: &str,
    initialize_params: Option<&Value>,
    request_meta: Option<&Value>,
) {
    let revision = requested_revision(initialize_params, request_meta);
    let client = client_identity(initialize_params, request_meta);
    let mut reg = global().lock().unwrap_or_else(|e| e.into_inner());
    let recorded = reg.observe_session(session_id, revision.as_deref(), &client);
    drop(reg);
    if recorded {
        emit_session_metrics(revision.as_deref(), &client);
    }
}

/// Shadow-log one `tools/list` on the process registry.
pub fn observe_tools_list(filters: ListFilters) -> ToolsListShadow {
    let mut reg = global().lock().unwrap_or_else(|e| e.into_inner());
    let shadow = reg.shadow_tools_list(filters);
    drop(reg);
    tracing::info!(
        principal = shadow.principal,
        profile = shadow.profile,
        session = shadow.session,
        would_emit_cache_scope = shadow.would_emit_cache_scope.as_str(),
        public_over_filtered = public_over_filtered(filters, shadow.would_emit_cache_scope),
        "mcp728.u1 tools/list cacheScope shadow"
    );
    shadow
}

/// Process snapshot for the measurement table.
pub fn global_snapshot() -> Snapshot {
    global()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .snapshot()
}

/// Process shadow log.
pub fn global_shadows() -> Vec<ToolsListShadow> {
    global()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .shadows()
        .to_vec()
}

fn emit_session_metrics(revision: Option<&str>, client: &str) {
    let _ = (revision, client);
    #[cfg(feature = "metrics")]
    {
        if let Some(rev) = revision {
            telemetry_metrics::counter!(
                "mcp_protocol_revision_sessions_total",
                "revision" => rev.to_string(),
                "client" => client.to_string()
            )
            .increment(1);
        } else {
            telemetry_metrics::counter!(
                "mcp_protocol_revision_unattributed_sessions_total",
                "client" => client.to_string()
            )
            .increment(1);
        }
    }
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn reset_global_for_tests() {
    global().lock().unwrap_or_else(|e| e.into_inner()).reset();
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn initialize_protocol_version_is_attributed() {
        let params = json!({"protocolVersion": "2025-06-18", "clientInfo": {"name": "claude"}});
        assert_eq!(
            requested_revision(Some(&params), None).as_deref(),
            Some("2025-06-18")
        );
        assert_eq!(client_identity(Some(&params), None), "claude");
    }

    #[test]
    fn missing_protocol_version_is_unattributed_not_defaulted() {
        let params = json!({"clientInfo": {"name": "old"}});
        assert_eq!(requested_revision(Some(&params), None), None);
        assert_eq!(requested_revision(None, None), None);
    }

    #[test]
    fn meta_protocol_version_wins_over_initialize() {
        let params = json!({"protocolVersion": "2025-06-18"});
        let meta = json!({META_PROTOCOL_VERSION: "2026-07-28"});
        assert_eq!(
            requested_revision(Some(&params), Some(&meta)).as_deref(),
            Some("2026-07-28")
        );
    }

    #[test]
    fn unattributed_is_its_own_series() {
        let mut reg = Registry::new();
        reg.observe_session("s1", Some("2025-11-25"), "claude");
        reg.observe_session("s2", None, "unknown");
        let snap = reg.snapshot();
        assert_eq!(snap.total, 2);
        assert_eq!(snap.unattributed, 1);
        assert_eq!(snap.by_revision.get("2025-11-25"), Some(&1));
        assert!(!snap.by_revision.contains_key("unattributed"));
        assert!((attribution_rate(&snap) - 0.5).abs() < f64::EPSILON);
        let table = distribution_table(&snap);
        assert!(table.contains("| unattributed | 1 |"));
        assert!(!table.contains("| unattributed | 1 |\n| unattributed |"));
    }

    #[test]
    fn same_session_is_not_double_counted() {
        let mut reg = Registry::new();
        assert!(reg.observe_session("s1", Some("2025-06-18"), "a"));
        assert!(!reg.observe_session("s1", Some("2026-07-28"), "a"));
        assert_eq!(reg.snapshot().total, 1);
        assert_eq!(reg.snapshot().by_revision.get("2025-06-18"), Some(&1));
    }

    #[test]
    fn cache_scope_public_only_when_unfiltered() {
        assert_eq!(
            cache_scope_decision(ListFilters::default()),
            CacheScope::Public
        );
        let filtered = ListFilters {
            principal: true,
            profile: false,
            session: false,
        };
        assert_eq!(cache_scope_decision(filtered), CacheScope::Private);
        assert!(!public_over_filtered(filtered, CacheScope::Private));
        assert!(public_over_filtered(filtered, CacheScope::Public));
    }

    #[test]
    fn two_percent_rule_does_not_fire_on_underattributed_or_empty() {
        let empty = Registry::new().snapshot();
        assert!(retire_revisions(&empty).is_empty());
        let mut low = Registry::new();
        low.observe_session("a", Some("2025-06-18"), "c");
        low.observe_session("b", None, "c");
        // 50% attributed < 80% floor
        assert!(retire_revisions(&low.snapshot()).is_empty());
    }

    #[test]
    fn two_percent_rule_retires_only_below_floor_when_attributed() {
        let mut reg = Registry::new();
        for i in 0..99 {
            reg.observe_session(&format!("keep-{i}"), Some("2025-11-25"), "c");
        }
        reg.observe_session("rare", Some("2024-11-05"), "c");
        let retired = retire_revisions(&reg.snapshot());
        assert_eq!(retired, vec!["2024-11-05".to_string()]);
        assert!(!retired.iter().any(|r| r == "2025-11-25"));
    }

    #[test]
    fn shadow_tools_list_records_filters_and_would_be_scope() {
        let mut reg = Registry::new();
        let shadow = reg.shadow_tools_list(ListFilters {
            principal: false,
            profile: true,
            session: true,
        });
        assert!(shadow.profile && shadow.session);
        assert_eq!(shadow.would_emit_cache_scope, CacheScope::Private);
        assert_eq!(reg.shadows().len(), 1);
    }
}
