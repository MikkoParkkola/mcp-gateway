// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7218 / RFC-0060 U1: measure which MCP revisions clients speak.
//!
//! Modern MCP has no protocol session, so the only comparable unit across the
//! legacy and modern eras is an inbound JSON-RPC request. Modern requests carry
//! their identity in `_meta`; legacy HTTP requests carry a protocol header, and
//! legacy stdio follow-ups reuse the bounded attribution learned at initialize.

use std::collections::{BTreeMap, VecDeque};
use std::fmt::Write as _;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

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
/// Minimum production observation window required by MIK-7218.
pub const MIN_MEASUREMENT_WINDOW: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// Hard bound for legacy session attribution retained in process memory.
const MAX_SESSION_ATTRIBUTIONS: usize = 4_096;
/// Revisions accepted as bounded metric labels. Everything else is `other`.
pub const MEASURED_REVISIONS: &[&str] = &[
    "2026-07-28",
    "2025-11-25",
    "2025-06-18",
    "2025-03-26",
    "2024-11-05",
    "2024-10-07",
];
/// Label for a present but unknown or malformed revision.
pub const OTHER_REVISION: &str = "other";

/// Inbound transport for a negotiated session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// Streamable HTTP route.
    Http,
    /// Process-local stdio server.
    Stdio,
    /// Direct library/test caller without a transport surface.
    Internal,
}

impl Transport {
    /// Stable, finite metric label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Stdio => "stdio",
            Self::Internal => "internal",
        }
    }
}

/// Filters that make a `tools/list` result session- or tenant-specific.
// These are four independent, bounded metric dimensions, not mutually
// exclusive states; an enum would obscure valid combinations.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ListFilters {
    /// API-key / principal assembly ran.
    pub principal: bool,
    /// Routing-profile assembly ran.
    pub profile: bool,
    /// Session-scoped assembly ran (promoted tools, session id).
    pub session: bool,
    /// Request-local query or URL override changed the list.
    pub request: bool,
}

impl ListFilters {
    /// True when any filter that forbids `cacheScope=public` is on.
    pub fn any(self) -> bool {
        self.principal || self.profile || self.session || self.request
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
// Mirrors ListFilters in test snapshots so each independent dimension remains
// directly assertable.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolsListShadow {
    /// Whether a principal filter ran.
    pub principal: bool,
    /// Whether a profile filter ran.
    pub profile: bool,
    /// Whether a session filter ran.
    pub session: bool,
    /// Whether request-local input changed the assembled list.
    pub request: bool,
    /// Scope the decision table would emit. Not sent to the client in this spike.
    pub would_emit_cache_scope: CacheScope,
}

#[derive(Debug, Clone, Copy)]
struct SessionAttribution {
    requested_revision: Option<&'static str>,
    negotiated_revision: &'static str,
    client: &'static str,
}

/// Process-wide counters. Every metric key is normalized to a finite label set.
#[derive(Debug, Default)]
pub struct Registry {
    /// Requested revisions. Kept as `by_revision` for the pre-registered table.
    by_revision: BTreeMap<String, u64>,
    by_negotiated_revision: BTreeMap<String, u64>,
    by_client: BTreeMap<String, u64>,
    by_transport: BTreeMap<String, u64>,
    unattributed: u64,
    total: u64,
    shadow_counts: [u64; 16],
    session_attributions: BTreeMap<u64, SessionAttribution>,
    session_order: VecDeque<u64>,
}

/// Snapshot for `/metrics` tests and the Linear table.
#[derive(Debug, Clone, PartialEq)]
pub struct Snapshot {
    /// Sessions whose revision was named on the wire.
    pub by_revision: BTreeMap<String, u64>,
    /// Sessions grouped by the revision the gateway actually served.
    pub by_negotiated_revision: BTreeMap<String, u64>,
    /// Sessions grouped by client identity (includes `unattributed`).
    pub by_client: BTreeMap<String, u64>,
    /// Sessions grouped by the bounded transport label.
    pub by_transport: BTreeMap<String, u64>,
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

    /// Record one inbound request observation.
    pub fn observe_request(
        &mut self,
        requested_revision: Option<&str>,
        negotiated_revision: &str,
        client: &str,
        transport: Transport,
    ) {
        self.total += 1;
        let client = client_label(client);
        *self.by_client.entry(client.to_string()).or_insert(0) += 1;
        *self
            .by_transport
            .entry(transport.as_str().to_string())
            .or_insert(0) += 1;
        let negotiated = revision_label(Some(negotiated_revision)).unwrap_or(OTHER_REVISION);
        *self
            .by_negotiated_revision
            .entry(negotiated.to_string())
            .or_insert(0) += 1;
        match revision_label(requested_revision) {
            Some(rev) => {
                *self.by_revision.entry(rev.to_string()).or_insert(0) += 1;
            }
            None => self.unattributed += 1,
        }
    }

    fn bind_session(&mut self, session_id: &str, attribution: SessionAttribution) {
        let key = session_key(session_id);
        if !self.session_attributions.contains_key(&key) {
            while self.session_attributions.len() >= MAX_SESSION_ATTRIBUTIONS {
                let Some(oldest) = self.session_order.pop_front() else {
                    break;
                };
                self.session_attributions.remove(&oldest);
            }
            self.session_order.push_back(key);
        }
        self.session_attributions.insert(key, attribution);
    }

    fn session_attribution(&self, session_id: Option<&str>) -> Option<SessionAttribution> {
        self.session_attributions
            .get(&session_key(session_id?))
            .copied()
    }

    /// Shadow-log one `tools/list` (not session-deduped: every list is a cache decision).
    pub fn shadow_tools_list(&mut self, filters: ListFilters) -> ToolsListShadow {
        let shadow = ToolsListShadow {
            principal: filters.principal,
            profile: filters.profile,
            session: filters.session,
            request: filters.request,
            would_emit_cache_scope: cache_scope_decision(filters),
        };
        self.shadow_counts[shadow_index(filters)] += 1;
        shadow
    }

    /// Current counters.
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            by_revision: self.by_revision.clone(),
            by_negotiated_revision: self.by_negotiated_revision.clone(),
            by_client: self.by_client.clone(),
            by_transport: self.by_transport.clone(),
            unattributed: self.unattributed,
            total: self.total,
        }
    }

    /// Count for one of the finite `tools/list` filter combinations.
    pub fn shadow_count(&self, filters: ListFilters) -> u64 {
        self.shadow_counts[shadow_index(filters)]
    }

    #[cfg(test)]
    #[allow(dead_code)]
    fn reset(&mut self) {
        *self = Self::default();
    }
}

fn session_key(session_id: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    session_id.hash(&mut hasher);
    hasher.finish()
}

fn shadow_index(filters: ListFilters) -> usize {
    usize::from(filters.principal)
        | (usize::from(filters.profile) << 1)
        | (usize::from(filters.session) << 2)
        | (usize::from(filters.request) << 3)
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
        .filter(|s| !s.trim().is_empty())
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
    meta?
        .get(key)?
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn revision_label(revision: Option<&str>) -> Option<&'static str> {
    let revision = revision.map(str::trim).filter(|v| !v.is_empty())?;
    MEASURED_REVISIONS
        .iter()
        .copied()
        .find(|candidate| *candidate == revision)
        .or(Some(OTHER_REVISION))
}

fn client_label(client: &str) -> &'static str {
    let client = client.trim().to_ascii_lowercase();
    if client.is_empty() || client == UNATTRIBUTED_CLIENT {
        UNATTRIBUTED_CLIENT
    } else if client.contains("claude") {
        "claude"
    } else if client.contains("codex") {
        "codex"
    } else if client.contains("cursor") {
        "cursor"
    } else if client.contains("vscode") || client.contains("visual studio code") {
        "vscode"
    } else if client.contains("chatgpt") {
        "chatgpt"
    } else {
        "other"
    }
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
    ratio(attributed, snapshot.total)
}

/// Revisions whose conservative upper-bound share is below 2% after one week.
///
/// Every unattributed observation is treated as if it belonged to the revision
/// being evaluated. This prevents missing attribution from making an older
/// revision look safer to remove. Empty, short, or under-attributed windows
/// return no candidates.
pub fn retire_revisions(snapshot: &Snapshot, elapsed: Duration) -> Vec<String> {
    if elapsed < MIN_MEASUREMENT_WINDOW
        || snapshot.total == 0
        || attribution_rate(snapshot) < ATTRIBUTION_FLOOR
    {
        return Vec::new();
    }
    crate::protocol::SUPPORTED_VERSIONS
        .iter()
        .filter(|rev| {
            let count = snapshot.by_revision.get(**rev).copied().unwrap_or(0);
            ratio(count.saturating_add(snapshot.unattributed), snapshot.total) < RETIRE_BELOW_SHARE
        })
        .map(|rev| (*rev).to_string())
        .collect()
}

/// Markdown table for the Linear comment. Unattributed is its own row, not a revision.
pub fn distribution_table(snapshot: &Snapshot) -> String {
    let mut rows = String::from("| revision | sessions | share |\n| --- | ---: | ---: |\n");
    for (rev, n) in &snapshot.by_revision {
        writeln!(rows, "| {rev} | {n} | {:.1}% |", share(*n, snapshot.total))
            .expect("writing to a String cannot fail");
    }
    writeln!(
        rows,
        "| unattributed | {} | {:.1}% |",
        snapshot.unattributed,
        share(snapshot.unattributed, snapshot.total)
    )
    .expect("writing to a String cannot fail");
    writeln!(
        rows,
        "| total | {} | {:.1}% |",
        snapshot.total,
        if snapshot.total == 0 { 0.0 } else { 100.0 }
    )
    .expect("writing to a String cannot fail");
    rows
}

fn share(n: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        ratio(n, total) * 100.0
    }
}

#[allow(clippy::cast_precision_loss)]
fn ratio(n: u64, total: u64) -> f64 {
    // The counters remain exact integers; floating point is used only for
    // human-facing shares and the pre-registered percentage threshold.
    n as f64 / total as f64
}

fn global() -> &'static Mutex<Registry> {
    static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(Registry::new()))
}

/// Record one parsed inbound JSON-RPC request.
///
/// Metric labels and remembered legacy attribution are bounded. Session IDs are
/// reduced to hashes and retained only for a fixed-capacity cache.
pub fn observe_inbound_request(
    request: &Value,
    params: Option<&Value>,
    method: &str,
    protocol_header: Option<&str>,
    session_id: Option<&str>,
    transport: Transport,
) {
    let meta = request_meta(request, params);
    let initialize_params = (method == "initialize").then_some(params).flatten();
    let explicit_requested = requested_revision(initialize_params, meta)
        .or_else(|| protocol_header.map(str::trim).map(str::to_string))
        .filter(|value| !value.is_empty());
    let explicit_client = client_identity(initialize_params, meta);

    let mut reg = global()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let previous = reg.session_attribution(session_id);
    let requested_label = revision_label(explicit_requested.as_deref())
        .or_else(|| previous.and_then(|item| item.requested_revision));
    let client = if explicit_client == UNATTRIBUTED_CLIENT {
        previous.map_or(UNATTRIBUTED_CLIENT, |item| item.client)
    } else {
        client_label(&explicit_client)
    };
    let negotiated_label = if method == "initialize" {
        let client_version = initialize_params
            .and_then(|value| value.get("protocolVersion"))
            .and_then(Value::as_str)
            .unwrap_or(crate::protocol::PROTOCOL_VERSION);
        revision_label(Some(crate::protocol::negotiate_version(client_version)))
            .unwrap_or(OTHER_REVISION)
    } else {
        previous
            .map(|item| item.negotiated_revision)
            .or(requested_label)
            .unwrap_or(OTHER_REVISION)
    };

    if method == "initialize"
        && let Some(session_id) = session_id
    {
        reg.bind_session(
            session_id,
            SessionAttribution {
                requested_revision: requested_label,
                negotiated_revision: negotiated_label,
                client,
            },
        );
    }
    reg.observe_request(requested_label, negotiated_label, client, transport);
    drop(reg);
    emit_session_metrics(requested_label, negotiated_label, client, transport);
    tracing::info!(
        requested_revision = requested_label.unwrap_or("unattributed"),
        negotiated_revision = negotiated_label,
        client,
        transport = transport.as_str(),
        "mcp728.u1 inbound request observation"
    );
}

/// Shadow-log one `tools/list` on the process registry.
pub fn observe_tools_list(filters: ListFilters) -> ToolsListShadow {
    let mut reg = global()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let shadow = reg.shadow_tools_list(filters);
    drop(reg);
    emit_tools_list_metrics(filters, shadow.would_emit_cache_scope);
    tracing::info!(
        principal = shadow.principal,
        profile = shadow.profile,
        session = shadow.session,
        request = shadow.request,
        would_emit_cache_scope = shadow.would_emit_cache_scope.as_str(),
        public_over_filtered = public_over_filtered(filters, shadow.would_emit_cache_scope),
        "mcp728.u1 tools/list cacheScope shadow"
    );
    shadow
}

fn emit_tools_list_metrics(filters: ListFilters, scope: CacheScope) {
    let _ = (filters, scope);
    #[cfg(feature = "metrics")]
    telemetry_metrics::counter!(
        "mcp_tools_list_cache_scope_shadow_total",
        "principal" => filters.principal.to_string(),
        "profile" => filters.profile.to_string(),
        "session" => filters.session.to_string(),
        "request" => filters.request.to_string(),
        "would_emit_cache_scope" => scope.as_str()
    )
    .increment(1);
}

/// Process snapshot for the measurement table.
pub fn global_snapshot() -> Snapshot {
    global()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .snapshot()
}

/// Process count for one `tools/list` filter combination.
pub fn global_shadow_count(filters: ListFilters) -> u64 {
    global()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .shadow_count(filters)
}

fn emit_session_metrics(
    requested_revision: Option<&str>,
    negotiated_revision: &str,
    client: &str,
    transport: Transport,
) {
    let _ = (requested_revision, negotiated_revision, client, transport);
    #[cfg(feature = "metrics")]
    {
        if let Some(rev) = requested_revision {
            telemetry_metrics::counter!(
                "mcp_protocol_revision_observations_total",
                "requested_revision" => rev.to_string(),
                "negotiated_revision" => negotiated_revision.to_string(),
                "client" => client.to_string(),
                "transport" => transport.as_str()
            )
            .increment(1);
        } else {
            telemetry_metrics::counter!(
                "mcp_protocol_revision_unattributed_observations_total",
                "negotiated_revision" => negotiated_revision.to_string(),
                "client" => client.to_string(),
                "transport" => transport.as_str()
            )
            .increment(1);
        }
    }
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn reset_global_for_tests() {
    global()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .reset();
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
        reg.observe_request(
            Some("2025-11-25"),
            "2025-11-25",
            "claude-desktop",
            Transport::Http,
        );
        reg.observe_request(None, "2025-11-25", "unknown", Transport::Stdio);
        let snap = reg.snapshot();
        assert_eq!(snap.total, 2);
        assert_eq!(snap.unattributed, 1);
        assert_eq!(snap.by_revision.get("2025-11-25"), Some(&1));
        assert_eq!(snap.by_negotiated_revision.get("2025-11-25"), Some(&2));
        assert_eq!(snap.by_client.get("claude"), Some(&1));
        assert_eq!(snap.by_client.get("other"), Some(&1));
        assert_eq!(snap.by_transport.get("http"), Some(&1));
        assert_eq!(snap.by_transport.get("stdio"), Some(&1));
        assert!(!snap.by_revision.contains_key("unattributed"));
        assert!((attribution_rate(&snap) - 0.5).abs() < f64::EPSILON);
        let table = distribution_table(&snap);
        assert!(table.contains("| unattributed | 1 |"));
        assert!(!table.contains("| unattributed | 1 |\n| unattributed |"));
    }

    #[test]
    fn arbitrary_labels_are_bounded() {
        let mut reg = Registry::new();
        for i in 0..100 {
            reg.observe_request(
                Some(&format!("attacker-revision-{i}")),
                "attacker-negotiated",
                &format!("attacker-client-{i}"),
                Transport::Http,
            );
        }
        let snapshot = reg.snapshot();
        assert_eq!(snapshot.by_revision.len(), 1);
        assert_eq!(snapshot.by_revision.get(OTHER_REVISION), Some(&100));
        assert_eq!(snapshot.by_negotiated_revision.len(), 1);
        assert_eq!(snapshot.by_client.len(), 1);
        assert_eq!(snapshot.by_client.get("other"), Some(&100));
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
            request: false,
        };
        assert_eq!(cache_scope_decision(filtered), CacheScope::Private);
        assert!(!public_over_filtered(filtered, CacheScope::Private));
        assert!(public_over_filtered(filtered, CacheScope::Public));
    }

    #[test]
    fn two_percent_rule_does_not_fire_on_underattributed_or_empty() {
        let empty = Registry::new().snapshot();
        assert!(retire_revisions(&empty, MIN_MEASUREMENT_WINDOW).is_empty());
        let mut low = Registry::new();
        low.observe_request(Some("2025-06-18"), "2025-06-18", "c", Transport::Http);
        low.observe_request(None, "2025-11-25", "c", Transport::Http);
        // 50% attributed < 80% floor
        assert!(retire_revisions(&low.snapshot(), MIN_MEASUREMENT_WINDOW).is_empty());
    }

    #[test]
    fn two_percent_rule_retires_only_below_floor_when_attributed() {
        let mut reg = Registry::new();
        for _ in 0..99 {
            reg.observe_request(Some("2025-11-25"), "2025-11-25", "c", Transport::Http);
        }
        reg.observe_request(Some("2024-11-05"), "2024-11-05", "c", Transport::Http);
        assert!(retire_revisions(&reg.snapshot(), Duration::from_secs(1)).is_empty());
        let retired = retire_revisions(&reg.snapshot(), MIN_MEASUREMENT_WINDOW);
        assert!(retired.iter().any(|r| r == "2024-11-05"));
        assert!(retired.iter().any(|r| r == "2024-10-07"));
        assert!(!retired.iter().any(|r| r == "2025-11-25"));
    }

    #[test]
    fn modern_request_is_observed_without_initialize() {
        let before = global_snapshot();
        let request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {
                "_meta": {
                    META_PROTOCOL_VERSION: "2026-07-28",
                    META_CLIENT_INFO: {"name": "Codex"}
                }
            }
        });
        observe_inbound_request(
            &request,
            request.get("params"),
            "tools/list",
            None,
            None,
            Transport::Http,
        );
        let after = global_snapshot();
        assert!(
            after.by_revision.get("2026-07-28").copied().unwrap_or(0)
                > before.by_revision.get("2026-07-28").copied().unwrap_or(0)
        );
        assert!(
            after.by_client.get("codex").copied().unwrap_or(0)
                > before.by_client.get("codex").copied().unwrap_or(0)
        );
    }

    #[test]
    fn legacy_stdio_followup_reuses_bounded_initialize_attribution() {
        let session_id = "mik-7218-legacy-stdio";
        let before = global_snapshot();
        let initialize = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "clientInfo": {"name": "Claude Desktop"}
            }
        });
        observe_inbound_request(
            &initialize,
            initialize.get("params"),
            "initialize",
            None,
            Some(session_id),
            Transport::Stdio,
        );
        let followup = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"});
        observe_inbound_request(
            &followup,
            None,
            "tools/list",
            None,
            Some(session_id),
            Transport::Stdio,
        );
        let after = global_snapshot();
        assert!(
            after.by_revision.get("2025-06-18").copied().unwrap_or(0)
                >= before.by_revision.get("2025-06-18").copied().unwrap_or(0) + 2
        );
    }

    #[test]
    fn shadow_tools_list_records_filters_and_would_be_scope() {
        let mut reg = Registry::new();
        let shadow = reg.shadow_tools_list(ListFilters {
            principal: false,
            profile: true,
            session: true,
            request: false,
        });
        assert!(shadow.profile && shadow.session);
        assert_eq!(shadow.would_emit_cache_scope, CacheScope::Private);
        assert_eq!(
            reg.shadow_count(ListFilters {
                principal: false,
                profile: true,
                session: true,
                request: false,
            }),
            1
        );
    }
}
