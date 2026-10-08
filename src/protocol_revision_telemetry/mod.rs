// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7218 / RFC-0060 U1: measure which MCP revisions clients speak.
//!
//! Modern MCP has no protocol session, so the only comparable unit across the
//! legacy and modern eras is an inbound JSON-RPC request. Modern requests carry
//! their identity in `_meta`; legacy HTTP requests carry a protocol header, and
//! legacy stdio follow-ups reuse the bounded attribution learned at initialize.

mod durable;
mod observe;

use std::collections::{BTreeMap, VecDeque};
use std::fmt::Write as _;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::protocol::extensions::Extension;

pub use durable::{
    DurableTelemetrySink, DurableWindow, durable_window_path, load_durable_window,
    production_retirement_decision, production_retirement_decision_at,
};
pub use observe::{
    bind_session_revision, extension_adoption, global_shadow_count, global_snapshot,
    observe_client_extensions, observe_inbound_request, observe_tools_list, register_metrics,
    session_negotiated_revision,
};

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
const MEASURED_CLIENTS: &[&str] = &[
    UNATTRIBUTED_CLIENT,
    "claude",
    "codex",
    "cursor",
    "vscode",
    "chatgpt",
    "other",
];
const MEASURED_TRANSPORTS: &[Transport] = &[Transport::Http, Transport::Stdio, Transport::Internal];
/// Directory below the gateway data directory that holds the restart-safe window.
pub const DURABLE_TELEMETRY_DIR: &str = "protocol-revision-telemetry";
/// Durable aggregate filename read by operators after the measurement window.
pub const DURABLE_WINDOW_FILE: &str = "window.json";
/// Schema identifier for the operator-readable aggregate.
pub const DURABLE_WINDOW_SCHEMA: &str = "mcp_protocol_revision_window.v1";

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
    client: &'static str,
    /// What the handshake ANSWERED, as opposed to what the client asked for.
    /// The two diverge whenever the ask is unsupported (`negotiate_version`
    /// falls back), and a session is served under the answer.
    negotiated_revision: Option<&'static str>,
}

/// Process-wide counters. Every metric key is normalized to a finite label set.
#[derive(Debug, Default)]
pub struct Registry {
    /// Requested revisions. Kept as `by_revision` for the pre-registered table.
    by_revision: BTreeMap<String, u64>,
    by_client: BTreeMap<String, u64>,
    by_transport: BTreeMap<String, u64>,
    unattributed: u64,
    total: u64,
    /// Per-identifier count of extensions clients negotiated on `tools/call`.
    ///
    /// Deliberately outside [`Snapshot`]: that structure is the pre-registered
    /// RFC-0060 aggregate written to an operator-readable file under a schema
    /// identifier, and extension adoption is a different question asked of the
    /// same stream. Adding a key there would change a durable schema to carry a
    /// series it was not registered for.
    ///
    /// Bounded by construction — the keys are [`Extension`] identifiers, never
    /// what a peer wrote.
    by_extension: BTreeMap<String, u64>,
    shadow_counts: [u64; 16],
    session_attributions: BTreeMap<u64, SessionAttribution>,
    session_order: VecDeque<u64>,
}

/// Snapshot for `/metrics` tests and the Linear table.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    /// Requests whose revision was named on the wire.
    pub by_revision: BTreeMap<String, u64>,
    /// Requests grouped by client identity (includes `unattributed`).
    pub by_client: BTreeMap<String, u64>,
    /// Requests grouped by the bounded transport label.
    pub by_transport: BTreeMap<String, u64>,
    /// Requests with no revision on either path. Own series, not a revision key.
    pub unattributed: u64,
    /// All observed requests, attributed or not.
    pub total: u64,
}

/// Why a production window cannot yet produce a retirement decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetirementBlocked {
    /// Fewer than seven days have elapsed.
    WindowTooShort,
    /// No request observations were recorded.
    NoObservations,
    /// Fewer than 80% of requests carried attributable revision data.
    AttributionBelowFloor,
    /// Unattributed requests alone could keep every revision above 2%.
    UnattributedAtOrAboveRetirementThreshold,
    /// Present but unrecognized revisions are too common to classify safely.
    OtherAtOrAboveRetirementThreshold,
    /// HTTP and stdio evidence do not cover the same production window.
    WindowMisaligned,
}

impl Registry {
    /// Empty counters.
    pub fn new() -> Self {
        Self::default()
    }

    /// Count one negotiated extension identifier.
    pub fn observe_extension(&mut self, extension: Extension) {
        *self
            .by_extension
            .entry(extension.id().to_string())
            .or_insert(0) += 1;
    }

    /// Extension adoption observed so far, by identifier.
    #[must_use]
    pub fn extension_adoption(&self) -> BTreeMap<String, u64> {
        self.by_extension.clone()
    }

    /// Record one inbound request observation.
    pub fn observe_request(
        &mut self,
        requested_revision: Option<&str>,
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

    /// Record the revision this session's handshake settled on, leaving the
    /// request-derived fields alone. Separate from `bind_session` because the
    /// two are written by different sites: the ask is read off the inbound
    /// message, the answer is known only once negotiation has run.
    fn bind_negotiated_revision(&mut self, session_id: &str, negotiated: &'static str) {
        let key = session_key(session_id);
        if let Some(entry) = self.session_attributions.get_mut(&key) {
            entry.negotiated_revision = Some(negotiated);
            return;
        }
        self.bind_session(
            session_id,
            SessionAttribution {
                requested_revision: None,
                client: UNATTRIBUTED_CLIENT,
                negotiated_revision: Some(negotiated),
            },
        );
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

    fn shadow_snapshot(&self) -> BTreeMap<String, u64> {
        all_filter_combinations()
            .map(|filters| {
                (
                    shadow_key(filters, cache_scope_decision(filters)),
                    self.shadow_count(filters),
                )
            })
            .collect()
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

fn all_filter_combinations() -> impl Iterator<Item = ListFilters> {
    [false, true].into_iter().flat_map(|principal| {
        [false, true].into_iter().flat_map(move |profile| {
            [false, true].into_iter().flat_map(move |session| {
                [false, true].into_iter().map(move |request| ListFilters {
                    principal,
                    profile,
                    session,
                    request,
                })
            })
        })
    })
}

fn shadow_key(filters: ListFilters, scope: CacheScope) -> String {
    format!(
        "principal={},profile={},session={},request={},would_emit_cache_scope={}",
        filters.principal,
        filters.profile,
        filters.session,
        filters.request,
        scope.as_str()
    )
}

fn empty_shadow_counts() -> BTreeMap<String, u64> {
    all_filter_combinations()
        .map(|filters| (shadow_key(filters, cache_scope_decision(filters)), 0))
        .collect()
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
///
/// MIK-6704: label only. The name is a metric label and a display string; it
/// reaches no authorization decision, and any caller can write any value there.
pub fn client_identity(initialize_params: Option<&Value>, request_meta: Option<&Value>) -> String {
    // MIK-6704: label only.
    client_info_name(request_meta.and_then(|m| m.get(META_CLIENT_INFO)))
        .or_else(|| client_info_name(initialize_params.and_then(|p| p.get("clientInfo"))))
        .unwrap_or_else(|| UNATTRIBUTED_CLIENT.to_string())
}

// MIK-6704: label only — extracted for telemetry attribution, never for a
// decision.
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

/// Resolve one `_meta` field with root-level precedence and per-field fallback.
fn request_meta_value<'a>(
    request: &'a Value,
    params: Option<&'a Value>,
    key: &str,
) -> Option<&'a Value> {
    request
        .get("_meta")
        .and_then(|meta| meta.get(key))
        .or_else(|| params.and_then(|p| p.get("_meta"))?.get(key))
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

/// Attributed requests / total. Empty window is 0.0, not NaN.
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
/// revision look safer to remove. An unusable window is returned separately
/// from a usable window with no retirement candidates.
pub fn retire_revisions(
    snapshot: &Snapshot,
    elapsed: Duration,
) -> Result<Vec<String>, RetirementBlocked> {
    if elapsed < MIN_MEASUREMENT_WINDOW {
        return Err(RetirementBlocked::WindowTooShort);
    }
    if snapshot.total == 0 {
        return Err(RetirementBlocked::NoObservations);
    }
    if attribution_rate(snapshot) < ATTRIBUTION_FLOOR {
        return Err(RetirementBlocked::AttributionBelowFloor);
    }
    if ratio(snapshot.unattributed, snapshot.total) >= RETIRE_BELOW_SHARE {
        return Err(RetirementBlocked::UnattributedAtOrAboveRetirementThreshold);
    }
    let other = snapshot
        .by_revision
        .get(OTHER_REVISION)
        .copied()
        .unwrap_or(0);
    if ratio(other, snapshot.total) >= RETIRE_BELOW_SHARE {
        return Err(RetirementBlocked::OtherAtOrAboveRetirementThreshold);
    }
    Ok(crate::protocol::SUPPORTED_VERSIONS
        .iter()
        .filter(|rev| {
            let count = snapshot.by_revision.get(**rev).copied().unwrap_or(0);
            ratio(
                count
                    .saturating_add(snapshot.unattributed)
                    .saturating_add(other),
                snapshot.total,
            ) < RETIRE_BELOW_SHARE
        })
        .map(|rev| (*rev).to_string())
        .collect())
}

/// Markdown table for the Linear comment. Unattributed is its own row, not a revision.
pub fn distribution_table(snapshot: &Snapshot) -> String {
    let mut rows = String::from("| revision | requests | share |\n| --- | ---: | ---: |\n");
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

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn reset_global_for_tests() {
    global()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .reset();
}

#[cfg(test)]
mod lock_tests;
#[cfg(test)]
mod tests;
