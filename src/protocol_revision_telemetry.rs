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
#[cfg(unix)]
use std::fs::File;
use std::fs::OpenOptions;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::fs_lock::ExclusiveFileLock;

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

/// Restart-safe aggregate for a production measurement window.
///
/// The file contains bounded labels only. It never stores raw client names,
/// session identifiers, request bodies, or tool arguments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurableWindow {
    /// Stable on-disk schema identifier.
    pub schema_version: String,
    /// Unix timestamp when this window started.
    pub started_at_unix_seconds: u64,
    /// Most recent successful aggregate update, recorded as Unix seconds for operator inspection
    /// after the seven-day window.
    pub updated_at_unix_seconds: u64,
    /// Cross-process request counters accumulated since `started_at_unix_seconds`.
    pub snapshot: Snapshot,
    /// All 16 bounded `tools/list` filter combinations, including zeroes.
    pub tools_list_shadow: BTreeMap<String, u64>,
}

impl DurableWindow {
    fn empty(now: u64) -> Self {
        Self {
            schema_version: DURABLE_WINDOW_SCHEMA.to_string(),
            started_at_unix_seconds: now,
            updated_at_unix_seconds: now,
            snapshot: Snapshot::default(),
            tools_list_shadow: empty_shadow_counts(),
        }
    }

    /// Evaluate the persisted counters using the durable start timestamp.
    pub fn retirement_decision_at(
        &self,
        now_unix_seconds: u64,
    ) -> Result<Vec<String>, RetirementBlocked> {
        let elapsed =
            Duration::from_secs(now_unix_seconds.saturating_sub(self.started_at_unix_seconds));
        retire_revisions(&self.snapshot, elapsed)
    }
}

/// Cross-process sink used by stdio servers.
///
/// Each process contributes only the delta since its preceding write. A shared
/// advisory lock serializes the aggregate update across gateway processes.
#[derive(Debug)]
pub struct DurableTelemetrySink {
    window_path: PathBuf,
    lock_path: PathBuf,
    previous_snapshot: Snapshot,
    previous_shadow: BTreeMap<String, u64>,
    parent_sync_pending: bool,
}

impl DurableTelemetrySink {
    /// Open or create the durable measurement window below `data_dir`.
    pub fn open(data_dir: &Path) -> io::Result<Self> {
        let directory = data_dir.join(DURABLE_TELEMETRY_DIR);
        std::fs::create_dir_all(&directory)?;
        force_directory_owner_only(&directory)?;
        let window_path = directory.join(DURABLE_WINDOW_FILE);
        let lock_path = directory.join(".window.lock");
        {
            let _lock = ExclusiveFileLock::acquire(&lock_path)?;
            if window_path.exists() {
                read_window_file(&window_path)?;
            } else {
                write_window_atomic(&window_path, &DurableWindow::empty(unix_seconds()?))?;
                sync_parent_directory(&window_path)?;
            }
        }
        Ok(Self {
            window_path,
            lock_path,
            previous_snapshot: Snapshot::default(),
            previous_shadow: empty_shadow_counts(),
            parent_sync_pending: false,
        })
    }

    /// Add counters observed since this sink's preceding successful write.
    pub fn persist_registry(&mut self, registry: &Registry) -> io::Result<()> {
        self.persist(
            registry.snapshot(),
            registry.shadow_snapshot(),
            unix_seconds()?,
        )
    }

    /// Persist the current process-global counters.
    pub fn persist_global(&mut self) -> io::Result<()> {
        let (snapshot, shadow) = {
            let registry = global()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            (registry.snapshot(), registry.shadow_snapshot())
        };
        self.persist(snapshot, shadow, unix_seconds()?)
    }

    fn persist(
        &mut self,
        current: Snapshot,
        current_shadow: BTreeMap<String, u64>,
        now: u64,
    ) -> io::Result<()> {
        self.persist_with_parent_sync(current, current_shadow, now, sync_parent_directory)
    }

    fn persist_with_parent_sync(
        &mut self,
        current: Snapshot,
        current_shadow: BTreeMap<String, u64>,
        now: u64,
        sync_parent: impl FnOnce(&Path) -> io::Result<()>,
    ) -> io::Result<()> {
        let snapshot_delta = snapshot_delta(&current, &self.previous_snapshot);
        let shadow_delta = map_delta(&current_shadow, &self.previous_shadow);
        if snapshot_delta.total == 0 && shadow_delta.values().all(|count| *count == 0) {
            if self.parent_sync_pending {
                sync_parent(&self.window_path)?;
                self.parent_sync_pending = false;
            }
            return Ok(());
        }

        let _lock = ExclusiveFileLock::acquire(&self.lock_path)?;
        let mut window = read_window_file(&self.window_path)?;
        add_snapshot(&mut window.snapshot, &snapshot_delta)?;
        add_map(&mut window.tools_list_shadow, &shadow_delta)?;
        window.updated_at_unix_seconds = window.updated_at_unix_seconds.max(now);
        validate_window(&window)?;
        write_window_atomic(&self.window_path, &window)?;
        self.previous_snapshot = current;
        self.previous_shadow = current_shadow;
        self.parent_sync_pending = true;
        sync_parent(&self.window_path)?;
        self.parent_sync_pending = false;
        Ok(())
    }
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

/// Location of the restart-safe aggregate below a gateway data directory.
pub fn durable_window_path(data_dir: &Path) -> PathBuf {
    data_dir
        .join(DURABLE_TELEMETRY_DIR)
        .join(DURABLE_WINDOW_FILE)
}

/// Load and validate the operator-readable production window.
pub fn load_durable_window(data_dir: &Path) -> io::Result<DurableWindow> {
    read_window_file(&durable_window_path(data_dir))
}

/// Evaluate the production decision from exact-window HTTP and stdio evidence.
///
/// HTTP observations live in Prometheus while stdio observations live in the
/// durable window. A revision is eligible only when both independent sources
/// mark it below the threshold for the same window.
pub fn production_retirement_decision(
    data_dir: &Path,
    http_snapshot: &Snapshot,
    http_started_at_unix_seconds: u64,
) -> io::Result<Result<Vec<String>, RetirementBlocked>> {
    production_retirement_decision_at(
        data_dir,
        http_snapshot,
        http_started_at_unix_seconds,
        unix_seconds()?,
    )
}

/// Time-injected production decision used by deterministic tests and offline exports.
pub fn production_retirement_decision_at(
    data_dir: &Path,
    http_snapshot: &Snapshot,
    http_started_at_unix_seconds: u64,
    ended_at_unix_seconds: u64,
) -> io::Result<Result<Vec<String>, RetirementBlocked>> {
    let window = load_durable_window(data_dir)?;
    if http_started_at_unix_seconds != window.started_at_unix_seconds {
        return Ok(Err(RetirementBlocked::WindowMisaligned));
    }
    let elapsed =
        Duration::from_secs(ended_at_unix_seconds.saturating_sub(http_started_at_unix_seconds));
    let stdio_candidates = match window.retirement_decision_at(ended_at_unix_seconds) {
        Ok(candidates) => candidates,
        Err(blocked) => return Ok(Err(blocked)),
    };
    let http_candidates = match retire_revisions(http_snapshot, elapsed) {
        Ok(candidates) => candidates,
        Err(blocked) => return Ok(Err(blocked)),
    };
    Ok(Ok(stdio_candidates
        .into_iter()
        .filter(|candidate| http_candidates.contains(candidate))
        .collect()))
}

fn snapshot_delta(current: &Snapshot, previous: &Snapshot) -> Snapshot {
    Snapshot {
        by_revision: map_delta(&current.by_revision, &previous.by_revision),
        by_client: map_delta(&current.by_client, &previous.by_client),
        by_transport: map_delta(&current.by_transport, &previous.by_transport),
        unattributed: counter_delta(current.unattributed, previous.unattributed),
        total: counter_delta(current.total, previous.total),
    }
}

fn map_delta(
    current: &BTreeMap<String, u64>,
    previous: &BTreeMap<String, u64>,
) -> BTreeMap<String, u64> {
    current
        .iter()
        .map(|(key, value)| {
            let prior = previous.get(key).copied().unwrap_or(0);
            (key.clone(), counter_delta(*value, prior))
        })
        .collect()
}

fn counter_delta(current: u64, previous: u64) -> u64 {
    current.checked_sub(previous).unwrap_or(current)
}

fn add_snapshot(target: &mut Snapshot, delta: &Snapshot) -> io::Result<()> {
    add_map(&mut target.by_revision, &delta.by_revision)?;
    add_map(&mut target.by_client, &delta.by_client)?;
    add_map(&mut target.by_transport, &delta.by_transport)?;
    target.unattributed = checked_counter_add(target.unattributed, delta.unattributed)?;
    target.total = checked_counter_add(target.total, delta.total)?;
    Ok(())
}

fn add_map(target: &mut BTreeMap<String, u64>, delta: &BTreeMap<String, u64>) -> io::Result<()> {
    for (key, increment) in delta {
        let value = target.entry(key.clone()).or_insert(0);
        *value = checked_counter_add(*value, *increment)?;
    }
    Ok(())
}

fn checked_counter_add(current: u64, increment: u64) -> io::Result<u64> {
    current
        .checked_add(increment)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "telemetry counter overflow"))
}

fn read_window_file(path: &Path) -> io::Result<DurableWindow> {
    let bytes = std::fs::read(path)?;
    let window: DurableWindow = serde_json::from_slice(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    validate_window(&window)?;
    Ok(window)
}

fn validate_window(window: &DurableWindow) -> io::Result<()> {
    if window.schema_version != DURABLE_WINDOW_SCHEMA {
        return Err(invalid_window("unsupported durable telemetry schema"));
    }
    if window.updated_at_unix_seconds < window.started_at_unix_seconds {
        return Err(invalid_window("window update precedes its start"));
    }
    validate_bounded_keys(
        &window.snapshot.by_revision,
        MEASURED_REVISIONS
            .iter()
            .copied()
            .chain(std::iter::once(OTHER_REVISION)),
        "revision",
    )?;
    validate_bounded_keys(
        &window.snapshot.by_client,
        MEASURED_CLIENTS.iter().copied(),
        "client",
    )?;
    validate_bounded_keys(
        &window.snapshot.by_transport,
        MEASURED_TRANSPORTS
            .iter()
            .map(|transport| transport.as_str()),
        "transport",
    )?;
    if checked_counter_sum(window.snapshot.by_revision.values().copied())?
        .checked_add(window.snapshot.unattributed)
        != Some(window.snapshot.total)
    {
        return Err(invalid_window("revision counters do not equal total"));
    }
    if checked_counter_sum(window.snapshot.by_client.values().copied())? != window.snapshot.total {
        return Err(invalid_window("client counters do not equal total"));
    }
    if checked_counter_sum(window.snapshot.by_transport.values().copied())? != window.snapshot.total
    {
        return Err(invalid_window("transport counters do not equal total"));
    }
    let expected_shadow = empty_shadow_counts();
    if window.tools_list_shadow.keys().ne(expected_shadow.keys()) {
        return Err(invalid_window("tools/list shadow labels are incomplete"));
    }
    Ok(())
}

fn validate_bounded_keys<'a>(
    values: &BTreeMap<String, u64>,
    allowed: impl Iterator<Item = &'a str>,
    label: &str,
) -> io::Result<()> {
    let allowed = allowed.collect::<std::collections::BTreeSet<_>>();
    if let Some(unbounded) = values.keys().find(|key| !allowed.contains(key.as_str())) {
        return Err(invalid_window(&format!(
            "unbounded {label} label in durable telemetry: {unbounded}"
        )));
    }
    Ok(())
}

fn invalid_window(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn checked_counter_sum(mut values: impl Iterator<Item = u64>) -> io::Result<u64> {
    values.try_fold(0, checked_counter_add)
}

fn unix_seconds() -> io::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn write_window_atomic(path: &Path, window: &DurableWindow) -> io::Result<()> {
    let bytes = serde_json::to_vec_pretty(window)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let temporary = path.with_extension("json.tmp");
    {
        let mut options = OpenOptions::new();
        options.create(true).write(true).truncate(true);
        set_owner_only(&mut options);
        let mut file = options.open(&temporary)?;
        force_file_owner_only(&file)?;
        file.write_all(&bytes)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
    }
    std::fs::rename(&temporary, path)?;
    Ok(())
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "window has no parent"))?;
    File::open(parent)?.sync_all()
}

#[cfg(not(unix))]
fn sync_parent_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_owner_only(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt as _;
    options.mode(0o600);
}

#[cfg(unix)]
fn force_file_owner_only(file: &std::fs::File) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn force_file_owner_only(_file: &std::fs::File) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn force_directory_owner_only(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn force_directory_owner_only(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(not(unix))]
fn set_owner_only(_options: &mut OpenOptions) {}

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
    if method.starts_with("notifications/") {
        return;
    }
    let initialize_params = (method == "initialize").then_some(params).flatten();
    let explicit_requested = request_meta_value(request, params, META_PROTOCOL_VERSION)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| requested_revision(initialize_params, None))
        .or_else(|| protocol_header.map(str::trim).map(str::to_string))
        .filter(|value| !value.is_empty());
    let explicit_client = client_info_name(request_meta_value(request, params, META_CLIENT_INFO))
        .or_else(|| client_info_name(initialize_params.and_then(|p| p.get("clientInfo"))))
        .unwrap_or_else(|| UNATTRIBUTED_CLIENT.to_string());

    let mut reg = global()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let previous = (transport == Transport::Stdio)
        .then(|| reg.session_attribution(session_id))
        .flatten();
    let requested_label = revision_label(explicit_requested.as_deref())
        .or_else(|| previous.and_then(|item| item.requested_revision));
    let client = if explicit_client == UNATTRIBUTED_CLIENT {
        previous.map_or(UNATTRIBUTED_CLIENT, |item| item.client)
    } else {
        client_label(&explicit_client)
    };
    if transport == Transport::Stdio
        && method == "initialize"
        && let Some(session_id) = session_id
    {
        reg.bind_session(
            session_id,
            SessionAttribution {
                requested_revision: requested_label,
                client,
            },
        );
    }
    reg.observe_request(requested_label, client, transport);
    drop(reg);
    emit_request_metrics(requested_label, client, transport);
    tracing::debug!(
        requested_revision = requested_label.unwrap_or("unattributed"),
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
    tracing::debug!(
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

/// Register every bounded protocol-revision and list-shadow metric series at zero.
///
/// Call this after installing the recorder and before taking the baseline scrape
/// for a measurement window. Zero registration prevents an unused revision or
/// client family from disappearing from `increase()` queries.
pub fn register_metrics() {
    #[cfg(feature = "metrics")]
    {
        for revision in MEASURED_REVISIONS
            .iter()
            .copied()
            .chain(std::iter::once(OTHER_REVISION))
        {
            for client in MEASURED_CLIENTS {
                for transport in MEASURED_TRANSPORTS {
                    telemetry_metrics::counter!(
                        "mcp_protocol_revision_observations_total",
                        "requested_revision" => revision,
                        "client" => *client,
                        "transport" => transport.as_str()
                    )
                    .increment(0);
                }
            }
        }

        for client in MEASURED_CLIENTS {
            for transport in MEASURED_TRANSPORTS {
                telemetry_metrics::counter!(
                    "mcp_protocol_revision_unattributed_observations_total",
                    "client" => *client,
                    "transport" => transport.as_str()
                )
                .increment(0);
            }
        }

        for principal in [false, true] {
            for profile in [false, true] {
                for session in [false, true] {
                    for request in [false, true] {
                        let filters = ListFilters {
                            principal,
                            profile,
                            session,
                            request,
                        };
                        let scope = cache_scope_decision(filters);
                        telemetry_metrics::counter!(
                            "mcp_tools_list_cache_scope_shadow_total",
                            "principal" => principal.to_string(),
                            "profile" => profile.to_string(),
                            "session" => session.to_string(),
                            "request" => request.to_string(),
                            "would_emit_cache_scope" => scope.as_str()
                        )
                        .increment(0);
                    }
                }
            }
        }
    }
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

fn emit_request_metrics(requested_revision: Option<&str>, client: &str, transport: Transport) {
    let _ = (requested_revision, client, transport);
    #[cfg(feature = "metrics")]
    {
        if let Some(rev) = requested_revision {
            telemetry_metrics::counter!(
                "mcp_protocol_revision_observations_total",
                "requested_revision" => rev.to_string(),
                "client" => client.to_string(),
                "transport" => transport.as_str()
            )
            .increment(1);
        } else {
            telemetry_metrics::counter!(
                "mcp_protocol_revision_unattributed_observations_total",
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
        reg.observe_request(Some("2025-11-25"), "claude-desktop", Transport::Http);
        reg.observe_request(None, "unknown", Transport::Stdio);
        let snap = reg.snapshot();
        assert_eq!(snap.total, 2);
        assert_eq!(snap.unattributed, 1);
        assert_eq!(snap.by_revision.get("2025-11-25"), Some(&1));
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
                &format!("attacker-client-{i}"),
                Transport::Http,
            );
        }
        let snapshot = reg.snapshot();
        assert_eq!(snapshot.by_revision.len(), 1);
        assert_eq!(snapshot.by_revision.get(OTHER_REVISION), Some(&100));
        assert_eq!(snapshot.by_client.len(), 1);
        assert_eq!(snapshot.by_client.get("other"), Some(&100));
    }

    #[test]
    fn every_supported_revision_has_a_dedicated_metric_label() {
        for revision in crate::protocol::SUPPORTED_VERSIONS {
            assert!(
                MEASURED_REVISIONS.contains(revision),
                "supported revision {revision} would collapse into the other bucket"
            );
        }
    }

    #[test]
    fn notifications_are_not_request_observations() {
        let before = global_snapshot()
            .by_revision
            .get(OTHER_REVISION)
            .copied()
            .unwrap_or(0);
        let notification = json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        });
        observe_inbound_request(
            &notification,
            None,
            "notifications/initialized",
            Some("notification-only-test-revision"),
            None,
            Transport::Http,
        );
        let after = global_snapshot()
            .by_revision
            .get(OTHER_REVISION)
            .copied()
            .unwrap_or(0);
        assert_eq!(after, before);
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
        assert_eq!(
            retire_revisions(&empty, MIN_MEASUREMENT_WINDOW),
            Err(RetirementBlocked::NoObservations)
        );
        let mut low = Registry::new();
        low.observe_request(Some("2025-06-18"), "c", Transport::Http);
        low.observe_request(None, "c", Transport::Http);
        // 50% attributed < 80% floor
        assert_eq!(
            retire_revisions(&low.snapshot(), MIN_MEASUREMENT_WINDOW),
            Err(RetirementBlocked::AttributionBelowFloor)
        );

        let mut ambiguous = Registry::new();
        for _ in 0..95 {
            ambiguous.observe_request(Some("2025-11-25"), "c", Transport::Http);
        }
        for _ in 0..5 {
            ambiguous.observe_request(None, "c", Transport::Http);
        }
        assert_eq!(
            retire_revisions(&ambiguous.snapshot(), MIN_MEASUREMENT_WINDOW),
            Err(RetirementBlocked::UnattributedAtOrAboveRetirementThreshold)
        );
    }

    #[test]
    fn two_percent_rule_retires_only_below_floor_when_attributed() {
        let mut reg = Registry::new();
        for _ in 0..99 {
            reg.observe_request(Some("2025-11-25"), "c", Transport::Http);
        }
        reg.observe_request(Some("2024-11-05"), "c", Transport::Http);
        assert_eq!(
            retire_revisions(&reg.snapshot(), Duration::from_secs(1)),
            Err(RetirementBlocked::WindowTooShort)
        );
        let retired = retire_revisions(&reg.snapshot(), MIN_MEASUREMENT_WINDOW)
            .expect("full attributed window is actionable");
        assert!(retired.iter().any(|r| r == "2024-11-05"));
        // A supported revision with no traffic at all is retirable too. 4.0.0
        // dropped `2024-10-07` from `SUPPORTED_VERSIONS`, so the zero-traffic
        // stand-in is a revision the server still offers.
        assert!(retired.iter().any(|r| r == "2025-03-26"));
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
    fn http_request_without_revision_does_not_reuse_session_attribution() {
        let session_id = "mik-7218-http-is-request-scoped";
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
        let before = global_snapshot();
        let request = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"});
        observe_inbound_request(
            &request,
            None,
            "tools/list",
            None,
            Some(session_id),
            Transport::Http,
        );
        let after = global_snapshot();
        assert!(after.unattributed > before.unattributed);
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

    #[test]
    fn committed_window_is_not_counted_twice_after_parent_sync_failure() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let mut sink = DurableTelemetrySink::open(directory.path()).expect("durable sink");
        let mut registry = Registry::new();
        registry.observe_request(Some("2025-11-25"), "codex", Transport::Stdio);

        let error = sink
            .persist_with_parent_sync(registry.snapshot(), registry.shadow_snapshot(), 1, |_| {
                Err(io::Error::other("injected parent sync failure"))
            })
            .expect_err("parent sync must fail after the rename");
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(sink.parent_sync_pending);
        assert_eq!(
            load_durable_window(directory.path())
                .unwrap()
                .snapshot
                .total,
            1
        );

        sink.persist_with_parent_sync(registry.snapshot(), registry.shadow_snapshot(), 2, |_| {
            Ok(())
        })
        .expect("retry pending parent sync");
        assert!(!sink.parent_sync_pending);
        assert_eq!(
            load_durable_window(directory.path())
                .unwrap()
                .snapshot
                .total,
            1
        );
    }
}
