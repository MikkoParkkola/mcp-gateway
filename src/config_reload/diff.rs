// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Structural diff between two config snapshots and the restart-required classification.

use serde::Serialize;
use serde_json::Value;

use super::ReloadOutcome;

use crate::config::{BackendConfig, Config, ServerConfig};

/// Structural diff computed between two [`Config`] snapshots.
///
/// Only the `backends` and other hot-reloadable config sections are included.
/// Server address changes are flagged separately so the caller can warn the
/// operator.
#[derive(Debug, Default, Clone)]
pub struct ConfigPatch {
    /// Backends that exist in `new` but not in `old` (enabled flag respected).
    pub backends_added: Vec<(String, BackendConfig)>,
    /// Names of backends present in `old` but absent (or disabled) in `new`.
    pub backends_removed: Vec<String>,
    /// Backends whose config changed between `old` and `new`.
    pub backends_modified: Vec<(String, BackendConfig)>,
    /// `true` when `server.host` or `server.port` changed (requires restart).
    pub server_changed: bool,
    /// `true` when any field outside of `backends` / `server` changed.
    pub profiles_changed: bool,
}

impl ConfigPatch {
    /// Returns `true` when no changes were detected.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.backends_added.is_empty()
            && self.backends_removed.is_empty()
            && self.backends_modified.is_empty()
            && !self.server_changed
            && !self.profiles_changed
    }

    /// Human-readable summary of the patch (one line per change type).
    #[must_use]
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        if !self.backends_added.is_empty() {
            parts.push(format!(
                "added backends: [{}]",
                self.backends_added
                    .iter()
                    .map(|(n, _)| n.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if !self.backends_removed.is_empty() {
            parts.push(format!(
                "removed backends: [{}]",
                self.backends_removed.join(", ")
            ));
        }
        if !self.backends_modified.is_empty() {
            parts.push(format!(
                "modified backends: [{}]",
                self.backends_modified
                    .iter()
                    .map(|(n, _)| n.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if self.server_changed {
            parts.push("server address changed (restart required)".to_string());
        }
        if self.profiles_changed {
            parts.push("profiles/meta config changed".to_string());
        }
        if parts.is_empty() {
            "no changes".to_string()
        } else {
            parts.join("; ")
        }
    }

    /// Returns `true` when some detected change requires a process restart.
    #[must_use]
    pub fn restart_required(&self) -> bool {
        self.server_changed
    }

    /// Stable machine-readable restart reason, if any.
    #[must_use]
    pub fn restart_reason(&self) -> Option<&'static str> {
        self.server_changed.then_some("server_address_changed")
    }

    /// Structured outcome derived from this patch.
    #[must_use]
    pub fn outcome(&self) -> ReloadOutcome {
        ReloadOutcome {
            changes: self.summary(),
            restart_required: self.restart_required(),
            restart_reason: self.restart_reason(),
            pending_restart_fields: Vec::new(),
        }
    }
}

/// Compute the structural diff between two config snapshots.
///
/// This is a pure function: it does not touch the registry or spawn any tasks.
/// The caller is responsible for applying the returned [`ConfigPatch`].
///
/// # Examples
///
/// ```
/// use mcp_gateway::config::Config;
/// use mcp_gateway::config_reload::compute_diff;
///
/// let old = Config::default();
/// let new = Config::default();
/// let patch = compute_diff(&old, &new);
/// assert!(patch.is_empty());
/// ```
#[must_use]
pub fn compute_diff(old: &Config, new: &Config) -> ConfigPatch {
    let mut patch = ConfigPatch {
        server_changed: server_address_changed(&old.server, &new.server),
        profiles_changed: profiles_changed(old, new),
        ..ConfigPatch::default()
    };

    classify_backends(old, new, &mut patch);

    patch
}

/// Fields the file changes that only a restart can apply.
///
/// The allow-list below names every field proven to be re-read on the request
/// path; everything else is restart-required by default. Each entry carries the
/// consumer that reads it, so a reader can check the claim rather than trust it.
///
/// - `server.public_url` — `router/well_known.rs`, `router/origin_guard.rs`
/// - `control_plane.role_mapping` — `ui/control_plane.rs`, `gateway/auth_live.rs`
pub(super) fn pending_restart_fields(running: &Config, wanted: &Config) -> Vec<&'static str> {
    let mut pending = Vec::new();

    // `server` wholesale, minus the one field that IS re-read per request.
    // Listing the restart-only fields by hand is how `shutdown_timeout` (and the
    // since-removed `request_timeout`) went unreported: subtracting the
    // single live field from the whole cannot drift as fields are added.
    let server_without_public_url = |c: &Config| {
        let mut server = c.server.clone();
        server.public_url = None;
        canonical_json(&server)
    };
    if server_without_public_url(running) != server_without_public_url(wanted) {
        pending.push("server");
    }
    // `control_plane` the same way as `server`: `role_mapping` IS re-read per
    // request (`ui::control_plane`), so comparing the section whole would tell
    // an operator to restart for a change that already took effect.
    let control_plane_without_role_mapping = |c: &Config| {
        let mut cp = c.control_plane.clone();
        cp.role_mapping = crate::control_plane::ControlPlaneRoleMappingConfig::default();
        canonical_json(&cp)
    };
    if control_plane_without_role_mapping(running) != control_plane_without_role_mapping(wanted) {
        pending.push("control_plane");
    }
    if canonical_json(&running.env_files) != canonical_json(&wanted.env_files) {
        pending.push("env_files");
    }
    if running.default_routing_profile != wanted.default_routing_profile {
        pending.push("default_routing_profile");
    }

    // Everything else is compared WHOLESALE and reported by name. An earlier
    // version listed the sections it knew about, which is the hand-list this
    // was supposed to replace: a section added later reported as applied while
    // nothing read it. Subtracting the live readers from the whole is the only
    // form that stays true as the config grows.
    for (name, differs) in tracked_sections(running, wanted) {
        if differs {
            pending.push(name);
        }
    }

    pending
}

/// Every tracked section, paired with whether the file differs from the running
/// process. Live-applied sections are excluded by name, and that list is short
/// enough to check: `backends` is applied by the reload itself,
/// `server.public_url` and `control_plane.role_mapping` are re-read per request
/// (see `router::well_known`, `router::origin_guard`, `ui::control_plane`, `auth::live`).
pub(super) fn tracked_sections(running: &Config, wanted: &Config) -> Vec<(&'static str, bool)> {
    // A macro so the list stays exhaustive: adding a section is one line.
    macro_rules! sections {
        ($($(#[$attr:meta])* $name:literal => $field:ident),* $(,)?) => {
            vec![$($(#[$attr])* (
                $name,
                canonical_json(&running.$field) != canonical_json(&wanted.$field),
            )),*]
        };
    }

    let mut sections = sections![
        "auth" => auth, // first: compared below without `dashboard_session`
        "mtls" => mtls,
        "key_server" => key_server,
        "agent_auth" => agent_auth,
        "security" => security,
        "webhooks" => webhooks,
        "meta_mcp" => meta_mcp,
        "capabilities" => capabilities,
        "playbooks" => playbooks,
        "routing_profiles" => routing_profiles,
        "code_mode" => code_mode,
        "streaming" => streaming,
        "failsafe" => failsafe,
        "error_budget" => error_budget,
        "cache" => cache,
        "runtime" => runtime,
        "tasks" => tasks,
        "events" => events,
        // Fail-closed on purpose. Eager replacement of a descriptor's authority,
        // resource, issuer or scopes is NOT implemented, so an `accounts` edit
        // is reported as outstanding until a restart rather than claimed as
        // applied. A field wrongly counted tells an operator to restart when
        // they need not; the reverse tells them a change took effect when it
        // did not.
        "accounts" => accounts,
        #[cfg(feature = "cost-governance")]
        "cost_governance" => cost_governance,
    ];
    sections[0].1 = running.auth.restart_only_json() != wanted.auth.restart_only_json();
    sections
}

/// Returns `true` when the TCP-listener address differs.
pub(super) fn server_address_changed(old: &ServerConfig, new: &ServerConfig) -> bool {
    old.host != new.host || old.port != new.port
}

/// Returns `true` when any non-backend, non-server field differs.
///
/// Uses canonical JSON with sorted object keys as a cheap structural equality
/// check so we don't need to `PartialEq` every nested config type.
pub(super) fn profiles_changed(old: &Config, new: &Config) -> bool {
    // Compare the sections that can be applied without backend restart.
    let fields_changed = |a: &Config, b: &Config| -> bool {
        // Avoid false positives from the backends map (handled separately).
        // We serialise and compare just the non-backends, non-server sections.
        let old_meta = MetaFields::from(a);
        let new_meta = MetaFields::from(b);
        old_meta != new_meta
    };
    fields_changed(old, new)
}

/// Serialize a value to canonical JSON with object keys sorted recursively.
///
/// This keeps diff detection stable across logically-equivalent `HashMap` and
/// JSON object instances that may iterate in a different order between reloads.
pub(super) fn canonical_json<T: Serialize + ?Sized>(value: &T) -> String {
    fn sort_json_value(value: &mut Value) {
        match value {
            Value::Object(map) => {
                let mut entries: Vec<_> = std::mem::take(map).into_iter().collect();
                entries.sort_by(|(left, _), (right, _)| left.cmp(right));

                for (_, entry_value) in &mut entries {
                    sort_json_value(entry_value);
                }

                *map = entries.into_iter().collect();
            }
            Value::Array(values) => {
                for entry in values {
                    sort_json_value(entry);
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }

    let mut json = serde_json::to_value(value).unwrap_or(Value::Null);
    sort_json_value(&mut json);
    serde_json::to_string(&json).unwrap_or_default()
}

/// Comparable snapshot of every top-level [`Config`] field **except**:
///
/// - `backends` — tracked individually via the `backends_added/removed/modified` buckets.
/// - `server.host` / `server.port` — tracked separately via `server_changed`
///   because they require a process restart to take effect.
/// - `env_files` — loaded once at process startup; changes only take effect
///   after a full process restart, so they are excluded from hot-reload detection.
#[derive(PartialEq)]
pub(super) struct MetaFields {
    // ── Always-tracked feature sections ─────────────────────────────────────
    auth: String,
    meta_mcp: String,
    streaming: String,
    failsafe: String,
    /// Error-budget thresholds (GH #475). Read once when the meta-MCP server
    /// is built, so an edit here is detected and reported as restart-required
    /// rather than silently ignored.
    error_budget: String,
    capabilities: String,
    cache: String,
    playbooks: String,
    security: String,
    webhooks: String,
    // ── Additional top-level fields (previously missing from diff) ───────────
    routing_profiles: String,
    default_routing_profile: String,
    code_mode: String,
    mtls: String,
    key_server: String,
    agent_auth: String,
    runtime: String,
    /// Control-plane section (RBAC role mapping). Tracked so a role-mapping-only
    /// edit is detected and triggers a reload — without this, removing an admin
    /// rule would not take effect until restart (MIK-6702 CP.RELOAD.2).
    control_plane: String,
    /// `server.public_url` only. The advertised RFC 9728 protected-resource
    /// origin is read from `live_config` at request time, so a `public_url`
    /// edit takes effect on reload without a restart — unlike `server.host` /
    /// `server.port`, which change the TCP listener and stay in
    /// `server_address_changed`. Tracked here so a public-url-only edit is not
    /// silently ignored until the next restart.
    server_public_url: String,
    #[cfg(feature = "cost-governance")]
    cost_governance: String,
    tasks: String,
    /// The `accounts` block. Absent from this comparison, an accounts-only edit
    /// — a descriptor's issuer, resource or scopes — produced no diff at all,
    /// so the reload reported nothing and the running gateway kept minting
    /// under a descriptor the file had already replaced.
    accounts: String,
}

impl MetaFields {
    fn from(c: &Config) -> Self {
        Self {
            auth: canonical_json(&c.auth),
            meta_mcp: canonical_json(&c.meta_mcp),
            streaming: canonical_json(&c.streaming),
            failsafe: canonical_json(&c.failsafe),
            error_budget: canonical_json(&c.error_budget),
            capabilities: canonical_json(&c.capabilities),
            cache: canonical_json(&c.cache),
            playbooks: canonical_json(&c.playbooks),
            security: canonical_json(&c.security),
            webhooks: canonical_json(&c.webhooks),
            routing_profiles: canonical_json(&c.routing_profiles),
            default_routing_profile: c.default_routing_profile.clone(),
            code_mode: canonical_json(&c.code_mode),
            mtls: canonical_json(&c.mtls),
            key_server: canonical_json(&c.key_server),
            agent_auth: canonical_json(&c.agent_auth),
            runtime: canonical_json(&c.runtime),
            control_plane: canonical_json(&c.control_plane),
            server_public_url: c.server.public_url.clone().unwrap_or_default(),
            #[cfg(feature = "cost-governance")]
            cost_governance: canonical_json(&c.cost_governance),
            tasks: canonical_json(&c.tasks),
            accounts: canonical_json(&c.accounts),
        }
    }
}

/// Partition backends into added / removed / modified buckets.
///
/// Compared and carried as EFFECTIVE configurations — what a bound backend
/// actually runs with, from `config::account_bindings::effective_backends`.
/// `apply_patch` constructs the replacement `Backend` straight from what it is
/// handed, so a raw config here would drop the `identity_propagation` a managed
/// descriptor compiled to and leave the replacement dispatching with no
/// per-user credential at all. Comparing effective configs also means an
/// unchanged binding stays byte-identical across a reload instead of appearing
/// modified.
pub(super) fn classify_backends(old: &Config, new: &Config, patch: &mut ConfigPatch) {
    let runtime_changed = canonical_json(&old.runtime) != canonical_json(&new.runtime);
    let old_effective = crate::config::account_bindings::effective_backends(old);
    let new_effective = crate::config::account_bindings::effective_backends(new);
    let old_enabled: std::collections::HashMap<&str, &BackendConfig> = old_effective
        .iter()
        .filter(|(_, c)| c.enabled)
        .map(|(k, v)| (k.as_str(), v))
        .collect();

    let new_enabled: std::collections::HashMap<&str, &BackendConfig> = new_effective
        .iter()
        .filter(|(_, c)| c.enabled)
        .map(|(k, v)| (k.as_str(), v))
        .collect();

    // Added: in new but not in old
    for (name, cfg) in &new_enabled {
        if !old_enabled.contains_key(name) {
            patch
                .backends_added
                .push(((*name).to_string(), (*cfg).clone()));
        }
    }

    // Removed: in old but not in new
    for name in old_enabled.keys() {
        if !new_enabled.contains_key(name) {
            patch.backends_removed.push((*name).to_string());
        }
    }

    // Modified: in both but config differs
    for (name, new_cfg) in &new_enabled {
        if let Some(old_cfg) = old_enabled.get(name)
            && (backend_config_changed(old_cfg, new_cfg)
                || (runtime_changed && new_cfg.runtime_profile.is_some()))
        {
            patch
                .backends_modified
                .push(((*name).to_string(), (*new_cfg).clone()));
        }
    }
}

/// Returns `true` when any observable field of a backend config differs.
///
/// Uses canonical JSON for a stable, deep equality check without requiring
/// `PartialEq` on all nested types.
pub(super) fn backend_config_changed(old: &BackendConfig, new: &BackendConfig) -> bool {
    canonical_json(old) != canonical_json(new)
}
