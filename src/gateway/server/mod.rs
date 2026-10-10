// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Gateway server

// Crate-visible on purpose: this is THE install a bound backend gets, and a
// test that drives a real startup must call the same one rather than a copy of
// its policy.
pub(crate) mod account_bindings;
#[cfg(test)]
mod attestation_start_tests;
#[cfg(test)]
mod audit_start_tests;
mod background;
mod build_meta;
mod cleartext;
#[cfg(all(test, feature = "firewall"))]
mod collusion_share_tests;
mod construct;
mod control_plane_store;
#[cfg(all(test, feature = "cost-governance"))]
mod cost_restart_tests;
mod events_wiring;
#[cfg(test)]
mod gh475_budget_decides_tests;
mod identity_grants;
#[cfg(all(test, feature = "firewall"))]
mod keyless_anomaly_tests;
mod listener;
mod persistence;
mod provenance_signer;
#[cfg(test)]
mod remote_provenance_start_tests;
#[cfg(test)]
mod replica_state_tests;
#[cfg(all(test, feature = "firewall"))]
pub(super) mod route_matrix_driver_tests;
mod run;
mod run_steps;
#[cfg(test)]
#[path = "tests/mod.rs"]
pub(crate) mod signing_allocation_tests;
mod start_checks;
mod stdio_catalogue;
mod stdio_channel;
mod stdio_delivery;
mod stdio_dispatch;
mod stdio_dispatches;
mod stdio_loop;
mod stdio_nonce;
mod stdio_notify;
mod stdio_refusal;
mod stdio_shutdown;
mod stdio_single;
mod stdio_tasks;
mod stdio_writer;
mod task_runtime;
#[cfg(test)]
mod test_seams;
pub(crate) use stdio_nonce::StdioNonce;
mod support;
mod tools_changed;
// Two questions leave this module, both to `config_reload`, and each is
// exported under the question it answers. A reload asks about the config that
// would be IN FORCE, so it goes through the overlay. A restart-only edit asks
// what the NEXT START does with the file, which is the startup check itself —
// the same function the bind path calls, named here for the caller.
pub(crate) use cleartext::reload_posture_refusal;
pub(crate) use support::start_refusal as next_start_refusal;
mod warmstart;

use std::path::PathBuf;
use std::sync::Arc;

use super::router::CallerStanding;

use crate::backend::BackendRegistry;
use crate::config::Config;

#[cfg(test)]
use super::meta_mcp::MetaMcp;
#[cfg(test)]
use crate::mtls::MtlsPolicy;
#[cfg(test)]
use crate::security::ToolPolicy;
pub(crate) use background::AbortOnDrop;
#[cfg(test)]
use background::poll_export_source;
use background::{spawn_export_task, spawn_health_loop, spawn_idle_reaper};
use build_meta::BuiltMetaMcp;
use control_plane_store::{build_control_plane_store, control_plane_base};
#[cfg(test)]
use identity_grants::load_configured_identity_grants;
#[cfg(test)]
use provenance_signer::{provenance_key, resolve_provenance_signer};
#[cfg(test)]
use stdio_refusal::{admit_stdio_request, stdio_busy_batch_response, stdio_busy_response};
#[cfg(test)]
use stdio_single::stdio_caller_context;
use stdio_single::{StdioClient, stdio_routing_keys_only, stdio_take_merged_client_meta};

/// State owner for the single client on a long-lived stdio connection.
const STDIO_SESSION_ID: &str = "stdio-session";

/// How long the EOF path waits for the dispatches it already accepted.
///
/// How many frames may wait for stdout before producers stall.
///
/// Deep enough that an ordinary burst of progress notifications never blocks
/// a dispatch, shallow enough that a client which stops reading stalls the
/// gateway instead of growing its memory.
const STDOUT_QUEUE_DEPTH: usize = 1024;

/// How many stdio requests may be in flight at once.
///
/// Concurrency is the point of MIK-7387, but an uncapped spawn turns a client
/// that writes faster than the backends answer into unbounded task and backend
/// load. One client, so the cap is generous rather than tuned.
const MAX_CONCURRENT_STDIO_DISPATCHES: usize = 64;

/// Accepted-but-unfinished stdio requests, which is a different question from
/// how many may run at once (`MAX_CONCURRENT_STDIO_DISPATCHES`). Sized to the
/// stdout queue: work admitted beyond what the writer can still hold has
/// nowhere to put its answer, so the client is told to slow down instead.
const MAX_INFLIGHT_STDIO_REQUESTS: usize = STDOUT_QUEUE_DEPTH;

/// Bounded rather than unbounded: past it the `JoinSet` aborts what is left,
/// which is exactly the pre-concurrency behaviour and no worse (design §6).
const STDIO_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// The stdio protocol-revision sink, shared by every spawned dispatch.
///
/// A `std::sync::Mutex` and never a `tokio` one: every writer is synchronous,
/// so the guard is taken and dropped without an await in between. Holding one
/// across an await would make the dispatch future `!Send` and serialise the
/// concurrent bridged calls this whole change exists to allow (design §5).
pub(crate) type StdioTelemetry =
    std::sync::Mutex<Option<crate::protocol_revision_telemetry::DurableTelemetrySink>>;

/// The standing stdio serves its resource and prompt surfaces at: the client
/// spawned this process, so it holds whatever the operator holds.
const STDIO: CallerStanding = CallerStanding::Admin;

fn expand_home_path(path: &str) -> PathBuf {
    if path == "~" {
        return crate::home_dir::home_dir().unwrap_or_else(|| PathBuf::from("."));
    }
    if let Some(rest) = path.strip_prefix("~/") {
        return crate::home_dir::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(rest);
    }
    PathBuf::from(path)
}

/// MCP Gateway server
pub struct Gateway {
    /// Configuration
    config: Config,
    /// Path to config file on disk (enables hot-reload when `Some`)
    config_path: Option<std::path::PathBuf>,
    /// A config file found by discovery rather than named (#1868): watched and
    /// reloaded, but never used where `config_path` picks a location (the
    /// governance store) or grants a write (admin config edits).
    watched_config: Option<std::path::PathBuf>,
    /// Backend registry
    backends: Arc<BackendRegistry>,
    /// Shutdown flag
    shutdown_tx: Option<tokio::sync::broadcast::Sender<()>>,
    /// The environment the config was evaluated against.
    ///
    /// Every lazy reader — capability credentials, the reload transaction, the
    /// file watcher — resolves through this rather than the process
    /// environment, which no env file is written to.
    env: Arc<crate::config::LiveEnv>,
    /// The one cross-tenant read history of this process (MIK-7116.MIN.2):
    /// both firewalls share it, so `/mcp` and `/mcp/{name}` meet in it.
    #[cfg(feature = "firewall")]
    reads: Arc<crate::security::firewall::tenant_reads::ReadHistory>,
    /// Managed personal-account custody, present only when the config carries an
    /// `accounts` block. `None` is the ordinary gateway: no store, no locks.
    ///
    /// Holding the handle rather than the store is deliberate: an explicit
    /// account shutdown releases the store and its two file locks while this
    /// handle stays here to refuse everything that arrives afterwards.
    custody: Option<Arc<crate::personal_accounts::GatewayCustody>>,
    /// In-process test settings: data directory and bound-port channel.
    #[cfg(test)]
    test_seams: test_seams::TestSeams,
}

/// Which single minting strategy kind, if any, this config installs
/// process-wide. Returns the minting kind present among backends
/// (`SignedAssertion` or `TokenExchange`), or `None` when only `Passthrough`
/// or no `identity_propagation` is configured.
///
/// This is a strict allow-list of *implemented* minting strategies, not a
/// `!= Passthrough` deny-list. The deny-list form was unsafe: a backend
/// configured for an as-yet-unimplemented minting strategy (`Vault`,
/// MIK-6730) is `!= Passthrough`, so it would silently install some other
/// strategy and let the meta route mint the wrong credential shape for a
/// backend the operator asked to reach via a different trust model, a silent
/// substitution and an INV-4 violation. Allow-listing means each minting
/// strategy installs its own machinery only once it is actually wired here:
/// `SignedAssertion` (MIK-6704) and `TokenExchange` (RFC 8693, MIK-6729) are
/// both wired; `Vault` is not yet and so returns `None`. `Passthrough` mints
/// nothing (ADR-008, GPT review F1/R2-3, MIK-6746).
///
/// `validate_single_minting_strategy_kind` guarantees at most one minting kind
/// across all backends, so returning the first match is unambiguous.
fn configured_minting_strategy_kind(
    config: &crate::config::Config,
) -> Option<crate::identity_propagation::PropagationStrategyKind> {
    use crate::identity_propagation::PropagationStrategyKind as Kind;
    config.backends.values().find_map(|b| {
        b.identity_propagation.as_ref().and_then(|c| {
            matches!(c.strategy, Kind::SignedAssertion | Kind::TokenExchange).then_some(c.strategy)
        })
    })
}

/// Whether startup should install a minting strategy at all. True iff at least
/// one backend opts into an implemented minting strategy (`SignedAssertion` or
/// `TokenExchange`); see [`configured_minting_strategy_kind`] for the full
/// allow-list rationale and the `Passthrough`-only "install nothing" contract.
///
/// Test-only: production keys off [`configured_minting_strategy_kind`] directly
/// so it can pick the concrete strategy. This stays as a readable predicate for
/// the install-decision tests.
#[cfg(test)]
fn config_installs_minting_strategy(config: &crate::config::Config) -> bool {
    configured_minting_strategy_kind(config).is_some()
}

/// Backends whose gateway-held OAuth token is not blessed for shared use
/// (`oauth.enabled && !oauth.shared_account`) — the set the GW.3 startup
/// warning names (MIK-6784).
///
/// Returns empty unless `auth.single_user` is asserted: the warning only
/// matters when that single switch is the sole thing suppressing the per-user
/// OAuth isolation guard. Under `single_user = true`, any such backend leaks
/// its token — and its upstream MCP session — across users the moment a second
/// identity reaches the gateway.
fn leaky_single_user_backends(config: &Config) -> Vec<&str> {
    if !config.auth.single_user {
        return Vec::new();
    }
    config
        .backends
        .iter()
        .filter(|(_, b)| {
            b.oauth
                .as_ref()
                .is_some_and(|o| o.enabled && !o.shared_account)
        })
        .map(|(name, _)| name.as_str())
        .collect()
}

/// The admission ledger namespaces a client-chosen idempotency key under a
/// principal. Stdio has no OIDC identity and no credential to derive one from,
/// so without a value here every modern mutating call is refused `-32003` and
/// the transport can carry no keyed write at all. A constant is sufficient
/// rather than a stopgap: a stdio process serves exactly the one client that
/// spawned it, and each process owns a separate in-memory
/// `ExecutionAdmission` (`src/idempotency/admission.rs`), so no second caller
/// and no second process can share the namespace this names. This is not an
/// authorization decision — reaching the gateway over stdio already grants
/// full tool access. If the ledger ever gains shared storage, revisit it.
pub(crate) const STDIO_CREDENTIAL_PRINCIPAL: &str = "stdio";

#[cfg(test)]
mod gateway_bootstrap_tests;

#[cfg(test)]
mod stdio_forward_path_tests;

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use chrono::Utc;
    use serde_json::json;

    use super::{
        Gateway, load_configured_identity_grants, provenance_key, resolve_provenance_signer,
    };
    use crate::{
        backend::BackendRegistry,
        config::{
            BackendConfig, Config, ContextIntegrityPresetConfig, IdentityGrantsConfig,
            TransportConfig,
        },
        gateway::meta_mcp::MetaMcp,
        identity_grants::{GrantAgent, GrantScope, GrantSubject, IdentityGrant, IdentityGrantFile},
        mtls::{MtlsConfig, MtlsPolicy},
        protocol::{JsonRpcResponse, RequestId},
        security::ToolPolicy,
    };

    mod order2_fsm;

    fn test_meta_mcp() -> Arc<MetaMcp> {
        Arc::new(MetaMcp::new(Arc::new(BackendRegistry::new())))
    }

    fn test_tool_policy() -> Arc<ToolPolicy> {
        Arc::new(ToolPolicy::default())
    }

    fn test_mtls_policy() -> Arc<MtlsPolicy> {
        Arc::new(MtlsPolicy::from_config(&MtlsConfig::default()))
    }

    mod boot;
    mod build_meta_wiring;
    mod startup_strategy;
    mod stdio_dispatch;

    // ── MIK-7212 OBS.1: the observation record on the stdio path ───────────
    //
    // Both record sites live in the HTTP handler (`router/handlers.rs:716` for
    // the revision, `:990` for the tools/list surface). `dispatch_single` is
    // what the stdio read loop calls and it passes neither, so a stdio session
    // is observed by nothing. This module pins that gap as a failing assertion
    // rather than describing it in prose: a criterion nobody can run is a
    // criterion nobody checks.
    //
    // RED ON ARRIVAL, deliberately. The repair is to emit the record from a
    // place both dispatchers reach; adding the emit is not this change's job.
    /// The saturation gate the stdio read loop consults (design §7).
    mod stdio_admission;

    mod stdio_observation;
}
