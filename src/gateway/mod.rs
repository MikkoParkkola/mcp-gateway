// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Gateway server implementation

pub mod auth;
mod change_feed;
pub(crate) use change_feed::ChangeFeed;
pub(crate) mod authz;
pub mod destructive_confirmation;
mod differential;
mod http_error;
pub mod input_bridge;
mod meta_mcp;
/// Where the CLI runner notes a child it started for the call's invocation
/// record (MIK-7926.FIX.2), without `meta_mcp` becoming crate-visible.
pub(crate) use meta_mcp::invoke::audit::note_process;
/// The per-delivery write record, shared with the response and idempotency
/// caches that store it beside an answer (MIK-7991).
pub(crate) use meta_mcp::invoke::gateway_writes;
/// The one write-then-bump-under-lock grant publisher, re-exported so the
/// reload path can share it WITHOUT `meta_mcp` itself becoming crate-visible.
/// Same shape as `STDIO_CREDENTIAL_PRINCIPAL`. A second copy of those four
/// lines is how the `Release` ordering gets dropped in a later edit.
pub(crate) use meta_mcp::publish_identity_grants;
/// MIK-8176: execution admission (`idempotency::admission`) co-owns the holds
/// of a stored delivery and adopts them on replay.
pub(crate) use meta_mcp::sealed_hold;
/// The notes scope and the gateway, for the CLI process audit rows
/// (MIK-7926.FIX.2), which run a real child in `capability::executor`.
#[cfg(test)]
pub(crate) use meta_mcp::{MetaMcp, invoke::audit::with_dispatch_scope};
mod meta_mcp_helpers;
mod meta_mcp_helpers_routing;
mod meta_mcp_helpers_text;
mod meta_mcp_search_schema;
mod meta_mcp_tool_defs;
mod meta_mcp_tool_total;
mod middleware;
pub mod oauth;
// Crate-internal on purpose: the adapter is wired by `router` and by nothing
// else, so no caller outside the gateway can install it without the standard
// auth layer that must run first.
#[cfg(test)]
pub(crate) mod chain_test_support;
// Every egress matrix it feeds is `firewall`-gated.
#[cfg(all(test, feature = "firewall"))]
pub(crate) mod egress_fixture;
mod openwebui_adapter;
pub(crate) mod outbound;
pub mod proxy;
#[cfg(test)]
mod proxy_scope_tests;
#[cfg(test)]
mod proxy_session_tests;
pub mod recovery;
mod router;
pub(crate) mod routes;
#[cfg(test)]
mod routes_tests;
/// The one constructor that turns a verified identity into a grant subject,
/// re-exported so the `MIK-7334.CATALOGUE.1` prefix cells can drive it WITHOUT
/// `router` itself becoming crate-visible. Same shape as
/// `STDIO_CREDENTIAL_PRINCIPAL` below. A fixture that reimplemented it could
/// not observe the trim/truncate-versus-raw-bytes divergence it exists to pin.
/// `#[cfg(test)]` because the cells are its only consumer today; MVP piece 3
/// (the reload loop) is what gives it a production caller.
#[cfg(test)]
pub(crate) use router::grant_subject_from_verified_identity;
pub(crate) mod search_disclosure;
mod server;
/// The one stdio admission identifier, re-exported so a consumer outside
/// `gateway` can name it WITHOUT `server` itself becoming crate-visible.
/// It is the stdio caller's audit and display principal only: it decides
/// nothing, since `CallerProvenance` and the retained-result keys follow the
/// transport's mark (`StdioNonce`) instead (MIK-7272.OWNER.3). Only tests
/// outside `gateway` still name it.
#[cfg(test)]
pub(crate) use server::STDIO_CREDENTIAL_PRINCIPAL;
/// The stdio transport's mark: the only proof of `CallerProvenance::LocalTransport`.
pub(crate) use server::StdioNonce;
/// The declared account catalogue, for `cap list`'s readiness answer; crate-only.
pub(crate) use server::account_bindings::declare_account_descriptors;
pub(crate) use server::account_bindings::{ServeMode, sole_operator_asserted};
/// The test-only allocation meter, for allocation rows outside `gateway`
/// (`MIK-8201`), without `server` becoming crate-visible. The meter needs
/// only `cfg(test)`; its readers include rows built without `firewall`.
#[cfg(test)]
pub(crate) use server::signing_allocation_tests::alloc_meter;
pub(crate) mod session_id;
pub mod session_lifecycle;
pub mod state;
pub mod streaming;
pub mod subscription_registry;
pub(crate) mod task_route;
pub(crate) mod task_service;
pub mod trace;
#[cfg(feature = "webui")]
pub mod ui;
pub mod webhooks;

pub use auth::{AuthState, ResolvedAuthConfig, auth_middleware};
// One owner for "is this host loopback", reachable crate-wide. `mod router` is
// private, so config validation and shadow discovery cannot spell the classifier
// without this line — and the alternative to the line is a second copy of the
// rule, which is what it exists to prevent. Crate-internal: no public surface.
pub use oauth::{
    AgentAuthState, AgentIdentity, AgentRegistry, GatewayKeyPair, agent_auth_middleware,
};
pub use proxy::ProxyManager;
pub(crate) use router::is_loopback_bind as is_loopback_host;
pub use server::Gateway;
pub(crate) use server::{next_start_refusal, reload_posture_refusal};
pub use streaming::{NotificationMultiplexer, TaggedNotification};
pub use webhooks::WebhookRegistry;

/// Where a credential may travel: `https://`, or `http://` to a loopback host,
/// which never leaves the machine. Every cleartext-credential guard decides
/// here, on [`is_loopback_host`], so no two of them can drift. A spelling the
/// classifier does not know (`localhost.`, `[::ffff:127.0.0.1]`) is refused.
pub(crate) fn is_tls_or_loopback(url: &url::Url) -> bool {
    match url.scheme() {
        "https" => true,
        "http" => is_loopback_host(url.host_str().unwrap_or_default()),
        _ => false,
    }
}

/// Public test helpers for integration tests in `tests/`.
///
/// Exposes internal types (`AppState`, `MetaMcp`, `create_router`) that are
/// not part of the public API but are needed to build an in-process router
/// without starting a real TCP server.
///
/// Hidden from docs; only used in the `tests/` directory.
#[doc(hidden)]
pub mod test_helpers {
    pub use super::meta_mcp::prune_constant_signals;
    pub use super::meta_mcp::{CacheKeyDeriver, stable_tool_order, tool_schema_fingerprint};
    pub use super::meta_mcp::{InvokeScope, MetaMcp};
    pub use super::router::{AppState, CallerStanding, create_router};
    pub use super::task_service::{
        ServiceError, StoreLimits, TaskExecutor, TaskService, open_runtime,
    };

    /// The one bound a test uses to say "this wait is a hang guard"
    /// (MIK-8247, MIK-8288): long enough that a loaded runner never reaches
    /// it on a green run, so it costs nothing until something is truly stuck.
    /// Lib tests reach it as `crate::test_wait::HANG_BOUND`.
    pub const HANG_BOUND: std::time::Duration = std::time::Duration::from_secs(30);

    /// Bind `meta` to the HTTP server's change feed, as `serve` does (F24), so
    /// an in-process fixture advertises what the HTTP server advertises.
    pub fn bind_http_change_feed(meta: &MetaMcp) {
        meta.set_change_feed(super::ChangeFeed::Http);
    }

    /// The authorizer a fixture's `SubscriptionRegistry` re-validates against:
    /// `config` with no key server, as a fixture's `AppState` carries it.
    #[must_use]
    pub fn auth_state(config: &crate::config::AuthConfig) -> super::AuthState {
        super::AuthState {
            auth_config: std::sync::Arc::new(super::ResolvedAuthConfig::from_config(config)),
            key_server: None,
            dashboard_bootstrap: std::sync::Arc::default(),
            tls_enabled: false,
            live_config: std::sync::Arc::new(crate::config_reload::LiveConfig::new(
                crate::config::Config::default(),
            )),
            agent_auth: crate::gateway::oauth::AgentAuthState::new(
                false,
                std::sync::Arc::default(),
            ),
        }
    }

    /// Writes a whole `config` to `path` for a test fixture, through the
    /// deprecated snapshot writer on purpose: a fixture sets up a file, it
    /// does not race another writer.
    ///
    /// # Errors
    ///
    /// The writer's own error message.
    pub fn write_config_fixture(
        path: &std::path::Path,
        config: &crate::config::Config,
    ) -> Result<(), String> {
        #[allow(deprecated)] // test fixture writes a whole config on purpose
        crate::config_persistence::write_config(path, config)
    }

    /// Writes config `text` to `path` for a test fixture, through the
    /// deprecated unlocked text writer on purpose (see
    /// [`write_config_fixture`]).
    ///
    /// # Errors
    ///
    /// The writer's own error message.
    pub fn write_config_text_fixture(path: &std::path::Path, text: &str) -> Result<(), String> {
        #[allow(deprecated)] // test fixture writes a whole config on purpose
        crate::config_persistence::write_config_text(path, text)
    }

    /// A receiver told once when a CLI config writer next starts waiting for
    /// `config`'s lock: a concurrency test overlaps two writers by it instead
    /// of a fixed sleep.
    pub fn when_waiting_for_config_lock(config: &std::path::Path) -> std::sync::mpsc::Receiver<()> {
        crate::config_persistence::when_waiting_for_lock(config)
    }

    /// Writes a fixture owner-only (0600 on Unix), as the gateway requires of
    /// a config or env file it loads (CONFIG.2). Same shape as `std::fs::write`,
    /// so a fixture swaps one call for the other.
    pub fn write_owner_only(
        path: impl AsRef<std::path::Path>,
        contents: impl AsRef<[u8]>,
    ) -> std::io::Result<()> {
        #[cfg(windows)]
        {
            use std::io::Write as _;
            match std::fs::remove_file(&path) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
                _ => {}
            }
            let mut file = crate::private_fs::create_file_private(
                path.as_ref(),
                crate::private_fs::Share::Exclusive,
            )?;
            file.write_all(contents.as_ref())
        }
        #[cfg(not(windows))]
        {
            std::fs::write(&path, contents)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
            }
            Ok(())
        }
    }
}
