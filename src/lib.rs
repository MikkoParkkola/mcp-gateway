// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Internal library of the `mcp-gateway` binary.
//!
//! This crate is published as a command-line gateway, not as a library. The
//! library target exists so the binary, its integration tests and its benches
//! share one build. It has no supported or stable API: every crate-root item
//! is `#[doc(hidden)]` and may change or vanish in any release, including a
//! patch release. Use the `mcp-gateway` binary, its configuration and its
//! HTTP and MCP interfaces instead (see the README).

#![deny(unsafe_code)]
// In stdio mode stdout is the JSON-RPC stream to the client, so library code
// never prints to it: a stray line breaks the client's framing. Diagnostics go
// to stderr or tracing. CLI output lives in the binary (`main.rs`,
// `commands`), and the library's two CLI-output modules write through
// `cli::stdout`'s macros, which this lint does not cover by design. Test code
// keeps `println!`: test-only child processes use stdout as their protocol.
#![cfg_attr(not(test), deny(clippy::print_stdout))]
#![warn(missing_docs)]
// Macro-generated arrays (e.g. include_bytes!) may exceed the 16 KiB stack
// threshold.  Clippy cannot show a source location for these — allow crate-wide.
#![allow(clippy::large_stack_arrays)]

#[cfg(feature = "a2a")]
pub(crate) mod a2a;
#[doc(hidden)]
pub mod attestation;
#[doc(hidden)]
pub mod autotag;
#[doc(hidden)]
pub mod backend;
#[doc(hidden)]
pub mod cache;
#[doc(hidden)]
pub mod capability;
#[doc(hidden)]
pub mod chains;
#[doc(hidden)]
pub mod cli;
mod clock;
#[doc(hidden)]
pub mod config;
#[doc(hidden)]
pub mod config_persistence;
#[doc(hidden)]
pub mod config_reload;
#[doc(hidden)]
pub mod context_compression;
#[doc(hidden)]
pub mod context_integrity;
#[doc(hidden)]
pub mod control_plane;
#[doc(hidden)]
pub mod cost_accounting;
mod debug_trust_roots;
#[doc(hidden)]
pub mod discovery;
mod duration_bound;
#[doc(hidden)]
pub mod error;
mod events;
#[doc(hidden)]
pub mod failsafe;
mod fs_lock;
#[doc(hidden)]
pub mod gateway;
mod hashing;
mod home_dir;
#[doc(hidden)]
pub mod honest_task_tokens;
#[doc(hidden)]
pub mod idempotency;
#[doc(hidden)]
pub mod identity_grants;
#[doc(hidden)]
pub mod identity_propagation;
#[doc(hidden)]
pub mod key_server;
#[doc(hidden)]
pub mod kill_switch;
#[doc(hidden)]
pub mod kubernetes;
#[cfg(feature = "metrics")]
#[doc(hidden)]
pub mod metrics;
#[doc(hidden)]
pub mod mtls;
#[doc(hidden)]
pub mod oauth;
mod observer;
pub(crate) mod personal_accounts;
#[doc(hidden)]
pub mod playbook;
#[doc(hidden)]
pub mod projection;
#[doc(hidden)]
pub mod protocol;
#[doc(hidden)]
pub mod protocol_imports;
#[doc(hidden)]
pub mod protocol_revision_telemetry;
#[doc(hidden)]
pub mod provider;
#[doc(hidden)]
pub mod ranking;
#[doc(hidden)]
pub mod registry;
#[doc(hidden)]
pub mod routing_profile;
#[doc(hidden)]
pub mod runtime;
#[doc(hidden)]
pub mod scheduler;
#[doc(hidden)]
pub mod secret_injection;
#[doc(hidden)]
pub mod secrets;
#[doc(hidden)]
pub mod security;
#[cfg(feature = "semantic-search")]
#[doc(hidden)]
pub mod semantic_search;
#[doc(hidden)]
pub mod simhash;
#[doc(hidden)]
pub mod skills;
#[doc(hidden)]
pub mod stats;
#[cfg(test)]
mod test_pause;
#[cfg(test)]
mod test_ports;
#[cfg(test)]
mod test_wait;
#[cfg(feature = "tool-profiles")]
#[doc(hidden)]
pub mod tool_profiles;
#[doc(hidden)]
pub mod tool_registry;
#[doc(hidden)]
pub mod tracing_context;
#[doc(hidden)]
pub mod transform;
#[doc(hidden)]
pub mod transition;
#[doc(hidden)]
pub mod transport;
#[doc(hidden)]
pub mod trust;
#[doc(hidden)]
pub mod validator;
// Windows owner-only store custody; `win_acl` is the one module allowed
// `unsafe` (ADR-016).
#[cfg(windows)]
mod private_fs;
#[cfg(windows)]
mod win_acl;

#[doc(hidden)]
pub use error::{Error, Result};

// Offline account-store initialization only — the same narrowing `config`
// already applies to the `AccountsConfig` DTO. The store, the service and the
// worker stay crate-private; this exposes one explicit, offline entry point so
// the `accounts init-store` command can reach it without opening the module.
#[doc(hidden)]
pub use personal_accounts::{
    InitializedStore, MigratedCredential, OfflineInitError, OfflineMigrationError,
    initialize_store_offline, migrate_legacy_credential_offline,
};

use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

/// MCP Protocol version supported by this gateway (latest)
#[doc(hidden)]
pub const MCP_PROTOCOL_VERSION: &str = "2025-11-25";

/// Cap third-party logging that writes credentials, whatever the operator asked for.
///
/// tungstenite's client handshake logs the whole upgrade request at TRACE:
/// the path with its query (`?token=`) and every header (`Authorization`).
/// Added after the operator's directives, and for the exact module as well as
/// its parent, so neither `RUST_LOG=trace` nor a directive naming the module
/// can re-enable it. DEBUG stays available for handshake diagnostics.
fn cap_handshake_logging(filter: EnvFilter) -> EnvFilter {
    [
        "tungstenite::handshake=debug",
        "tungstenite::handshake::client=debug",
    ]
    .into_iter()
    .filter_map(|directive| directive.parse().ok())
    .fold(filter, EnvFilter::add_directive)
}

/// Setup tracing/logging
///
/// All log output is written to **stderr**. In stdio transport mode
/// (`serve --stdio`) stdout is reserved exclusively for newline-delimited
/// JSON-RPC frames; emitting logs there corrupts the stream and breaks MCP
/// clients (see issue #224). Writing to stderr is also correct for the HTTP
/// server mode, where supervisors (systemd, Docker) capture stderr normally.
///
/// # Errors
///
/// This function currently always succeeds but returns `Result` for
/// forward compatibility with fallible tracing configurations.
#[doc(hidden)]
pub fn setup_tracing(level: &str, format: Option<&str>) -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    let filter = cap_handshake_logging(filter);

    let subscriber = tracing_subscriber::registry().with(filter);

    match format {
        Some("json") => {
            subscriber
                .with(fmt::layer().json().with_writer(std::io::stderr))
                .init();
        }
        _ => {
            subscriber
                .with(fmt::layer().with_writer(std::io::stderr))
                .init();
        }
    }

    Ok(())
}

#[cfg(test)]
#[path = "log_filter_tests.rs"]
mod log_filter_tests;

#[cfg(test)]
pub(crate) mod test_classification_count;
#[cfg(test)]
pub(crate) mod test_log_capture;

// Unix-only (W-L8): `mkfifo` has no Windows counterpart.
#[cfg(all(test, unix))]
pub(crate) mod test_fifo;

#[cfg(test)]
pub(crate) mod test_symlink;
