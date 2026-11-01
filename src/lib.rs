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
#[doc(hidden)]
pub mod cli_support;
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
mod counters;
mod debug_trust_roots;
// The decision set serves only the web UI's routes and stream.
#[cfg(feature = "webui")]
mod decisions;
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
pub use fs_lock::lock_directory_finding;
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
mod jitter;
#[doc(hidden)]
pub mod key_server;
#[doc(hidden)]
pub mod kill_switch;
#[doc(hidden)]
pub mod kubernetes;
pub(crate) mod local_day;
mod log_escape;
mod log_writer;
#[cfg(feature = "metrics")]
#[doc(hidden)]
pub mod metrics;
#[doc(hidden)]
pub mod mtls;
#[doc(hidden)]
pub mod oauth;
mod observer;
mod open_nonblocking;
pub(crate) mod personal_accounts;
#[doc(hidden)]
pub mod playbook;
#[doc(hidden)]
pub mod preview_sandbox;

// The preview sandbox's test seams must never ship: a release build with them
// fails here, and CI proves it with a build that must fail.
#[cfg(all(feature = "sandbox-fixtures", not(debug_assertions)))]
compile_error!(
    "the sandbox-fixtures feature is for tests only and cannot be built without debug_assertions"
);
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
// The UI save core is its first caller (ADR-024); until then only tests use it.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        unused_imports,
        reason = "the UI save core is its first caller"
    )
)]
mod secret_store;
// The one read-only view `mcp-gateway doctor` takes of the store.
#[doc(hidden)]
pub use secret_store::{SecretStoreReport, doctor_report};
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
// Every caller judges a daily budget, which only a cost-governance build has.
#[cfg(all(test, feature = "cost-governance"))]
pub(crate) mod test_day;
#[cfg(test)]
pub(crate) mod test_fixture_host;
#[cfg(test)]
pub(crate) mod test_late_write;
#[cfg(test)]
mod test_pause;
#[cfg(test)]
mod test_ports;
#[cfg(test)]
pub(crate) mod test_source_text;
#[cfg(test)]
mod test_source_text_tests;
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
mod transport_key;
mod truncate;
#[doc(hidden)]
pub mod trust;
#[cfg(test)]
mod unsafe_allowlist_tests;
#[doc(hidden)]
pub mod validator;
// Windows owner-only store custody and Credential Manager: `win_acl` and
// `win_cred` are the modules allowed `unsafe` (ADR-016, ADR-028 §2a).
#[cfg(windows)]
mod private_fs;
#[cfg(windows)]
mod win_acl;
#[cfg(windows)]
mod win_cred;
#[cfg(all(test, windows))]
mod win_cred_tests;
mod wiped_bytes;
/// The one YAML seam (MIK-8425); crate-private.
mod yaml;

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
/// Lines go through a bounded queue to one writer thread
/// ([`log_writer`]): a stderr that stops draining drops and counts lines
/// instead of blocking the thread that logs. Keep the returned guard alive
/// for the life of the process and drop it last: dropping it flushes the
/// queue, waiting at most [`log_writer::LOG_FLUSH_DEADLINE`].
///
/// Library callers must keep the returned value until the process exits:
/// `let _logs = setup_tracing(level, format)?;`. Discarding it flushes at
/// once, and lines logged later are no longer flushed at exit.
///
/// # Errors
///
/// Fails when the writer thread cannot be started.
#[doc(hidden)]
#[must_use = "hold the returned guard for the life of the process: dropping it flushes the log queue"]
pub fn setup_tracing(level: &str, format: Option<&str>) -> Result<impl Sized + use<>> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    let filter = cap_handshake_logging(filter);
    let notice = match format {
        Some("json") => log_writer::NoticeFormat::Json,
        _ => log_writer::NoticeFormat::Text,
    };
    let (writer, flush) = log_writer::spawn(
        Box::new(std::io::stderr()),
        log_writer::LOG_QUEUE_LINES,
        log_writer::LOG_QUEUE_BYTES,
        notice,
    )
    .map_err(|e| Error::Internal(format!("cannot start the log writer thread: {e}")))?;
    tracing_subscriber::registry()
        .with(filter)
        .with(log_layer(notice, writer))
        .init();
    Ok(flush)
}

/// The one fmt layer: JSON, or text through [`log_escape::escaping`], written
/// by `writer`. Shared with the tests so they run the production pipeline.
fn log_layer<S, W>(
    format: log_writer::NoticeFormat,
    writer: W,
) -> Box<dyn tracing_subscriber::Layer<S> + Send + Sync>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    W: for<'w> tracing_subscriber::fmt::MakeWriter<'w> + Send + Sync + 'static,
{
    match format {
        log_writer::NoticeFormat::Json => Box::new(fmt::layer().json().with_writer(writer)),
        log_writer::NoticeFormat::Text => {
            Box::new(log_escape::escaping(fmt::layer().with_writer(writer)))
        }
    }
}

#[cfg(test)]
#[path = "log_filter_tests.rs"]
mod log_filter_tests;

/// LOG.2: no tracing line is written while a lock guard is held.
#[cfg(test)]
mod log_under_lock_scan_tests;

// Unix-only: asserts POSIX mode bits under a child's umask.
#[cfg(all(test, unix))]
mod file_mode_inherit_tests;

#[cfg(test)]
pub(crate) mod test_classification_count;
#[cfg(test)]
pub(crate) mod test_log_capture;

// Unix-only (W-L8): `mkfifo` has no Windows counterpart.
#[cfg(all(test, unix))]
pub(crate) mod test_fifo;

#[cfg(test)]
pub(crate) mod test_symlink;
