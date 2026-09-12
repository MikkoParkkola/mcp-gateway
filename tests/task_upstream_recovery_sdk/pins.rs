// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Preconditions for the real-SDK vertical.
//!
//! Every one of these is a REQUIREMENT, not a switch. A missing pin fails the
//! test loudly and says exactly what to set: a test that skipped itself here
//! would report success while proving nothing about the pinned stack.

use std::path::{Path, PathBuf};
use std::time::Duration;

/// Interpreter of the pinned environment (fastmcp 4.0.3, fastmcp-tasks 4.0.3,
/// pydocket 0.25.0).
pub const PYTHON_ENV: &str = "MCP_GATEWAY_TASK_SDK_PYTHON";
/// Loopback URL of the dedicated Redis instance the supervisor owns. `memory://`
/// and any in-process substitute are refused below: the point of the fixture is
/// that a real task runtime holds the job.
pub const REDIS_ENV: &str = "MCP_GATEWAY_TASK_SDK_REDIS_URL";

/// Bound on every HTTP send-and-read this test performs, applied at the client
/// so no request can hang without a deadline.
pub const REQUEST_BOUND: Duration = Duration::from_secs(30);
/// Bound on a child becoming ready, a gate transition, or a job settling.
pub const PEER_BOUND: Duration = Duration::from_secs(120);
pub const POLL_GAP: Duration = Duration::from_millis(100);

fn required(name: &str, what: &str) -> String {
    let value = std::env::var(name).unwrap_or_default();
    assert!(
        !value.trim().is_empty(),
        "this test runs the ACTUAL pinned stack and substitutes nothing for it. \
         Set {name} to {what}."
    );
    value.trim().to_string()
}

pub fn pinned_python() -> PathBuf {
    let path = PathBuf::from(required(
        PYTHON_ENV,
        "the interpreter of the pinned environment \
         (fastmcp==4.0.3, fastmcp-tasks==4.0.3, pydocket==0.25.0)",
    ));
    assert!(
        path.exists(),
        "{PYTHON_ENV} points at {}, which does not exist",
        path.display()
    );
    path
}

pub fn redis_url() -> String {
    let url = required(
        REDIS_ENV,
        "the loopback URL of the dedicated Redis instance for this run \
         (e.g. redis://127.0.0.1:<port>/0)",
    );
    assert!(
        url.starts_with("redis://") || url.starts_with("rediss://"),
        "{REDIS_ENV} must name an actual Redis service; got {url:?}. \
         `memory://` is an in-process substitute and does not prove that a task \
         runtime outside the gateway held the job."
    );
    assert!(
        url.contains("127.0.0.1") || url.contains("localhost") || url.contains("[::1]"),
        "{REDIS_ENV} must be loopback-only; got {url:?}. This test uses no \
         external service and no user data."
    );
    url
}

pub fn fixture_script() -> PathBuf {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/task_upstream_sdk/server.py");
    assert!(
        path.exists(),
        "the pinned SDK fixture is missing at {}",
        path.display()
    );
    path
}

/// The child-scoped trust anchor this test installs is `SSL_CERT_FILE`, which
/// reaches the gateway's JWKS client through
/// `reqwest 0.13 (feature "rustls") -> rustls-platform-verifier ->
/// rustls-native-certs -> openssl-probe`. That chain is the Unix-non-Apple
/// branch of `rustls-platform-verifier`; on Apple targets the verifier asks the
/// Security framework instead and honours no such variable. Rather than assert
/// an override the dependency does not implement, this says so and stops.
#[expect(
    clippy::assertions_on_constants,
    reason = "cfg!(...) is deliberately a compile-time constant here: it gates this test to the one target family where SSL_CERT_FILE is honoured, not a runtime condition"
)]
pub fn require_supported_trust_override() {
    assert!(
        cfg!(all(unix, not(target_vendor = "apple"))),
        "the gateway's OIDC/JWKS client resolves roots through \
         rustls-platform-verifier, which only consults SSL_CERT_FILE on its \
         Unix-non-Apple branch. There is no supported way to hand this child a \
         temporary CA on this target, and adding a production test bypass is \
         out of scope, so this proof runs on Linux."
    );
}
