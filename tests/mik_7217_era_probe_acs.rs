// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Acceptance tests for the outbound era probe:
//!
//! - `MIK-7217.DISCOVER.4` — the gateway MUST detect a backend's protocol era by probing, not by
//!   trusting a version string.
//! - `MIK-7217.DISCOVER.5` — the detected era MUST be cached per backend and re-probed when a
//!   cached assumption fails.
//!
//! These are written BEFORE the implementation. Every one of them fails now, and that failure is
//! the point: a test written after the code agrees with the code, not with the requirement.
//!
//! Every assertion here reads the *frames the backend actually sent*, recorded by a dumb stdio
//! fixture that logs each request line before answering it. Nothing is asserted about the era
//! value itself, because no accessor for it exists on `Backend`; see the header of each test for
//! what it does and does not pin.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use mcp_gateway::backend::Backend;
use mcp_gateway::config::{BackendConfig, FailsafeConfig, TransportConfig};
use tempfile::TempDir;

/// A recorder, not a peer: every received line is appended to the log **before** any answer is
/// printed, so a frame that produced a response is on disk by the time the caller sees that
/// response. No era logic lives here — the fixture answers the same canned frames whatever the
/// gateway believes.
const FIXTURE: &str = r#"LOG='__LOG__'
while IFS= read -r request; do
    printf '%s\n' "$request" >> "$LOG"
    id=$(printf '%s' "$request" | tr ',' '\n' | sed -n 's/^"id":\([0-9][0-9]*\).*/\1/p' | head -1)
    case "$request" in
        *'"method":"initialize"'*)
            printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"__VERSION__","capabilities":{},"serverInfo":{"name":"era-fixture","version":"1"}}}\n' "$id"
            ;;
        *'"method":"server/discover"'*)
            printf '{"jsonrpc":"2.0","id":%s,__DISCOVER__}\n' "$id"
            ;;
        *'"method":"tools/list"'*)
            printf '{"jsonrpc":"2.0","id":%s,__TOOLS__}\n' "$id"
            ;;
    esac
done
"#;

struct Fixture {
    _dir: TempDir,
    log: PathBuf,
    command: String,
}

impl Fixture {
    /// `discover` and `tools` are the JSON-RPC payload that follows the echoed `id` — either
    /// `"result":{...}` or `"error":{...}`.
    fn new(handshake_version: &str, discover: &str, tools: &str) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("frames.log");
        let script = dir.path().join("peer.sh");
        let body = FIXTURE
            .replace("__LOG__", &log.display().to_string())
            .replace("__VERSION__", handshake_version)
            .replace("__DISCOVER__", discover)
            .replace("__TOOLS__", tools);
        std::fs::write(&script, body).expect("write fixture");
        let command = format!("sh {}", script.display());
        Self {
            _dir: dir,
            log,
            command,
        }
    }

    fn backend(&self, name: &str) -> Backend {
        let config = BackendConfig {
            description: format!("era probe fixture: {name}"),
            enabled: true,
            transport: TransportConfig::Stdio {
                command: self.command.clone(),
                cwd: None,
                protocol_version: None,
            },
            // No reaper: an idle sweep mid-test would restart the peer and re-probe it.
            stop_when_idle_for: None,
            timeout: Duration::from_secs(30),
            env: HashMap::default(),
            headers: HashMap::default(),
            oauth: None,
            secrets: Vec::new(),
            passthrough: false,
            runtime_profile: None,
            identity_propagation: None,
        };
        Backend::new(
            name,
            config,
            &FailsafeConfig::default(),
            Duration::from_secs(300),
        )
    }

    fn frames(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    fn discover_count(&self) -> usize {
        self.frames()
            .lines()
            .filter(|line| line.contains(r#""method":"server/discover""#))
            .count()
    }
}

const MODERN_DISCOVER: &str =
    r#""result":{"capabilities":{},"supportedVersions":["2026-07-28","2025-11-25"]}"#;
const LEGACY_DISCOVER: &str = r#""error":{"code":-32601,"message":"Method not found"}"#;
const EMPTY_TOOLS: &str = r#""result":{"tools":[]}"#;

/// DISCOVER.4 — the probe is sent even when the handshake already named a 2026 version.
///
/// This pins the half of DISCOVER.4 that frames can see: a probe is issued, and it is not
/// short-circuited by the `initialize` result's `protocolVersion`. The fixture answers the
/// handshake with `2026-07-28`, which is exactly the version string an implementation is tempted
/// to trust instead of probing. That premise is real, not assumed: the stdio transport reads
/// `protocolVersion` out of the `initialize` result and retains it
/// (`src/transport/stdio.rs:326-341`), so the announced version is available to be trusted.
///
/// It does NOT pin the shape-classification half — that the answer's `capabilities` object and
/// `supportedVersions` intersection decide the era — because reading the verdict needs an accessor
/// `Backend` does not have.
#[tokio::test]
async fn discover_4_era_probe_is_sent_even_when_the_handshake_names_a_modern_version() {
    let fixture = Fixture::new("2026-07-28", MODERN_DISCOVER, EMPTY_TOOLS);
    let backend = fixture.backend("modern-handshake");

    backend.ensure_started().await.expect("backend starts");

    assert_eq!(
        fixture.discover_count(),
        1,
        "starting a backend whose handshake announced 2026-07-28 must still send exactly one \
         server/discover probe; recorded frames were:\n{}",
        fixture.frames()
    );
}

/// DISCOVER.5, caching half — one probe per backend, reused across requests.
///
/// Exact equality is what keeps this honest in both directions: an upper bound (`<= 1`) passes
/// vacuously today, when no probe is sent at all.
#[tokio::test]
async fn discover_5_the_era_is_probed_once_and_reused_across_requests() {
    let fixture = Fixture::new("2025-11-25", MODERN_DISCOVER, EMPTY_TOOLS);
    let backend = fixture.backend("cached-era");

    backend.ensure_started().await.expect("backend starts");
    for _ in 0..3 {
        backend
            .request("tools/list", None)
            .await
            .expect("tools/list answered");
    }

    assert_eq!(
        fixture.discover_count(),
        1,
        "the era must be probed once and cached; three later requests must add no probes. \
         recorded frames were:\n{}",
        fixture.frames()
    );
}

/// DISCOVER.5, re-probe half — a contradicted cached era is probed again.
///
/// The trigger under test is the one that is reachable in this increment: **an answer carrying one
/// of the three 2026 codes while the cached era is Legacy**. The fixture answers the start-path
/// probe `-32601`, which classifies Legacy, then answers a `tools/list` with `-32022` — a 2026
/// code a Legacy-cached peer has no business emitting.
///
/// The design's other trigger — a `-32601` to a request the gateway *shaped because* the cached
/// era is Modern — is deliberately not tested here: modern request shaping is HEADER.9 and is out
/// of scope for this increment, so that precondition cannot be reached and a test for it could
/// never go green.
///
/// The re-probe is detached and the triggering request does not wait for it, so this polls to a
/// bounded deadline rather than reading the log once.
#[tokio::test]
async fn discover_5_a_contradicted_era_is_re_probed() {
    let fixture = Fixture::new(
        "2025-11-25",
        LEGACY_DISCOVER,
        r#""error":{"code":-32022,"message":"Elicitation declined"}"#,
    );
    let backend = fixture.backend("contradicted-era");

    backend.ensure_started().await.expect("backend starts");
    let _ = backend.request("tools/list", None).await;

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut probes = fixture.discover_count();
    while probes < 2 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
        probes = fixture.discover_count();
    }

    assert_eq!(
        probes,
        2,
        "a 2026 error code from a Legacy-cached peer must trigger exactly one re-probe within 5s \
         (a count of 1 means no re-probe ever fired; 0 means no probe fires at all). \
         recorded frames were:\n{}",
        fixture.frames()
    );
}

/// DISCOVER.5, discriminator — a 2026 code re-probes; an ordinary error does not.
///
/// The two backends share one test because the negative half cannot go red alone: "no extra probe
/// fired" is satisfied by zero, and zero is what HEAD does. Paired with the positive half it is
/// red today (nothing probes at all) and still red against the implementation this actually
/// targets — `if response.error.is_some() { reprobe() }`, which test 3 on its own passes.
///
/// The design concedes the gap in its own words on the row this replaces: "nothing probes, so this
/// row passes vacuously on HEAD — recorded as a regression row, not hidden". This is the test that
/// row declined to write.
///
/// Both arms are cached **Legacy** — each start-path probe is answered `-32601` — and only the
/// later `tools/list` answer differs. The design specifies a cached Modern era for the
/// discriminating case; that is deliberately not followed, because the probe that would produce a
/// cached Modern era does not exist yet, so a test behind it could never go green.
#[tokio::test]
async fn discover_5_only_a_2026_code_re_probes_an_ordinary_error_does_not() {
    let contradicted = Fixture::new(
        "2025-11-25",
        LEGACY_DISCOVER,
        r#""error":{"code":-32022,"message":"Elicitation declined"}"#,
    );
    let ordinary = Fixture::new(
        "2025-11-25",
        LEGACY_DISCOVER,
        r#""error":{"code":-32602,"message":"Invalid params"}"#,
    );
    let contradicted_backend = contradicted.backend("differential-contradicted");
    let ordinary_backend = ordinary.backend("differential-ordinary");

    contradicted_backend
        .ensure_started()
        .await
        .expect("backend starts");
    ordinary_backend
        .ensure_started()
        .await
        .expect("backend starts");
    let _ = contradicted_backend.request("tools/list", None).await;
    let _ = ordinary_backend.request("tools/list", None).await;

    // Both halves wait out the same deadline. A re-probe is detached, so a probe that will never
    // fire and one that has not fired yet look identical until the clock runs out — asserting the
    // negative half immediately would pass on a race rather than on the behaviour.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut after_2026_code = contradicted.discover_count();
    let mut after_ordinary_error = ordinary.discover_count();
    while Instant::now() < deadline && !(after_2026_code >= 2 && after_ordinary_error >= 2) {
        tokio::time::sleep(Duration::from_millis(50)).await;
        after_2026_code = contradicted.discover_count();
        after_ordinary_error = ordinary.discover_count();
    }

    assert_eq!(
        after_2026_code,
        2,
        "a 2026 error code from a Legacy-cached peer must trigger exactly one re-probe within 5s; \
         recorded frames were:\n{}",
        contradicted.frames()
    );
    assert_eq!(
        after_ordinary_error,
        1,
        "an ordinary -32602 says nothing about the peer's era and must NOT trigger a re-probe, so \
         the start-path probe must remain the only one; recorded frames were:\n{}",
        ordinary.frames()
    );
}
