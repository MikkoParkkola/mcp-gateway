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
use mcp_gateway::protocol::era::Era;
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
            __DISCOVER_ARM__
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
        let arm = format!(r#"printf '{{"jsonrpc":"2.0","id":%s,{discover}}}\n' "$id""#);
        Self::with_discover_arm(handshake_version, &arm, tools)
    }

    /// A peer that completes `initialize` and then never answers the probe at all.
    ///
    /// `:` is the shell no-op: the request line is still logged by the loop above — so the frame
    /// count still sees the probe — and nothing is written back. This is the only way to reach
    /// `ProbeOutcome::NoAnswer` from a fixture without the fixture deciding anything: silence is
    /// produced by not answering, not by a canned "no answer" payload.
    fn silently_ignoring_discover(handshake_version: &str, tools: &str) -> Self {
        Self::with_discover_arm(handshake_version, ":", tools)
    }

    fn with_discover_arm(handshake_version: &str, discover_arm: &str, tools: &str) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("frames.log");
        let script = dir.path().join("peer.sh");
        let body = FIXTURE
            .replace("__LOG__", &log.display().to_string())
            .replace("__VERSION__", handshake_version)
            .replace("__DISCOVER_ARM__", discover_arm)
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
            allow_cleartext_credentials: false,
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

/// DISCOVER.4, classification half — a peer that rejects the probe is remembered as `Legacy`.
///
/// This is the cell the first four tests deliberately left empty. They prove the gateway *asked*;
/// this proves it *classified*, and neither stands in for the other. It became expressible only
/// when `Backend::cached_era` landed as a reader production itself uses — a `pub` method on a type
/// no test could construct would have been a debug helper wearing a nicer hat.
///
/// Not vacuous in the direction that matters: an implementation that never probes returns `None`
/// here, so this assertion cannot be satisfied by doing nothing.
#[tokio::test]
async fn discover_4_a_peer_that_rejects_the_probe_is_classified_legacy() {
    let fixture = Fixture::new("2025-11-25", LEGACY_DISCOVER, EMPTY_TOOLS);
    let backend = fixture.backend("rejects-probe");

    backend.ensure_started().await.expect("backend starts");

    assert_eq!(
        backend.cached_era().await,
        Some(Era::Legacy),
        "a peer that answered server/discover with -32601 must be classified Legacy and that \
         verdict cached; recorded frames were:\n{}",
        fixture.frames()
    );
}

/// DISCOVER.4, classification half — silence is not a finding, so nothing is cached.
///
/// `ProbeOutcome::NoAnswer` classifies as `Legacy` for the purpose of treating the *next* request
/// and is deliberately not written to the cache (`src/protocol/era.rs`, "Silence is not a finding"
/// — cache only what the peer actually told us), so a briefly-unreachable peer is not pinned to
/// the legacy path for the life of the process.
///
/// The probe-count assertion comes FIRST and is the whole reason this row can fail. `None` is also
/// what a backend nobody probed returns, so the cache assertion alone would pass vacuously against
/// an implementation that never probes at all — the same defect shape as an upper bound that holds
/// at zero. Asserting the probe was sent, and only then that its silence was not remembered, makes
/// the pair falsifiable in both directions.
#[tokio::test]
async fn discover_4_a_probe_that_is_never_answered_caches_nothing() {
    let fixture = Fixture::silently_ignoring_discover("2025-11-25", EMPTY_TOOLS);
    let backend = fixture.backend("never-answers-probe");

    backend.ensure_started().await.expect("backend starts");

    assert_eq!(
        fixture.discover_count(),
        1,
        "a peer that never answers the probe must still have been probed exactly once; recorded \
         frames were:\n{}",
        fixture.frames()
    );
    assert_eq!(
        backend.cached_era().await,
        None,
        "a probe that timed out with no answer must leave the cache empty, so the next request \
         re-probes instead of treating the peer as permanently Legacy; recorded frames were:\n{}",
        fixture.frames()
    );
}

/// DISCOVER.5, restart half — a restarted backend is a new peer, so the belief is discarded.
///
/// The cached era describes the process on the other end of the transport. A restart swaps that
/// process: the peer that answered the first probe is gone, and the one that replaced it may
/// speak a different dialect after an upgrade or a downgrade. Carrying the old verdict across
/// the swap is the gateway asserting something it has not observed about the peer it now has.
///
/// Exact equality, for the same reason the caching test uses it: `>= 1` would pass on a build
/// that never re-probes at all.
#[tokio::test]
async fn discover_5_a_restart_discards_the_cached_era() {
    let fixture = Fixture::new("2025-11-25", MODERN_DISCOVER, EMPTY_TOOLS);
    let backend = fixture.backend("restarted-era");

    backend.ensure_started().await.expect("backend starts");
    backend
        .request("tools/list", None)
        .await
        .expect("tools/list answered before the restart");

    backend.force_restart().await.expect("backend restarts");
    backend
        .request("tools/list", None)
        .await
        .expect("tools/list answered after the restart");

    assert_eq!(
        fixture.discover_count(),
        2,
        "a restart swaps the peer, so the era must be probed again rather than carried over. \
         recorded frames were:\n{}",
        fixture.frames()
    );
}

/// A peer that answers the first probe as modern and every later `server/discover` with
/// `method not found`.
///
/// The marker file is what makes the second answer differ from the first. It is the only way to
/// reach "a cached Modern verdict whose assumption later fails" from a fixture that decides
/// nothing about eras: the change has to come from the peer, not from a canned era value.
fn modern_then_method_not_found_arm() -> String {
    concat!(
        r#"if [ -f "$LOG.probed" ]; then "#,
        r#"printf '{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"Method not found"}}\n' "$id"; "#,
        r#"else : > "$LOG.probed"; "#,
        r#"printf '{"jsonrpc":"2.0","id":%s,"result":{"capabilities":{},"supportedVersions":["2026-07-28"]}}\n' "$id"; "#,
        "fi",
    )
    .to_string()
}

/// DISCOVER.5b, the other direction — a cached Modern verdict is re-probed when it fails.
///
/// The Legacy arm is covered above. This is its mirror: the clause says "the cached assumption
/// fails", which is symmetric, and until this test the Modern half was never re-probed at all.
///
/// Narrow by decision (operator, 2026-09-05): only `-32601 method not found`, and only against a
/// method the 2026 revision defines. A modern peer may reject any other method for its own
/// reasons, and a transport fault or a refused credential is a failure to surface — not evidence
/// about which dialect the peer speaks.
///
/// Frame counting: the start probe is 1, the client's own `server/discover` passthrough is 2, and
/// the re-probe this test exists to prove is 3.
#[tokio::test]
async fn discover_5b_a_failing_modern_assumption_is_re_probed() {
    let fixture = Fixture::with_discover_arm(
        "2026-07-28",
        &modern_then_method_not_found_arm(),
        EMPTY_TOOLS,
    );
    let backend = fixture.backend("contradicted-modern");

    backend.ensure_started().await.expect("backend starts");
    assert_eq!(
        backend.cached_era().await,
        Some(Era::Modern),
        "the start probe answered with a 2026 discovery document, so the peer must be cached \
         Modern before the contradiction; recorded frames were:\n{}",
        fixture.frames()
    );

    let _ = backend.request("server/discover", None).await;

    // The corrected verdict, not the frame, is what this waits on. A frame is recorded when the
    // re-probe is *sent*; the cache is written when its answer comes back, so waiting on the
    // count alone would leave the verdict assertion below racing the store that satisfies it.
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && backend.cached_era().await != Some(Era::Legacy) {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    assert_eq!(
        fixture.discover_count(),
        3,
        "a `method not found` answer to a 2026-only method must drop the cached Modern verdict \
         and trigger exactly one re-probe within 5s (a count of 2 means no re-probe fired); \
         recorded frames were:\n{}",
        fixture.frames()
    );
    assert_eq!(
        backend.cached_era().await,
        Some(Era::Legacy),
        "the re-probe was itself answered `method not found`, which is the honest legacy answer, \
         so the corrected verdict must be Legacy; recorded frames were:\n{}",
        fixture.frames()
    );
}

/// DISCOVER.5b, discriminator — `-32601` on an ordinary method leaves a Modern verdict alone.
///
/// This is the half that keeps the rule narrow. A modern peer is entitled to answer
/// `method not found` to a method it simply does not implement; treating that as proof the peer
/// is not modern would discard a correct verdict on every unimplemented call.
#[tokio::test]
async fn discover_5b_method_not_found_on_an_ordinary_method_does_not_re_probe() {
    let fixture = Fixture::new(
        "2026-07-28",
        MODERN_DISCOVER,
        r#""error":{"code":-32601,"message":"Method not found"}"#,
    );
    let backend = fixture.backend("modern-unimplemented-method");

    backend.ensure_started().await.expect("backend starts");
    let _ = backend.request("tools/list", None).await;

    // A re-probe is detached, so "will never fire" and "has not fired yet" look identical until
    // the clock runs out. The wait is the assertion.
    tokio::time::sleep(Duration::from_secs(2)).await;

    assert_eq!(
        fixture.discover_count(),
        1,
        "`method not found` on tools/list says nothing about the peer's era, so the start-path \
         probe must remain the only one; recorded frames were:\n{}",
        fixture.frames()
    );
    assert_eq!(
        backend.cached_era().await,
        Some(Era::Modern),
        "the cached Modern verdict must survive an unimplemented ordinary method; recorded \
         frames were:\n{}",
        fixture.frames()
    );
}
