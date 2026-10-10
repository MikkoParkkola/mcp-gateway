// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `NFR.OBS.3` — era detection per backend MUST be observable: which era, by
//! what evidence, and when re-probed
//! (`docs/requirements/RELEASE-4.0.0-requirements.md:292`).
//!
//! Written from the reviewed plan at
//! `docs/design/2026-09-04-nfr-obs-3-test-plan.md`, BEFORE the implementation.
//! Every case here fails now. That order is the point: a test written after the
//! code agrees with the code, and one written first agrees with the criterion.
//!
//! Two rules the plan fixes and this file obeys. Every evidence case drives the
//! real probe through a real stdio peer, because a case that builds an
//! observation and asserts its own fields cannot fail. Every read goes through
//! the `gateway_list_servers` response rather than an accessor, because the
//! serialisation gap is exactly what `NFR.OBS.1` and `NFR.OBS.2` were re-opened
//! for.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use mcp_gateway::backend::{Backend, BackendRegistry};
use mcp_gateway::config::{BackendConfig, FailsafeConfig, TransportConfig};
use serde_json::{Value, json};
use tempfile::TempDir;
use tracing::field::{Field, Visit};
use tracing::subscriber::set_global_default;
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
use tracing_subscriber::registry::Registry;

// A shell-script peer on a stalled Windows runner can answer the start probe
// after the 2 s cap; the probe then reads as silence and the era stays
// assumed, so a read that should hit the cache misses (MIK-7774).
#[path = "common/era_probe_cap.rs"]
mod era_probe_cap;
use era_probe_cap::widen_probe_cap;

// ---------------------------------------------------------------------------
// Captured events — the second observability surface
// ---------------------------------------------------------------------------

/// One captured event: its target and its fields, stringified.
#[derive(Clone, Debug)]
struct Record {
    target: String,
    fields: HashMap<String, String>,
}

impl Record {
    fn field(&self, name: &str) -> &str {
        self.fields.get(name).map_or("", String::as_str)
    }
}

fn captured() -> &'static Mutex<Vec<Record>> {
    static BUFFER: OnceLock<Mutex<Vec<Record>>> = OnceLock::new();
    BUFFER.get_or_init(|| Mutex::new(Vec::new()))
}

struct Collector;

impl<S: tracing::Subscriber> Layer<S> for Collector {
    fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, S>) {
        let mut fields = HashMap::new();
        event.record(&mut FieldVisitor(&mut fields));
        captured().lock().expect("buffer").push(Record {
            target: event.metadata().target().to_string(),
            fields,
        });
    }
}

struct FieldVisitor<'a>(&'a mut HashMap<String, String>);

impl Visit for FieldVisitor<'_> {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().to_string(), value.to_string());
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.0.insert(field.name().to_string(), value.to_string());
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.0.insert(field.name().to_string(), value.to_string());
    }
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.0.insert(field.name().to_string(), value.to_string());
    }
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0
            .insert(field.name().to_string(), format!("{value:?}"));
    }
}

/// Serialises the cases: one global subscriber and one shared buffer mean two
/// concurrent cases would read each other's events.
async fn capture_lock() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    static INSTALLED: OnceLock<()> = OnceLock::new();
    let guard = LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    INSTALLED.get_or_init(|| {
        let subscriber = Registry::default()
            .with(Collector)
            .with(tracing::level_filters::LevelFilter::DEBUG);
        set_global_default(subscriber).expect("no other global subscriber in this test binary");
    });
    captured().lock().expect("buffer").clear();
    guard
}

/// Records the gateway emits about what it observed, newest last.
fn observed(name: &str) -> Vec<Record> {
    captured()
        .lock()
        .expect("buffer")
        .iter()
        .filter(|r| r.target == "mcp_gateway::observed" && r.fields.contains_key(name))
        .cloned()
        .collect()
}

/// The one record of its kind, or a failure naming what was actually captured.
fn only(kind: &str) -> Record {
    let found = observed(kind);
    assert_eq!(
        found.len(),
        1,
        "expected exactly one `{kind}` record on target `mcp_gateway::observed`, captured: {:?}",
        captured().lock().expect("buffer")
    );
    found.into_iter().next().expect("checked above")
}

// ---------------------------------------------------------------------------
// The peer — a recorder, not a participant
// ---------------------------------------------------------------------------

/// Logs every received line before answering it, so a frame that produced a
/// response is on disk by the time the caller sees that response. No era logic
/// lives here: the fixture answers the same canned frames whatever the gateway
/// believes, which is what keeps the classification under test.
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

const MODERN_DISCOVER: &str =
    r#""result":{"capabilities":{},"supportedVersions":["2026-07-28","2025-11-25"]}"#;
/// A discovery document that answers, and names no revision we can speak
/// statelessly — the dual-era peer offering only 2025.
const NOT_MODERN_DISCOVER: &str =
    r#""result":{"capabilities":{},"supportedVersions":["2025-11-25"]}"#;
const METHOD_NOT_FOUND: &str = r#""error":{"code":-32601,"message":"Method not found"}"#;
/// `-32022`, which only a 2026-07-28 peer knows how to raise.
const UNSUPPORTED_VERSION: &str =
    r#""error":{"code":-32022,"message":"Unsupported protocol version"}"#;
/// An error carrying no era signal either way.
const OTHER_ERROR: &str = r#""error":{"code":-32000,"message":"Server error"}"#;
const EMPTY_TOOLS: &str = r#""result":{"tools":[]}"#;

struct Fixture {
    _dir: TempDir,
    command: String,
}

impl Fixture {
    /// `discover` is the JSON-RPC payload following the echoed `id` — either
    /// `"result":{...}` or `"error":{...}`.
    fn new(discover: &str) -> Self {
        let arm = format!(r#"printf '{{"jsonrpc":"2.0","id":%s,{discover}}}\n' "$id""#);
        Self::with_discover_arm(&arm)
    }

    /// A peer that completes `initialize` and then never answers the probe.
    ///
    /// `:` is the shell no-op: the request is still logged, and nothing is
    /// written back. This is the only honest route to `no_answer` — silence is
    /// produced by not answering, not by a canned "no answer" payload.
    fn silent() -> Self {
        Self::with_discover_arm(":")
    }

    /// A peer that answers the start probe one way and every later probe
    /// another, and whose ordinary responses carry `-32022` so the first real
    /// request contradicts a legacy verdict and triggers the re-probe.
    ///
    /// An empty `later` is silence, which is how the second transition reaches
    /// `no_answer` from a backend that had already answered once.
    fn reprobing(first: &str, later: &str) -> Self {
        let discover_arm = format!(
            "if [ -f \"$LOG.probed\" ]; then {}; else : > \"$LOG.probed\"; {}; fi",
            Self::arm(later),
            Self::arm(first)
        );
        Self::with_arms(&discover_arm, UNSUPPORTED_VERSION)
    }

    /// A discover arm answering `payload`, or the shell no-op for silence.
    fn arm(payload: &str) -> String {
        if payload.is_empty() {
            ":".to_string()
        } else {
            format!(r#"printf '{{"jsonrpc":"2.0","id":%s,{payload}}}\n' "$id""#)
        }
    }

    fn with_discover_arm(discover_arm: &str) -> Self {
        Self::with_arms(discover_arm, EMPTY_TOOLS)
    }

    fn with_arms(discover_arm: &str, tools: &str) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("frames.log");
        let script = dir.path().join("peer.sh");
        let body = FIXTURE
            .replace("__LOG__", &log.display().to_string())
            .replace("__VERSION__", "2025-11-25")
            .replace("__DISCOVER_ARM__", discover_arm)
            .replace("__TOOLS__", tools);
        std::fs::write(&script, body).expect("write fixture");
        Self {
            _dir: dir,
            command: format!("sh {}", script.display()),
        }
    }

    fn backend(&self, name: &str) -> Backend {
        widen_probe_cap();
        let config = BackendConfig {
            description: format!("era observability fixture: {name}"),
            enabled: true,
            transport: TransportConfig::Stdio {
                command: self.command.clone(),
                cwd: None,
                protocol_version: None,
            },
            // No reaper: an idle sweep mid-test would restart the peer and
            // re-probe it, moving the very fields under assertion.
            stop_when_idle_for: None,
            max_frame_bytes: None,
            timeout: Duration::from_secs(30),
            env: HashMap::default(),
            headers: HashMap::default(),
            oauth: None,
            secrets: Vec::new(),
            // Every other field keeps its default.
            ..BackendConfig::default()
        };
        Backend::new(
            name,
            config,
            &FailsafeConfig::default(),
            Duration::from_secs(300),
        )
    }
}

// ---------------------------------------------------------------------------
// The read — through the router, never through an accessor
// ---------------------------------------------------------------------------

#[path = "nfr_obs_3_era_observability/read.rs"]
mod read;

/// The entry for one backend, or a failure naming what the response did carry.
fn entry(servers: &[Value], name: &str) -> Value {
    servers
        .iter()
        .find(|s| s["name"] == name)
        .unwrap_or_else(|| panic!("no `{name}` entry in {servers:?}"))
        .clone()
}

/// The five operator-read fields, absences included, as one comparable value.
///
/// A whole snapshot rather than five assertions: an `era` from the latest probe
/// beside an `era_evidence` from the previous one is internally inconsistent,
/// and no per-field assertion sees that.
fn snapshot(entry: &Value) -> Value {
    let mut fields = serde_json::Map::new();
    for name in [
        "era",
        "era_source",
        "era_evidence",
        "era_probe_trigger",
        "era_probed_at",
    ] {
        if let Some(value) = entry.get(name) {
            fields.insert(name.to_string(), value.clone());
        }
    }
    Value::Object(fields)
}

/// Starts one backend against `fixture`, then reads it back off the wire.
async fn probe_and_read(fixture: &Fixture, name: &str) -> Value {
    let backends = Arc::new(BackendRegistry::new());
    let backend = Arc::new(fixture.backend(name));
    assert!(
        backends.register(Arc::clone(&backend)),
        "backend must register"
    );
    backend
        .ensure_started()
        .await
        .unwrap_or_else(|e| panic!("backend must start: {e}"));
    let servers = read::servers(backends).await;
    entry(&servers, name)
}

/// Rides every row of the matrix: the raw JSON-RPC code is an event field, and
/// a read that leaks it has widened the operator surface past what the design
/// fixed — which no positive assertion in the matrix would notice.
fn assert_no_error_code(entry: &Value) {
    assert!(
        entry.get("error_code").is_none(),
        "the operator read must not carry the raw error code: {entry}"
    );
}

// ---------------------------------------------------------------------------
// (a) The evidence matrix — one case per `EraEvidence` variant
// ---------------------------------------------------------------------------

/// A backend that has never been probed reads as an assumption, not a finding.
///
/// It observes a backend that was never probed rather than one whose
/// observation was reset: a reset reaches the same values by a path the
/// criterion does not describe.
#[tokio::test]
async fn never_probed_reads_as_an_assumed_legacy_era() {
    let _guard = capture_lock().await;
    let fixture = Fixture::new(MODERN_DISCOVER);
    let backends = Arc::new(BackendRegistry::new());
    assert!(
        backends.register(Arc::new(fixture.backend("unstarted"))),
        "backend must register"
    );

    // Deliberately not started: the probe runs on the start path.
    let servers = read::servers(backends).await;
    let entry = entry(&servers, "unstarted");

    assert_eq!(
        snapshot(&entry),
        json!({
            "era": "legacy",
            "era_source": "assumed",
            "era_evidence": "never_probed",
        }),
        "an unprobed backend reads as assumed, with no trigger and no time: {entry}"
    );
    assert_no_error_code(&entry);
}

/// A discovery document naming a revision we can speak statelessly.
#[tokio::test]
async fn a_modern_discovery_document_reads_as_discover_modern() {
    let _guard = capture_lock().await;
    let fixture = Fixture::new(MODERN_DISCOVER);
    let entry = probe_and_read(&fixture, "modern-doc").await;

    assert_eq!(entry["era"], "modern", "read: {entry}");
    assert_eq!(entry["era_source"], "probed", "read: {entry}");
    assert_eq!(entry["era_evidence"], "discover_modern", "read: {entry}");
    assert_eq!(entry["era_probe_trigger"], "start", "read: {entry}");
    assert!(
        entry.get("era_probed_at").is_some(),
        "a completed probe stamps a time: {entry}"
    );
    assert_no_error_code(&entry);
}

/// A discovery document that answers and names no speakable revision.
#[tokio::test]
async fn a_dual_era_discovery_document_reads_as_discover_not_modern() {
    let _guard = capture_lock().await;
    let fixture = Fixture::new(NOT_MODERN_DISCOVER);
    let entry = probe_and_read(&fixture, "not-modern-doc").await;

    assert_eq!(entry["era"], "legacy", "read: {entry}");
    assert_eq!(entry["era_source"], "probed", "read: {entry}");
    assert_eq!(
        entry["era_evidence"], "discover_not_modern",
        "read: {entry}"
    );
    assert_eq!(entry["era_probe_trigger"], "start", "read: {entry}");
    assert!(entry.get("era_probed_at").is_some(), "read: {entry}");
    assert_no_error_code(&entry);
}

/// `-32022` — an error only a modern peer knows how to raise.
///
/// Also the case that pins the design's "one enum, both readers" property: the
/// event's `evidence` is compared against the read's, not against a literal,
/// because two literals let the surfaces drift while both suites stay green.
#[tokio::test]
async fn a_modern_only_error_code_reads_as_modern_error_code() {
    let _guard = capture_lock().await;
    let fixture = Fixture::new(UNSUPPORTED_VERSION);
    let entry = probe_and_read(&fixture, "modern-error").await;

    assert_eq!(entry["era"], "modern", "read: {entry}");
    assert_eq!(entry["era_source"], "probed", "read: {entry}");
    assert_eq!(entry["era_evidence"], "modern_error_code", "read: {entry}");
    assert_eq!(entry["era_probe_trigger"], "start", "read: {entry}");
    assert!(entry.get("era_probed_at").is_some(), "read: {entry}");
    assert_no_error_code(&entry);

    let event = only("evidence");
    assert_eq!(
        Value::from(event.field("evidence")),
        entry["era_evidence"],
        "event and read must name the same evidence: {event:?} vs {entry}"
    );
    assert_eq!(
        event.field("error_code"),
        "-32022",
        "the raw code belongs on the event: {event:?}"
    );
}

/// `-32601` — the honest legacy answer to a method the peer does not implement.
#[tokio::test]
async fn method_not_found_reads_as_method_not_found() {
    let _guard = capture_lock().await;
    let fixture = Fixture::new(METHOD_NOT_FOUND);
    let entry = probe_and_read(&fixture, "method-not-found").await;

    assert_eq!(entry["era"], "legacy", "read: {entry}");
    assert_eq!(entry["era_source"], "probed", "read: {entry}");
    assert_eq!(entry["era_evidence"], "method_not_found", "read: {entry}");
    assert_eq!(entry["era_probe_trigger"], "start", "read: {entry}");
    assert!(entry.get("era_probed_at").is_some(), "read: {entry}");
    assert_no_error_code(&entry);

    let event = only("evidence");
    assert_eq!(
        Value::from(event.field("evidence")),
        entry["era_evidence"],
        "event and read must name the same evidence: {event:?} vs {entry}"
    );
}

/// An error carrying no era signal is not evidence of modernity.
#[tokio::test]
async fn an_unrelated_error_code_reads_as_other_error() {
    let _guard = capture_lock().await;
    let fixture = Fixture::new(OTHER_ERROR);
    let entry = probe_and_read(&fixture, "other-error").await;

    assert_eq!(entry["era"], "legacy", "read: {entry}");
    assert_eq!(entry["era_source"], "probed", "read: {entry}");
    assert_eq!(entry["era_evidence"], "other_error", "read: {entry}");
    assert_eq!(entry["era_probe_trigger"], "start", "read: {entry}");
    assert!(entry.get("era_probed_at").is_some(), "read: {entry}");
    assert_no_error_code(&entry);

    let event = only("evidence");
    assert_eq!(
        Value::from(event.field("evidence")),
        entry["era_evidence"],
        "event and read must name the same evidence: {event:?} vs {entry}"
    );
}

/// Silence — the regression row.
///
/// The only case where `era_source` is `assumed` while `era_probed_at` is set.
/// An implementation that marks the era `probed` whenever a probe *completes*
/// passes every other row in this matrix and fails only here.
#[tokio::test]
async fn a_probe_that_gets_no_answer_stays_assumed_while_stamping_a_time() {
    let _guard = capture_lock().await;
    let fixture = Fixture::silent();
    let entry = probe_and_read(&fixture, "silent").await;

    assert_eq!(entry["era"], "legacy", "read: {entry}");
    assert_eq!(
        entry["era_source"], "assumed",
        "silence is not a finding, so the era stays assumed: {entry}"
    );
    assert_eq!(entry["era_evidence"], "no_answer", "read: {entry}");
    assert_eq!(entry["era_probe_trigger"], "start", "read: {entry}");
    assert!(
        entry.get("era_probed_at").is_some(),
        "the probe ran, so its time is known even though its answer is not: {entry}"
    );
    assert_no_error_code(&entry);
}

/// RFC 3339, UTC, second precision, `Z` suffix — asserted once.
///
/// Once rather than per row: asserting it everywhere tests the fixture, and
/// asserting it nowhere leaves the design's stated format unenforced.
#[tokio::test]
async fn the_probe_time_is_rfc_3339_utc_at_second_precision() {
    let _guard = capture_lock().await;
    let fixture = Fixture::new(MODERN_DISCOVER);
    let entry = probe_and_read(&fixture, "timestamp").await;
    let stamp = entry["era_probed_at"]
        .as_str()
        .unwrap_or_else(|| panic!("era_probed_at must be a string: {entry}"));

    let parsed = chrono::DateTime::parse_from_rfc3339(stamp)
        .unwrap_or_else(|e| panic!("era_probed_at must be RFC 3339: {stamp} ({e})"));
    assert!(
        stamp.ends_with('Z'),
        "the time must be UTC with a `Z` suffix, not an offset: {stamp}"
    );
    assert_eq!(
        stamp,
        parsed
            .with_timezone(&chrono::Utc)
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "second precision, so two reads compare as times not formats: {stamp}"
    );
}

#[path = "nfr_obs_3_era_observability/reprobe_and_records.rs"]
mod reprobe_and_records;
